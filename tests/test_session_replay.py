"""会话生命周期与重放：标识轮换、登出/过期后旧标识不可复活。"""
import pytest

from authapp.errors import ErrorCode
from authapp.security.totp import code_at


def _login(client, username, password):
    r = client.post("/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return client.cookies.get("sid")


def test_login_rotates_identifier_and_old_id_cannot_be_replayed(client, svc):
    svc.register("alice", "password123", roles=["member"])
    sid1 = _login(client, "alice", "password123")
    sid2 = _login(client, "alice", "password123")  # 登录成功即换新标识
    assert sid1 != sid2
    # 旧标识已在登录临界区删除：重放得到“不存在”，无法复活
    client.cookies.clear(); client.cookies.set("sid", sid1)
    r = client.get("/auth/me")
    assert r.status_code == 401 and r.json()["error"]["code"] == "unauthenticated"
    # 当前新标识有效；登出后同样不可复活
    client.cookies.clear(); client.cookies.set("sid", sid2)
    assert client.get("/auth/me").status_code == 200
    client.post("/auth/logout")
    client.cookies.clear(); client.cookies.set("sid", sid2)
    r = client.get("/auth/me")
    assert r.status_code == 401 and r.json()["error"]["code"] == "unauthenticated"


def test_mfa_login_rotates_id_and_old_pending_id_is_dead(client, svc):
    """会话固定防护：登录升级（MFA 通过）必须更换标识，旧标识立即失效。"""
    svc.register("alice", "password123", roles=["member"])
    client.post("/auth/login", json={"username": "alice", "password": "password123"})
    # 服务层绑定 MFA
    with svc.store.lock():
        user = svc.store.get_user("alice")
        secret, _ = svc.mfa.begin_bind(user)
        svc.mfa.confirm_bind(user, secret, code_at(secret, svc.clock.now()))
    client.post("/auth/login", json={"username": "alice", "password": "password123"})
    pending = client.cookies.get("sid")
    code = code_at(secret, svc.clock.now())
    r = client.post("/auth/mfa", json={"code": code})
    assert r.status_code == 200
    upgraded = client.cookies.get("sid")
    assert upgraded != pending
    # 旧的待二因素标识重放：已物理删除，无法复活
    client.cookies.clear(); client.cookies.set("sid", pending)
    r = client.get("/auth/me")
    assert r.status_code == 401 and r.json()["error"]["code"] == "unauthenticated"


def test_logout_then_replay_old_session_fails(client, svc):
    svc.register("alice", "password123", roles=["member"])
    sid = _login(client, "alice", "password123")
    assert client.post("/auth/logout").status_code == 200
    client.cookies.clear(); client.cookies.set("sid", sid)
    r = client.get("/auth/me")
    assert r.status_code == 401 and r.json()["error"]["code"] == "unauthenticated"
    assert client.post("/auth/logout").status_code == 200  # 幂等
    r = client.get("/auth/me")
    assert r.status_code == 401


def test_expired_session_cannot_be_resurrected(client, svc, clock):
    svc.register("alice", "password123", roles=["member"])
    sid = _login(client, "alice", "password123")
    clock.advance(svc.config.session_ttl_seconds + 1)
    r = client.get("/auth/me")
    assert r.status_code == 401
    assert r.json()["error"]["code"] == ErrorCode.SESSION_EXPIRED.value
    client.cookies.clear(); client.cookies.set("sid", sid)
    r = client.get("/auth/me")
    assert r.status_code == 401
    assert r.json()["error"]["code"] == ErrorCode.UNAUTHENTICATED.value


def test_password_change_revokes_all_sessions_atomically(client, svc, origin):
    svc.register("alice", "password123", roles=["member"])
    s1 = _login(client, "alice", "password123")
    s2 = _login(client, "alice", "password123")
    token = client.get("/auth/csrf").json()["csrf_token"]
    r = client.post(
        "/auth/password",
        headers={"x-csrf-token": token, "origin": origin},
        json={"old_password": "password123", "new_password": "newpassword456"},
    )
    assert r.status_code == 200
    for sid in (s1, s2):
        record = svc.store.get_session(sid)
        assert record is None or record.revoked
        client.cookies.clear(); client.cookies.set("sid", sid)
        r = client.get("/auth/me")
        assert r.status_code == 401
        assert r.json()["error"]["code"] in (
            ErrorCode.SESSION_REVOKED.value,
            ErrorCode.UNAUTHENTICATED.value,
        )
    r = client.post("/auth/login", json={"username": "alice", "password": "password123"})
    assert r.status_code == 401  # 旧口令失效


def test_epoch_mismatch_revokes_session(svc):
    svc.register("alice", "password123", roles=["member"])
    sid = svc.login("alice", "password123")["session"]
    with svc.store.lock():
        user = svc.store.get_user("alice")
        user.auth_epoch += 1
        svc.store.put_user(user)
    with pytest.raises(Exception) as ei:
        svc.authenticate(sid)
    assert ei.value.code == ErrorCode.SESSION_REVOKED
    with pytest.raises(Exception) as ei2:
        svc.authenticate(sid)  # 已登出，不可复活
    assert ei2.value.code == ErrorCode.UNAUTHENTICATED
