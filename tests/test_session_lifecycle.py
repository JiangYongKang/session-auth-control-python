"""会话生命周期：标识轮换防固定、登出/过期后不可重放复活。"""
from __future__ import annotations

from app.errors import ErrorCode


def test_explicit_rotation_revokes_old_id(api):
    api.register("alice", roles=["viewer"])
    api.login("alice")
    old = api.session_id
    r = api.post("/auth/rotate")
    assert r.status_code == 200, r.text
    new = r.json()["session_id"]
    assert new != old

    # 旧标识立即失效，且判定为"重放已撤销标识"
    r1 = api.post("/access/resource",
                  json_body={"resource": "docs/x", "action": "read"},
                  raw_session=old, with_csrf=False)
    assert r1.status_code == 401
    assert r1.json()["reason"] == ErrorCode.SESSION_REPLAYED.value

    # 新标识可用
    api.adopt(new, r.json()["csrf_token"])
    r2 = api.post("/access/resource",
                  json_body={"resource": "docs/x", "action": "read"})
    assert r2.status_code == 200, r2.text


def test_logout_then_replay_not_resurrected(api):
    api.register("alice")
    api.login("alice")
    sid = api.session_id
    assert api.post("/auth/logout").status_code == 200
    for _ in range(3):  # 重放多次
        r = api.post("/access/resource",
                     json_body={"resource": "docs/x", "action": "read"},
                     raw_session=sid, with_csrf=False)
        assert r.status_code == 401
        assert r.json()["reason"] == ErrorCode.SESSION_REPLAYED.value


def test_unknown_session_id_distinct_from_replay(api):
    r = api.post("/access/resource",
                 json_body={"resource": "docs/x", "action": "read"},
                 raw_session="ab" * 32, with_csrf=False)
    assert r.status_code == 401
    assert r.json()["reason"] == ErrorCode.UNAUTHENTICATED.value


def test_session_idle_expiry(api, time_source):
    api.register("alice")
    api.login("alice")
    time_source.advance(1801)  # idle_timeout 默认 1800s
    r = api.post("/access/resource",
                 json_body={"resource": "docs/x", "action": "read"})
    assert r.status_code == 401
    assert r.json()["reason"] == ErrorCode.SESSION_EXPIRED.value
    # 过期后标识进入墓碑：再次使用被判重放，不会复活
    r2 = api.post("/access/resource",
                  json_body={"resource": "docs/x", "action": "read"})
    assert r2.json()["reason"] == ErrorCode.SESSION_REPLAYED.value


def test_session_absolute_expiry(api, time_source):
    api.register("alice")
    api.login("alice")
    # 持续活动也无法越过绝对过期
    time_source.advance(28801)
    r = api.post("/access/resource",
                 json_body={"resource": "docs/x", "action": "read"})
    assert r.json()["reason"] == ErrorCode.SESSION_EXPIRED.value


def test_mfa_enrollment_invalidates_existing_session(api, time_source):
    from app.security.totp import current_step, generate_code
    api.register("alice")
    api.login("alice")
    sid = api.session_id
    # 开始绑定
    r = api.post("/mfa/enroll/start")
    assert r.status_code == 200
    secret = r.json()["secret"]
    code = generate_code(secret, current_step(time_source.now(), 30))
    r = api.post("/mfa/enroll/confirm", json_body={"code": code})
    assert r.status_code == 200, r.text
    # 安全状态变化：旧会话立即作废
    r2 = api.post("/access/resource",
                  json_body={"resource": "docs/x", "action": "read"},
                  raw_session=sid, with_csrf=False)
    assert r2.json()["reason"] == ErrorCode.SESSION_INVALIDATED.value


def test_logout_all_endpoint_invalidates_every_session(api):
    api.register("alice")
    b1 = api.c.post("/auth/login",
                    json={"username": "alice", "password": "Sup3rSecret"},
                    headers={"Origin": "http://testserver"}).json()
    b2 = api.c.post("/auth/login",
                    json={"username": "alice", "password": "Sup3rSecret"},
                    headers={"Origin": "http://testserver"}).json()
    api.adopt(b1["session_id"], b1["csrf_token"])
    r = api.post("/auth/logout-all")
    assert r.status_code == 200, r.text
    assert r.json()["sessions_invalidated"] == 2
    for sid in (b1["session_id"], b2["session_id"]):
        rr = api.c.post("/access/resource",
                        json={"resource": "docs/x", "action": "read"},
                        headers={"X-Session-Id": sid})
        assert rr.json()["reason"] in ("SESSION_REPLAYED",
                                       "SESSION_INVALIDATED")
