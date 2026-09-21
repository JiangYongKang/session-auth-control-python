"""CSRF：缺失/过期/跨会话复用/跨来源全部拒绝；令牌一次性。"""
from authapp.errors import ErrorCode


def _login_member(client):
    r = client.post("/auth/login", json={"username": "bob", "password": "password123"})
    assert r.status_code == 200


def _seed(svc):
    svc.register("bob", "password123", roles=["member"])


def test_state_change_requires_csrf(client, svc, origin):
    _seed(svc)
    _login_member(client)
    # 无令牌
    r = client.post("/api/resource/app/self", headers={"origin": origin}, json={})
    assert r.status_code == 403 and r.json()["error"]["code"] == ErrorCode.CSRF_MISSING.value
    # 无来源
    r = client.post("/api/resource/app/self", json={})
    assert r.status_code == 403 and r.json()["error"]["code"] == ErrorCode.CSRF_ORIGIN_MISMATCH.value
    # 来源不可信
    r = client.post(
        "/api/resource/app/self",
        headers={"origin": "https://evil.example", "x-csrf-token": "t"},
        json={},
    )
    assert r.status_code == 403 and r.json()["error"]["code"] == ErrorCode.CSRF_ORIGIN_MISMATCH.value
    # 令牌未知
    r = client.post(
        "/api/resource/app/self",
        headers={"origin": origin, "x-csrf-token": "nope"},
        json={},
    )
    assert r.status_code == 403 and r.json()["error"]["code"] == ErrorCode.CSRF_INVALID.value


def test_csrf_token_single_use_replay_fails(client, svc, origin):
    _seed(svc)
    _login_member(client)
    token = client.get("/auth/csrf").json()["csrf_token"]
    headers = {"origin": origin, "x-csrf-token": token}
    assert client.post("/api/resource/app/self", headers=headers, json={}).status_code == 200
    # 重放已消费令牌
    r = client.post("/api/resource/app/self", headers=headers, json={})
    assert r.status_code == 403 and r.json()["error"]["code"] == ErrorCode.CSRF_INVALID.value


def test_csrf_token_rejected_from_other_session(client, svc, origin):
    _seed(svc)
    svc.register("root", "rootpassword1", roles=["admin"])
    # bob 会话申领令牌
    _login_member(client)
    bob_token = client.get("/auth/csrf").json()["csrf_token"]
    # 另一客户端（root 会话）偷用 bob 的令牌
    other = type(client)(client.app)
    r = other.post("/auth/login", json={"username": "root", "password": "rootpassword1"})
    assert r.status_code == 200
    r = other.post(
        "/api/resource/app/self",
        headers={"origin": origin, "x-csrf-token": bob_token},
        json={},
    )
    assert r.status_code == 403
    assert r.json()["error"]["code"] == ErrorCode.CSRF_SESSION_MISMATCH.value


def test_csrf_token_expiry(client, svc, clock, origin):
    _seed(svc)
    _login_member(client)
    token = client.get("/auth/csrf").json()["csrf_token"]
    clock.advance(svc.config.csrf_token_ttl_seconds + 1)
    # 会话 TTL 默认大于 CSRF TTL，因此这里是令牌先过期
    r = client.post(
        "/api/resource/app/self",
        headers={"origin": origin, "x-csrf-token": token},
        json={},
    )
    assert r.status_code == 403 and r.json()["error"]["code"] == ErrorCode.CSRF_EXPIRED.value


def test_csrf_needed_on_all_mutating_endpoints(client, svc, origin):
    """改密、绑定确认、解绑、管理员建户等有状态变更均必须过 CSRF。"""
    svc.register("root", "rootpassword1", roles=["admin"])
    client.post("/auth/login", json={"username": "root", "password": "rootpassword1"})
    for path, body in [
        ("/auth/password", {"old_password": "rootpassword1", "new_password": "another-pw-1"}),
        ("/auth/mfa/unbind", {"code": "123456"}),
        ("/admin/users", {"username": "x", "password": "password123", "roles": []}),
    ]:
        r = client.post(path, headers={"origin": origin}, json=body)
        assert r.status_code == 403 and r.json()["error"]["code"] == ErrorCode.CSRF_MISSING.value, path
