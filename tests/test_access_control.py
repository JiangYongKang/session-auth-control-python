"""默认拒绝的权限判定：越权访问、伪造角色/范围、资源存在性不泄漏。"""
from authapp.errors import ErrorCode


def _login(client, username, password):
    r = client.post("/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text


def _bootstrap(svc):
    svc.register("root", "rootpassword1", roles=["admin"])
    svc.register("aud", "audpassword1", roles=["auditor"])
    svc.register("bob", "password123", roles=["member"])
    svc.register("nobody", "password123", roles=[])


def test_self_service_register_ignores_client_claimed_roles(client, svc, origin):
    # 请求体里即使塞 roles 字段，Pydantic 模型会丢弃；服务端也显式传 None
    r = client.post(
        "/auth/register",
        json={"username": "x", "password": "password123", "roles": ["admin"]},
    )
    assert r.status_code == 201
    _login(client, "x", "password123")
    me = client.get("/auth/me").json()
    assert me["roles"] == []
    r = client.get("/api/resource/admin/audit")
    assert r.status_code == 403 and r.json()["error"]["code"] == ErrorCode.FORBIDDEN.value


def test_member_cannot_reach_admin_resources(client, svc):
    _bootstrap(svc)
    _login(client, "bob", "password123")
    for resource in ("admin/audit", "admin/sessions", "admin/users"):
        r = client.get(f"/api/resource/{resource}")
        assert r.status_code == 403, resource
        assert r.json()["error"]["code"] == ErrorCode.FORBIDDEN.value


def test_auditor_is_read_only_and_scoped(client, svc, origin):
    _bootstrap(svc)
    _login(client, "aud", "audpassword1")
    assert client.get("/api/resource/admin/audit").status_code == 200
    # 写操作即便资源属于其可读范围也拒绝
    r = client.post("/api/resource/admin/audit", json={})
    # 先被 CSRF 拦截；带 CSRF 后仍应被权限拒绝
    assert r.status_code == 403
    token = client.get("/auth/csrf").json()["csrf_token"]
    r = client.post(
        "/api/resource/admin/audit",
        headers={"origin": origin, "x-csrf-token": token},
        json={},
    )
    assert r.status_code == 403 and r.json()["error"]["code"] == ErrorCode.FORBIDDEN.value
    # 审计不能访问应用资源
    assert client.get("/api/resource/app/self").status_code == 403


def test_admin_wildcard_within_known_resources(client, svc):
    _bootstrap(svc)
    _login(client, "root", "rootpassword1")
    for resource in ("admin/audit", "app/self", "app/public"):
        assert client.get(f"/api/resource/{resource}").status_code == 200, resource


def test_missing_resource_indistinguishable_from_forbidden(client, svc):
    _bootstrap(svc)
    _login(client, "root", "rootpassword1")
    # 即使是管理员，未知资源也返回 403，与“无权限”不可区分
    r1 = client.get("/api/resource/this/does/not/exist")
    client.cookies.clear()
    _login(client, "bob", "password123")
    r2 = client.get("/api/resource/admin/audit")
    assert r1.status_code == r2.status_code == 403
    assert r1.json() == r2.json()


def test_no_role_is_denied_everything(client, svc):
    _bootstrap(svc)
    _login(client, "nobody", "password123")
    for resource in ("app/public", "app/self", "admin/audit"):
        assert client.get(f"/api/resource/{resource}").status_code == 403


def test_unauthenticated_requests_are_denied(client, svc):
    r = client.get("/api/resource/app/public")
    assert r.status_code == 401 and r.json()["error"]["code"] == ErrorCode.UNAUTHENTICATED.value


def test_server_side_role_change_takes_effect_immediately(svc):
    """服务端角色调整即时生效；权限永不读取客户端提交值。"""
    svc.register("bob", "password123", roles=["member"])
    sid = svc.login("bob", "password123")["session"]
    svc.authorize(sid, "read", "app/self")  # 允许
    with svc.store.lock():
        user = svc.store.get_user("bob")
        user.roles = []
        svc.store.put_user(user)
    import pytest
    from authapp.errors import AuthError
    with pytest.raises(AuthError) as ei:
        svc.authorize(sid, "read", "app/self")
    assert ei.value.code == ErrorCode.FORBIDDEN
