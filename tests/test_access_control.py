"""默认拒绝的权限判定：角色×资源范围；不泄漏资源存在性。"""
from __future__ import annotations

from app.errors import ErrorCode


def _login(api, name, role):
    api.register(name, roles=[role] if role else None)
    api.login(name)


def test_default_deny_no_roles(api):
    _login(api, "norole", None)
    r = api.post("/access/resource",
                 json_body={"resource": "docs/x", "action": "read"})
    assert r.status_code == 403
    assert r.json()["reason"] == ErrorCode.FORBIDDEN.value


def test_viewer_cannot_write_or_escape_scope(api, audit):
    _login(api, "alice", "viewer")
    # 越权写
    r = api.post("/access/resource",
                 json_body={"resource": "docs/x", "action": "write"})
    assert r.status_code == 403 and r.json()["reason"] == "FORBIDDEN"
    # 跳出资源范围
    r2 = api.post("/access/resource",
                  json_body={"resource": "secret/x", "action": "read"})
    assert r2.status_code == 403
    # 前缀边界：docs-evil 不属于 docs/ 前缀
    r3 = api.post("/access/resource",
                  json_body={"resource": "docs-evil", "action": "read"})
    assert r3.status_code == 403
    basis = [r.fields["decision_basis"] for r in audit.records()
             if r.event == "ACCESS_DENIED"]
    assert all(b.startswith("default_deny") for b in basis)


def test_allowed_path_audited_with_basis(api, audit):
    _login(api, "alice", "viewer")
    r = api.post("/access/resource",
                 json_body={"resource": "docs/a/b", "action": "read"})
    assert r.status_code == 200
    rec = [r for r in audit.records() if r.event == "ACCESS_ALLOWED"][-1]
    assert "role_scope_match" in rec.fields["decision_basis"]


def test_client_supplied_roles_ignored(api):
    # 注册成无角色；请求体里塞 roles/admin 也无法提权
    api.register("sneaky")
    api.login("sneaky")
    for payload in (
        {"resource": "anything", "action": "admin", "roles": ["admin"]},
        {"resource": "anything", "action": "admin", "scope": "",
         "is_admin": True},
    ):
        r = api.post("/access/resource", json_body=payload)
        assert r.status_code == 403, r.text


def test_nonexistent_vs_forbidden_indistinguishable(api):
    _login(api, "alice", "viewer")
    # 无权资源与"不存在资源"返回完全同构
    r1 = api.post("/access/resource",
                  json_body={"resource": "secret/db", "action": "read"})
    r2 = api.post("/access/resource",
                  json_body={"resource": "secret/does-not-exist",
                             "action": "read"})
    assert r1.status_code == r2.status_code == 403
    assert r1.json() == r2.json()


def test_admin_wildcard_scope(api):
    api.provision("root", roles=("admin",))
    api.login("root")
    r = api.post("/access/resource",
                 json_body={"resource": "anything/deep", "action": "admin"})
    assert r.status_code == 200


def test_self_service_cannot_register_admin(api, audit):
    """特权角色不得通过自助注册获取（防垂直越权）。"""
    r = api.register("evil", roles=["admin"])
    assert r.status_code == 403
    assert r.json()["reason"] == ErrorCode.FORBIDDEN.value
    # 即使注册被拒，也不应落库
    assert api.c.app.state.services.store.get_user("evil") is None
    denials = [x for x in audit.records()
               if x.fields.get("decision_basis", "").startswith(
                   "self_service_role_denied")]
    assert denials


def test_admin_can_grant_role_and_it_invalidates_sessions(api):
    api.register("alice")                 # 无角色
    api.login("alice")
    alice_sid = api.session_id
    # viewer 自助注册管理员账号做授权人
    api.provision("root", roles=("admin",))
    api.login("root")
    r = api.post("/admin/users/alice/roles",
                 json_body={"roles": ["viewer"]})
    assert r.status_code == 200, r.text
    # 角色变更立即让 alice 旧会话失效
    r2 = api.c.post("/access/resource",
                    json={"resource": "docs/x", "action": "read"},
                    headers={"X-Session-Id": alice_sid})
    assert r2.status_code == 401
    assert r2.json()["reason"] in ("SESSION_REPLAYED", "SESSION_INVALIDATED")
    # 非管理员不能授角
    api.register("bob")
    api.login("bob")
    r3 = api.post("/admin/users/bob/roles", json_body={"roles": ["admin"]})
    assert r3.status_code == 403


def test_json_and_form_entries_consistent(api):
    _login(api, "alice", "viewer")
    body = {"resource": "secret/x", "action": "read"}
    rj = api.post("/access/resource", json_body=body, with_csrf=False)
    rf = api.post("/access/resource-form", data=body, with_csrf=False)
    assert rj.status_code == rf.status_code == 403
    assert rj.json()["reason"] == rf.json()["reason"] == "FORBIDDEN"


def test_mfa_pending_session_cannot_access(api):
    from app.security.totp import current_step, generate_code
    api.register("alice", roles=["viewer"])
    # 先登录、绑定 MFA
    api.login("alice")
    r = api.post("/mfa/enroll/start")
    secret = r.json()["secret"]
    import tests.conftest  # noqa
    api.post("/mfa/enroll/confirm",
             json_body={"code": generate_code(
                 secret, current_step(api.c.app.state.services.time.now(), 30))})
    # 再次登录停在 MFA 待确认
    api.login("alice")
    r = api.post("/access/resource",
                 json_body={"resource": "docs/x", "action": "read"})
    assert r.status_code == 403
    assert r.json()["reason"] == "SESSION_CONFIRMATION_PENDING"
