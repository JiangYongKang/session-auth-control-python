"""端到端集成：注册 -> 登录 -> MFA -> CSRF 写 -> 越权拒绝 -> 登出重放。"""
from authapp.security.totp import code_at
from tests.conftest import verdict


def test_full_journey_with_mfa_and_csrf(client, svc, origin, audit_buf):
    # 0) 管理员受控开通 member 用户（角色只来自服务端）
    svc.register("root", "rootpassword1", roles=["admin"])
    svc.register("alice", "password123", roles=["member"])
    # 1) 登录 + 引导 MFA
    client.post("/auth/login", json={"username": "alice", "password": "password123"})
    with svc.store.lock():
        user = svc.store.get_user("alice")
        secret, _ = svc.mfa.begin_bind(user)
        svc.mfa.confirm_bind(user, secret, code_at(secret, svc.clock.now()))

    # 2) 登录进入待二因素
    r = client.post("/auth/login", json={"username": "alice", "password": "password123"})
    assert r.json()["status"] == "mfa_required"
    assert client.get("/auth/me").status_code == 401

    # 3) MFA 通过并换标识
    code = code_at(secret, svc.clock.now())
    r = client.post("/auth/mfa", json={"code": code})
    assert r.status_code == 200
    sid_upgraded = client.cookies.get("sid")

    # 4) 申领 CSRF 并执行有状态变更
    token = client.get("/auth/csrf").json()["csrf_token"]
    r = client.post(
        "/api/resource/app/self",
        headers={"origin": origin, "x-csrf-token": token},
        json={"payload": {"op": "write"}},
    )
    verdict(
        "MFA 后带 CSRF 写自身资源",
        {"origin": origin, "resource": "app/self", "token": "<one-time, consumed>"},
        (r.status_code, r.json()),
    )
    assert r.status_code == 200

    # 5) 越权读管理资源 -> 可区分 forbidden
    r = client.get("/api/resource/admin/audit")
    verdict("member 越权读 admin/audit", {"role": "<server-side: member>"}, (r.status_code, r.json()["error"]["code"]))
    assert r.status_code == 403 and r.json()["error"]["code"] == "forbidden"

    # 6) 审计无任何敏感明文
    log = audit_buf.getvalue()
    for leak in ("password123", code, secret, sid_upgraded):
        assert leak not in log

    # 7) 登出后重放
    client.post("/auth/logout")
    client.cookies.clear(); client.cookies.set("sid", sid_upgraded)
    r = client.get("/auth/me")
    verdict("登出后重放旧会话", {"session": "<replayed old id redacted>"},
            (r.status_code, r.json()["error"]["code"]))
    assert r.status_code == 401 and r.json()["error"]["code"] == "unauthenticated"
