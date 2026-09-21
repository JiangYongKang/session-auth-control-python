"""审计覆盖：登录/登出/权限拒绝/锁定/MFA 变更；敏感字段零泄漏。"""
from __future__ import annotations

from app.security.totp import current_step, generate_code


def test_audit_covers_required_events(api, audit, time_source):
    # 注册 + 登录成功
    api.register("alice", roles=["viewer"])
    api.login("alice")
    # 权限拒绝
    api.post("/access/resource",
             json_body={"resource": "secret/x", "action": "read"})
    # 登出
    api.post("/auth/logout")
    # 登录失败 + 锁定（阈值 3）
    for i in range(3):
        api.login("alice", "wrongpass1")
    events = set(audit.events())
    assert "REGISTER" in events
    assert "LOGIN_SUCCESS" in events
    assert "LOGIN_FAILURE" in events
    assert "LOGIN_LOCKED" in events
    assert "LOGOUT" in events
    assert "ACCESS_DENIED" in events


def test_audit_mfa_change_events(api, audit, time_source):
    api.register("alice", roles=["viewer"])
    api.login("alice")
    secret = api.post("/mfa/enroll/start").json()["secret"]
    api.post("/mfa/enroll/confirm",
             json_body={"code": generate_code(
                 secret, current_step(time_source.now(), 30))})
    time_source.advance(30)
    api.login("alice")
    api.post("/mfa/verify",
             json_body={"code": generate_code(
                 audit and api.c.app.state.services.store
                 .get_user("alice").totp_secret,
                 current_step(time_source.now(), 30))})
    events = set(audit.events())
    assert {"MFA_ENROLL", "MFA_VERIFY"} <= events


def test_no_secrets_in_audit_log(api, audit, caplog):
    api.register("alice", roles=["viewer"])
    api.login("alice")
    api.post("/mfa/enroll/start")
    # 失败登录
    api.login("alice", "wrongpass1")
    # 越权
    api.post("/access/resource",
             json_body={"resource": "secret/x", "action": "read"})
    text = caplog.text
    # 口令明文
    assert "Sup3rSecret" not in text
    assert "wrongpass1" not in text
    # 会话标识 / CSRF 不以明文出现
    assert api.session_id not in text
    assert api.csrf not in text
    # 但判定结论必须可见
    assert "INVALID_CREDENTIALS" in text
    assert "FORBIDDEN" in text


def test_audit_redaction_unit():
    from app.audit import redact
    out = redact({
        "password": "p", "new_password": "n", "totp_code": "123456",
        "session_id": "s", "csrf_token": "t", "secret": "k",
        "resource": "docs/x", "result": "ok",
    })
    sensitive = ["password", "new_password", "totp_code", "session_id",
                 "csrf_token", "secret"]
    assert all(out[k] == "<redacted>" for k in sensitive)
    assert out["resource"] == "docs/x"


def test_reproducible_decision_fields(api, audit):
    """被拒绝路径给出可复现的输入与判定依据。"""
    api.register("alice", roles=["viewer"])
    api.login("alice")
    api.post("/access/resource",
             json_body={"resource": "secret/x", "action": "read"})
    rec = [r for r in audit.records() if r.event == "ACCESS_DENIED"][-1]
    # 含可复现输入（资源/动作/角色）与稳定判定依据
    assert "secret/x" in rec.fields["decision_basis"]
    assert "read" in rec.fields["decision_basis"]
    assert rec.reason == "FORBIDDEN"
