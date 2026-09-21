"""审计覆盖与脱敏；存储/时钟/配置异常归一化且不降级放行；可区分判定。"""
import logging

import pytest

from authapp.audit import AuditLogger
from authapp.config import AuthConfig
from authapp.errors import AuthError, ErrorCode


def test_audit_covers_required_events_without_secrets(client, svc, audit_buf, origin):
    svc.register("alice", "password123", roles=["member"])
    client.post("/auth/login", json={"username": "alice", "password": "wrong-pw-1"})
    client.post("/auth/login", json={"username": "alice", "password": "password123"})
    client.get("/api/resource/admin/audit")  # 权限拒绝
    client.post("/auth/logout")
    log = audit_buf.getvalue()
    for event in ("register", "login", "access_denied", "logout"):
        assert f'"event": "{event}"' in log, event
    # 任何敏感明文都不得出现
    for secret in ("password123", "wrong-pw-1"):
        assert secret not in log
    assert "alice" not in log  # 用户名只以指纹出现


def test_lock_event_is_audited(client, svc, audit_buf):
    svc.register("alice", "password123")
    for _ in range(svc.config.fail_threshold):
        client.post("/auth/login", json={"username": "alice", "password": "nope"})
    log = audit_buf.getvalue()
    assert '"event": "account_locked"' in log
    assert '"threshold": 5' in log and '"lock_seconds": 600' in log


def test_mfa_changes_are_audited_without_codes(client, svc, audit_buf, origin):
    from authapp.security.totp import code_at
    svc.register("alice", "password123", roles=["member"])
    client.post("/auth/login", json={"username": "alice", "password": "password123"})
    r = client.get("/auth/mfa/bind")
    secret = r.json()["secret"]
    code = code_at(secret, svc.clock.now())
    token = client.get("/auth/csrf").json()["csrf_token"]
    client.post(
        "/auth/mfa/bind/confirm",
        headers={"x-csrf-token": token, "origin": origin},
        json={"code": code},
    )
    log = audit_buf.getvalue()
    assert "mfa_change" in log
    assert code not in log and secret not in log


def test_audit_logger_drops_sensitive_kwargs_directly():
    import io
    buf = io.StringIO()
    lg = logging.getLogger("direct-audit")
    lg.handlers = [logging.StreamHandler(buf)]
    lg.setLevel(logging.INFO)
    lg.propagate = False
    audit = AuditLogger(lg)
    audit.record(
        "login", result="denied", password="p@ss", code="123456",
        session="raw-sid", csrf="raw-csrf", reason="bad_password",
    )
    out = buf.getvalue()
    for leak in ("p@ss", "123456", "raw-sid", "raw-csrf"):
        assert leak not in out
    assert "bad_password" in out


def test_storage_error_never_fails_open():
    from authapp.deps import build_service
    from authapp.store.memory import MemoryStore

    class ExplodingStore(MemoryStore):
        def get_user(self, username):
            raise RuntimeError("disk on fire")

    svc = build_service(AuthConfig(fail_open=False), store=ExplodingStore())
    with pytest.raises(AuthError) as ei:
        svc.login("alice", "password123")
    assert ei.value.code == ErrorCode.STORAGE_ERROR


def test_clock_failure_is_normalized_and_denies():
    from authapp.deps import build_service

    class DeadClock:
        def now(self):
            raise AuthError(ErrorCode.TIME_SOURCE_ERROR, "时间源不可用")

    svc = build_service(AuthConfig(), clock=DeadClock())
    with pytest.raises(AuthError) as ei:
        svc.login("alice", "password123")
    assert ei.value.code == ErrorCode.TIME_SOURCE_ERROR


def test_config_refuses_fail_open_and_bad_values():
    with pytest.raises(AuthError) as ei:
        AuthConfig(fail_open=True).validate()
    assert ei.value.code == ErrorCode.CONFIG_ERROR
    with pytest.raises(AuthError) as ei:
        AuthConfig(fail_threshold=0).validate()
    assert ei.value.code == ErrorCode.CONFIG_ERROR


def test_http_error_envelope_is_uniform(client, svc):
    # 404 走 FastAPI 默认（无该路由）；认证类错误必须统一为 error.code 结构
    r = client.post("/auth/login", json={"username": "ghost", "password": "password123"})
    assert set(r.json()) == {"error"}
    assert set(r.json()["error"]) == {"code", "message"}


def test_malformed_body_is_normalized_to_invalid_request(client):
    r = client.post("/auth/login", json={"username": "x"})  # 缺 password
    assert r.status_code == 400
    assert r.json()["error"]["code"] == ErrorCode.INVALID_REQUEST.value
    r = client.post("/auth/register", json={"username": "x", "password": "short"})
    # min_length=1 的模型先过，长度策略在服务内区分（注册要求 >=8）
    assert r.json()["error"]["code"] == ErrorCode.INVALID_REQUEST.value
