"""注册/登录：口令不可逆存储；用户名不存在与口令错误不可区分。"""
from __future__ import annotations

from app.security.passwords import verify_password
from app.errors import ErrorCode


def test_register_and_login_ok(api, store):
    r = api.register("alice", roles=["viewer"])
    assert r.status_code == 200, r.text
    user = store.get_user("alice")
    assert user.password_hash.startswith("pbkdf2_sha256$")
    assert "Sup3rSecret" not in user.password_hash
    assert verify_password("Sup3rSecret", user.password_hash)

    r = api.login("alice")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["mfa_required"] is False
    assert len(body["session_id"]) == 64 and len(body["csrf_token"]) == 64


def test_unknown_user_and_bad_password_indistinguishable(api):
    api.register("alice")
    r1 = api.login("ghost", "whatever1")
    r2 = api.login("alice", "wrongpass1")
    assert r1.status_code == r2.status_code == 401
    b1, b2 = r1.json(), r2.json()
    assert b1["reason"] == b2["reason"] == ErrorCode.INVALID_CREDENTIALS.value
    assert b1["detail"] == b2["detail"]


def test_audit_distinguishes_failure_cause_but_redacts_secrets(api, audit, caplog):
    api.register("alice")
    api.login("ghost", "whatever1")
    api.login("alice", "wrongpass1")
    causes = {r.fields.get("failure_cause") for r in audit.records()
              if r.event == "LOGIN_FAILURE"}
    assert causes == {"user_not_found", "bad_password"}
    full = caplog.text
    assert "whatever1" not in full and "wrongpass1" not in full
    assert "Sup3rSecret" not in full
    # 单测日志中必须可复现输入与判定结论
    assert "INVALID_CREDENTIALS" in full


def test_register_weak_password_rejected(api):
    r = api.register("weak", password="123")
    assert r.status_code == 422
    assert r.json()["reason"] == ErrorCode.VALIDATION_ERROR.value


def test_register_duplicate_conflict(api):
    assert api.register("alice").status_code == 200
    r = api.register("alice")
    assert r.status_code == 409
    assert r.json()["reason"] == ErrorCode.CONFLICT.value


def test_login_unknown_user_not_persisted(api, store):
    api.login("ghost", "whatever1")
    assert store.get_user("ghost") is None  # 不留枚举侧信道
