"""口令不可逆存储与不可区分失败。"""
from authapp.errors import ErrorCode
from authapp.security.passwords import hash_password, verify_password


def test_password_hash_is_irreversible_and_salted():
    h1 = hash_password("supersecret1")
    h2 = hash_password("supersecret1")
    assert h1 != h2  # 同口令不同盐
    assert "supersecret1" not in h1
    assert verify_password("supersecret1", h1)
    assert not verify_password("supersecret2", h1)
    assert not verify_password("anything", "garbage-not-a-hash")


def test_login_failures_indistinguishable(client, svc):
    svc.register("alice", "password123", roles=["member"])
    body_missing = {"username": "ghost", "password": "password123"}
    body_bad_pw = {"username": "alice", "password": "wrong-password"}
    r1 = client.post("/auth/login", json=body_missing)
    r2 = client.post("/auth/login", json=body_bad_pw)
    assert r1.status_code == r2.status_code == 401
    assert r1.json() == r2.json() == {
        "error": {"code": ErrorCode.INVALID_CREDENTIALS.value, "message": "用户名或口令不正确"}
    }


def test_audit_distinguishes_reason_but_response_does_not(client, svc, audit_buf):
    svc.register("alice", "password123")
    client.post("/auth/login", json={"username": "ghost", "password": "password123"})
    client.post("/auth/login", json={"username": "alice", "password": "nope-nope"})
    log = audit_buf.getvalue()
    assert "user_not_found" in log and "bad_password" in log  # 受控日志区分
    assert "ghost" not in log and "password123" not in log and "nope-nope" not in log
