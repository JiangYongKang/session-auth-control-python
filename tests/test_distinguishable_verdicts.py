"""参数化：被拒绝路径必须给出可区分判定依据，并打印可复现输入与结论。"""
import pytest

from authapp.errors import ErrorCode
from tests.conftest import verdict


def _json(resp):
    return resp.status_code, resp.json()["error"]["code"]


@pytest.mark.parametrize(
    "given, expected_code",
    [
        ("不存在用户登录", "invalid_credentials"),
        ("错误口令登录", "invalid_credentials"),
    ],
)
def test_login_rejections_uniform_externally(client, svc, given, expected_code):
    svc.register("alice", "password123")
    payload = (
        {"username": "ghost", "password": "password123"}
        if given == "不存在用户登录"
        else {"username": "alice", "password": "nope-nope-1"}
    )
    r = client.post("/auth/login", json=payload)
    status, code = _json(r)
    verdict(given, payload | {"password": "<redacted>"}, (status, code))
    assert (status, code) == (401, expected_code)


@pytest.mark.parametrize(
    "given, expected_code",
    [
        ("无会话访问", "unauthenticated"),
        ("登出后重放", "unauthenticated"),
    ],
)
def test_session_rejection_codes(client, svc, given, expected_code):
    svc.register("alice", "password123", roles=["member"])
    if given == "登出后重放":
        client.post("/auth/login", json={"username": "alice", "password": "password123"})
        sid = client.cookies.get("sid")
        client.post("/auth/logout")
        client.cookies.clear(); client.cookies.set("sid", sid)
    r = client.get("/auth/me")
    verdict(given, {"path": "/auth/me"}, (r.status_code, r.json()["error"]["code"]))
    assert r.json()["error"]["code"] == expected_code


@pytest.mark.parametrize(
    "given, headers, expected_code",
    [
        ("缺 CSRF 令牌", {"origin": "https://app.example.local"}, "csrf_missing"),
        ("缺来源", {}, "csrf_origin_mismatch"),
        ("伪造来源", {"origin": "https://evil.example", "x-csrf-token": "t"}, "csrf_origin_mismatch"),
        ("未知令牌", {"origin": "https://app.example.local", "x-csrf-token": "bogus"}, "csrf_invalid"),
    ],
)
def test_csrf_rejection_codes_distinguishable(client, svc, given, headers, expected_code):
    svc.register("bob", "password123", roles=["member"])
    client.post("/auth/login", json={"username": "bob", "password": "password123"})
    r = client.post("/api/resource/app/self", headers=headers, json={})
    verdict(given, {"headers": {k: ("<redacted>" if k == "x-csrf-token" else v) for k, v in headers.items()}},
            (r.status_code, r.json()["error"]["code"]))
    assert r.status_code == 403 and r.json()["error"]["code"] == expected_code


def test_forbidden_is_distinct_from_unauthenticated(client, svc):
    svc.register("bob", "password123", roles=["member"])
    r1 = client.get("/api/resource/admin/audit")
    assert r1.status_code == 401 and r1.json()["error"]["code"] == ErrorCode.UNAUTHENTICATED.value
    client.post("/auth/login", json={"username": "bob", "password": "password123"})
    r2 = client.get("/api/resource/admin/audit")
    verdict("已认证但越权", {"resource": "admin/audit", "action": "read"},
            (r2.status_code, r2.json()["error"]["code"]))
    assert r2.status_code == 403 and r2.json()["error"]["code"] == ErrorCode.FORBIDDEN.value
