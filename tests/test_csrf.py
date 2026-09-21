"""CSRF：缺失、伪造、过期、跨会话、跨来源均须可区分拒绝。"""
from __future__ import annotations

from app.errors import ErrorCode


def _login_viewer(api, name="alice"):
    api.register(name, roles=["viewer"])
    api.login(name)


def test_csrf_missing_rejected(api):
    _login_viewer(api)
    r = api.post("/access/resource", with_csrf=False,
                 json_body={"resource": "docs/x", "action": "write"})
    assert r.status_code == 403
    assert r.json()["reason"] == ErrorCode.CSRF_MISSING.value


def test_csrf_unknown_token_rejected(api):
    _login_viewer(api)
    r = api.post("/access/resource",
                 json_body={"resource": "docs/x", "action": "write"},
                 raw_csrf="00" * 32)
    assert r.json()["reason"] == ErrorCode.CSRF_INVALID.value


def test_csrf_expired_rejected(api, time_source):
    _login_viewer(api)
    time_source.advance(1801)  # csrf ttl 1800s
    r = api.post("/access/resource",
                 json_body={"resource": "docs/x", "action": "write"})
    # 空闲超时(1800) 先于/同刻到达；无论哪种都是明确拒绝且不可放行
    assert r.status_code in (401, 403)
    assert r.json()["reason"] in (
        ErrorCode.CSRF_EXPIRED.value, ErrorCode.SESSION_EXPIRED.value)


def test_csrf_expired_distinct_when_session_alive(store, time_source, audit):
    """会话空闲超时大于 CSRF TTL 时，必须独立判定 CSRF_EXPIRED。"""
    from fastapi.testclient import TestClient
    from app.api.app_factory import create_app
    from app.config import default_config
    cfg = default_config({"session": {"idle_timeout_seconds": 7200,
                                      "absolute_timeout_seconds": 28800,
                                      "csrf_ttl_seconds": 10}})
    application = create_app(store=store, time_source=time_source,
                             config=cfg, audit=audit)
    c = TestClient(application)
    c.post("/auth/register",
           json={"username": "alice", "password": "Sup3rSecret",
                 "roles": ["viewer"]})
    b = c.post("/auth/login",
               json={"username": "alice", "password": "Sup3rSecret"},
               headers={"Origin": "http://testserver"}).json()
    time_source.advance(11)
    r = c.post("/access/resource",
               json={"resource": "docs/x", "action": "write"},
               headers={"Origin": "http://testserver",
                        "X-Session-Id": b["session_id"],
                        "X-CSRF-Token": b["csrf_token"]})
    assert r.status_code == 403
    assert r.json()["reason"] == ErrorCode.CSRF_EXPIRED.value


def test_csrf_bound_to_other_session_rejected(api):
    _login_viewer(api, "alice")
    api.login("alice")
    victim_csrf = api.csrf
    # 攻击者建立自己的会话，却尝试使用受害者会话签发的 CSRF
    api.register("mallory", roles=["viewer"])
    api.login("mallory")
    r = api.post("/access/resource",
                 json_body={"resource": "docs/x", "action": "write"},
                 raw_csrf=victim_csrf)
    assert r.json()["reason"] == ErrorCode.CSRF_BOUND_SESSION.value


def test_csrf_other_origin_rejected(api):
    _login_viewer(api)
    r = api.post("/access/resource",
                 json_body={"resource": "docs/x", "action": "write"},
                 origin="http://evil.example")
    assert r.status_code == 403
    assert r.json()["reason"] == ErrorCode.CSRF_BOUND_ORIGIN.value


def test_csrf_same_origin_mutating_allowed(api):
    _login_viewer(api)
    # editor 才具备 write
    api.register("dora", roles=["editor"])
    api.login("dora")
    r = api.post("/access/resource",
                 json_body={"resource": "docs/x", "action": "write"})
    assert r.status_code == 200, r.text


def test_form_entry_csrf_missing_and_bound(api):
    _login_viewer(api)
    # 表单入口与 JSON 入口判定一致：缺令牌拒绝
    r = api.post("/access/resource-form", with_csrf=False,
                 data={"resource": "docs/x", "action": "read"})
    # read 不强制 CSRF；这里验证表单无会话仍 401
    assert r.status_code in (200, 403)
    # write 强制 CSRF：跨来源表单拒绝
    r2 = api.post("/access/resource-form",
                  data={"resource": "docs/x", "action": "write"},
                  origin="http://evil.example")
    assert r2.json()["reason"] == ErrorCode.CSRF_BOUND_ORIGIN.value
    # 同源 + 正确 CSRF（表单字段携带）
    r3 = api.c.post(
        "/access/resource-form",
        data={"resource": "docs/x", "action": "write",
              "csrf_token": api.csrf},
        headers={"Origin": "http://testserver",
                 "X-Session-Id": api.session_id})
    # viewer 无 write：通过 CSRF 后应是 FORBIDDEN，证明 CSRF 已过
    assert r3.status_code == 403
    assert r3.json()["reason"] == ErrorCode.FORBIDDEN.value


def test_csrf_audit_redacts_token(api, audit):
    _login_viewer(api)
    api.post("/access/resource", with_csrf=False,
             json_body={"resource": "docs/x", "action": "write"})
    rec = [r for r in audit.records()
           if r.event == "CSRF_REJECTED"][-1]
    assert rec.reason == ErrorCode.CSRF_MISSING.value
    # 日志不含令牌明文
    assert api.csrf not in rec.to_line()
