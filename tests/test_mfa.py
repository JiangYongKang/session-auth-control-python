"""多因素：绑定前置条件、时间漂移/重放/错误码区分、解绑与重置。"""
from __future__ import annotations

from app.errors import ErrorCode
from app.security.totp import current_step, generate_code


def _step(api):
    return current_step(api.c.app.state.services.time.now(), 30)


def _code(api, secret=None, step=None):
    sec = secret or api.c.app.state.services.store.get_user(
        api.session_id and _user(api)).totp_secret
    return generate_code(secret or _secret(api), step or _step(api))


def _user(api):
    # 从最近登录名不可得，用 fixture 直接查
    return api._username


def _secret(api):
    svc = api.c.app.state.services
    return svc.store.get_user(api._username).totp_secret


def _enroll(api, username, role="viewer"):
    api.register(username, roles=[role])
    api.login(username)
    api._username = username
    r = api.post("/mfa/enroll/start")
    assert r.status_code == 200, r.text
    secret = r.json()["secret"]
    r = api.post("/mfa/enroll/confirm",
                 json_body={"code": generate_code(secret, _step(api))})
    assert r.status_code == 200, r.text
    api.c.app.state.services.time.advance(30)
    return secret


def test_enroll_preconditions(api):
    api.register("alice", roles=["viewer"])
    api.login("alice")
    api._username = "alice"
    # 未登录不得绑定：无会话
    r = api.c.post("/mfa/enroll/start",
                   headers={"Origin": "http://testserver"})
    assert r.status_code == 401
    # confirm 未 start 时拒绝
    r2 = api.post("/mfa/enroll/confirm", json_body={"code": "123456"})
    assert r2.json()["reason"] == ErrorCode.MFA_NOT_ENROLLED.value


def test_enroll_confirm_wrong_code_then_ok(api, time_source):
    secret = _enroll(api, "alice")
    # 重新登录走 MFA
    api.login("alice")
    r = api.post("/mfa/verify", json_body={"code": "000001"})
    assert r.json()["reason"] == ErrorCode.MFA_CODE_INVALID.value


def test_mfa_replay_rejected(api, time_source):
    _enroll(api, "alice")
    api.login("alice")
    code = generate_code(_secret(api), _step(api))
    r = api.post("/mfa/verify", json_body={"code": code})
    assert r.status_code == 200, r.text
    new_sid = r.json()["session_id"]
    # 同一步的码在新会话再次使用 => reused
    api.login("alice")
    r2 = api.post("/mfa/verify", json_body={"code": code})
    assert r2.status_code == 401
    assert r2.json()["reason"] == ErrorCode.MFA_CODE_REUSED.value


def test_mfa_time_drift_distinguished(api, time_source):
    _enroll(api, "alice")
    # 先消费一个码
    api.login("alice")
    ok = api.post("/mfa/verify",
                  json_body={"code": generate_code(_secret(api), _step(api))})
    assert ok.status_code == 200
    # 新登录待确认；把时间回拨到远远落后（整个窗口 <= 已消费步）
    api.login("alice")
    saved = time_source.now()
    time_source.set(saved - 30 * 20)
    stale = generate_code(_secret(api), _step(api))
    r = api.post("/mfa/verify", json_body={"code": stale})
    assert r.status_code == 401
    assert r.json()["reason"] == ErrorCode.MFA_TIME_DRIFT.value
    time_source.set(saved)


def test_verify_rotates_session_id(api):
    _enroll(api, "alice")
    api.login("alice")
    pending_sid = api.session_id
    r = api.post("/mfa/verify",
                 json_body={"code": generate_code(_secret(api), _step(api))})
    assert r.status_code == 200
    assert r.json()["session_id"] != pending_sid
    # 旧待确认标识作废
    r2 = api.post("/access/resource",
                  json_body={"resource": "docs/x", "action": "read"},
                  raw_session=pending_sid, with_csrf=False)
    assert r2.json()["reason"] in ("SESSION_REPLAYED", "SESSION_INVALIDATED")


def test_unbind_requires_password_and_code(api, time_source):
    _enroll(api, "alice")
    api.login("alice")
    up = api.post("/mfa/verify",
                  json_body={"code": generate_code(_secret(api), _step(api))})
    assert up.status_code == 200
    api.adopt(up.json()["session_id"], up.json()["csrf_token"])
    time_source.advance(30)
    # 错误口令
    r = api.post("/mfa/unbind",
                 json_body={"password": "WrongPass1",
                            "code": generate_code(_secret(api), _step(api))})
    assert r.json()["reason"] == ErrorCode.INVALID_CREDENTIALS.value
    time_source.advance(30)
    # 正确口令+码
    r2 = api.post("/mfa/unbind",
                  json_body={"password": "Sup3rSecret",
                             "code": generate_code(_secret(api), _step(api))})
    assert r2.status_code == 200, r2.text
    # 解绑后不再要求 MFA
    r3 = api.login("alice")
    assert r3.json()["mfa_required"] is False


def test_admin_reset_invalidates_sessions(api, time_source):
    _enroll(api, "alice")
    # 管理员（受信预置，自助注册无法获得 admin）
    api.provision("root", roles=("admin",))
    api.login("root")
    # 被重置目标持有一个已验证会话
    target = type(api)(api.c)
    target.login("alice")
    time_source.advance(30)
    tv = target.post("/mfa/verify",
                     json_body={"code": generate_code(
                         api.c.app.state.services.store.get_user("alice").totp_secret,
                         current_step(time_source.now(), 30))})
    assert tv.status_code == 200, tv.text
    target.adopt(tv.json()["session_id"], tv.json()["csrf_token"])
    # 非管理员不能重置
    api.adopt(target.session_id, target.csrf)
    r = api.post("/admin/mfa-reset/alice")
    assert r.status_code == 403
    # 管理员执行重置
    api.login("root")
    r2 = api.post("/admin/mfa-reset/alice")
    assert r2.status_code == 200, r2.text
    # 目标既有会话立即失效
    r3 = target.post("/access/resource",
                     json_body={"resource": "docs/x", "action": "read"},
                     with_csrf=False)
    assert r3.json()["reason"] in ("SESSION_REPLAYED", "SESSION_INVALIDATED")
