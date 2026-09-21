"""多因素：绑定前置条件、错误/时间偏移/重放区分、解绑使既有会话失效。"""
from authapp.errors import ErrorCode
from authapp.security.totp import code_at


def _code(secret, clock, offset_steps=0):
    return code_at(secret, clock.t + offset_steps * 30)


def _enable_mfa(svc, client, origin, username="alice"):
    """在已登录会话上完成一次绑定，返回 secret。绑定不吊销当前会话，
    旧会话在下次成功 MFA 登录时与标识轮换一起被原子吊销。"""
    r = client.get("/auth/mfa/bind")
    assert r.status_code == 200, r.text
    secret = r.json()["secret"]
    token = client.get("/auth/csrf").json()["csrf_token"]
    r = client.post(
        "/auth/mfa/bind/confirm",
        headers={"x-csrf-token": token, "origin": origin},
        json={"code": _code(secret, svc.clock)},
    )
    assert r.status_code == 200, r.text
    return secret


def test_mfa_login_requires_second_factor_and_rotates_id(client, svc, origin):
    svc.register("alice", "password123", roles=["member"])
    client.post("/auth/login", json={"username": "alice", "password": "password123"})
    pre_sid = client.cookies.get("sid")
    secret = _enable_mfa(svc, client, origin)
    # 绑定完成在当前会话内生效；再次登录进入“待二因素”阶段
    r = client.post("/auth/login", json={"username": "alice", "password": "password123"})
    assert r.json()["status"] == "mfa_required"
    pending_sid = client.cookies.get("sid")
    # 待二因素会话不能访问受保护资源
    assert client.get("/auth/me").status_code == 401
    assert client.post("/auth/mfa", json={"code": _code(secret, svc.clock)}).status_code == 200
    new_sid = client.cookies.get("sid")
    assert new_sid != pending_sid and new_sid != pre_sid  # 标识已轮换
    assert client.get("/auth/me").status_code == 200
    # 旧标识（待二因素、绑定前会话）重放均无效
    for old in (pending_sid, pre_sid):
        client.cookies.clear(); client.cookies.clear(); client.cookies.set("sid", old)
        r = client.get("/auth/me")
        assert r.status_code == 401, old
    # 新纪元记录与用户纪元一致
    with svc.store.lock():
        user = svc.store.get_user("alice")
        assert svc.store.get_session(new_sid).auth_epoch == user.auth_epoch


def test_mfa_wrong_code_skew_replay_are_distinguishable(client, svc):
    svc.register("alice", "password123", roles=["member"])
    client.post("/auth/login", json={"username": "alice", "password": "password123"})
    # 无需 CSRF：mfa_login 是登录动作，不要求已认证会话
    r = client.get("/auth/mfa/bind")
    secret = r.json()["secret"]
    # 直接在服务层完成绑定，专注校验 mfa_login 的判定差异
    with svc.store.lock():
        user = svc.store.get_user("alice")
        svc.mfa.confirm_bind(user, secret, code_at(secret, svc.clock.now()))
    client.post("/auth/login", json={"username": "alice", "password": "password123"})

    r = client.post("/auth/mfa", json={"code": "000000"})
    assert r.status_code == 401 and r.json()["error"]["code"] == ErrorCode.MFA_INVALID_CODE.value

    old_code = _code(secret, svc.clock, offset_steps=-1)
    r = client.post("/auth/mfa", json={"code": old_code})
    assert r.status_code == 401 and r.json()["error"]["code"] == ErrorCode.MFA_TIME_SKEW.value
    assert client.get("/auth/me").status_code == 401  # 时间偏移未通过、未消费

    good = _code(secret, svc.clock)
    assert client.post("/auth/mfa", json={"code": good}).status_code == 200
    r = client.post("/auth/mfa", json={"code": good})  # 同码重放
    assert r.status_code == 401 and r.json()["error"]["code"] == ErrorCode.MFA_REPLAYED_CODE.value
    svc.clock.advance(30)
    r = client.post("/auth/mfa", json={"code": good})  # 旧码 -> 时间偏移
    assert r.status_code == 401 and r.json()["error"]["code"] == ErrorCode.MFA_TIME_SKEW.value


def test_mfa_replay_in_service_layer_blocks_reuse(svc):
    svc.register("alice", "password123", roles=["member"])
    with svc.store.lock():
        user = svc.store.get_user("alice")
        secret, _ = svc.mfa.begin_bind(user)
        svc.mfa.confirm_bind(user, secret, code_at(secret, svc.clock.now()))
        sid = svc.sessions.create(user.user_id, user.auth_epoch, mfa_completed=False)
        record = svc.sessions.resolve(sid)
        fresh = code_at(user.mfa_secret, svc.clock.now())
        svc.mfa.verify(record, user, fresh)
        try:
            svc.mfa.verify(record, user, fresh)
        except Exception as e:
            assert e.code == ErrorCode.MFA_REPLAYED_CODE
        else:  # pragma: no cover
            raise AssertionError("重复使用验证码竟然成功")
        # 记录中确实只消费了一次
        assert len(record.consumed_mfa) == 1


def test_mfa_bind_preconditions(client, svc, origin):
    svc.register("alice", "password123", roles=["member"])
    client.post("/auth/login", json={"username": "alice", "password": "password123"})
    def fresh_csrf():
        return client.get("/auth/csrf").json()["csrf_token"]
    # 未先 begin_bind 就 confirm：拒绝
    r = client.post(
        "/auth/mfa/bind/confirm",
        headers={"x-csrf-token": fresh_csrf(), "origin": origin},
        json={"code": "123456"},
    )
    assert r.status_code == 400 and r.json()["error"]["code"] == ErrorCode.INVALID_REQUEST.value
    secret = client.get("/auth/mfa/bind").json()["secret"]
    r = client.post(
        "/auth/mfa/bind/confirm",
        headers={"x-csrf-token": fresh_csrf(), "origin": origin},
        json={"code": "000000"},
    )
    assert r.status_code == 401 and r.json()["error"]["code"] == ErrorCode.MFA_INVALID_CODE.value
    # 未绑定时解绑 -> not_bound
    r = client.post(
        "/auth/mfa/unbind",
        headers={"x-csrf-token": fresh_csrf(), "origin": origin},
        json={"code": "123456"},
    )
    assert r.status_code == 409 and r.json()["error"]["code"] == ErrorCode.MFA_NOT_BOUND.value


def test_unbind_mfa_revokes_existing_sessions(client, svc, origin):
    svc.register("alice", "password123", roles=["member"])
    client.post("/auth/login", json={"username": "alice", "password": "password123"})
    secret = _enable_mfa(svc, client, origin)
    # 用另一会话完成 MFA 登录转正
    client.post("/auth/login", json={"username": "alice", "password": "password123"})
    client.post("/auth/mfa", json={"code": _code(secret, svc.clock)})
    sid_before = client.cookies.get("sid")
    other_session = svc.sessions.create(
        svc.store.get_user("alice").user_id,
        svc.store.get_user("alice").auth_epoch,
        mfa_completed=True,
    )
    token = client.get("/auth/csrf").json()["csrf_token"]
    r = client.post(
        "/auth/mfa/unbind",
        headers={"x-csrf-token": token, "origin": origin},
        json={"code": _code(secret, svc.clock)},
    )
    assert r.status_code == 200, r.text
    # 解绑后该账号全部既有会话立即失效
    for sid in (sid_before, other_session):
        record = svc.store.get_session(sid)
        assert record is None or record.revoked
    with svc.store.lock():
        assert svc.store.get_user("alice").mfa_secret is None
    # 解绑后无需二因素即可登录
    r = client.post("/auth/login", json={"username": "alice", "password": "password123"})
    assert r.json()["status"] == "success"
