"""同一 TOTP 验证码即使换会话/换入口重放也不得成功。"""
from authapp.errors import ErrorCode
from authapp.security.totp import code_at


def _bind(svc, username="alice"):
    with svc.store.lock():
        user = svc.store.get_user(username)
        secret, _ = svc.mfa.begin_bind(user)
        svc.mfa.confirm_bind(user, secret, code_at(secret, svc.clock.now()))
    return secret


def test_code_replayed_in_second_session_is_rejected(svc):
    svc.register("alice", "password123", roles=["member"])
    secret = _bind(svc)
    # 第一个待二因素会话成功使用验证码
    r1 = svc.login("alice", "password123")
    sid1 = r1["session"]
    code = code_at(secret, svc.clock.now())
    upgraded1 = svc.mfa_login(sid1, code)
    assert upgraded1
    # 攻击者另开一个待二因素会话，重放同一验证码
    r2 = svc.login("alice", "password123")
    sid2 = r2["session"]
    try:
        svc.mfa_login(sid2, code)
    except Exception as e:
        assert e.code == ErrorCode.MFA_REPLAYED_CODE
    else:  # pragma: no cover
        raise AssertionError("跨会话重放验证码竟然成功")
    # 下一时刻的新验证码可正常用于第二个会话
    import pytest
    svc.clock.advance(svc.config.totp_period)
    new_code = code_at(secret, svc.clock.now())
    upgraded2 = svc.mfa_login(sid2, new_code)
    assert upgraded2 != sid2
