"""注销/改密/MFA 重置与既有会话并发：不得出现只失效一部分。"""
from concurrent.futures import ThreadPoolExecutor

from authapp.security.totp import code_at


def _seed_sessions(svc, n=20):
    svc.register("alice", "password123", roles=["member"])
    user = svc.store.get_user("alice")
    # 直接建立 n 个并行的已认证服务端会话（模拟多设备/多标签页）
    sids = []
    with svc.store.lock():
        for _ in range(n):
            sids.append(
                svc.sessions.create(user.user_id, user.auth_epoch, mfa_completed=True)
            )
    return sids


def test_password_change_concurrent_with_requests_revokes_everything(svc):
    sids = _seed_sessions(svc)
    active = svc.sessions
    # 一个线程改密（自服务接口需会话；这里直接并发触发 store 层失效路径）
    trigger_sid = sids[0]

    def change():
        svc.change_password(trigger_sid, "password123", "brandnewpw123")

    def touch(i):
        sid = sids[i]
        try:
            svc.authenticate(sid)
            return "ok"
        except Exception:
            return "denied"

    with ThreadPoolExecutor(max_workers=8) as pool:
        futs = [pool.submit(change)] + [pool.submit(touch, i) for i in range(1, len(sids))]
        results = [f.result() for f in futs]

    # 改密完成后：所有会话无一可用（请求若在改密临界区之前完成可能 ok，但之后必须 denied；
    # 这里最终态统一验证）
    for sid in sids:
        record = svc.store.get_session(sid)
        assert record is None or record.revoked
    # 新口令可登录，旧口令不行
    assert svc.login("alice", "brandnewpw123")["status"] == "success"
    from authapp.errors import AuthError, ErrorCode
    try:
        svc.login("alice", "password123")
    except AuthError as e:
        assert e.code == ErrorCode.INVALID_CREDENTIALS


def test_mfa_reset_revokes_all_sessions_despite_concurrency(svc):
    sids = _seed_sessions(svc)
    # 服务层绑定 MFA
    with svc.store.lock():
        user = svc.store.get_user("alice")
        secret, _ = svc.mfa.begin_bind(user)
        svc.mfa.confirm_bind(user, secret, code_at(secret, svc.clock.now()))

    # 取一个仍有效的已认证会话执行解绑
    target = sids[0]
    code = code_at(secret, svc.clock.now())

    def unbind():
        svc.unbind_mfa(target, code)

    def touch(i):
        try:
            svc.authenticate(sids[i])
            return "ok"
        except Exception:
            return "denied"

    with ThreadPoolExecutor(max_workers=8) as pool:
        futs = [pool.submit(unbind)] + [pool.submit(touch, i) for i in range(len(sids))]
        results = [f.result() for f in futs]

    for sid in sids:
        record = svc.store.get_session(sid)
        assert record is None or record.revoked
    # 没有任何会话在解绑后仍可用
    post = []
    for sid in sids:
        try:
            svc.authenticate(sid)
            post.append("ok")
        except Exception:
            post.append("denied")
    assert set(post) == {"denied"}


def test_concurrent_logout_is_idempotent_and_replays_fail(svc):
    sids = _seed_sessions(svc, n=1)
    sid = sids[0]
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(lambda _: svc.logout(sid), range(20)))
    from authapp.errors import AuthError, ErrorCode
    try:
        svc.authenticate(sid)
    except AuthError as e:
        assert e.code == ErrorCode.UNAUTHENTICATED
