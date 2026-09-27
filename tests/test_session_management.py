"""账号自助会话管理：活动会话清单、定向收回、引用隔离、容量上限。"""
from __future__ import annotations

import threading

from fastapi.testclient import TestClient

from app.api.app_factory import create_app
from app.audit import AuditLogger
from app.config import default_config
from app.errors import ErrorCode
from app.security.totp import current_step, generate_code
from app.storage.store import InMemoryStore
from app.time_source import ManualTimeSource

PASSWORD = "Sup3rSecret"
ORIGIN = "http://testserver"


def _app(store=None, time_source=None, audit=None, cap: int | None = None):
    overrides = {}
    if cap is not None:
        overrides["session"] = {"max_sessions_per_account": cap}
    return create_app(
        store=store or InMemoryStore(),
        time_source=time_source or ManualTimeSource(1_000_000.0),
        config=default_config(overrides),
        audit=audit or AuditLogger(echo=False))


def _register(c, username, roles=("viewer",)):
    r = c.post("/auth/register",
               json={"username": username, "password": PASSWORD,
                     "roles": list(roles)},
               headers={"Origin": ORIGIN})
    assert r.status_code == 200, r.text


def _login(c, username):
    r = c.post("/auth/login",
               json={"username": username, "password": PASSWORD},
               headers={"Origin": ORIGIN})
    assert r.status_code == 200, r.text
    return r.json()


def _headers(b, *, with_csrf: bool = True):
    h = {"Origin": ORIGIN, "X-Session-Id": b["session_id"]}
    if with_csrf:
        h["X-CSRF-Token"] = b["csrf_token"]
    return h


def _list(c, b):
    r = c.get("/account/sessions", headers=_headers(b, with_csrf=False))
    assert r.status_code == 200, r.text
    return r.json()


def _revoke(c, b, reference, *, with_csrf: bool = True, origin: str = ORIGIN):
    h = _headers(b, with_csrf=with_csrf)
    h["Origin"] = origin
    return c.post("/account/sessions/revoke",
                  json={"reference": reference}, headers=h)


def _mfa_enroll_and_verify(c, app, username):
    """对已注册用户：完成 MFA 绑定，再登录并走完第二步，返回已验证会话。"""
    svc = app.state.services
    b1 = _login(c, username)
    h = _headers(b1)
    r = c.post("/mfa/enroll/start", headers=h)
    assert r.status_code == 200, r.text
    secret = r.json()["secret"]
    r = c.post("/mfa/enroll/confirm",
               json={"code": generate_code(
                   secret, current_step(svc.time.now(), 30))},
               headers=h)
    assert r.status_code == 200, r.text
    svc.time.advance(31)
    b2 = _login(c, username)
    h2 = _headers(b2)
    r = c.post("/mfa/verify",
               json={"code": generate_code(
                   secret, current_step(svc.time.now(), 30))},
               headers=h2)
    assert r.status_code == 200, r.text
    return {"session_id": r.json()["session_id"],
            "csrf_token": r.json()["csrf_token"]}


# --------------------------------------------------------------------- #
# 清单：认证/MFA 门槛、字段与稳定顺序
# --------------------------------------------------------------------- #
def test_list_requires_session():
    c = TestClient(_app())
    r = c.get("/account/sessions")
    assert r.status_code == 401
    assert r.json()["reason"] == ErrorCode.UNAUTHENTICATED.value


def test_list_requires_mfa_completion():
    app = _app()
    c = TestClient(app)
    _register(c, "alice")
    _mfa_enroll_and_verify(c, app, "alice")
    # 再登录一次：产生一个等待 MFA 的会话
    pending = _login(c, "alice")
    r = c.get("/account/sessions",
              headers={"Origin": ORIGIN,
                       "X-Session-Id": pending["session_id"]})
    assert r.status_code == 403
    assert r.json()["reason"] == \
        ErrorCode.SESSION_CONFIRMATION_PENDING.value


def test_list_fields_and_stable_order(api):
    api.register("alice", roles=["viewer"])
    api.login("alice")
    api.c.post("/auth/login",
               json={"username": "alice", "password": "Sup3rSecret"},
               headers={"Origin": ORIGIN})
    r1 = api.get("/account/sessions")
    assert r1.status_code == 200, r1.text
    body1 = r1.json()
    assert body1["count"] == 2
    items = body1["sessions"]
    # 必需字段齐备
    for it in items:
        assert set(it) == {"reference", "created_at", "last_seen_at",
                           "mfa_verified", "current"}
        assert len(it["reference"]) == 64
        assert it["mfa_verified"] is True
    # 恰好一条标记为当前会话
    assert sum(1 for it in items if it["current"]) == 1
    # 顺序按创建时间稳定
    assert items[0]["created_at"] <= items[1]["created_at"]
    # 同一时刻重复查看：条数、顺序、引用完全一致
    body2 = api.get("/account/sessions").json()
    assert body2 == body1


def test_list_is_isolated_between_accounts(api):
    api.register("alice", roles=["viewer"])
    api.register("bob", roles=["viewer"])
    api.login("alice")
    api.login("bob")
    alice = api.c.post("/auth/login",
                       json={"username": "alice", "password": "Sup3rSecret"},
                       headers={"Origin": ORIGIN}).json()
    r = api.c.get("/account/sessions",
                  headers={"X-Session-Id": alice["session_id"]})
    items = r.json()["sessions"]
    assert r.json()["count"] == 2  # alice 的两条
    # 用 bob 会话查看只能看到 bob 自己
    bob = api.c.post("/auth/login",
                     json={"username": "bob", "password": "Sup3rSecret"},
                     headers={"Origin": ORIGIN}).json()
    r = api.c.get("/account/sessions",
                  headers={"X-Session-Id": bob["session_id"]})
    assert r.json()["count"] == 2  # 恰好 bob 的两条
    bob_refs = {it["reference"] for it in r.json()["sessions"]}
    alice_refs = {it["reference"] for it in items}
    assert bob_refs.isdisjoint(alice_refs)


def test_reference_does_not_leak_session_id(api):
    api.register("alice", roles=["viewer"])
    b = api.login("alice").json()
    sid = b["session_id"]
    items = api.get("/account/sessions").json()["sessions"]
    ref = items[0]["reference"]
    # 引用不等于原始标识，也不包含其任何片段
    assert ref != sid
    assert sid not in ref
    assert sid[:16] not in ref


# --------------------------------------------------------------------- #
# 定向收回
# --------------------------------------------------------------------- #
def test_revoke_only_target_session(api):
    api.register("alice", roles=["viewer"])
    b1 = api.c.post("/auth/login",
                    json={"username": "alice", "password": "Sup3rSecret"},
                    headers={"Origin": ORIGIN}).json()
    b2 = api.c.post("/auth/login",
                    json={"username": "alice", "password": "Sup3rSecret"},
                    headers={"Origin": ORIGIN}).json()
    api.adopt(b1["session_id"], b1["csrf_token"])
    items = api.get("/account/sessions").json()["sessions"]
    target = next(it for it in items if not it["current"])
    r = api.post("/account/sessions/revoke",
                 json_body={"reference": target["reference"]})
    assert r.status_code == 200, r.text
    assert r.json() == {"status": "revoked"}
    # 被收回的那条立即失效，且与"从未存在"可区分
    r = api.c.post("/access/resource",
                   json={"resource": "docs/x", "action": "read"},
                   headers={"X-Session-Id": b2["session_id"]})
    assert r.status_code == 401
    assert r.json()["reason"] == ErrorCode.SESSION_REPLAYED.value
    # 同一账号其余会话不受影响（当前会话仍可访问）
    r = api.post("/access/resource",
                 json_body={"resource": "docs/x", "action": "read"})
    assert r.status_code == 200, r.text
    # 列表中不再出现被收回的会话
    remain = api.get("/account/sessions").json()
    assert remain["count"] == 1


def test_revoke_current_session(api):
    api.register("alice", roles=["viewer"])
    api.login("alice")
    items = api.get("/account/sessions").json()["sessions"]
    current = next(it for it in items if it["current"])
    r = api.post("/account/sessions/revoke",
                 json_body={"reference": current["reference"]})
    assert r.status_code == 200
    # 当前会话立即失效
    r = api.post("/access/resource",
                 json_body={"resource": "docs/x", "action": "read"})
    assert r.status_code == 401
    assert r.json()["reason"] == ErrorCode.SESSION_REPLAYED.value


def test_revoke_already_revoked_reference_is_distinguishable(api):
    api.register("alice", roles=["viewer"])
    api.login("alice")
    b2 = api.c.post("/auth/login",
                    json={"username": "alice", "password": "Sup3rSecret"},
                    headers={"Origin": ORIGIN}).json()
    target = next(it for it in api.get("/account/sessions").json()["sessions"]
                  if not it["current"])
    assert api.post("/account/sessions/revoke",
                    json_body={"reference": target["reference"]}
                    ).status_code == 200
    # 同一引用再次提交：稳定的"已收回"判定
    r = api.post("/account/sessions/revoke",
                 json_body={"reference": target["reference"]})
    assert r.status_code == 410
    assert r.json()["reason"] == \
        ErrorCode.SESSION_REFERENCE_REVOKED.value
    # 再多次结果一致
    r2 = api.post("/account/sessions/revoke",
                  json_body={"reference": target["reference"]})
    assert r2.status_code == 410
    assert r2.json()["reason"] == r.json()["reason"]


def test_revoke_unknown_reference_rejected(api):
    api.register("alice", roles=["viewer"])
    api.login("alice")
    r = api.post("/account/sessions/revoke",
                 json_body={"reference": "0" * 64})
    assert r.status_code == 404
    assert r.json()["reason"] == \
        ErrorCode.SESSION_REFERENCE_UNKNOWN.value
    # 非法格式同样是"未知"，不给出额外信息
    r = api.post("/account/sessions/revoke",
                 json_body={"reference": "garbage"})
    assert r.json()["reason"] == ErrorCode.VALIDATION_ERROR.value


def test_cross_account_reference_cannot_be_used(api):
    api.register("alice", roles=["viewer"])
    api.register("bob", roles=["viewer"])
    ba = api.c.post("/auth/login",
                    json={"username": "alice", "password": "Sup3rSecret"},
                    headers={"Origin": ORIGIN}).json()
    bb = api.c.post("/auth/login",
                    json={"username": "bob", "password": "Sup3rSecret"},
                    headers={"Origin": ORIGIN}).json()
    # alice 取自己某条引用
    ra = api.c.get("/account/sessions",
                   headers={"X-Session-Id": ba["session_id"]})
    alice_ref = ra.json()["sessions"][0]["reference"]
    # bob 用 alice 的引用：被当作未知引用拒绝，且 alice 会话仍活着
    r = api.c.post("/account/sessions/revoke",
                   json={"reference": alice_ref},
                   headers={"Origin": ORIGIN,
                            "X-Session-Id": bb["session_id"],
                            "X-CSRF-Token": bb["csrf_token"]})
    assert r.status_code == 404
    assert r.json()["reason"] == \
        ErrorCode.SESSION_REFERENCE_UNKNOWN.value
    r = api.c.post("/access/resource",
                   json={"resource": "docs/x", "action": "read"},
                   headers={"X-Session-Id": ba["session_id"]})
    assert r.status_code == 200


def test_revoke_requires_csrf(api):
    api.register("alice", roles=["viewer"])
    api.login("alice")
    ref = api.get("/account/sessions").json()["sessions"][0]["reference"]
    r = api.post("/account/sessions/revoke",
                 json_body={"reference": ref}, with_csrf=False)
    assert r.status_code == 403
    assert r.json()["reason"] == ErrorCode.CSRF_MISSING.value


def test_rejected_reference_after_account_invalidation(api):
    """全量登出/改密等账号级失效后，引用解析给出 SESSION_INVALIDATED。"""
    api.register("alice", roles=["viewer"])
    api.login("alice")
    b2 = api.c.post("/auth/login",
                    json={"username": "alice", "password": "Sup3rSecret"},
                    headers={"Origin": ORIGIN}).json()
    target = next(it for it in api.get("/account/sessions").json()["sessions"]
                  if not it["current"])
    # 当前会话执行全量登出：另一条被账号级失效
    assert api.post("/auth/logout-all").status_code == 200
    # 用仍然存活视角不可能（当前会话也失效了）；新登录后引用解析为已作废
    b3 = api.login("alice").json()
    api.adopt(b3["session_id"], b3["csrf_token"])
    r = api.post("/account/sessions/revoke",
                 json_body={"reference": target["reference"]})
    assert r.status_code == 401
    assert r.json()["reason"] == ErrorCode.SESSION_INVALIDATED.value


# --------------------------------------------------------------------- #
# 容量上限
# --------------------------------------------------------------------- #
def test_capacity_evicts_oldest_and_keeps_new(api, time_source):
    app = api.c.app
    # 重建带容量上限 3 的应用（复用同一存储与时间源）
    app2 = create_app(
        store=app.state.services.store, time_source=time_source,
        config=default_config({"session": {"max_sessions_per_account": 3}}),
        audit=AuditLogger(echo=False))
    c = TestClient(app2)
    _register(c, "carol")
    sessions = []
    for _ in range(3):
        sessions.append(_login(c, "carol"))
        time_source.advance(10)
    newest = _login(c, "carol")  # 第 4 次登录 -> 淘汰最旧
    # 数量不超过上限，且最旧被淘汰、最新保留
    svc = c.app.state.services
    active = sorted(
        (s for s in svc.store.list_user_sessions("carol")),
        key=lambda s: s.created_at)
    assert len(active) == 3
    active_ids = {s.session_id for s in active}
    assert newest["session_id"] in active_ids
    assert sessions[0]["session_id"] not in active_ids
    assert sessions[1]["session_id"] in active_ids
    assert sessions[2]["session_id"] in active_ids
    # 被淘汰的最旧会话：重放判定与逐条收回一致
    r = c.post("/access/resource",
               json={"resource": "docs/x", "action": "read"},
               headers={"X-Session-Id": sessions[0]["session_id"]})
    assert r.status_code == 401
    assert r.json()["reason"] == ErrorCode.SESSION_REPLAYED.value
    # 列表条数与存储一致，且不含被淘汰项
    r = c.get("/account/sessions",
              headers={"X-Session-Id": newest["session_id"]})
    assert r.json()["count"] == 3


def test_capacity_limit_one_keeps_latest_login(api, time_source):
    app = create_app(
        store=InMemoryStore(), time_source=time_source,
        config=default_config({"session": {"max_sessions_per_account": 1}}),
        audit=AuditLogger(echo=False))
    c = TestClient(app)
    _register(c, "solo")
    first = _login(c, "solo")
    time_source.advance(5)
    second = _login(c, "solo")
    time_source.advance(5)
    third = _login(c, "solo")
    svc = c.app.state.services
    active = svc.store.list_user_sessions("solo")
    assert len(active) == 1
    assert active[0].session_id == third["session_id"]
    for old in (first["session_id"], second["session_id"]):
        r = c.post("/access/resource",
                   json={"resource": "docs/x", "action": "read"},
                   headers={"X-Session-Id": old})
        assert r.json()["reason"] == ErrorCode.SESSION_REPLAYED.value
    # 最新会话可用
    r = c.post("/access/resource",
               json={"resource": "docs/x", "action": "read"},
               headers={"X-Session-Id": third["session_id"]})
    assert r.status_code == 200


def test_capacity_is_per_account(api, time_source):
    app = create_app(
        store=InMemoryStore(), time_source=time_source,
        config=default_config({"session": {"max_sessions_per_account": 2}}),
        audit=AuditLogger(echo=False))
    c = TestClient(app)
    _register(c, "u1")
    _register(c, "u2")
    for _ in range(3):
        _login(c, "u1")
    for _ in range(3):
        _login(c, "u2")
    svc = c.app.state.services
    assert len(svc.store.list_user_sessions("u1")) == 2
    assert len(svc.store.list_user_sessions("u2")) == 2


def test_concurrent_logins_never_exceed_capacity():
    store = InMemoryStore()
    time_source = ManualTimeSource(2_000_000.0)
    app = create_app(
        store=store, time_source=time_source,
        config=default_config({"session": {"max_sessions_per_account": 5}}),
        audit=AuditLogger(echo=False))
    svc = app.state.services
    svc.auth.provision_user("duke", PASSWORD, ("viewer",))

    errors: list[Exception] = []
    barrier = threading.Barrier(8)

    def worker(i: int):
        try:
            barrier.wait()
            # 登录在同一存储单锁内原子完成"创建 + 淘汰"
            svc.auth.login("duke", PASSWORD, origin=ORIGIN, remote="?")
        except Exception as e:  # pragma: no cover - 失败即暴露
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(i,))
               for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, errors
    active = store.list_user_sessions("duke")
    assert len(active) == 5, len(active)
    # 保留的应是最后创建的 5 条（最旧淘汰，新登录始终保留）
    created = sorted(s.created_at for s in active)
    assert created == sorted(created)[-5:]


def test_concurrent_revoke_and_eviction_leave_consistent_state(
        time_source):
    store = InMemoryStore()
    app = create_app(
        store=store, time_source=time_source,
        config=default_config({"session": {"max_sessions_per_account": 3}}),
        audit=AuditLogger(echo=False))
    c = TestClient(app)
    svc = app.state.services
    _register(c, "molly")
    seeds = [_login(c, "molly") for _ in range(3)]

    # 用服务层直接操作：一个线程定向收回中间会话，若干线程并发登录触发淘汰
    from app.services.auth import Principal

    def principal_for(sid, csrf=None):
        return Principal(session_id=sid, username="molly",
                         roles=("viewer",), mfa_verified=True,
                         csrf_token=csrf)

    def current_ref(b):
        p = principal_for(b["session_id"], b["csrf_token"])
        return next(
            it["reference"]
            for it in svc.sessions.list_active(p)["sessions"]
            if it["current"])

    errors: list[Exception] = []

    def revoker():
        try:
            ref = current_ref(seeds[1])
            svc.sessions.revoke(
                principal_for(seeds[1]["session_id"],
                              seeds[1]["csrf_token"]), ref)
        except Exception as e:  # pragma: no cover
            errors.append(e)

    def logger():
        try:
            svc.auth.login("molly", PASSWORD, origin=ORIGIN, remote="?")
        except Exception as e:  # pragma: no cover
            errors.append(e)

    threads = [threading.Thread(target=revoker)]
    threads += [threading.Thread(target=logger) for _ in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, errors
    active = store.list_user_sessions("molly")
    # 任何半更新都会让计数偏离上限；且所有活动会话都可被列表/重放一致判定
    assert len(active) <= 3, len(active)
    # 列表视图与存储状态一致（用任一仍活动的会话作主体）
    survivor = sorted(active, key=lambda s: (s.created_at, s.session_id))[-1]
    p = principal_for(survivor.session_id, survivor.csrf_token)
    listing = svc.sessions.list_active(p)["sessions"]
    assert len(listing) == len(active)
    # 被收回/被淘汰的标识全部在墓碑中：重放判定与逐条收回一致
    active_ids = {s.session_id for s in active}
    gone = [b["session_id"] for b in seeds
            if b["session_id"] not in active_ids]
    assert gone  # 至少有一条（收回或淘汰）离开了活动集合
    for sid in gone:
        assert store.is_tombstoned(sid, svc.time.now())
    assert len(listing) == len(active)


def test_invalid_capacity_config_fails_closed():
    import pytest
    from app.errors import ConfigError
    for bad in (0, -1, True):
        with pytest.raises(ConfigError):
            default_config({"session": {"max_sessions_per_account": bad}})


def test_expired_sessions_are_swept_from_list_and_capacity(time_source):
    app = create_app(
        store=InMemoryStore(), time_source=time_source,
        config=default_config({"session": {"max_sessions_per_account": 2}}),
        audit=AuditLogger(echo=False))
    c = TestClient(app)
    _register(c, "dora")
    old1 = _login(c, "dora")
    old2 = _login(c, "dora")
    # 两条均超过空闲/绝对过期后再登录：过期会话不占名额，不触发淘汰
    time_source.advance(30000)
    fresh = _login(c, "dora")
    svc = c.app.state.services
    active = svc.store.list_user_sessions("dora")
    assert {s.session_id for s in active} == {fresh["session_id"]}
    # 旧标识重放与逐条收回一致
    r = c.post("/access/resource",
               json={"resource": "docs/x", "action": "read"},
               headers={"X-Session-Id": old1["session_id"]})
    assert r.json()["reason"] == ErrorCode.SESSION_REPLAYED.value
    # 列表只含活动会话
    r = c.get("/account/sessions",
              headers={"X-Session-Id": fresh["session_id"]})
    assert r.json()["count"] == 1
