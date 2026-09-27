"""账号自助会话管理：活动会话清单、稳定引用、定向收回、容量淘汰。

重点断言：
- 清单顺序/条数稳定、字段齐全、跨账号隔离、引用不可反推且跨账号不可用；
- 定向收回只影响目标；重放与"从未存在"可区分；已失效/未知引用可区分；
- 容量上限在串行与并发登录下都成立，新登录始终保留，淘汰与逐条收回一致。
"""
from __future__ import annotations

import concurrent.futures as cf
import secrets

from fastapi.testclient import TestClient

from app.api.app_factory import create_app
from app.config import ConfigError, default_config
from app.errors import ErrorCode
from app.security.totp import current_step, generate_code
from app.storage.store import InMemoryStore
from app.time_source import ManualTimeSource
from tests.conftest import Api, ORIGIN

PW = "Sup3rSecret"


def _capacity_client(audit, max_active, *, start=1_000_000.0):
    store = InMemoryStore()
    ts = ManualTimeSource(start=start)
    cfg = default_config({
        "throttle": {"max_failures": 3, "window_seconds": 300,
                     "lock_seconds": 600},
        "session": {"max_active_sessions_per_account": max_active},
    })
    app = create_app(store=store, time_source=ts, config=cfg, audit=audit)
    return Api(TestClient(app)), store, ts


def _login_pair(api, username, password=PW):
    r = api.c.post("/auth/login",
                   json={"username": username, "password": password},
                   headers={"Origin": ORIGIN})
    assert r.status_code == 200, r.text
    body = r.json()
    return body["session_id"], body["csrf_token"]


def _raw_get(client, sid):
    return client.get("/account/sessions",
                      headers={"Origin": ORIGIN, "X-Session-Id": sid})


# --------------------------------------------------------------------- #
# 活动会话清单
# --------------------------------------------------------------------- #
def test_list_sessions_stable_and_isolated(api):
    api.register("alice", roles=["viewer"])
    api.register("bob", roles=["viewer"])
    sid_a1, _ = _login_pair(api, "alice")
    sid_a2, _ = _login_pair(api, "alice")
    sid_b1, _ = _login_pair(api, "bob")
    sid_a3, csrf_a3 = _login_pair(api, "alice")
    api.adopt(sid_a3, csrf_a3)

    r1 = api.get("/account/sessions")
    assert r1.status_code == 200, r1.text
    first = r1.json()["sessions"]
    assert len(first) == 3
    # 重复查看：条数与顺序稳定
    second = api.get("/account/sessions").json()["sessions"]
    assert first == second

    # 排序：created_at 升序；字段齐全；引用为 64 位十六进制、不等于原标识
    created = [s["created_at"] for s in first]
    assert created == sorted(created)
    for s in first:
        assert set(s) == {"ref", "created_at", "last_seen",
                          "mfa_verified", "current"}
        assert len(s["ref"]) == 64 and all(c in "0123456789abcdef" for c in s["ref"])
        assert s["ref"] not in (sid_a1, sid_a2, sid_a3)
    currents = [s for s in first if s["current"]]
    assert len(currents) == 1 and currents[0]["ref"] == \
        api.c.app.state.services.sessions.ref_for("alice", sid_a3)

    # 同一引用对同一会话恒定
    assert first[0]["ref"] == second[0]["ref"]

    # 跨账号隔离：bob 只看到自己的会话，且看不到 alice 的引用
    bob = Api(api.c)
    bob.adopt(sid_b1, None)
    bob.csrf = None
    rb = _raw_get(api.c, sid_b1).json()["sessions"]
    assert len(rb) == 1
    alice_refs = {s["ref"] for s in first}
    assert rb[0]["ref"] not in alice_refs


def test_list_requires_mfa_verified(api, time_source):
    api.register("alice", roles=["viewer"])
    api.login("alice")
    api._username = "alice"
    r = api.post("/mfa/enroll/start")
    secret = r.json()["secret"]
    r = api.post("/mfa/enroll/confirm",
                 json_body={"code": generate_code(
                     secret, current_step(time_source.now(), 30))})
    assert r.status_code == 200, r.text
    # 重新登录后处于待 MFA 状态：清单与收回都被挡
    api.login("alice")
    assert api.get("/account/sessions").json()["reason"] == \
        ErrorCode.SESSION_CONFIRMATION_PENDING.value
    r = api.post("/account/sessions/" + "a" * 64 + "/revoke")
    assert r.json()["reason"] == \
        ErrorCode.SESSION_CONFIRMATION_PENDING.value
    # 完成第二步后可查看
    time_source.advance(30)
    r = api.post("/mfa/verify",
                 json_body={"code": generate_code(
                     secret, current_step(time_source.now(), 30))})
    assert r.status_code == 200, r.text
    api.session_id = r.json()["session_id"]
    api.csrf = r.json()["csrf_token"]
    assert api.get("/account/sessions").status_code == 200


def test_list_excludes_expired_sessions(audit):
    store = InMemoryStore()
    ts = ManualTimeSource(start=1_000_000.0)
    cfg = default_config({
        "throttle": {"max_failures": 3, "window_seconds": 300,
                     "lock_seconds": 600},
        "session": {"idle_timeout_seconds": 100},
    })
    app = create_app(store=store, time_source=ts, config=cfg, audit=audit)
    api = Api(TestClient(app))
    api.register("alice", roles=["viewer"])
    sid_old, _ = _login_pair(api, "alice")
    ts.advance(50)
    sid_new, csrf_new = _login_pair(api, "alice")
    # 旧会话空闲超时（100 < 110），新会话仍活跃（150 > 110）
    ts.advance(60)
    api.adopt(sid_new, csrf_new)
    sessions = api.get("/account/sessions").json()["sessions"]
    assert len(sessions) == 1
    svc = api.c.app.state.services.sessions
    assert sessions[0]["ref"] == svc.ref_for("alice", sid_new)


# --------------------------------------------------------------------- #
# 定向收回
# --------------------------------------------------------------------- #
def test_revoke_only_target_session(api, audit):
    api.register("alice", roles=["viewer"])
    sid1, _ = _login_pair(api, "alice")
    sid2, _ = _login_pair(api, "alice")
    sid3, csrf3 = _login_pair(api, "alice")
    api.adopt(sid3, csrf3)

    svc = api.c.app.state.services.sessions
    ref1 = svc.ref_for("alice", sid1)
    ref2 = svc.ref_for("alice", sid2)

    r = api.post(f"/account/sessions/{ref1}/revoke")
    assert r.status_code == 200 and r.json() == {"status": "revoked"}

    # 目标立即失效，且重放与"从未存在"可区分
    assert _raw_get(api.c, sid1).json()["reason"] == \
        ErrorCode.SESSION_REPLAYED.value
    fake = secrets.token_hex(32)
    assert _raw_get(api.c, fake).json()["reason"] == \
        ErrorCode.UNAUTHENTICATED.value
    # 同账号其余会话不受影响
    assert _raw_get(api.c, sid2).status_code == 200
    assert _raw_get(api.c, sid3).status_code == 200
    remaining = {s["ref"] for s in
                 _raw_get(api.c, sid3).json()["sessions"]}
    assert remaining == {ref2, svc.ref_for("alice", sid3)}
    assert ref1 not in remaining

    rec = [r for r in audit.records() if r.event == "SESSION_REVOKED"
           and r.fields.get("cause") == "targeted"
           and r.result == "ok"]
    assert len(rec) == 1


def test_revoke_invalid_refs_distinguishable(api):
    api.register("alice", roles=["viewer"])
    api.register("bob", roles=["viewer"])
    sid_a, _ = _login_pair(api, "alice")          # 收回目标
    sid_a2, csrf_a2 = _login_pair(api, "alice")   # 操作者会话
    sid_b, csrf_b = _login_pair(api, "bob")
    api.adopt(sid_a2, csrf_a2)
    svc = api.c.app.state.services.sessions

    # 已存在但属于其他账号的引用：与随机垃圾完全同形（404 NOT_FOUND）
    ref_b = svc.ref_for("bob", sid_b)
    r_cross = api.post(f"/account/sessions/{ref_b}/revoke")
    r_garbage = api.post(f"/account/sessions/{'f' * 64}/revoke")
    assert r_cross.status_code == r_garbage.status_code == 404
    assert r_cross.json()["reason"] == r_garbage.json()["reason"] == \
        ErrorCode.NOT_FOUND.value

    # 收回自己的会话后再次引用：稳定的 409，与 404 可区分
    ref_a = svc.ref_for("alice", sid_a)
    r = api.post(f"/account/sessions/{ref_a}/revoke")
    assert r.status_code == 200
    r_again = api.post(f"/account/sessions/{ref_a}/revoke")
    assert r_again.status_code == 409
    assert r_again.json()["reason"] == \
        ErrorCode.SESSION_ALREADY_REVOKED.value
    # 该已失效引用对其他账号仍表现为不存在（不跨账号泄漏）
    bob = Api(api.c).adopt(sid_b, csrf_b)
    assert bob.post(f"/account/sessions/{ref_a}/revoke"
                    ).json()["reason"] == ErrorCode.NOT_FOUND.value


def test_revoke_requires_csrf(api):
    api.register("alice", roles=["viewer"])
    sid, csrf = _login_pair(api, "alice")
    api.adopt(sid, csrf)
    svc = api.c.app.state.services.sessions
    r = api.post(f"/account/sessions/{svc.ref_for('alice', sid)}/revoke",
                 with_csrf=False)
    assert r.status_code == 403
    assert r.json()["reason"] == ErrorCode.CSRF_MISSING.value
    # 未通过 CSRF 不得作废任何会话
    assert _raw_get(api.c, sid).status_code == 200


def test_revoke_requires_session(api):
    r = api.c.post(f"/account/sessions/{'a' * 64}/revoke",
                   headers={"Origin": ORIGIN})
    assert r.status_code == 401


# --------------------------------------------------------------------- #
# 每账号容量上限
# --------------------------------------------------------------------- #
def test_capacity_evicts_oldest_and_keeps_newest(audit, time_source):
    api, store, ts = _capacity_client(audit, 2)
    api.register("alice", roles=["viewer"])
    sids = []
    for i in range(3):
        sids.append(_login_pair(api, "alice")[0])
        ts.advance(10)
    sid1, sid2, sid3 = sids

    # 最旧被淘汰，新登录全部保留
    sessions = _raw_get(api.c, sid3).json()["sessions"]
    svc = api.c.app.state.services.sessions
    refs = {s["ref"] for s in sessions}
    assert len(sessions) == 2
    assert refs == {svc.ref_for("alice", sid2), svc.ref_for("alice", sid3)}

    # 淘汰与逐条收回表现一致：重放 SESSION_REPLAYED，且区别于从未存在
    assert _raw_get(api.c, sid1).json()["reason"] == \
        ErrorCode.SESSION_REPLAYED.value
    assert _raw_get(api.c, secrets.token_hex(32)).json()["reason"] == \
        ErrorCode.UNAUTHENTICATED.value

    ev = [r for r in audit.records() if r.event == "SESSION_REVOKED"
          and r.fields.get("cause") == "capacity_eviction"]
    assert len(ev) == 1
    # 存储内活动数任何时刻（此刻）也不超过上限
    assert len(store.list_user_sessions("alice")) == 2


def test_capacity_never_evicts_new_session_under_concurrency(audit):
    api, store, ts = _capacity_client(audit, 2)
    api.register("alice", roles=["viewer"])
    n = 8

    def one(_):
        r = api.c.post("/auth/login",
                       json={"username": "alice", "password": PW},
                       headers={"Origin": ORIGIN})
        assert r.status_code == 200, r.text
        return r.json()["session_id"]

    with cf.ThreadPoolExecutor(n) as ex:
        new_sids = list(ex.map(one, range(n)))

    svc = api.c.app.state.services.sessions
    survivors = store.list_user_sessions("alice")
    assert len(survivors) == 2
    # 清单、存储与引用判定三方一致
    listed = _raw_get(api.c, survivors[0].session_id).json()["sessions"]
    assert {s["ref"] for s in listed} == {
        svc.ref_for("alice", s.session_id) for s in survivors}
    # 保留的都是并发期间的新登录会话；被淘汰者重放可区分
    assert {s.session_id for s in survivors} <= set(new_sids)
    evicted = [sid for sid in new_sids
               if sid not in {s.session_id for s in survivors}]
    assert evicted
    for sid in evicted:
        assert _raw_get(api.c, sid).json()["reason"] == \
            ErrorCode.SESSION_REPLAYED.value


def test_concurrent_revoke_and_eviction_consistent(audit):
    api, store, ts = _capacity_client(audit, 4)
    api.register("alice", roles=["viewer"])
    s1, _ = _login_pair(api, "alice"); ts.advance(10)
    s2, _ = _login_pair(api, "alice"); ts.advance(10)
    s3, _ = _login_pair(api, "alice"); ts.advance(10)
    s4, csrf4 = _login_pair(api, "alice"); ts.advance(10)
    preexisting = {s1, s2, s3, s4}
    svc = api.c.app.state.services.sessions
    ref2 = svc.ref_for("alice", s2)

    def evict_twice():
        _login_pair(api, "alice"); ts.advance(10)
        return _login_pair(api, "alice")

    def revoke_middle():
        # 操作者 s4 在两次新登录后仍保留（最多淘汰 s1、s2）
        api.adopt(s4, csrf4)
        return api.post(f"/account/sessions/{ref2}/revoke").status_code

    with cf.ThreadPoolExecutor(2) as ex:
        f_evict = ex.submit(evict_twice)
        f_revoke = ex.submit(revoke_middle)
        sid_last, _ = f_evict.result()
        revoke_code = f_revoke.result()

    # 收回要么在淘汰前命中（200），要么会话已先被淘汰（409），无半更新/5xx
    assert revoke_code in (200, 409)
    survivors = {s.session_id for s in store.list_user_sessions("alice")}
    assert len(survivors) <= 4
    # 最后登录的会话必定保留且可用
    assert sid_last in survivors
    assert _raw_get(api.c, sid_last).status_code == 200
    # 所有离开活动集的预置会话都稳定落在墓碑，重放判定一致（与逐条收回相同）
    gone = preexisting - survivors
    assert s1 in gone  # 两次淘汰必先淘汰 s1
    for sid in gone:
        assert _raw_get(api.c, sid).json()["reason"] == \
            ErrorCode.SESSION_REPLAYED.value
    # 清单与存储条数一致
    listed = _raw_get(api.c, sid_last).json()["sessions"]
    assert len(listed) == len(survivors)


def test_capacity_config_validation():
    try:
        default_config({"session": {"max_active_sessions_per_account": 0}})
    except ConfigError:
        pass
    else:
        raise AssertionError("zero capacity must fail config validation")
    try:
        default_config({"session": {"reference_secret": "short"}})
    except ConfigError:
        pass
    else:
        raise AssertionError("short reference_secret must fail validation")
