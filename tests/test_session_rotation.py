"""显式会话标识轮换后的 CSRF / 墓碑 / 隔离 / 并发一致性。

覆盖需求：
- 轮换响应中的新 CSRF 令牌立即生效，可同源完成各类状态变更
  （写资源、登出、改密、定向收回）；
- 旧 CSRF 令牌立即失效且判 CSRF_REVOKED，与伪造令牌 CSRF_INVALID 可区分，
  且该判定在超过 TTL 后仍稳定（CSRF 墓碑不早于重放判定被清理）；
- 旧会话标识稳定判 SESSION_REPLAYED，与从未存在的 UNAUTHENTICATED 可区分；
- 轮换只作用于本条会话：同账号其他会话照常使用/可定向收回，
  旧引用得 SESSION_ALREADY_REVOKED，他账号提交任何引用一律 NOT_FOUND；
- 轮换与并发登录的容量淘汰、并发定向收回交错时不出现半更新，
  结束后活动条数、清单引用、墓碑原因与审计计数完全对平。
"""
from __future__ import annotations

import threading
import concurrent.futures as cf
import secrets

from fastapi.testclient import TestClient

from app.api.app_factory import create_app
from app.config import default_config
from app.errors import ErrorCode
from app.storage.store import InMemoryStore
from app.time_source import ManualTimeSource
from tests.conftest import Api, ORIGIN

PW = "Sup3rSecret"
H_ORIGIN = {"Origin": ORIGIN}


def _rotate(api) -> dict:
    r = api.post("/auth/rotate")
    assert r.status_code == 200, r.text
    body = r.json()
    api.adopt(body["session_id"], body["csrf_token"])
    return body


def _raw_replay(client, sid) -> dict:
    r = client.post(
        "/access/resource",
        json={"resource": "docs/x", "action": "read"},
        headers={"Origin": ORIGIN, "X-Session-Id": sid})
    return r.json()


# --------------------------------------------------------------------- #
# 1. 新令牌立即用于状态变更
# --------------------------------------------------------------------- #
def test_new_csrf_works_immediately_for_mutating_resource(api):
    api.register("alice", roles=["editor"])
    api.login("alice")
    _rotate(api)
    r = api.post("/access/resource",
                 json_body={"resource": "docs/x", "action": "write"})
    assert r.status_code == 200, r.text


def test_new_csrf_works_for_logout_and_sid_then_replays(api):
    api.register("alice")
    api.login("alice")
    new_id = _rotate(api)["session_id"]
    r = api.post("/auth/logout")
    assert r.status_code == 200, r.text
    assert _raw_replay(api.c, new_id)["reason"] == \
        ErrorCode.SESSION_REPLAYED.value


def test_new_csrf_works_for_password_change(api):
    api.register("alice")
    api.login("alice")
    new_id = _rotate(api)["session_id"]
    r = api.post("/account/password",
                 json_body={"old_password": PW,
                            "new_password": "N3wSup3rSecret"})
    assert r.status_code == 200, r.text
    # 轮换产生的这一条被改密纪元作废
    assert r.json()["sessions_invalidated"] == 1
    assert _raw_replay(api.c, new_id)["reason"] == \
        ErrorCode.SESSION_INVALIDATED.value


def test_new_csrf_works_for_targeted_revoke(api):
    api.register("alice", roles=["viewer"])
    c = api.c
    b1 = c.post("/auth/login", json={"username": "alice", "password": PW},
                headers=H_ORIGIN).json()
    api.login("alice")  # 操作者会话
    _rotate(api)        # 操作者先轮换一次
    svc = c.app.state.services.sessions
    ref1 = svc.ref_for("alice", b1["session_id"])
    r = api.post(f"/account/sessions/{ref1}/revoke")
    assert r.status_code == 200, r.text
    assert _raw_replay(c, b1["session_id"])["reason"] == \
        ErrorCode.SESSION_REPLAYED.value
    # 轮换后的操作者会话仍活动
    assert api.get("/account/sessions").status_code == 200


def test_rotated_csrf_keeps_origin_binding(api):
    api.register("alice", roles=["editor"])
    api.login("alice")
    _rotate(api)
    # 同源立即放行
    r = api.post("/access/resource",
                 json_body={"resource": "docs/x", "action": "write"})
    assert r.status_code == 200, r.text
    # 跨来源仍按来源绑定拒绝（来源被新令牌继承）
    r_evil = api.post("/access/resource",
                      json_body={"resource": "docs/x", "action": "write"},
                      origin="http://evil.example")
    assert r_evil.status_code == 403
    assert r_evil.json()["reason"] == ErrorCode.CSRF_BOUND_ORIGIN.value


# --------------------------------------------------------------------- #
# 2. 旧令牌失效原因可区分
# --------------------------------------------------------------------- #
def test_old_csrf_revoked_distinct_from_forged(api, audit):
    api.register("alice", roles=["editor"])
    api.login("alice")
    old_csrf = api.csrf
    body = _rotate(api)

    # 新标识 + 旧令牌：曾签发但已随轮换撤销
    r = api.post("/access/resource",
                 json_body={"resource": "docs/x", "action": "write"},
                 raw_session=body["session_id"], raw_csrf=old_csrf)
    assert r.status_code == 403
    assert r.json()["reason"] == ErrorCode.CSRF_REVOKED.value

    # 新标识 + 伪造令牌：从未签发
    r_fake = api.post("/access/resource",
                      json_body={"resource": "docs/x", "action": "write"},
                      raw_csrf="00" * 32)
    assert r_fake.json()["reason"] == ErrorCode.CSRF_INVALID.value

    reasons = [r_.reason for r_ in audit.records()
               if r_.event == "CSRF_REJECTED"][-2:]
    assert reasons == [ErrorCode.CSRF_REVOKED.value,
                       ErrorCode.CSRF_INVALID.value]


def test_revoked_csrf_stays_distinguishable_after_ttl(audit):
    """CSRF TTL 到期后：新令牌判 EXPIRED，旧令牌仍稳定判 REVOKED。"""
    store = InMemoryStore()
    ts = ManualTimeSource(start=1_000_000.0)
    cfg = default_config({
        "throttle": {"max_failures": 3, "window_seconds": 300,
                     "lock_seconds": 600},
        "session": {"idle_timeout_seconds": 7200,
                    "absolute_timeout_seconds": 28800,
                    "csrf_ttl_seconds": 10},
    })
    app = create_app(store=store, time_source=ts, config=cfg, audit=audit)
    c = TestClient(app)
    c.post("/auth/register",
           json={"username": "alice", "password": PW, "roles": ["editor"]},
           headers=H_ORIGIN)
    b = c.post("/auth/login",
               json={"username": "alice", "password": PW},
               headers=H_ORIGIN).json()
    rot = c.post("/auth/rotate",
                 headers={"Origin": ORIGIN,
                          "X-Session-Id": b["session_id"],
                          "X-CSRF-Token": b["csrf_token"]}).json()
    ts.advance(11)

    def call(tok):
        return c.post("/access/resource",
                      json={"resource": "docs/x", "action": "write"},
                      headers={"Origin": ORIGIN,
                               "X-Session-Id": rot["session_id"],
                               "X-CSRF-Token": tok})

    assert call(rot["csrf_token"]).json()["reason"] == \
        ErrorCode.CSRF_EXPIRED.value
    assert call(b["csrf_token"]).json()["reason"] == \
        ErrorCode.CSRF_REVOKED.value
    assert call("ab" * 32).json()["reason"] == \
        ErrorCode.CSRF_INVALID.value


# --------------------------------------------------------------------- #
# 3. 旧标识重放判定稳定，且与从未存在可区分
# --------------------------------------------------------------------- #
def test_old_sid_replay_stable_and_distinct(api):
    api.register("alice", roles=["editor"])
    api.login("alice")
    old_sid = api.session_id
    _rotate(api)
    for _ in range(3):
        assert _raw_replay(api.c, old_sid)["reason"] == \
            ErrorCode.SESSION_REPLAYED.value
    assert _raw_replay(api.c, secrets.token_hex(32))["reason"] == \
        ErrorCode.UNAUTHENTICATED.value


def test_repeated_rotation_chain_consistent(api):
    api.register("alice", roles=["editor"])
    api.login("alice")
    chain = [api.session_id]
    old_tokens = []
    for _ in range(3):
        old_tokens.append(api.csrf)
        chain.append(_rotate(api)["session_id"])

    head_sid, head_csrf = chain[-1], api.csrf
    # 最新凭证可用
    r = api.post("/access/resource",
                 json_body={"resource": "docs/x", "action": "write"})
    assert r.status_code == 200, r.text
    # 链上所有历史标识稳定重放
    for sid in chain[:-1]:
        assert _raw_replay(api.c, sid)["reason"] == \
            ErrorCode.SESSION_REPLAYED.value
    # 所有历史令牌在最新标识上一律 CSRF_REVOKED，绝不残留可用
    for tok in old_tokens:
        r = api.post("/access/resource",
                     json_body={"resource": "docs/x", "action": "write"},
                     raw_session=head_sid, raw_csrf=tok)
        assert r.json()["reason"] == ErrorCode.CSRF_REVOKED.value


# --------------------------------------------------------------------- #
# 4. 轮换只作用于本条会话；引用隔离
# --------------------------------------------------------------------- #
def test_rotation_scoped_to_one_session(api):
    api.register("alice", roles=["viewer"])
    c = api.c
    b1 = c.post("/auth/login", json={"username": "alice", "password": PW},
                headers=H_ORIGIN).json()
    api.login("alice")
    sid2 = api.session_id
    rotated = _rotate(api)
    new_sid = rotated["session_id"]

    # 同账号另一条会话完全不受影响
    r_other = c.get("/account/sessions",
                    headers={"Origin": ORIGIN,
                             "X-Session-Id": b1["session_id"]})
    assert r_other.status_code == 200
    listing = {s["ref"] for s in
               r_other.json()["sessions"]}
    svc = c.app.state.services.sessions
    assert listing == {svc.ref_for("alice", b1["session_id"]),
                       svc.ref_for("alice", new_sid)}

    # 被轮换的旧标识不在清单，重放可区分
    assert _raw_replay(c, sid2)["reason"] == \
        ErrorCode.SESSION_REPLAYED.value


def test_rotated_old_ref_already_revoked_and_not_leaked_across_accounts(api):
    api.register("alice", roles=["viewer"])
    api.register("bob", roles=["viewer"])
    c = api.c
    b_old = c.post("/auth/login",
                   json={"username": "alice", "password": PW},
                   headers=H_ORIGIN).json()
    api.login("alice")
    rotated_sid = api.session_id
    _rotate(api)
    svc = c.app.state.services.sessions

    # 轮换前那条会话的引用：第一次定向收回成功（200），之后稳定 409
    ref_other = svc.ref_for("alice", b_old["session_id"])
    assert api.post(f"/account/sessions/{ref_other}/revoke"
                    ).status_code == 200
    r = api.post(f"/account/sessions/{ref_other}/revoke")
    assert r.status_code == 409
    assert r.json()["reason"] == ErrorCode.SESSION_ALREADY_REVOKED.value

    # 被轮换掉的标识：未经过任何收回动作，其引用也直接稳定 409
    ref_rotated = svc.ref_for("alice", rotated_sid)
    r2 = api.post(f"/account/sessions/{ref_rotated}/revoke")
    assert r2.status_code == 409
    assert r2.json()["reason"] == ErrorCode.SESSION_ALREADY_REVOKED.value

    # 他账号拿这些旧引用 / alice 活动引用：一律 404 NOT_FOUND，同形不泄漏
    bob = Api(c)
    bob.login("bob")
    active_refs = {s["ref"] for s in
                   api.get("/account/sessions").json()["sessions"]}
    for ref in {ref_other, ref_rotated, *active_refs}:
        rr = bob.post(f"/account/sessions/{ref}/revoke")
        assert rr.status_code == 404
        assert rr.json()["reason"] == ErrorCode.NOT_FOUND.value


# --------------------------------------------------------------------- #
# 5. 并发：轮换 × 容量淘汰 × 定向收回交错，无半更新
# --------------------------------------------------------------------- #
def _env(audit, capacity: int):
    store = InMemoryStore()
    ts = ManualTimeSource(start=1_000_000.0)
    cfg = default_config({
        "throttle": {"max_failures": 3, "window_seconds": 300,
                     "lock_seconds": 600},
        "session": {"max_active_sessions_per_account": capacity},
    })
    app = create_app(store=store, time_source=ts, config=cfg, audit=audit)
    return TestClient(app), store


class _Stats:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.issued: set[str] = set()
        self.rotated: set[str] = set()
        self.violations: list[str] = []
        self.statuses: list[tuple[str, int, str | None]] = []

    def note(self, op: str, status: int, reason: str | None) -> None:
        with self.lock:
            self.statuses.append((op, status, reason))

    def fail(self, msg: str) -> None:
        with self.lock:
            self.violations.append(msg)


def _write(c, sid, csrf):
    r = c.post("/access/resource",
               json={"resource": "docs/x", "action": "write"},
               headers={"Origin": ORIGIN, "X-Session-Id": sid,
                        "X-CSRF-Token": csrf})
    return r.status_code, r.json().get("reason")


def test_concurrent_rotate_evict_revoke_no_half_state(audit):
    CAP, PRE, LOGINS, SPINS = 3, 3, 24, 12
    c, store = _env(audit, CAP)
    c.post("/auth/register",
           json={"username": "alice", "password": PW, "roles": ["editor"]},
           headers=H_ORIGIN)
    stats = _Stats()

    def fresh_login() -> tuple[str, str]:
        r = c.post("/auth/login",
                   json={"username": "alice", "password": PW},
                   headers=H_ORIGIN)
        assert r.status_code == 200, r.text
        b = r.json()
        stats.issued.add(b["session_id"])
        return b["session_id"], b["csrf_token"]

    pre = [fresh_login() for _ in range(PRE)]
    barrier = threading.Barrier(4)

    def rotator(idx):
        barrier.wait()
        sid, csrf = pre[idx]
        for _ in range(SPINS):
            r = c.post("/auth/rotate",
                       headers={"Origin": ORIGIN, "X-Session-Id": sid,
                                "X-CSRF-Token": csrf})
            if r.status_code != 200:
                # 自己的会话被并发收回/淘汰：只能是明确的重放判定
                stats.note("rotate", r.status_code, r.json().get("reason"))
                if (r.status_code, r.json().get("reason")) != (
                        401, ErrorCode.SESSION_REPLAYED.value):
                    stats.fail(f"rotate unexpected {r.status_code} "
                               f"{r.json()}")
                return
            body = r.json()
            old_sid, old_csrf, sid, csrf = (
                sid, csrf, body["session_id"], body["csrf_token"])
            with stats.lock:
                stats.issued.add(sid)
                stats.rotated.add(old_sid)
            # 新凭证立刻可用（除非新会话在两次请求之间已被淘汰）
            st, why = _write(c, sid, csrf)
            stats.note("new-token-write", st, why)
            if (st, why) not in ((200, None),
                                 (401, ErrorCode.SESSION_REPLAYED.value),
                                 (401, ErrorCode.SESSION_EXPIRED.value)):
                stats.fail(f"new token unusable: {st} {why}")
            # 旧令牌绝不能在新标识上残留有效或退化成跨会话/伪造判定
            st2, why2 = _write(c, sid, old_csrf)
            stats.note("old-token-probe", st2, why2)
            if (st2, why2) == (200, None):
                stats.fail("old token still accepted after rotation")
            if why2 in (ErrorCode.CSRF_BOUND_SESSION.value,
                        ErrorCode.CSRF_INVALID.value):
                stats.fail(f"old token misclassified: {why2}")

    def evictor():
        barrier.wait()
        for _ in range(LOGINS):
            fresh_login()  # 新登录触发容量淘汰；凭证丢弃即成为淘汰候选

    def revoker():
        barrier.wait()
        op = Api(c)
        op_sid, op_csrf = fresh_login()
        op.adopt(op_sid, op_csrf)
        svc = c.app.state.services.sessions
        for _ in range(LOGINS):
            lr = c.get("/account/sessions",
                       headers={"Origin": ORIGIN,
                                "X-Session-Id": op.session_id})
            if lr.status_code != 200:
                sid, tok = fresh_login()  # 操作者被淘汰：重新登录继续
                op.adopt(sid, tok)
                continue
            refs = [s["ref"] for s in lr.json()["sessions"]
                    if not s["current"]]
            for ref in refs:
                r = op.post(f"/account/sessions/{ref}/revoke")
                stats.note("revoke", r.status_code, r.json().get("reason"))
                if r.status_code not in (200, 404, 409, 401):
                    stats.fail(f"revoke unexpected {r.status_code} {r.text}")

    with cf.ThreadPoolExecutor(max_workers=4) as ex:
        futs = [ex.submit(rotator, i) for i in range(2)]
        futs += [ex.submit(evictor), ex.submit(revoker)]
        for f in futs:
            f.result()

    assert stats.violations == [], stats.violations
    # 任何请求都不得出现 5xx
    assert all(st < 500 for _, st, _ in stats.statuses), stats.statuses

    # 并发结束后用一条最新登录会话核对最终一致性
    final = Api(c)
    final.login("alice")
    svc = c.app.state.services.sessions
    active = store.list_user_sessions("alice")
    # 上限从不被突破（定向收回会使条数低于上限，后续登录不负责补齐）
    assert len(active) <= CAP
    listed = final.get("/account/sessions").json()["sessions"]
    assert {s["ref"] for s in listed} == {
        svc.ref_for("alice", s.session_id) for s in active}

    active_ids = {s.session_id for s in active}
    gone = stats.issued - active_ids
    causes = {}
    for sid in gone:
        info = store.tombstone_info(sid)
        assert info is not None, f"issued sid {sid[:8]} neither active nor tomb"
        causes[sid] = info["cause"]
        # 重放判定与逐条收回一致
        assert _raw_replay(c, sid)["reason"] == \
            ErrorCode.SESSION_REPLAYED.value

    n_rotated = sum(1 for v in causes.values() if v == "rotated")
    n_evicted = sum(1 for v in causes.values() if v == "evicted")
    n_revoked = sum(1 for v in causes.values() if v == "revoked")
    # 轮换走的标识必须全部落在 rotated 分区（不会错记成淘汰/收回）
    assert stats.rotated <= gone
    assert n_rotated == len(stats.rotated)
    assert set(causes.values()) <= {"rotated", "evicted", "revoked"}
    assert n_rotated + n_evicted + n_revoked == len(gone)

    audit_records = audit.records()
    evict_events = [r for r in audit_records
                    if r.event == "SESSION_REVOKED"
                    and r.fields.get("cause") == "capacity_eviction"]
    targeted_ok = [r for r in audit_records
                   if r.event == "SESSION_REVOKED"
                   and r.fields.get("cause") == "targeted"
                   and r.result == "ok"]
    assert n_evicted == len(evict_events)
    assert n_revoked == len(targeted_ok)

    # 已离开标识的引用再次收回：稳定 409（不与 404 混淆）
    for sid in list(gone)[:6]:
        ref = svc.ref_for("alice", sid)
        r = final.post(f"/account/sessions/{ref}/revoke")
        assert r.status_code == 409
        assert r.json()["reason"] == ErrorCode.SESSION_ALREADY_REVOKED.value


def test_concurrent_rotate_and_revoke_same_session(audit):
    c, store = _env(audit, 8)
    c.post("/auth/register",
           json={"username": "alice", "password": PW, "roles": ["editor"]},
           headers=H_ORIGIN)
    victim = Api(c)
    victim.login("alice")
    operator = Api(c)
    operator.login("alice")
    svc = c.app.state.services.sessions
    stats = _Stats()
    stop = threading.Event()
    barrier = threading.Barrier(2)

    def rotate_side():
        barrier.wait()
        for _ in range(40):
            if stop.is_set():
                break
            r = victim.post("/auth/rotate")
            stats.note("rotate", r.status_code, r.json().get("reason"))
            if r.status_code == 200:
                body = r.json()
                with stats.lock:
                    stats.issued.add(body["session_id"])
                    stats.rotated.add(victim.session_id)
                victim.adopt(body["session_id"], body["csrf_token"])
                st, why = _write(c, victim.session_id, victim.csrf)
                # 新令牌要么立刻可用；要么这条新会话在两个请求之间恰好被
                # 并发收回（容量上限下几乎不会，仅留语义余地）。
                if (st, why) not in (
                        (200, None),
                        (401, ErrorCode.SESSION_REPLAYED.value)):
                    stats.fail(f"fresh rotated token failed: {st} {why}")
            else:
                if (r.status_code, r.json().get("reason")) != (
                        401, ErrorCode.SESSION_REPLAYED.value):
                    stats.fail(f"rotate bad: {r.status_code} {r.json()}")
                # 被收回后重新登录再继续
                b = c.post("/auth/login",
                           json={"username": "alice", "password": PW},
                           headers=H_ORIGIN).json()
                with stats.lock:
                    stats.issued.add(b["session_id"])
                victim.adopt(b["session_id"], b["csrf_token"])

    def revoke_side():
        barrier.wait()
        for _ in range(40):
            refs = [s["ref"] for s in
                    operator.get("/account/sessions").json()["sessions"]
                    if not s["current"]]
            for ref in refs:
                r = operator.post(f"/account/sessions/{ref}/revoke")
                stats.note("revoke", r.status_code, r.json().get("reason"))
                if r.status_code not in (200, 409, 404):
                    stats.fail(f"revoke bad: {r.status_code} {r.text}")

    with cf.ThreadPoolExecutor(max_workers=2) as ex:
        f1 = ex.submit(rotate_side)
        f2 = ex.submit(revoke_side)
        f2.result()
        stop.set()
        f1.result()

    assert stats.violations == [], stats.violations
    assert all(st < 500 for _, st, _ in stats.statuses)

    # 最终：每条签发过的标识要么活动、要么稳定重放；原因只可能 rotated/revoked
    active = {s.session_id for s in store.list_user_sessions("alice")}
    for sid in stats.issued:
        if sid in active:
            continue
        info = store.tombstone_info(sid)
        assert info is not None and info["cause"] in ("rotated", "revoked")
        assert _raw_replay(c, sid)["reason"] == \
            ErrorCode.SESSION_REPLAYED.value


def test_concurrent_rotation_isolated_between_accounts(audit):
    N, CHAIN = 6, 6
    c, store = _env(audit, 16)
    for i in range(N):
        c.post("/auth/register",
               json={"username": f"user{i}", "password": PW,
                     "roles": ["editor"]},
               headers=H_ORIGIN)
    workers = [Api(c) for _ in range(N)]
    for i, w in enumerate(workers):
        w.login(f"user{i}")
    barrier = threading.Barrier(N)

    def run(i):
        w = workers[i]
        barrier.wait()
        for _ in range(CHAIN):
            old_sid, old_csrf = w.session_id, w.csrf
            r = w.post("/auth/rotate")
            assert r.status_code == 200, r.text
            body = r.json()
            st, why = _write(c, body["session_id"], body["csrf_token"])
            assert (st, why) == (200, None), (st, why)
            st2, why2 = _write(c, body["session_id"], old_csrf)
            assert (st2, why2) == (403, ErrorCode.CSRF_REVOKED.value)
            assert _raw_replay(c, old_sid)["reason"] == \
                ErrorCode.SESSION_REPLAYED.value
            w.adopt(body["session_id"], body["csrf_token"])

    with cf.ThreadPoolExecutor(max_workers=N) as ex:
        list(ex.map(run, range(N)))

    # 每账号恰好一条活动会话，即各自链头
    svc = c.app.state.services.sessions
    for i, w in enumerate(workers):
        active = store.list_user_sessions(f"user{i}")
        assert len(active) == 1
        assert active[0].session_id == w.session_id
    # 跨账号引用一律 NOT_FOUND（含他账号旧引用）
    for i in range(N):
        j = (i + 1) % N
        other_active_ref = svc.ref_for(f"user{j}", workers[j].session_id)
        r = workers[i].post(
            f"/account/sessions/{other_active_ref}/revoke")
        assert r.status_code == 404
        assert r.json()["reason"] == ErrorCode.NOT_FOUND.value
