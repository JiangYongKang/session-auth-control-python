"""会话标识轮换（/auth/rotate）的令牌语义与一致性。

覆盖：
- 轮换响应里的新 CSRF 令牌可立即在同一来源完成各类状态变更；
- 旧 CSRF 令牌立即失效，判 CSRF_REVOKED，与伪造令牌 CSRF_INVALID 可区分；
- 旧会话标识重放判 SESSION_REPLAYED，与从未存在 UNAUTHENTICATED 可区分；
- 轮换只影响本会话：同账号其他会话与他账号会话不受影响；
- 本账号旧引用再收回判 SESSION_ALREADY_REVOKED，他账号提交该引用判 NOT_FOUND；
- 轮换与容量淘汰、并发登录、定向收回交错时不出现半更新。
"""
from __future__ import annotations

import concurrent.futures as cf
import threading

from fastapi.testclient import TestClient

from app.api.app_factory import create_app
from app.config import default_config
from app.errors import ErrorCode
from app.storage.store import InMemoryStore
from app.time_source import ManualTimeSource
from tests.conftest import Api, ORIGIN

PW = "Sup3rSecret"


def _rotate(api):
    r = api.post("/auth/rotate")
    assert r.status_code == 200, r.text
    body = r.json()
    api.adopt(body["session_id"], body["csrf_token"])
    return body


# --------------------------------------------------------------------- #
# 新令牌立即可用 / 旧令牌立即可区分失效
# --------------------------------------------------------------------- #
def test_new_token_immediately_usable_for_all_mutations(api):
    api.register("alice", roles=["editor"])
    api.login("alice")
    body = _rotate(api)
    new_sid, new_csrf = body["session_id"], body["csrf_token"]

    # 1) 带写操作的资源请求（同源、新令牌）
    r = api.post("/access/resource",
                 json_body={"resource": "docs/x", "action": "write"})
    assert r.status_code == 200, r.text

    # 2) 收回另一条会话
    sid2 = api.c.post("/auth/login",
                      json={"username": "alice", "password": PW},
                      headers={"Origin": ORIGIN}).json()["session_id"]
    svc = api.c.app.state.services.sessions
    ref2 = svc.ref_for("alice", sid2)
    r = api.post(f"/account/sessions/{ref2}/revoke")
    assert r.status_code == 200, r.text

    # 3) 再次轮换后立即登出（链式轮换）
    body2 = _rotate(api)
    r = api.post("/auth/logout")
    assert r.status_code == 200, r.text
    # 登出后新标识也已失效
    r = api.post("/access/resource",
                 json_body={"resource": "docs/x", "action": "read"})
    assert r.status_code == 401


def test_new_token_works_for_password_change(api):
    api.register("alice")
    api.login("alice")
    _rotate(api)
    r = api.post("/account/password",
                 json_body={"old_password": PW, "new_password": "BrandNew9"})
    assert r.status_code == 200, r.text
    assert r.json()["sessions_invalidated"] == 1


def test_old_token_immediately_revoked_and_distinguishable(api, audit):
    api.register("alice", roles=["editor"])
    api.login("alice")
    old_sid, old_csrf = api.session_id, api.csrf
    _rotate(api)

    # 旧令牌配新会话：曾签发但已撤销 -> CSRF_REVOKED（不是跨会话误判）
    r = api.post("/access/resource",
                 json_body={"resource": "docs/x", "action": "write"},
                 raw_csrf=old_csrf)
    assert r.status_code == 403
    assert r.json()["reason"] == ErrorCode.CSRF_REVOKED.value

    # 伪造/从未签发的令牌 -> CSRF_INVALID，二者稳定可区分
    r = api.post("/access/resource",
                 json_body={"resource": "docs/x", "action": "write"},
                 raw_csrf="00" * 32)
    assert r.json()["reason"] == ErrorCode.CSRF_INVALID.value

    # 旧令牌 + 旧标识同样拒绝（标识先判重放）
    r = api.post("/access/resource",
                 json_body={"resource": "docs/x", "action": "write"},
                 raw_session=old_sid, raw_csrf=old_csrf)
    assert r.status_code == 401
    assert r.json()["reason"] == ErrorCode.SESSION_REPLAYED.value

    rec = [x for x in audit.records() if x.event == "CSRF_REJECTED"
           and x.reason == ErrorCode.CSRF_REVOKED.value]
    assert rec  # 可区分判定有审计落点


def test_old_token_revoked_for_every_mutating_endpoint(api):
    api.register("alice", roles=["editor"])
    api.login("alice")
    sid2 = api.c.post("/auth/login",
                      json={"username": "alice", "password": PW},
                      headers={"Origin": ORIGIN}).json()["session_id"]
    old_csrf = api.csrf
    _rotate(api)
    svc = api.c.app.state.services.sessions
    ref2 = svc.ref_for("alice", sid2)

    for path, body in (
        ("/auth/logout", None),
        ("/auth/logout-all", None),
        ("/auth/rotate", None),
        (f"/account/sessions/{ref2}/revoke", None),
        ("/account/password",
         {"old_password": PW, "new_password": "BrandNew9"}),
        ("/access/resource",
         {"resource": "docs/x", "action": "write"}),
    ):
        r = api.post(path, json_body=body, raw_csrf=old_csrf)
        assert r.status_code == 403, (path, r.text)
        assert r.json()["reason"] == ErrorCode.CSRF_REVOKED.value, path

    # 被拒后不得发生任何状态变更：会话仍在、可再收回
    r = api.get("/account/sessions")
    refs = {s["ref"] for s in r.json()["sessions"]}
    assert ref2 in refs


def test_rotated_session_id_replay_distinct_from_unknown(api):
    api.register("alice")
    api.login("alice")
    old_sid = api.session_id
    _rotate(api)
    for _ in range(3):
        r = api.post("/access/resource",
                     json_body={"resource": "docs/x", "action": "read"},
                     raw_session=old_sid, with_csrf=False)
        assert r.status_code == 401
        assert r.json()["reason"] == ErrorCode.SESSION_REPLAYED.value
    r = api.post("/access/resource",
                 json_body={"resource": "docs/x", "action": "read"},
                 raw_session="ab" * 32, with_csrf=False)
    assert r.json()["reason"] == ErrorCode.UNAUTHENTICATED.value


def test_cannot_rotate_tombstoned_session(api):
    api.register("alice")
    api.login("alice")
    old_sid, old_csrf = api.session_id, api.csrf
    _rotate(api)
    # 用旧标识 + 旧令牌再轮换：标识先判重放
    r = api.post("/auth/rotate", raw_session=old_sid, raw_csrf=old_csrf)
    assert r.status_code == 401
    assert r.json()["reason"] == ErrorCode.SESSION_REPLAYED.value


def test_origin_binding_carried_to_new_token(api):
    api.register("alice", roles=["editor"])
    api.login("alice", origin=ORIGIN)
    _rotate(api)
    # 新令牌继承来源绑定：跨来源仍被拒
    r = api.post("/access/resource",
                 json_body={"resource": "docs/x", "action": "write"},
                 origin="http://evil.example")
    assert r.status_code == 403
    assert r.json()["reason"] == ErrorCode.CSRF_BOUND_ORIGIN.value
    # 同源立即放行
    r = api.post("/access/resource",
                 json_body={"resource": "docs/x", "action": "write"})
    assert r.status_code == 200, r.text


# --------------------------------------------------------------------- #
# 作用范围：只轮换本会话，跨账号不泄漏
# --------------------------------------------------------------------- #
def test_rotation_only_affects_current_session(api):
    api.register("alice", roles=["viewer"])
    api.register("bob", roles=["viewer"])
    a1, c1 = api.c.post("/auth/login",
                        json={"username": "alice", "password": PW},
                        headers={"Origin": ORIGIN}).json(), None
    a2 = api.c.post("/auth/login",
                    json={"username": "alice", "password": PW},
                    headers={"Origin": ORIGIN}).json()
    b1 = api.c.post("/auth/login",
                    json={"username": "bob", "password": PW},
                    headers={"Origin": ORIGIN}).json()
    api.adopt(a1["session_id"], a1["csrf_token"])
    rotated = _rotate(api)

    # 同账号另一条会话照常可用、可被定向收回
    r = api.c.get("/account/sessions",
                  headers={"Origin": ORIGIN,
                           "X-Session-Id": a2["session_id"]})
    assert r.status_code == 200
    svc = api.c.app.state.services.sessions
    ref2 = svc.ref_for("alice", a2["session_id"])
    r = api.post(f"/account/sessions/{ref2}/revoke")
    assert r.status_code == 200

    # 旧引用再收回：本账号稳定判 409
    old_ref = svc.ref_for("alice", a1["session_id"])
    r = api.post(f"/account/sessions/{old_ref}/revoke")
    assert r.status_code == 409
    assert r.json()["reason"] == ErrorCode.SESSION_ALREADY_REVOKED.value

    # 他账号拿旧/新引用提交一律 NOT_FOUND，借差异探不到 alice 的会话
    bob = Api(api.c).adopt(b1["session_id"], b1["csrf_token"])
    for ref in (old_ref, svc.ref_for("alice", rotated["session_id"])):
        r = bob.post(f"/account/sessions/{ref}/revoke")
        assert r.status_code == 404
        assert r.json()["reason"] == ErrorCode.NOT_FOUND.value

    # 他账号旧标识仍可正常使用
    r = api.c.get("/account/sessions",
                  headers={"Origin": ORIGIN,
                           "X-Session-Id": b1["session_id"]})
    assert r.status_code == 200


# --------------------------------------------------------------------- #
# 并发：轮换 × 容量淘汰 × 定向收回 交错
# --------------------------------------------------------------------- #
def _capacity_client(audit, max_active):
    store = InMemoryStore()
    ts = ManualTimeSource(start=1_000_000.0)
    cfg = default_config({
        "throttle": {"max_failures": 3, "window_seconds": 300,
                     "lock_seconds": 600},
        "session": {"max_active_sessions_per_account": max_active},
    })
    application = create_app(store=store, time_source=ts, config=cfg,
                             audit=audit)
    return Api(TestClient(application)), store, ts


def test_concurrent_rotations_never_half_updated(audit):
    api, store, ts = _capacity_client(audit, 8)
    api.register("alice", roles=["viewer"])
    starts = []
    for i in range(4):
        body = api.c.post("/auth/login",
                          json={"username": "alice", "password": PW},
                          headers={"Origin": ORIGIN}).json()
        starts.append((body["session_id"], body["csrf_token"]))
        ts.advance(10)

    def rotate_pair(item):
        sid, csrf = item
        h = {"Origin": ORIGIN, "X-Session-Id": sid, "X-CSRF-Token": csrf}
        r = api.c.post("/auth/rotate", headers=h)
        return sid, csrf, r

    with cf.ThreadPoolExecutor(4) as ex:
        results = list(ex.map(rotate_pair, starts))

    svc = api.c.app.state.services.sessions
    for old_sid, old_csrf, r in results:
        # 要么成功轮换，要么旧会话已被交错的容量淘汰（重放）；无 5xx
        assert r.status_code in (200, 401), r.text
        if r.status_code == 200:
            new_sid = r.json()["session_id"]
            new_csrf = r.json()["csrf_token"]
            # 新令牌立即可用于同源状态变更（读，无需 CSRF 也先验会话）
            rr = api.c.get(
                "/account/sessions",
                headers={"Origin": ORIGIN, "X-Session-Id": new_sid})
            assert rr.status_code == 200, rr.text
            # 旧令牌必入 CSRF 墓碑
            assert store.csrf_tombstone_info(old_csrf) is not None
            # 旧标识必入会话墓碑
            assert store.tombstone_info(old_sid) is not None
            # 新令牌必须已落库且绑定新标识
            rec = store.get_csrf(new_csrf)
            assert rec is not None and rec.session_id == new_sid
        else:
            assert r.json()["reason"] == ErrorCode.SESSION_REPLAYED.value

    # 活动会话清单与存储一致，墓碑引用可区分
    survivors = store.list_user_sessions("alice")
    listed = api.c.get(
        "/account/sessions",
        headers={"Origin": ORIGIN,
                 "X-Session-Id": survivors[0].session_id}).json()["sessions"]
    assert {s["ref"] for s in listed} == {
        svc.ref_for("alice", s.session_id) for s in survivors}
    for old_sid, _ in starts:
        active = store.get_session(old_sid)
        if active is None:
            assert store.tombstone_info(old_sid) is not None


def test_concurrent_rotate_login_eviction_revoke_consistent(audit):
    """轮换 × 并发登录容量淘汰 × 定向收回 三路交错，且无半更新。

    预置 s1、s2（容量=2，created_at 拉开）。栅栏同时放行：
      - s2 发起自身轮换（保留 created_at，不改变淘汰顺序，故必成功）；
      - 一次并发新登录（登录事务内做容量淘汰）；
      - s1 用自己的凭据定向收回 s1 自己。
    s1 的离开原因只可能是"自收回"或"容量淘汰"（二者都是受控结局，
    墓碑原因与逐条操作一致）；s2 轮换必整体生效；终态恒为
    {轮换新会话, 并发新登录会话}。
    """
    api, store, ts = _capacity_client(audit, 2)
    api.register("alice", roles=["viewer"])
    pres = []
    for _ in range(2):
        pres.append(api.c.post(
            "/auth/login", json={"username": "alice", "password": PW},
            headers={"Origin": ORIGIN}).json())
        ts.advance(10)  # 拉开 created_at：s1 确定最旧
    s1, s2 = pres
    preexisting = {s["session_id"] for s in pres}
    svc = api.c.app.state.services.sessions
    ref1 = svc.ref_for("alice", s1["session_id"])

    start = threading.Barrier(3)

    def _h(s):
        return {"Origin": ORIGIN, "X-Session-Id": s["session_id"],
                "X-CSRF-Token": s["csrf_token"]}

    def rotate_s2():
        start.wait()
        return api.c.post("/auth/rotate", headers=_h(s2))

    def login_once():
        start.wait()
        r = api.c.post("/auth/login",
                       json={"username": "alice", "password": PW},
                       headers={"Origin": ORIGIN})
        ts.advance(10)
        return r

    def revoke_self_s1():
        start.wait()
        return api.c.post(f"/account/sessions/{ref1}/revoke",
                          headers=_h(s1))

    with cf.ThreadPoolExecutor(3) as ex:
        f_rot = ex.submit(rotate_s2)
        f_login = ex.submit(login_once)
        f_rev = ex.submit(revoke_self_s1)
        login = f_login.result()
        rot = f_rot.result()
        rev = f_rev.result()

    assert login.status_code == 200, login.text
    # s1 自收回：200（先收回）或 401/403（先被容量淘汰，标识重放/令牌已撤）
    assert rev.status_code in (200, 401, 403), rev.text
    assert rot.status_code == 200, rot.text

    new_sid = rot.json()["session_id"]
    new_csrf = rot.json()["csrf_token"]

    # 终态恒为两条：轮换新会话 + 并发新登录会话
    survivors = {s.session_id for s in store.list_user_sessions("alice")}
    assert survivors == {new_sid, login.json()["session_id"]}

    # s1 的墓碑原因受控：自收回 -> revoked；被淘汰 -> evicted
    info1 = store.tombstone_info(s1["session_id"])
    assert info1 is not None and info1["cause"] in ("revoked", "evicted")
    if rev.status_code == 200:
        assert info1["cause"] == "revoked"

    # s2 轮换：旧标识原因 rotated，旧令牌入 CSRF 墓碑
    info2 = store.tombstone_info(s2["session_id"])
    assert info2 is not None and info2["cause"] == "rotated"

    # CSRF 半更新不变量：旧令牌必撤入墓碑，新令牌必落库并绑定新标识
    assert store.csrf_tombstone_info(s2["csrf_token"]) is not None
    rec = store.get_csrf(new_csrf)
    assert rec is not None and rec.session_id == new_sid
    # s1 无论被收回还是被淘汰，其活动令牌都必已撤入墓碑
    assert store.get_csrf(s1["csrf_token"]) is None
    assert store.csrf_tombstone_info(s1["csrf_token"]) is not None

    # 两条预置标识重放判定一致：SESSION_REPLAYED，与从未存在可区分
    for sid in preexisting:
        r = api.c.post("/access/resource",
                       json={"resource": "docs/x", "action": "read"},
                       headers={"X-Session-Id": sid})
        assert r.status_code == 401
        assert r.json()["reason"] == ErrorCode.SESSION_REPLAYED.value
    r = api.c.post("/access/resource",
                   json={"resource": "docs/x", "action": "read"},
                   headers={"X-Session-Id": "ab" * 32})
    assert r.json()["reason"] == ErrorCode.UNAUTHENTICATED.value

    # 轮换后的新令牌立即在同一来源完成状态变更（此处登出自己）
    r = api.c.post("/auth/logout", headers={
        "Origin": ORIGIN, "X-Session-Id": new_sid,
        "X-CSRF-Token": new_csrf})
    assert r.status_code == 200, r.text

    # 登出后：清单只剩并发新登录，条数与存储一致
    listed = api.c.get("/account/sessions",
                       headers={"Origin": ORIGIN,
                                "X-Session-Id": login.json()["session_id"]})
    assert listed.status_code == 200
    assert len(listed.json()["sessions"]) == 1
    assert len(store.list_user_sessions("alice")) == 1
