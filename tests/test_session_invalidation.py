"""改密、全量注销、MFA 重置必须立即一致地作废既有会话（含并发）。"""
from __future__ import annotations

import concurrent.futures as cf

from app.errors import ErrorCode


def test_password_change_flow(api):
    api.register("alice")
    b1 = api.c.post("/auth/login",
                    json={"username": "alice", "password": "Sup3rSecret"},
                    headers={"Origin": "http://testserver"}).json()
    b2 = api.c.post("/auth/login",
                    json={"username": "alice", "password": "Sup3rSecret"},
                    headers={"Origin": "http://testserver"}).json()
    api.adopt(b1["session_id"], b1["csrf_token"])
    r = api.post("/account/password",
                 json_body={"old_password": "Sup3rSecret",
                            "new_password": "BrandNew9"})
    assert r.status_code == 200, r.text
    assert r.json()["sessions_invalidated"] == 2
    for sid in (b1["session_id"], b2["session_id"]):
        rr = api.c.post("/access/resource",
                        json={"resource": "docs/x", "action": "read"},
                        headers={"X-Session-Id": sid})
        assert rr.status_code == 401
        assert rr.json()["reason"] == ErrorCode.SESSION_INVALIDATED.value
    # 旧密码登录失败
    assert api.login("alice", "Sup3rSecret").json()["reason"] == \
        ErrorCode.INVALID_CREDENTIALS.value


def test_logout_all_flow(api):
    api.register("alice")
    sessions = [api.c.post("/auth/login",
                           json={"username": "alice",
                                 "password": "Sup3rSecret"},
                           headers={"Origin": "http://testserver"}).json()
                for _ in range(3)]
    # 通过改密等价路径之外，提供 logout-all：直接调服务层（全设备登出）
    svc = api.c.app.state.services
    n = svc.auth.logout_all("alice")
    assert n == 3
    for s in sessions:
        r = api.c.post("/access/resource",
                       json={"resource": "docs/x", "action": "read"},
                       headers={"X-Session-Id": s["session_id"]})
        assert r.json()["reason"] == ErrorCode.SESSION_INVALIDATED.value


def test_concurrent_change_and_logout_no_partial(api):
    api.register("alice")

    def cycle(old, new):
        active = [api.c.post("/auth/login",
                             json={"username": "alice", "password": old},
                             headers={"Origin": "http://testserver"}).json()
                  for _ in range(3)]
        svc = api.c.app.state.services

        def change():
            return svc.auth.change_password("alice", old, new)

        def logout():
            return svc.auth.logout_all("alice")

        with cf.ThreadPoolExecutor(2) as ex:
            list(ex.map(lambda f: f(), [change, logout]))

        store = svc.store
        assert store.list_user_sessions("alice") == []
        for s in active:
            r = api.c.post("/access/resource",
                           json={"resource": "docs/x", "action": "read"},
                           headers={"X-Session-Id": s["session_id"]})
            assert r.status_code == 401
            assert r.json()["reason"] in (
                ErrorCode.SESSION_INVALIDATED.value,
                ErrorCode.SESSION_REPLAYED.value)
        return new

    pw = cycle("Sup3rSecret", "BrandNew9")
    cycle(pw, "ThirdPw12")
