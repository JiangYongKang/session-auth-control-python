"""登录失败节流：阈值/窗口可配置；并发不绕过计数、不重复锁定。"""
from __future__ import annotations

import concurrent.futures as cf

import pytest

from app.errors import ErrorCode


def test_lock_after_threshold_and_distinct_prompt(api, store, config):
    api.register("bob")
    for i in range(config.throttle.max_failures - 1):
        r = api.login("bob", "wrongpass1")
        assert r.status_code == 401
        assert r.json()["reason"] == ErrorCode.INVALID_CREDENTIALS.value
    # 达到阈值：可区分的 LOCKED
    r = api.login("bob", "wrongpass1")
    assert r.status_code == 423
    body = r.json()
    assert body["reason"] == ErrorCode.LOCKED.value
    assert "retry_after" in body["detail"]

    # 锁定期内即使口令正确也必须拒绝
    r_ok = api.login("bob", "Sup3rSecret")
    assert r_ok.status_code == 423
    assert r_ok.json()["reason"] == ErrorCode.LOCKED.value


def test_window_expiry_allows_login_again(api, store, time_source, config):
    api.register("bob")
    for _ in range(config.throttle.max_failures):
        api.login("bob", "wrongpass1")
    assert api.login("bob", "Sup3rSecret").status_code == 423
    time_source.advance(config.throttle.lock_seconds + 1)
    r = api.login("bob", "Sup3rSecret")
    assert r.status_code == 200, r.text


def test_failures_outside_window_do_not_accumulate(api, store, time_source,
                                                   config):
    api.register("bob")
    api.login("bob", "wrongpass1")
    time_source.advance(config.throttle.window_seconds + 1)
    api.login("bob", "wrongpass1")  # 窗口已过，重新计数
    user = store.get_user("bob")
    assert user.fail_count == 1
    assert user.locked_until is None


def test_concurrent_failures_lock_once(api, store, audit, config):
    api.register("bob")
    n_threads = 20

    def one(_):
        r = api.c.post("/auth/login",
                       json={"username": "bob", "password": "wrongpass1"},
                       headers={"Origin": "http://testserver"})
        return r.json()["reason"]

    with cf.ThreadPoolExecutor(n_threads) as ex:
        reasons = list(ex.map(one, range(n_threads)))

    # 计数恰好停在阈值（不超计、不漏计）
    user = store.get_user("bob")
    assert user.fail_count == config.throttle.max_failures
    # 只有一次"设置锁定"审计；其余为锁定期拒绝
    lock_sets = [r for r in audit.records()
                 if r.event == "LOGIN_LOCKED"
                 and r.fields.get("lock_set") == "True"]
    assert len(lock_sets) == 1
    assert ErrorCode.LOCKED.value in reasons
    assert ErrorCode.INVALID_CREDENTIALS.value in reasons


def test_concurrent_failures_never_bypass_to_success(api, store, config):
    api.register("bob")
    # 先串行把账号打到锁定（确定性前置，不依赖线程调度）
    for _ in range(config.throttle.max_failures):
        api.login("bob", "wrongpass1")
    assert store.get_user("bob").locked_until is not None

    def one(_):
        r = api.c.post("/auth/login",
                       json={"username": "bob", "password": "Sup3rSecret"},
                       headers={"Origin": "http://testserver"})
        return r.status_code

    # 锁定期内并发提交正确口令：任何 200 都是绕过，必须全部 423
    with cf.ThreadPoolExecutor(10) as ex:
        codes = list(ex.map(one, range(10)))
    assert codes and all(c == 423 for c in codes), codes

    # 锁定期结束前再次确认仍被锁
    assert api.login("bob", "Sup3rSecret").status_code == 423


def test_thresholds_configurable(store, time_source, audit):
    from app.api.app_factory import create_app
    from app.config import default_config
    from fastapi.testclient import TestClient
    cfg = default_config({"throttle": {"max_failures": 1, "window_seconds": 10,
                                       "lock_seconds": 30}})
    app = create_app(store=store, time_source=time_source, config=cfg,
                     audit=audit)
    c = TestClient(app)
    c.post("/auth/register",
           json={"username": "carol", "password": "Sup3rSecret"})
    r1 = c.post("/auth/login",
                json={"username": "carol", "password": "bad1"})
    # 一次失败即锁定
    assert r1.json()["reason"] == ErrorCode.LOCKED.value
