"""登录失败节流与临时锁定：并发原子计数、锁定可区分、锁内正确口令也拒绝。"""
from concurrent.futures import ThreadPoolExecutor

from authapp.errors import ErrorCode


def test_concurrent_failures_do_not_skip_count_or_double_lock(svc):
    svc.register("alice", "password123")
    threshold = svc.config.fail_threshold

    def attempt(_):
        # 整个“读-判-写”在同一把存储锁中
        with svc.store.lock():
            return svc.throttle.record_failure("alice")

    with ThreadPoolExecutor(max_workers=8) as pool:
        flags = list(pool.map(attempt, range(threshold * 3)))

    # 只有一次“从未锁定到锁定”的跃迁
    assert sum(1 for f in flags if f) == 1
    with svc.store.lock():
        failure = svc.store.get_failure("alice")
        assert failure.count == threshold * 3
        assert failure.locked is True
        user = svc.store.get_user("alice")
        assert user.locked_until is not None


def test_lock_rejects_even_correct_password_with_distinct_code(client, svc):
    svc.register("alice", "password123")
    for i in range(svc.config.fail_threshold):
        r = client.post("/auth/login", json={"username": "alice", "password": "nope"})
    # 达到阈值的当次即锁定并可区分（423 account_locked）
    assert r.status_code == 423
    body = r.json()["error"]
    assert body["code"] == ErrorCode.ACCOUNT_LOCKED.value
    assert "锁定" in body["message"]
    # 锁定期内即使口令正确也必须被拒绝，且判定仍是 account_locked
    r = client.post("/auth/login", json={"username": "alice", "password": "password123"})
    assert r.status_code == 423
    assert r.json()["error"]["code"] == ErrorCode.ACCOUNT_LOCKED.value


def test_sliding_window_expires_and_allows_login(client, svc, clock):
    svc.register("alice", "password123")
    for _ in range(svc.config.fail_threshold - 1):
        client.post("/auth/login", json={"username": "alice", "password": "nope"})
    clock.advance(svc.config.fail_window_seconds + 1)
    # 窗口外失败不再累计：应仍可正常登录
    r = client.post("/auth/login", json={"username": "alice", "password": "password123"})
    assert r.status_code == 200 and r.json()["status"] == "success"


def test_lock_expires_after_configured_duration(client, svc, clock):
    svc.register("alice", "password123")
    for _ in range(svc.config.fail_threshold):
        client.post("/auth/login", json={"username": "alice", "password": "nope"})
    r = client.post("/auth/login", json={"username": "alice", "password": "password123"})
    assert r.status_code == 423
    clock.advance(svc.config.lock_seconds + 1)
    r = client.post("/auth/login", json={"username": "alice", "password": "password123"})
    assert r.status_code == 200


def test_successful_login_clears_failures(client, svc):
    svc.register("alice", "password123")
    for _ in range(svc.config.fail_threshold - 1):
        client.post("/auth/login", json={"username": "alice", "password": "nope"})
    assert client.post("/auth/login", json={"username": "alice", "password": "password123"}).status_code == 200
    client.post("/auth/logout")
    # 计数已清空：再失败 threshold-1 次也不会锁
    for _ in range(svc.config.fail_threshold - 1):
        r = client.post("/auth/login", json={"username": "alice", "password": "nope"})
        assert r.status_code == 401
    assert client.post("/auth/login", json={"username": "alice", "password": "password123"}).status_code == 200
