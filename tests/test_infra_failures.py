"""存储/时间源/配置异常时必须 fail-closed，归一为可区分错误码。"""
from __future__ import annotations

from fastapi.testclient import TestClient

from app.api.app_factory import create_app
from app.config import default_config
from app.errors import ErrorCode
from app.storage.store import InMemoryStore
from app.time_source import FailingTimeSource, ManualTimeSource


def test_store_failure_on_login_does_not_pass(store, audit):
    app = create_app(store=store, time_source=ManualTimeSource(),
                     config=default_config(), audit=audit,
                     failing_methods=frozenset({"get_user"}))
    c = TestClient(app, raise_server_exceptions=False)
    r = c.post("/auth/login",
               json={"username": "alice", "password": "Sup3rSecret"})
    assert r.status_code == 503
    assert r.json()["reason"] == ErrorCode.STORE_UNAVAILABLE.value


def test_store_failure_on_session_resolve_denies(store, audit):
    # 正常注册登录
    good = create_app(store=store, time_source=ManualTimeSource(),
                      config=default_config(), audit=audit)
    c = TestClient(good, raise_server_exceptions=False)
    c.post("/auth/register",
           json={"username": "alice", "password": "Sup3rSecret",
                 "roles": ["viewer"]})
    b = c.post("/auth/login",
               json={"username": "alice", "password": "Sup3rSecret"},
               headers={"Origin": "http://testserver"}).json()
    # 换一个在 get_session 上注入故障的应用（共享存储）
    broken = create_app(store=store, time_source=ManualTimeSource(),
                        config=default_config(), audit=audit,
                        failing_methods=frozenset({"get_session"}))
    c2 = TestClient(broken, raise_server_exceptions=False)
    r = c2.post("/access/resource",
                json={"resource": "docs/x", "action": "read"},
                headers={"X-Session-Id": b["session_id"]})
    assert r.status_code == 503
    assert r.json()["reason"] == ErrorCode.STORE_UNAVAILABLE.value


def test_time_source_failure_denies(store, audit):
    app = create_app(store=store, time_source=FailingTimeSource(),
                     config=default_config(), audit=audit)
    c = TestClient(app, raise_server_exceptions=False)
    r = c.post("/auth/login",
               json={"username": "alice", "password": "Sup3rSecret"})
    assert r.status_code == 503
    assert r.json()["reason"] == ErrorCode.TIME_SOURCE_UNAVAILABLE.value


def test_health_reflects_infra_failure(store, audit):
    app = create_app(store=store, time_source=ManualTimeSource(),
                     config=default_config(), audit=audit,
                     failing_methods=frozenset({"transaction"}))
    c = TestClient(app, raise_server_exceptions=False)
    r = c.get("/health")
    assert r.status_code == 503
    assert r.json()["reason"] == ErrorCode.STORE_UNAVAILABLE.value


def test_invalid_config_fails_closed():
    from app.errors import ConfigError
    from app.config import load_config
    import pytest
    with pytest.raises(ConfigError):
        load_config({"throttle": {"max_failures": 0}})


def test_unknown_exception_normalized_internal(store, time_source, audit,
                                               monkeypatch):
    # 非受控异常 -> 归一为 INTERNAL_ERROR，不返回 500 裸栈、不放行
    app = create_app(store=store, time_source=time_source,
                     config=default_config(), audit=audit)
    c = TestClient(app, raise_server_exceptions=False)
    c.post("/auth/register",
           json={"username": "alice", "password": "Sup3rSecret",
                 "roles": ["viewer"]})
    b = c.post("/auth/login",
               json={"username": "alice", "password": "Sup3rSecret"},
               headers={"Origin": "http://testserver"}).json()

    def boom(*a, **k):
        raise RuntimeError("unexpected")

    monkeypatch.setattr(app.state.services.access, "authorize", boom)
    r = c.post("/access/resource",
               json={"resource": "docs/x", "action": "read"},
               headers={"X-Session-Id": b["session_id"]})
    assert r.status_code == 500
    assert r.json()["reason"] == ErrorCode.INTERNAL_ERROR.value
    assert r.json().get("status") != "allowed"
