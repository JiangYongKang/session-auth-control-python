"""pytest 公共夹具：可控时间源、内存存储、审计缓冲、TestClient。

单测日志要求打印"可复现的输入 + 判定结论"：
- AuditLogger 以 warning 输出 JSON 行（已脱敏）；
- 每个测试末尾由 assert_* 帮助器把关键输入/结论写到 caplog/标准输出。
"""
from __future__ import annotations

import logging

import pytest
from fastapi.testclient import TestClient

from app.api.app_factory import create_app
from app.audit import AuditLogger
from app.config import SecurityConfig, default_config
from app.storage.faults import FailingStore
from app.storage.store import InMemoryStore
from app.time_source import ManualTimeSource

ORIGIN = "http://testserver"


@pytest.fixture
def time_source() -> ManualTimeSource:
    return ManualTimeSource(start=1_000_000.0)


@pytest.fixture
def store() -> InMemoryStore:
    return InMemoryStore()


@pytest.fixture
def audit(caplog) -> AuditLogger:
    caplog.set_level(logging.WARNING, logger="app.audit")
    return AuditLogger(echo=True)


@pytest.fixture
def config() -> SecurityConfig:
    return default_config({"throttle": {"max_failures": 3,
                                        "window_seconds": 300,
                                        "lock_seconds": 600}})


@pytest.fixture
def app(store, time_source, config, audit):
    application = create_app(store=store, time_source=time_source,
                             config=config, audit=audit)
    return application


@pytest.fixture
def client(app) -> TestClient:
    return TestClient(app)


class Api:
    """便于测试的薄封装：自动带会话/CSRF 头与同源 Origin。"""

    def __init__(self, client: TestClient, *, origin: str = ORIGIN):
        self.c = client
        self.origin = origin
        self.session_id: str | None = None
        self.csrf: str | None = None

    def _headers(self, *, with_csrf: bool, origin: str | None = None,
                 extra: dict | None = None) -> dict:
        h = {"Origin": origin or self.origin}
        if self.session_id:
            h["X-Session-Id"] = self.session_id
        if with_csrf and self.csrf:
            h["X-CSRF-Token"] = self.csrf
        if extra:
            h.update(extra)
        return h

    def register(self, username: str, password: str = "Sup3rSecret",
                 roles=None, origin: str | None = None):
        return self.c.post("/auth/register",
                           json={"username": username, "password": password,
                                 "roles": roles},
                           headers={"Origin": origin or self.origin})

    def provision(self, username: str, password: str = "Sup3rSecret",
                  roles=("admin",)):
        """受信引导（绕过自助白名单），用于预置特权用户。"""
        self.c.app.state.services.auth.provision_user(
            username, password, tuple(roles))

    def login(self, username: str, password: str = "Sup3rSecret",
              origin: str | None = None):
        r = self.c.post("/auth/login",
                        json={"username": username, "password": password},
                        headers={"Origin": origin or self.origin})
        if r.status_code == 200:
            body = r.json()
            self.session_id = body["session_id"]
            self.csrf = body["csrf_token"]
        return r

    def adopt(self, session_id: str, csrf: str | None) -> "Api":
        self.session_id = session_id
        self.csrf = csrf
        return self

    def get(self, path, **kw):
        return self.c.get(path, headers=self._headers(with_csrf=False), **kw)

    def post(self, path, *, with_csrf: bool = True, json_body=None,
             data=None, origin: str | None = None, raw_session=None,
             raw_csrf=None, headers=None):
        h = self._headers(with_csrf=with_csrf, origin=origin)
        if raw_session is not None:
            h["X-Session-Id"] = raw_session
        if raw_csrf is not None:
            h["X-CSRF-Token"] = raw_csrf
        if headers:
            h.update(headers)
        if data is not None:
            return self.c.post(path, data=data, headers=h)
        return self.c.post(path, json=json_body, headers=h)


@pytest.fixture
def api(client) -> Api:
    return Api(client)
