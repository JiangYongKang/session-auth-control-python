"""测试公共夹具：可控时钟、独立服务实例、审计日志捕获与判定打印。

每个测试用例都会打印“可复现输入 -> 判定结论”，便于在单测日志中复盘。
"""
from __future__ import annotations

import io
import logging

import pytest
from fastapi.testclient import TestClient

from authapp.api import create_app
from authapp.audit import AuditLogger
from authapp.config import AuthConfig
from authapp.deps import reset_service
from authapp.deps import build_service

ORIGIN = "https://app.example.local"


class FakeClock:
    def __init__(self, start: float = 1_000_000.0):
        self.t = start

    def now(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


@pytest.fixture()
def clock():
    return FakeClock()


@pytest.fixture()
def audit_buf():
    return io.StringIO()


@pytest.fixture()
def audit(audit_buf):
    logger = logging.getLogger(f"authapp.test.{id(audit_buf)}")
    logger.handlers = [logging.StreamHandler(audit_buf)]
    logger.setLevel(logging.INFO)
    logger.propagate = False
    return AuditLogger(logger)


@pytest.fixture()
def config():
    return AuthConfig(
        allowed_origins=(ORIGIN,),
        fail_threshold=5,
        fail_window_seconds=300,
        lock_seconds=600,
        csrf_token_ttl_seconds=300,
    )


@pytest.fixture()
def svc(config, clock, audit):
    service = build_service(config, clock, audit=audit)
    reset_service(service)
    return service


@pytest.fixture()
def app(svc):
    return create_app(svc)


@pytest.fixture()
def client(app):
    return TestClient(app)


@pytest.fixture()
def origin():
    return ORIGIN


def verdict(case: str, given: dict, got) -> None:
    """打印可复现输入与判定结论（不包含口令/验证码/会话明文）。"""
    print(f"\n[CASE] {case}\n  输入: {given}\n  判定: {got}")
