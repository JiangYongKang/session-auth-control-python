"""依赖装配：默认单例（配置、时钟、存储、审计、服务、FastAPI app）。"""
from __future__ import annotations

from authapp.api import create_app
from authapp.audit import AuditLogger
from authapp.clock import Clock, SystemClock
from authapp.config import AuthConfig
from authapp.service import AuthService
from authapp.store.memory import MemoryStore


def build_service(
    config: AuthConfig | None = None,
    clock: Clock | None = None,
    *,
    audit: AuditLogger | None = None,
    store: MemoryStore | None = None,
) -> AuthService:
    cfg = config or AuthConfig()
    cfg.validate()  # 非法配置直接拒绝启动
    return AuthService(
        store=store or MemoryStore(),
        config=cfg,
        clock=clock or SystemClock(),
        audit=audit,
    )


_service: AuthService | None = None


def get_service(
    config: AuthConfig | None = None,
    clock: Clock | None = None,
) -> AuthService:
    """获取默认单例；测试可用 reset_service() 后传入定制依赖重建。"""
    global _service
    if _service is None or config is not None or clock is not None:
        _service = build_service(config, clock)
    return _service


def reset_service(service: AuthService | None = None) -> None:
    global _service
    _service = service


def __getattr__(name: str):
    if name == "service":
        return get_service()
    if name == "app":
        return create_app(get_service())
    raise AttributeError(name)
