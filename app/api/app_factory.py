"""应用组装：存储、时间源、配置、审计、服务、路由、异常归一化。

边界原则：
- 任何异常经 normalize() 归一为 {error, reason}，绝不 stacktrace 放行；
- 存储/时间源异常 -> 5xx 可区分码，不降级；
- 有状态变更的端点统一经 CSRF 校验依赖。
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.audit import AuditEvent, AuditLogger
from app.config import SecurityConfig, default_config
from app.errors import AppError, ErrorCode, normalize
from app.services.access import AccessService
from app.services.auth import AuthService
from app.services.mfa import MfaService
from app.storage.faults import FailingStore
from app.storage.store import InMemoryStore, Store
from app.time_source import SystemTimeSource, TimeSource


class ServiceContainer:
    """运行期服务容器（挂在 app.state.services）。"""

    def __init__(self, store: Store, time: TimeSource,
                 config: SecurityConfig, audit: AuditLogger) -> None:
        self.store = store
        self.time = time
        self.config = config
        self.audit = audit
        self.auth = AuthService(store, time, config, audit)
        self.mfa = MfaService(store, time, config, audit, self.auth)
        self.access = AccessService(config, audit)


def create_app(store: Store | None = None, *,
               time_source: TimeSource | None = None,
               config: SecurityConfig | None = None,
               audit: AuditLogger | None = None,
               failing_methods: frozenset[str] | None = None,
               audit_logger: logging.Logger | None = None,
               bootstrap_admin: tuple[str, str] | None = None) -> FastAPI:
    audit = audit or AuditLogger(audit_logger)
    config = config or default_config()
    base_store: Store = store or InMemoryStore()
    if failing_methods:
        base_store = FailingStore(base_store, failing_methods)
    time = time_source or SystemTimeSource()

    app = FastAPI(title="session-auth-control", version="0.1.0")
    services = ServiceContainer(base_store, time, config, audit)
    app.state.services = services

    # 可选：受信引导初始管理员（不开放自助注册）。
    if bootstrap_admin is not None:
        admin_user, admin_pw = bootstrap_admin
        services.auth.provision_user(admin_user, admin_pw, ("admin",))

    @app.exception_handler(AppError)
    async def app_error_handler(request: Request, exc: AppError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": "request_denied", "reason": exc.code.value,
                     "detail": exc.detail},
        )

    @app.exception_handler(RequestValidationError)
    async def validation_handler(request: Request,
                                 exc: RequestValidationError) -> JSONResponse:
        # 不回显输入明文，仅回字段级判定
        fields = sorted({
            ".".join(str(p) for p in e.get("loc", []) if p != "body")
            for e in exc.errors()
        })
        return JSONResponse(
            status_code=422,
            content={"error": "request_denied",
                     "reason": ErrorCode.VALIDATION_ERROR.value,
                     "detail": f"invalid fields: {fields}"})

    @app.exception_handler(Exception)
    async def fallback_handler(request: Request, exc: Exception) -> JSONResponse:
        normalized = normalize(exc)
        audit.record(AuditEvent.INFRA_ERROR,
                     result="error",
                     reason=normalized.code.value,
                     path=request.url.path,
                     error_type=type(exc).__name__)
        return JSONResponse(
            status_code=normalized.status_code,
            content={"error": "request_denied",
                     "reason": normalized.code.value,
                     "detail": "internal failure; request not allowed"})

    @app.get("/health")
    async def health() -> dict[str, Any]:
        # 主动探测时间源与存储：异常即失败，绝不报健康
        services: ServiceContainer = app.state.services
        services.time.now()
        with services.store.transaction():
            services.store.get_user("__health__")
        return {"status": "ok"}

    from app.api.routes_auth import router as auth_router
    from app.api.routes_mfa import router as mfa_router
    from app.api.routes_resources import router as res_router
    app.include_router(auth_router)
    app.include_router(mfa_router)
    app.include_router(res_router)
    return app
