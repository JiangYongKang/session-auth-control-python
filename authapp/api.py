"""HTTP 入口：所有入口共享同一个 AuthService，判定保持一致。

约定：
- 会话标识仅经 HttpOnly Cookie（sid）下发，脚本与跨站请求无法读取；
- 有状态变更的接口统一经过 require_csrf（头部 x-csrf-token + Origin）；
- 注册接口忽略请求体中的任何 roles；角色只能由已授权管理员经受控接口分配；
- 错误统一为 {"error": {"code", "message"}}，code 可区分判定依据，
  message 不含敏感信息。
"""
from __future__ import annotations

from fastapi import FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from authapp.errors import AuthError, ErrorCode
from authapp.service import CSRF_HEADER, SESSION_COOKIE, AuthService

# 归一化错误码 -> HTTP 状态。
_STATUS = {
    ErrorCode.INVALID_CREDENTIALS: 401,
    ErrorCode.ACCOUNT_LOCKED: 423,
    ErrorCode.MFA_REQUIRED: 401,
    ErrorCode.MFA_NOT_BOUND: 409,
    ErrorCode.MFA_ALREADY_BOUND: 409,
    ErrorCode.MFA_INVALID_CODE: 401,
    ErrorCode.MFA_REPLAYED_CODE: 401,
    ErrorCode.MFA_TIME_SKEW: 401,
    ErrorCode.UNAUTHENTICATED: 401,
    ErrorCode.SESSION_EXPIRED: 401,
    ErrorCode.SESSION_REVOKED: 401,
    ErrorCode.FORBIDDEN: 403,
    ErrorCode.CSRF_INVALID: 403,
    ErrorCode.CSRF_MISSING: 403,
    ErrorCode.CSRF_EXPIRED: 403,
    ErrorCode.CSRF_SESSION_MISMATCH: 403,
    ErrorCode.CSRF_ORIGIN_MISMATCH: 403,
    ErrorCode.USER_EXISTS: 409,
    ErrorCode.NOT_FOUND: 404,
    ErrorCode.INVALID_REQUEST: 400,
    ErrorCode.RATE_LIMITED: 429,
    ErrorCode.CONFIG_ERROR: 500,
    ErrorCode.TIME_SOURCE_ERROR: 500,
    ErrorCode.STORAGE_ERROR: 500,
}


class CredentialsBody(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class CodeBody(BaseModel):
    code: str = Field(min_length=1, max_length=16)


class PasswordChangeBody(BaseModel):
    old_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=1, max_length=256)


class AdminCreateBody(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)
    roles: list[str] = Field(default_factory=list)


class WriteBody(BaseModel):
    payload: dict | None = None


def create_app(service: AuthService | None = None) -> FastAPI:
    if service is None:
        from authapp.deps import get_service

        service = get_service()
    app = FastAPI(title="会话式身份认证与访问控制", version="1.0.0")

    @app.exception_handler(AuthError)
    async def _auth_error_handler(request: Request, exc: AuthError):
        status = _STATUS.get(exc.code, 500)
        return JSONResponse(
            status_code=status,
            content={"error": {"code": exc.code.value, "message": exc.message}},
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_handler(request: Request, exc: RequestValidationError):
        # 统一归一化为 invalid_request，不逐字段回显，避免借校验差异枚举。
        return JSONResponse(
            status_code=400,
            content={
                "error": {"code": ErrorCode.INVALID_REQUEST.value, "message": "请求参数不合法"}
            },
        )

    def _set_session(response: Response, session_id: str) -> None:
        response.set_cookie(
            key=SESSION_COOKIE,
            value=session_id,
            httponly=True,
            samesite="strict",
            secure=False,  # 本地 HTTP 验证；生产反代 HTTPS 下应置 True
            max_age=service.config.session_ttl_seconds,
            path="/",
        )

    def _clear_session(response: Response) -> None:
        response.delete_cookie(SESSION_COOKIE, path="/")

    def _sid(request: Request) -> str | None:
        return request.cookies.get(SESSION_COOKIE)

    def _origin(request: Request) -> str | None:
        return request.headers.get("origin") or request.headers.get("referer")

    def require_csrf(request: Request) -> str:
        """状态变更接口共用：会话 + 一次性令牌 + 来源三重校验。"""
        sid = _sid(request)
        token = request.headers.get(CSRF_HEADER)
        service.verify_csrf(sid, token, _origin(request))
        return sid  # type: ignore[return-value]

    # ------------------------------ 健康 ------------------------------ #
    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

    # ------------------------------ 注册 ------------------------------ #
    @app.post("/auth/register", status_code=201)
    def register(body: CredentialsBody):
        # 显式忽略客户端任何角色声明：新用户默认无角色（最小权限）。
        result = service.register(body.username, body.password, roles=None)
        return {"user_id": result["user_id"], "username": result["username"]}

    # --------------------------- 管理员建户 --------------------------- #
    @app.post("/admin/users", status_code=201)
    def admin_create_user(request: Request, body: AdminCreateBody):
        sid = require_csrf(request)
        # 服务端校验调用者具备 admin 动作权限（角色来自服务端会话）。
        service.authorize(sid, "admin", "admin/users")
        return service.register(body.username, body.password, roles=body.roles)

    # ------------------------------ 登录 ------------------------------ #
    @app.post("/auth/login")
    def login(body: CredentialsBody):
        result = service.login(body.username, body.password)
        response = JSONResponse(status_code=200, content={"status": result["status"]})
        _set_session(response, result["session"])
        return response

    @app.post("/auth/mfa")
    def mfa_login(request: Request, body: CodeBody):
        sid = _sid(request)
        new_id = service.mfa_login(sid, body.code.strip())
        response = JSONResponse(status_code=200, content={"status": "success"})
        # 登录升级：更换会话标识，抵御会话固定。
        _set_session(response, new_id)
        return response

    @app.post("/auth/logout")
    def logout(request: Request):
        sid = _sid(request)
        service.logout(sid)
        response = JSONResponse(status_code=200, content={"status": "logged_out"})
        _clear_session(response)
        return response

    @app.get("/auth/me")
    def me(request: Request):
        _, user = service.authenticate(_sid(request))
        return {"user_id": user.user_id, "username": user.username, "roles": user.roles}

    # ------------------------------ 改密 ------------------------------ #
    @app.post("/auth/password")
    def change_password(request: Request, body: PasswordChangeBody):
        sid = require_csrf(request)
        service.change_password(sid, body.old_password, body.new_password)
        response = JSONResponse(status_code=200, content={"status": "password_changed"})
        _clear_session(response)  # 改密后全部会话失效，要求重新登录
        return response

    # --------------------------- MFA 自助管理 -------------------------- #
    @app.get("/auth/mfa/bind")
    def begin_bind(request: Request):
        secret, uri = service.begin_bind_mfa(_sid(request))
        return {"secret": secret, "otpauth_uri": uri}

    @app.post("/auth/mfa/bind/confirm")
    def confirm_bind(request: Request, body: CodeBody):
        sid = require_csrf(request)
        service.confirm_bind_mfa(sid, body.code.strip())
        response = JSONResponse(status_code=200, content={"status": "mfa_bound"})
        _clear_session(response)  # 绑定后旧会话全部失效，需重新登录
        return response

    @app.post("/auth/mfa/unbind")
    def unbind(request: Request, body: CodeBody):
        sid = require_csrf(request)
        service.unbind_mfa(sid, body.code.strip())
        response = JSONResponse(status_code=200, content={"status": "mfa_unbound"})
        _clear_session(response)
        return response

    # ------------------------------ CSRF ------------------------------ #
    @app.get("/auth/csrf")
    def get_csrf(request: Request):
        sid = _sid(request)
        token = service.issue_csrf(sid)  # 需有效会话，否则抛认证错误
        return {"csrf_token": token}

    # --------------------------- 受保护资源 ---------------------------- #
    @app.get("/api/resource/{resource:path}")
    def read_resource(resource: str, request: Request):
        _, user = service.authorize(_sid(request), "read", resource)
        return {"resource": resource, "access": "read", "as": user.username}

    @app.post("/api/resource/{resource:path}")
    def write_resource(resource: str, request: Request, body: WriteBody | None = None):
        sid = require_csrf(request)  # 有状态变更：强制 CSRF 校验
        _, user = service.authorize(sid, "write", resource)
        return {"resource": resource, "access": "write", "as": user.username}

    return app
