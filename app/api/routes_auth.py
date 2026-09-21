"""注册、登录、登出、改密、会话轮换路由。

状态变更类请求（logout/password/rotate）强制 CSRF 校验。
会话标识仅通过 X-Session-Id 头读取，角色与范围只取自服务端。
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from app.api.deps import (require_csrf, require_mfa_session, require_session,
                         services)
from app.api.schemas import (ChangePasswordRequest, LoginRequest,
                             RegisterRequest, RolesRequest)
from app.services.auth import Principal

router = APIRouter(tags=["auth"])


def _remote(request: Request) -> str:
    return request.client.host if request.client else "?"


def _origin(request: Request) -> str:
    return request.headers.get("origin") or (
        f"{request.url.scheme}://{request.url.netloc}")


@router.post("/auth/register")
def register(body: RegisterRequest, request: Request) -> dict:
    svc = services(request)
    svc.auth.register(body.username, body.password,
                      tuple(body.roles or ()))
    return {"status": "registered", "username": body.username}


@router.post("/auth/login")
def login(body: LoginRequest, request: Request) -> dict:
    svc = services(request)
    result = svc.auth.login(
        body.username, body.password,
        origin=_origin(request), remote=_remote(request))
    return {"status": "ok", **result}


@router.post("/auth/logout")
def logout(request: Request,
           principal: Principal = Depends(require_session)) -> dict:
    require_csrf(request, principal)
    services(request).auth.logout(principal.session_id,
                                  remote=_remote(request))
    return {"status": "logged_out"}


@router.post("/auth/logout-all")
def logout_all(request: Request,
               principal: Principal = Depends(require_session)) -> dict:
    """全设备登出：作废该账号所有会话（带 CSRF）。"""
    require_csrf(request, principal)
    n = services(request).auth.logout_all(principal.username)
    return {"status": "logged_out_all", "sessions_invalidated": n}


@router.post("/auth/rotate")
def rotate(request: Request,
           principal: Principal = Depends(require_session)) -> dict:
    """显式轮换会话标识（登录态不变，防会话固定的可复核入口）。"""
    require_csrf(request, principal)
    new_sid, csrf = services(request).auth.rotate_session(
        principal.session_id)
    return {"status": "rotated", "session_id": new_sid, "csrf_token": csrf}


@router.post("/admin/users/{username}/roles")
def set_user_roles(username: str, body: RolesRequest, request: Request,
                   principal: Principal = Depends(require_mfa_session)) -> dict:
    """管理员授予角色：需要 admin 动作权限 + CSRF。特权角色不可自助获取。"""
    require_csrf(request, principal)
    svc = services(request)
    svc.access.authorize(principal.roles, "admin/users", "admin",
                         user=principal.username)
    svc.auth.set_roles(principal.username, username, tuple(body.roles))
    return {"status": "roles_updated", "username": username,
            "roles": body.roles}


@router.post("/account/password")
def change_password(body: ChangePasswordRequest, request: Request,
                    principal: Principal = Depends(require_mfa_session)) -> dict:
    require_csrf(request, principal)
    n = services(request).auth.change_password(
        principal.username, body.old_password, body.new_password)
    return {"status": "password_changed", "sessions_invalidated": n}
