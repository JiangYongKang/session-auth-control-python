"""多因素绑定/校验/解绑/管理员重置路由。

- enroll/unbind/reset 属状态变更，强制 CSRF；
- verify（登录第二步）作用于"待确认"会话，使用登录时签发的 CSRF。
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from app.api.deps import (require_csrf, require_mfa_session, require_session,
                         services)
from app.api.schemas import MfaCodeRequest, UnbindRequest
from app.services.auth import Principal

router = APIRouter(tags=["mfa"])


@router.post("/mfa/enroll/start")
def enroll_start(request: Request,
                 principal: Principal = Depends(require_mfa_session)) -> dict:
    require_csrf(request, principal)
    return services(request).mfa.begin_enroll(principal)


@router.post("/mfa/enroll/confirm")
def enroll_confirm(body: MfaCodeRequest, request: Request,
                   principal: Principal = Depends(require_session)) -> dict:
    require_csrf(request, principal)
    services(request).mfa.confirm_enroll(principal, body.code)
    return {"status": "enrolled"}


@router.post("/mfa/verify")
def mfa_verify(body: MfaCodeRequest, request: Request,
               principal: Principal = Depends(require_session)) -> dict:
    require_csrf(request, principal)
    result = services(request).mfa.verify_for_login(principal, body.code)
    return {"status": "mfa_verified", **result}


@router.post("/mfa/unbind")
def mfa_unbind(body: UnbindRequest, request: Request,
               principal: Principal = Depends(require_mfa_session)) -> dict:
    require_csrf(request, principal)
    services(request).mfa.unbind(principal, body.password, body.code)
    return {"status": "unbound"}


@router.post("/admin/mfa-reset/{username}")
def mfa_reset(username: str, request: Request,
              principal: Principal = Depends(require_mfa_session)) -> dict:
    require_csrf(request, principal)
    svc = services(request)
    # 管理员动作本身也要过访问控制（默认拒绝 + admin 动作）
    svc.access.authorize(principal.roles, "admin/mfa", "admin",
                         user=principal.username)
    svc.mfa.reset(principal, username)
    return {"status": "mfa_reset", "target": username}
