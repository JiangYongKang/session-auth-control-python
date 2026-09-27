"""账号自助会话管理路由：查看活动会话 / 定向收回。

- GET  /account/sessions        列出本人活动会话（登录 + MFA；只读无需 CSRF）
- POST /account/sessions/revoke 定向收回一条会话（登录 + MFA + CSRF 状态变更）
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from app.api.deps import require_csrf, require_mfa_session, services
from app.api.schemas import SessionRevokeRequest
from app.services.auth import Principal

router = APIRouter(tags=["sessions"])


@router.get("/account/sessions")
def list_sessions(request: Request,
                  principal: Principal = Depends(require_mfa_session)) -> dict:
    return services(request).sessions.list_active(principal)


@router.post("/account/sessions/revoke")
def revoke_session(body: SessionRevokeRequest, request: Request,
                   principal: Principal = Depends(require_mfa_session)) -> dict:
    require_csrf(request, principal)
    services(request).sessions.revoke(principal, body.reference)
    return {"status": "revoked"}
