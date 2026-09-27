"""账号自助会话管理路由。

- GET  /account/sessions                查看本人活动会话（读，要求已完成 MFA）
- POST /account/sessions/{ref}/revoke   定向收回一条会话（状态变更，强制 CSRF）
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from app.api.deps import require_csrf, require_mfa_session, services
from app.services.auth import Principal

router = APIRouter(tags=["sessions"])


@router.get("/account/sessions")
def list_sessions(request: Request,
                  principal: Principal = Depends(require_mfa_session)) -> dict:
    views = services(request).sessions.list_active(
        principal.username, current_session_id=principal.session_id)
    return {"sessions": [
        {"ref": v.ref, "created_at": v.created_at,
         "last_seen": v.last_seen, "mfa_verified": v.mfa_verified,
         "current": v.current}
        for v in views
    ]}


@router.post("/account/sessions/{ref}/revoke")
def revoke_session(ref: str, request: Request,
                   principal: Principal = Depends(require_mfa_session)) -> dict:
    require_csrf(request, principal)
    services(request).sessions.revoke(principal.username, ref,
                                      remote=_remote(request))
    return {"status": "revoked"}


def _remote(request: Request) -> str:
    return request.client.host if request.client else "?"
