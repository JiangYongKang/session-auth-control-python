"""受保护资源访问：JSON 与表单两种入口，行为完全一致。

- 必须携带有效会话且完成 MFA；
- 服务端按会话角色做默认拒绝判定；
- 不存在与无权统一 FORBIDDEN，不泄漏资源是否存在；
- 状态变更动作（write/admin）额外要求 CSRF；read 不强制但仍需会话。
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from app.api.deps import (require_csrf, require_mfa_session,
                         services)
from app.api.schemas import ResourceRequest
from app.services.auth import Principal

router = APIRouter(tags=["resources"])

_MUTATING_ACTIONS = frozenset({"write", "admin"})


def _decide(request: Request, principal: Principal, resource: str,
            action: str) -> JSONResponse:
    svc = services(request)
    if action in _MUTATING_ACTIONS:
        require_csrf(request, principal)
    svc.access.authorize(principal.roles, resource, action,
                         user=principal.username)
    return JSONResponse(
        {"status": "allowed", "resource": resource, "action": action,
         "decision": "server_side_roles"})


@router.post("/access/resource")
def access_json(body: ResourceRequest, request: Request,
                principal: Principal = Depends(require_mfa_session)
                ) -> JSONResponse:
    return _decide(request, principal, body.resource, body.action)


@router.post("/access/resource-form")
async def access_form(request: Request,
                      principal: Principal = Depends(require_mfa_session)):
    form = await request.form()
    request.state.form_data = form
    resource = str(form.get("resource", ""))
    action = str(form.get("action", ""))
    if not resource or not action:
        from app.errors import AppError, ErrorCode
        raise AppError(ErrorCode.VALIDATION_ERROR,
                       "resource and action are required")
    return _decide(request, principal, resource, action)
