"""请求依赖：服务容器、会话解析、MFA 门槛、CSRF 校验。

CSRF 校验对以下情形给出可区分判定：
- CSRF_MISSING        未提交令牌
- CSRF_INVALID        令牌服务端从未签发（伪造）
- CSRF_REVOKED        令牌曾签发，但所属会话标识已轮换/升级（旧令牌）
- CSRF_EXPIRED        令牌超过 TTL
- CSRF_BOUND_SESSION  令牌属于其他会话
- CSRF_BOUND_ORIGIN   令牌来源与请求 Origin 不一致
"""
from __future__ import annotations

from fastapi import Request

from app.audit import AuditEvent
from app.errors import AppError, ErrorCode
from app.api.app_factory import ServiceContainer
from app.services.auth import Principal

SESSION_HEADER = "X-Session-Id"
CSRF_HEADER = "X-CSRf-Token"
CSRF_FORM_FIELD = "csrf_token"


def services(request: Request) -> ServiceContainer:
    return request.app.state.services


def _session_id_from(request: Request) -> str | None:
    sid = request.headers.get(SESSION_HEADER)
    if sid:
        return sid.strip() or None
    return None


def require_session(request: Request) -> Principal:
    svc = services(request)
    sid = _session_id_from(request)
    return svc.auth.resolve_session(sid)


def require_mfa_session(request: Request) -> Principal:
    """已完成 MFA 的会话才能访问（登录后普通资源）。"""
    p = require_session(request)
    if not p.mfa_verified:
        raise AppError(ErrorCode.SESSION_CONFIRMATION_PENDING,
                       "mfa verification pending")
    return p


def _presented_csrf(request: Request) -> str | None:
    token = request.headers.get(CSRF_HEADER)
    if token:
        return token.strip() or None
    # 表单入口允许字段携带（JSON 入口必须用头）
    form = getattr(request.state, "form_data", None)
    if form is not None:
        val = form.get(CSRF_FORM_FIELD)
        if val:
            return str(val).strip()
    return None


def _request_origin(request: Request) -> str:
    origin = request.headers.get("origin")
    if origin:
        return origin
    # 退化到 scheme+host，同源表单客户端应显式带 Origin
    return f"{request.url.scheme}://{request.url.netloc}"


def require_csrf(request: Request, principal: Principal) -> None:
    """对有状态变更的请求做 CSRF 校验。必须在 require_session 之后调用。"""
    svc = services(request)
    presented = _presented_csrf(request)
    if not presented:
        svc.audit.record(AuditEvent.CSRF_REJECTED, user=principal.username,
                         result="denied",
                         reason=ErrorCode.CSRF_MISSING.value)
        raise AppError(ErrorCode.CSRF_MISSING, "csrf token missing")

    now = svc.time.now()
    record = svc.store.get_csrf(presented)
    if record is None:
        # 活动令牌中不存在：进一步区分"曾签发但已撤销（轮换/升级的旧令牌）"
        # 与"从未签发（伪造）"。前者稳定判 CSRF_REVOKED；墓碑在进程内长期
        # 保留，因此即使超过 TTL 重放也仍按已撤销判定。
        revoked = svc.store.get_revoked_csrf(presented)
        if revoked is not None:
            svc.audit.record(AuditEvent.CSRF_REJECTED,
                             user=principal.username, result="denied",
                             reason=ErrorCode.CSRF_REVOKED.value,
                             token_owner="rotated_session")
            raise AppError(ErrorCode.CSRF_REVOKED,
                           "csrf token revoked by session rotation")
        svc.audit.record(AuditEvent.CSRF_REJECTED, user=principal.username,
                         result="denied",
                         reason=ErrorCode.CSRF_INVALID.value)
        raise AppError(ErrorCode.CSRF_INVALID, "csrf token not recognized")

    if record.expires_at <= now:
        svc.audit.record(AuditEvent.CSRF_REJECTED, user=principal.username,
                         result="denied",
                         reason=ErrorCode.CSRF_EXPIRED.value)
        raise AppError(ErrorCode.CSRF_EXPIRED, "csrf token expired")

    if record.session_id != principal.session_id:
        svc.audit.record(AuditEvent.CSRF_REJECTED, user=principal.username,
                         result="denied",
                         reason=ErrorCode.CSRF_BOUND_SESSION.value,
                         token_owner="other_session")
        raise AppError(ErrorCode.CSRF_BOUND_SESSION,
                       "csrf token bound to another session")

    origin = _request_origin(request)
    if record.origin not in ("unknown",) and not _origin_match(
            record.origin, origin):
        svc.audit.record(AuditEvent.CSRF_REJECTED, user=principal.username,
                         result="denied",
                         reason=ErrorCode.CSRF_BOUND_ORIGIN.value,
                         origin=origin)
        raise AppError(ErrorCode.CSRF_BOUND_ORIGIN,
                       "csrf token origin mismatch")


def _origin_match(bound: str, presented: str) -> bool:
    def norm(o: str) -> str:
        return o.rstrip("/").lower()
    return norm(bound) == norm(presented)
