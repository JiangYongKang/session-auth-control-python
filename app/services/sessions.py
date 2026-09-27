"""账号自助会话管理：查看本人活动会话、定向收回单条会话。

关键不变量：
- 列表仅返回属于当前账号的活动会话；稳定顺序（创建时间, 标识），
  同一时刻重复查看条数与顺序不变；不同账号之间完全隔离。
- 对外的"引用"是 (账号, 会话标识) 的密钥 HMAC：不可反推原始标识、
  不能跨账号使用（解析只在该账号的候选集合内进行）。
- 定向收回只作废被引用的那一条；引用已失效（会话已收回/过期/被淘汰）
  与引用对该账号不存在给出两个稳定且可区分的拒绝结果。
- 收回是状态变更：入口路由强制登录态 + 已完成 MFA + CSRF。
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from app.audit import AuditEvent, AuditLogger
from app.config import SecurityConfig
from app.errors import AppError, ErrorCode
from app.security.session_ref import SessionReferenceSigner
from app.services.auth import Principal
from app.storage.store import Store
from app.time_source import TimeSource

if TYPE_CHECKING:
    from app.services.auth import AuthService

# 收回后，在墓碑视角下与"账号级失效"同义的撤销原因
_ACCOUNT_INVALIDATION_CAUSES = frozenset({
    "invalidated", "password_change"})


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(
        timespec="seconds").replace("+00:00", "Z")


class SessionsService:
    def __init__(self, store: Store, time: TimeSource,
                 config: SecurityConfig, audit: AuditLogger,
                 signer: SessionReferenceSigner,
                 auth: "AuthService | None" = None) -> None:
        self.store = store
        self.time = time
        self.config = config
        self.audit = audit
        self.signer = signer
        # 由容器后置注入：复用登录态服务的过期清扫等持锁逻辑
        self.auth: AuthService | None = auth

    # ------------------------------------------------------------------ #
    # 查看本人活动会话
    # ------------------------------------------------------------------ #
    def list_active(self, principal: Principal) -> dict:
        username = principal.username
        now = self.time.now()
        with self.store.transaction():
            # 过期会话在列表视图中原子转为墓碑（与 resolve 路径判定一致）
            self.auth.sweep_expired_user_sessions(username, now)
            sessions = sorted(
                self.store.list_user_sessions(username),
                key=lambda s: (s.created_at, s.session_id))
            items = [{
                "reference": self.signer.sign(username, s.session_id),
                "created_at": _iso(s.created_at),
                "last_seen_at": _iso(s.last_seen),
                "mfa_verified": s.mfa_verified,
                "current": s.session_id == principal.session_id,
            } for s in sessions]
        self.audit.record(AuditEvent.ACCESS_ALLOWED, user=username,
                          result="ok", reason="sessions_listed",
                          session_count=len(items))
        return {"sessions": items, "count": len(items)}

    # ------------------------------------------------------------------ #
    # 定向收回
    # ------------------------------------------------------------------ #
    def revoke(self, principal: Principal, reference: str) -> None:
        username = principal.username
        reference = (reference or "").strip()
        if not reference:
            raise AppError(ErrorCode.VALIDATION_ERROR,
                           "session reference is required")
        now = self.time.now()
        with self.store.transaction():
            self.auth.sweep_expired_user_sessions(username, now)

            active = self.store.list_user_sessions(username)
            target_sid = self.signer.restrict(
                username, reference, [s.session_id for s in active])

            if target_sid is not None:
                target = next(s for s in active
                              if s.session_id == target_sid)
                is_current = target.session_id == principal.session_id
                # 只作废被引用的那一条；其余会话不触碰
                self.store.delete_session(target.session_id,
                                          cause="self_revoke")
            else:
                # 在该账号的墓碑中再解析一次，以区分"已收回"与"不存在"
                tombed = self.store.list_user_tombstone_ids(username)
                tomb_sid = self.signer.restrict(username, reference, tombed)
                if tomb_sid is None:
                    # 不存在 / 属于其他账号 / 伪造：统一"未知引用"，
                    # 不借此泄漏任何账号的会话存在性。
                    self.audit.record(
                        AuditEvent.ACCESS_DENIED, user=username,
                        result="denied",
                        reason=ErrorCode.SESSION_REFERENCE_UNKNOWN.value)
                    raise AppError(ErrorCode.SESSION_REFERENCE_UNKNOWN,
                                   "session reference not recognized")
                info = self.store.tombstone_info(tomb_sid) or {}
                cause = info.get("cause")
                if cause in _ACCOUNT_INVALIDATION_CAUSES:
                    code = ErrorCode.SESSION_INVALIDATED
                    detail = "session invalidated by account change"
                else:
                    code = ErrorCode.SESSION_REFERENCE_REVOKED
                    detail = "session reference has already been revoked"
                self.audit.record(
                    AuditEvent.ACCESS_DENIED, user=username, result="denied",
                    reason=code.value, tombstone_cause=cause)
                raise AppError(code, detail)

        self.audit.record(
            AuditEvent.SESSION_REVOKED, user=username, result="ok",
            reason="self_revoke", cause="self_revoke",
            target_current=is_current)
