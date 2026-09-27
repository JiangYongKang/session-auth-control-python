"""账号自助会话管理：活动会话清单、稳定引用、定向收回。

引用（ref）语义：
- ref = HMAC-SHA256(密钥, "<username>:<session_id>")，不可反推原始会话标识；
- 绑定账号：同一 session_id 对不同账号产生不同引用，跨账号提交必然不命中；
- 稳定：同一会话在密钥不变时引用恒定，重复查看结果一致。

收回语义：
- 定向收回只作废目标会话，同账号其余会话不受影响；
- 被收回标识入墓碑（cause="revoked"），重放判定 SESSION_REPLAYED，
  与"从未存在"（UNAUTHENTICATED）可区分；
- 引用不命中活动会话但命中本账号墓碑 -> SESSION_ALREADY_REVOKED；
  完全不命中（含其他账号的引用）-> NOT_FOUND，不泄漏他账号会话存在性。
"""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

from app.audit import AuditEvent, AuditLogger
from app.config import SecurityConfig
from app.errors import AppError, ErrorCode, TimeSourceError
from app.storage.store import Store
from app.time_source import TimeSource

REF_HEX_LEN = 64  # HMAC-SHA256 hexdigest


@dataclass(frozen=True)
class SessionView:
    """对外呈现的活动会话条目（不含原始会话标识）。"""
    ref: str
    created_at: float
    last_seen: float
    mfa_verified: bool
    current: bool


class SessionManagementService:
    def __init__(self, store: Store, time: TimeSource,
                 config: SecurityConfig, audit: AuditLogger,
                 *, reference_secret: str) -> None:
        self.store = store
        self.time = time
        self.config = config
        self.audit = audit
        self._key = reference_secret.encode("utf-8")

    def ref_for(self, username: str, session_id: str) -> str:
        """计算某账号某会话的稳定引用（HMAC，不可反推、跨账号不可用）。"""
        msg = f"{username}:{session_id}".encode("utf-8")
        return hmac.new(self._key, msg, hashlib.sha256).hexdigest()

    def list_active(self, username: str,
                    *, current_session_id: str | None = None
                    ) -> list[SessionView]:
        """该账号当前活动会话清单；按 (created_at, session_id) 排序保证稳定。

        只呈现：未到空闲/绝对过期、且纪元与账号当前纪元一致的会话；
        已过期或被改密/重置作废但尚未惰性清理的条目不暴露给用户。
        """
        now = self._now()
        with self.store.transaction():
            user = self.store.get_user(username)
            epoch = user.session_epoch if user is not None else None
            records = self.store.list_user_sessions(username)
            active = [
                s for s in records
                if now < s.absolute_expiry and now < s.idle_expiry
                and s.epoch == epoch
            ]
            active.sort(key=lambda s: (s.created_at, s.session_id))
            return [
                SessionView(
                    ref=self.ref_for(username, s.session_id),
                    created_at=s.created_at, last_seen=s.last_seen,
                    mfa_verified=s.mfa_verified,
                    current=(s.session_id == current_session_id))
                for s in active
            ]

    def revoke(self, username: str, ref: str,
               *, remote: str | None = None) -> None:
        """定向收回一条会话。未知引用 NOT_FOUND；已失效 SESSION_ALREADY_REVOKED。

        判定只在本账号的活动会话/墓碑范围内进行，因此他账号的引用与
        随机伪造引用返回完全一致的 NOT_FOUND，不能用于探测他账号会话。
        """
        ref = (ref or "").strip()
        now = self._now()
        with self.store.transaction():
            for sess in self.store.list_user_sessions(username):
                if self._ref_matches(username, sess.session_id, ref):
                    self.store.delete_session(sess.session_id, cause="revoked")
                    self.audit.record(
                        AuditEvent.SESSION_REVOKED, user=username,
                        result="ok", reason=None, cause="targeted",
                        remote=remote or "?")
                    return

            # 活动会话未命中：区分"本账号已撤销引用"与"根本不存在的引用"。
            for sid in self.store.list_user_tombstone_ids(username):
                if self._ref_matches(username, sid, ref):
                    self.audit.record(
                        AuditEvent.SESSION_REVOKED, user=username,
                        result="denied",
                        reason=ErrorCode.SESSION_ALREADY_REVOKED.value,
                        cause="targeted", remote=remote or "?")
                    raise AppError(
                        ErrorCode.SESSION_ALREADY_REVOKED,
                        "session reference has already been revoked")

            self.audit.record(
                AuditEvent.SESSION_REVOKED, user=username, result="denied",
                reason=ErrorCode.NOT_FOUND.value, cause="targeted",
                remote=remote or "?")
            raise AppError(ErrorCode.NOT_FOUND,
                           "session reference not found")

    def _ref_matches(self, username: str, session_id: str,
                     presented: str) -> bool:
        if len(presented) != REF_HEX_LEN:
            return False
        return hmac.compare_digest(
            self.ref_for(username, session_id), presented)

    def _now(self) -> float:
        try:
            return self.time.now()
        except TimeSourceError:
            self.audit.record(AuditEvent.INFRA_ERROR, result="error",
                              reason=ErrorCode.TIME_SOURCE_UNAVAILABLE.value)
            raise
