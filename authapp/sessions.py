"""服务端会话：创建、校验、标识轮换、登出、过期与重放拒绝。

不变量：
- 会话标识仅在服务端存储中存在时有效；登出/轮换即从存储删除旧标识，
  重放旧标识得到的是“不存在”，无法复活；
- 会话记录带用户 auth_epoch；用户改密/注销/MFA 重置使纪元递增，
  所有旧会话立即失效（session_revoked）；
- 过期会话判定为 session_expired，且不会被续期复活。
"""
from __future__ import annotations

from authapp.clock import Clock
from authapp.config import AuthConfig
from authapp.errors import AuthError, ErrorCode
from authapp.models import SessionRecord
from authapp.security.tokens import random_token
from authapp.store.base import Store


class SessionManager:
    def __init__(self, store: Store, config: AuthConfig, clock: Clock) -> None:
        self.store = store
        self.config = config
        self.clock = clock

    def create(self, user_id: str, epoch: int, *, mfa_completed: bool) -> str:
        now = self.clock.now()
        session_id = random_token(32)
        record = SessionRecord(
            session_id=session_id,
            user_id=user_id,
            created_at=now,
            expires_at=now + self.config.session_ttl_seconds,
            auth_epoch=epoch,
            last_seen=now,
            mfa_completed=mfa_completed,
        )
        self.store.put_session(record)
        return session_id

    def resolve(self, session_id: str | None) -> SessionRecord:
        """解析为有效会话，否则抛 UNAUTHENTICATED/EXPIRED/REVOKED。"""
        if not session_id or not isinstance(session_id, str):
            raise AuthError(ErrorCode.UNAUTHENTICATED, "缺少会话标识")
        record = self.store.get_session(session_id)
        if record is None:
            # 登出/轮换后旧标识落到这里，且无法区分，天然防重放。
            raise AuthError(ErrorCode.UNAUTHENTICATED, "会话不存在或已失效")
        now = self.clock.now()
        if record.revoked:
            raise AuthError(ErrorCode.SESSION_REVOKED, "会话已被注销")
        if now >= record.expires_at:
            # 过期即物理删除，确保旧标识之后永远“不存在”。
            self.store.delete_session(record.session_id)
            raise AuthError(ErrorCode.SESSION_EXPIRED, "会话已过期")
        record.last_seen = now
        self.store.put_session(record)
        return record

    def rotate(self, record: SessionRecord, *, mfa_completed: bool) -> str:
        """登录后升级（MFA 通过）更换标识：旧标识立即删除，不可复活。"""
        new_id = random_token(32)
        now = self.clock.now()
        new_record = SessionRecord(
            session_id=new_id,
            user_id=record.user_id,
            created_at=now,
            expires_at=now + self.config.session_ttl_seconds,
            auth_epoch=record.auth_epoch,
            last_seen=now,
            mfa_completed=mfa_completed,
        )
        # 先放新、再删旧；即便极端失败，也只会留下冗余有效会话，
        # 绝不会出现“无会话可用”之外的安全降级（旧标识随后删除）。
        self.store.put_session(new_record)
        self.store.delete_session(record.session_id)
        return new_id

    def logout(self, session_id: str) -> None:
        # 幂等：重复登出/旧标识重放都不会复活任何会话。
        self.store.delete_session(session_id)

    def revoke_all_for_user(self, user_id: str, new_epoch: int) -> None:
        # 纪元校验是第二道防线；物理标记失效是第一道。
        self.store.revoke_user_sessions(user_id, new_epoch)
