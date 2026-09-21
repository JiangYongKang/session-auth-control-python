"""存储层数据模型。"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class UserRecord:
    username: str
    password_hash: str
    roles: tuple[str, ...]
    totp_secret: str | None = None
    totp_enrolled: bool = False
    totp_last_step: int | None = None      # 已消费的 TOTP 时间步（防重放）
    fail_count: int = 0
    fail_window_start: float | None = None
    locked_until: float | None = None
    session_epoch: int = 0                 # 会话纪元：改密/重置/全量注销时 +1


@dataclass
class SessionRecord:
    session_id: str
    username: str
    created_at: float
    last_seen: float
    absolute_expiry: float
    idle_expiry: float
    mfa_verified: bool
    epoch: int                            # 创建时用户的 session_epoch
    csrf_token: str | None = None         # 该会话当前活动 CSRF 令牌
    rotated: bool = False                 # 被轮换后置位（重放检测）


@dataclass
class CsrfTokenRecord:
    """服务端 CSRF 记录：与会话、来源绑定，独立 TTL。"""
    token: str
    session_id: str
    username: str
    origin: str
    expires_at: float
