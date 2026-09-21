"""核心领域模型（类型定义层，承载极少量纯数据辅助方法）。"""
from __future__ import annotations

from dataclasses import dataclass, field, replace


@dataclass
class User:
    user_id: str
    username: str
    password_hash: str
    roles: list[str] = field(default_factory=list)
    mfa_secret: str | None = None
    mfa_bound_at: float | None = None
    # 全局失效纪元：口令变更/MFA 重置/注销时递增，旧会话一律失效
    auth_epoch: int = 0
    locked_until: float | None = None
    # 最近一次成功消费的 TOTP 时间步（用户级重放防护；同一时间步只有一个合法码）
    mfa_last_step: int | None = None

    @property
    def mfa_enabled(self) -> bool:
        return self.mfa_secret is not None

    def is_locked(self, now: float) -> bool:
        return self.locked_until is not None and self.locked_until > now

    def snapshot(self) -> "User":
        """返回脱离开存储内部对象的副本（角色列表独立拷贝）。"""
        return replace(self, roles=list(self.roles))


@dataclass
class SessionRecord:
    session_id: str
    user_id: str
    created_at: float
    expires_at: float
    auth_epoch: int
    last_seen: float = 0.0
    revoked: bool = False
    # 该会话上已消费的 MFA 验证码 -> 所在时间步，防重放
    consumed_mfa: dict[str, int] = field(default_factory=dict)
    # MFA 是否已通过（未启用 MFA 的账号登录即视为已完成）
    mfa_completed: bool = False

    def alive(self, now: float) -> bool:
        return not self.revoked and now < self.expires_at


@dataclass
class LoginFailure:
    username: str
    count: int
    window_started_at: float
    first_failures: list[float] = field(default_factory=list)
    locked: bool = False

    def prune(self, now: float, window: int) -> None:
        """丢弃观察窗口之外的失败时间戳并重置计数。"""
        cutoff = now - window
        fresh = [t for t in self.first_failures if t > cutoff]
        if fresh:
            self.first_failures = fresh
            self.count = len(fresh)
            self.window_started_at = fresh[0]
        else:
            self.first_failures = []
            self.count = 0
            self.window_started_at = now
