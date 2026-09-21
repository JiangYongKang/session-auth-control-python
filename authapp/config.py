"""集中配置：阈值、窗口、TTL 等均可配置。

非法配置在装配时即抛 CONFIG_ERROR，拒绝启动；fail_open 仅允许 False，
从结构上禁止“异常时降级放行”。
"""
from __future__ import annotations

from dataclasses import dataclass

from authapp.errors import AuthError, ErrorCode


@dataclass(frozen=True)
class AuthConfig:
    # 会话
    session_ttl_seconds: int = 1800
    # CSRF
    csrf_token_ttl_seconds: int = 1800
    allowed_origins: tuple[str, ...] = ("https://app.example.local",)
    # 登录节流 / 临时锁定
    fail_window_seconds: int = 300
    fail_threshold: int = 5
    lock_seconds: int = 900
    # 一次性口令（TOTP）
    totp_period: int = 30
    totp_digits: int = 6
    totp_lookback_steps: int = 1
    totp_lookahead_steps: int = 1
    totp_issuer: str = "session-auth-local"
    # 口令策略
    min_password_length: int = 8
    # 存储/时钟异常时是否降级放行——永远为 False（默认拒绝）
    fail_open: bool = False

    def validate(self) -> None:
        positive = {
            "session_ttl_seconds": self.session_ttl_seconds,
            "csrf_token_ttl_seconds": self.csrf_token_ttl_seconds,
            "fail_window_seconds": self.fail_window_seconds,
            "fail_threshold": self.fail_threshold,
            "lock_seconds": self.lock_seconds,
            "totp_period": self.totp_period,
            "min_password_length": self.min_password_length,
        }
        for name, value in positive.items():
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise AuthError(
                    ErrorCode.CONFIG_ERROR, f"配置项 {name} 必须为正整数"
                )
        if self.totp_digits not in (6, 7, 8):
            raise AuthError(ErrorCode.CONFIG_ERROR, "totp_digits 仅支持 6/7/8")
        if self.totp_lookback_steps < 0 or self.totp_lookahead_steps < 0:
            raise AuthError(ErrorCode.CONFIG_ERROR, "TOTP 时间偏移步数不能为负")
        if not self.allowed_origins:
            raise AuthError(ErrorCode.CONFIG_ERROR, "allowed_origins 不能为空")
        if self.fail_open:
            # 硬性安全不变量：任何基础设施异常都不得降级放行。
            raise AuthError(ErrorCode.CONFIG_ERROR, "fail_open 被禁止")
