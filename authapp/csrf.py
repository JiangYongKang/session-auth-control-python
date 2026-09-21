"""防跨站请求伪造：令牌与会话、来源绑定，一次性使用并可过期。

令牌服务端保存：token -> (session_id, expires_at)。
- 缺失 -> CSRF_MISSING
- 未知/已消费 -> CSRF_INVALID
- 属于其它会话 -> CSRF_SESSION_MISMATCH（不依赖令牌自声明）
- 超过 TTL -> CSRF_EXPIRED
- Origin/Referer 不在白名单 -> CSRF_ORIGIN_MISMATCH
通过后立即销毁令牌，保证不可重放；调用方在需要时重新申领。
"""
from __future__ import annotations

from dataclasses import dataclass

from authapp.clock import Clock
from authapp.config import AuthConfig
from authapp.errors import AuthError, ErrorCode
from authapp.security.tokens import constant_time_equals, random_token


@dataclass
class _IssuedToken:
    session_id: str
    expires_at: float


class CsrfManager:
    def __init__(self, config: AuthConfig, clock: Clock) -> None:
        self.config = config
        self.clock = clock
        self._tokens: dict[str, _IssuedToken] = {}

    def issue(self, session_id: str) -> str:
        token = random_token(24)
        now = self.clock.now()
        self._tokens[token] = _IssuedToken(
            session_id=session_id,
            expires_at=now + self.config.csrf_token_ttl_seconds,
        )
        return token

    def _check_origin(self, origin: str | None) -> None:
        if origin is None or origin == "":
            # 非浏览器客户端可不带 Origin，但浏览器同源 POST 必然携带；
            # 一律要求显式来源，避免“无 Origin”被当作放行。
            raise AuthError(ErrorCode.CSRF_ORIGIN_MISMATCH, "缺少来源信息")
        allowed = self.config.allowed_origins
        if not any(constant_time_equals(origin, a) for a in allowed):
            raise AuthError(ErrorCode.CSRF_ORIGIN_MISMATCH, "来源不受信任")

    def verify(
        self,
        token: str | None,
        session_id: str,
        origin: str | None,
    ) -> None:
        # 先校验来源，再校验令牌，两者缺一即拒绝（默认拒绝）。
        self._check_origin(origin)
        if not token:
            raise AuthError(ErrorCode.CSRF_MISSING, "缺少 CSRF 令牌")
        issued = self._tokens.get(token)
        if issued is None:
            # 未知或已被消费（一次性）。
            raise AuthError(ErrorCode.CSRF_INVALID, "CSRF 令牌无效或已使用")
        now = self.clock.now()
        if now >= issued.expires_at:
            self._tokens.pop(token, None)
            raise AuthError(ErrorCode.CSRF_EXPIRED, "CSRF 令牌已过期")
        if issued.session_id != session_id:
            # 令牌被搬到另一个会话中使用。
            raise AuthError(
                ErrorCode.CSRF_SESSION_MISMATCH, "CSRF 令牌与会话不匹配"
            )
        # 通过：立即消费，防止重放。
        self._tokens.pop(token, None)

    def drop_for_session(self, session_id: str) -> None:
        """会话轮换/登出时清理其名下所有令牌。"""
        dead = [t for t, meta in self._tokens.items() if meta.session_id == session_id]
        for token in dead:
            self._tokens.pop(token, None)
