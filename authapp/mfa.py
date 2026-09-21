"""多因素校验编排：绑定/校验/解绑前置条件，区分三类失败。

判定依据（对外可区分，且不泄漏验证码本身）：
- MFA_NOT_BOUND     : 账号未绑定却要求校验；
- MFA_ALREADY_BOUND : 已绑定再次发起绑定；
- MFA_INVALID_CODE  : 窗口内无匹配验证码（含格式非法）；
- MFA_TIME_SKEW     : 验证码落在非当前时间步（时间偏移），不消费、不通过；
- MFA_REPLAYED_CODE : 该时间步的验证码在本会话已成功使用过。

仅“当前时间步且首次使用”的验证码被消费并通过，从根本上杜绝重复使用成功。
绑定/解绑属于 MFA 变更，完成后令用户 auth_epoch +1 并失效其全部既有会话。
"""
from __future__ import annotations

from authapp.clock import Clock
from authapp.config import AuthConfig
from authapp.errors import AuthError, ErrorCode
from authapp.models import SessionRecord, User
from authapp.security import totp
from authapp.store.base import Store


class MfaService:
    def __init__(self, store: Store, config: AuthConfig, clock: Clock) -> None:
        self.store = store
        self.config = config
        self.clock = clock

    def _params(self, secret: str) -> totp.TotpParams:
        return totp.TotpParams(
            secret=secret,
            period=self.config.totp_period,
            digits=self.config.totp_digits,
            lookback=self.config.totp_lookback_steps,
            lookahead=self.config.totp_lookahead_steps,
        )

    def begin_bind(self, user: User) -> tuple[str, str]:
        """已绑定者禁止重复绑定。返回 (secret, provisioning_uri)。

        此时尚未落库：secret 仅用于本次确认，确认成功才真正绑定。
        """
        if user.mfa_enabled:
            raise AuthError(
                ErrorCode.MFA_ALREADY_BOUND, "账号已绑定多因素，请先解绑"
            )
        secret = totp.generate_totp_secret()
        return secret, totp.provisioning_uri(
            secret, user.username, self.config.totp_issuer
        )

    def confirm_bind(self, user: User, secret: str, code: str) -> None:
        """用首屏验证码确认绑定；成功即生效。

        绑定不立即吊销会话：调用方应在受保护会话中完成绑定，随后
        在下次 MFA 登录成功、会话转正并轮换的同一临界区内统一做纪元
        递增与既有会话吊销（见 AuthService.mfa_login），保证原子一致。
        """
        if user.mfa_enabled:
            raise AuthError(
                ErrorCode.MFA_ALREADY_BOUND, "账号已绑定多因素，请先解绑"
            )
        now = self.clock.now()
        params = self._params(secret)
        step = totp.locate_code(code, secret, now, params)
        if step is None:
            raise AuthError(ErrorCode.MFA_INVALID_CODE, "验证码错误")
        if step != totp.current_step(now, params.period):
            raise AuthError(ErrorCode.MFA_TIME_SKEW, "验证码时间偏移，绑定未确认")
        user.mfa_secret = secret
        user.mfa_bound_at = now
        self.store.put_user(user)

    def verify(self, record: SessionRecord, user: User, code: str) -> None:
        """在已登录会话上完成 MFA 校验；失败原因严格区分。"""
        if not user.mfa_enabled or not user.mfa_secret:
            raise AuthError(ErrorCode.MFA_NOT_BOUND, "账号未绑定多因素")
        now = self.clock.now()
        params = self._params(user.mfa_secret)
        current = totp.current_step(now, params.period)
        step = totp.locate_code(code, user.mfa_secret, now, params)
        if step is None:
            raise AuthError(ErrorCode.MFA_INVALID_CODE, "验证码错误")
        if step != current:
            # 落在偏移窗口的旧/新码：归类为时间偏移，且永不消费、永不通过。
            raise AuthError(ErrorCode.MFA_TIME_SKEW, "检测到时间偏移，请使用当前验证码")
        # 用户级重放防护：同一时间步只允许成功一次。即便攻击者更换会话
        # 重放同一验证码，也会在此被拒绝，且绝不再次成功。
        if user.mfa_last_step == step or step in record.consumed_mfa.values():
            raise AuthError(
                ErrorCode.MFA_REPLAYED_CODE, "验证码已被使用，请勿重复提交"
            )
        record.consumed_mfa[code] = step
        user.mfa_last_step = step
        self.store.put_session(record)
        self.store.put_user(user)

    def unbind(self, user: User, code: str) -> None:
        """解绑前必须通过当前一次性口令校验；成功后失效既有会话。"""
        if not user.mfa_enabled or not user.mfa_secret:
            raise AuthError(ErrorCode.MFA_NOT_BOUND, "账号未绑定多因素")
        now = self.clock.now()
        params = self._params(user.mfa_secret)
        current = totp.current_step(now, params.period)
        step = totp.locate_code(code, user.mfa_secret, now, params)
        if step is None:
            raise AuthError(ErrorCode.MFA_INVALID_CODE, "验证码错误")
        if step != current:
            raise AuthError(ErrorCode.MFA_TIME_SKEW, "检测到时间偏移，请使用当前验证码")
        user.mfa_secret = None
        user.mfa_bound_at = None
        user.mfa_last_step = None
        user.auth_epoch += 1
        self.store.put_user(user)
        self.store.revoke_user_sessions(user.user_id, user.auth_epoch)
