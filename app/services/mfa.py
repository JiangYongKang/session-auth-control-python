"""多因素服务：绑定、登录后校验、解绑、重置。

前置条件（明确且可解释）：
- begin/confirm enroll：必须已登录，且尚未绑定；confirm 成功才算绑定完成；
- verify（登录第二步）：会话必须 mfa_verified=False（即等待 MFA）；
- unbind：必须已登录、已绑定，且需再验口令 + 一次性码；
- reset（管理员）：目标已绑定，重置即纪元 +1，立即作废其全部既有会话。

TOTP 失败区分（顺序见 security/totp.py）：
- MFA_TIME_DRIFT 时间偏移超窗
- MFA_CODE_REUSED 同一码（步）重复使用
- MFA_CODE_INVALID 验证码错误
"""
from __future__ import annotations

from app.audit import AuditEvent, AuditLogger
from app.config import SecurityConfig
from app.errors import AppError, ErrorCode
from app.security.passwords import verify_password
from app.security.totp import (classify_window, generate_secret,
                               provisioning_uri, verify_code)
from app.services.auth import AuthService, Principal
from app.storage.models import CsrfTokenRecord, SessionRecord
from app.storage.store import Store
from app.time_source import TimeSource

_TOTP_REASON_TO_CODE = {
    "invalid": ErrorCode.MFA_CODE_INVALID,
    "reused": ErrorCode.MFA_CODE_REUSED,
    "time_drift": ErrorCode.MFA_TIME_DRIFT,
}


class MfaService:
    def __init__(self, store: Store, time: TimeSource,
                 config: SecurityConfig, audit: AuditLogger,
                 auth: AuthService) -> None:
        self.store = store
        self.time = time
        self.config = config
        self.audit = audit
        self.auth = auth

    # ------------------------------------------------------------------ #
    # 绑定
    # ------------------------------------------------------------------ #
    def begin_enroll(self, principal: Principal) -> dict:
        now = self._now()
        with self.store.transaction():
            user = self._get_user(principal.username)
            self._require_not_enrolled(user)
            secret = user.totp_secret or generate_secret()
            user.totp_secret = secret
            user.totp_enrolled = False  # confirm 成功前不算绑定
            self.store.put_user(user)
        uri = provisioning_uri(secret, user.username,
                               self.config.totp.issuer)
        self.audit.record(AuditEvent.MFA_ENROLL, user=user.username,
                          result="pending", reason="enroll_begin")
        return {"secret": secret, "otpauth_uri": uri, "enrolled": False}

    def confirm_enroll(self, principal: Principal, code: str) -> None:
        now = self._now()
        with self.store.transaction():
            user = self._get_user(principal.username)
            if user.totp_enrolled:
                raise AppError(ErrorCode.MFA_ALREADY_ENROLLED,
                               "already enrolled")
            if not user.totp_secret:
                raise AppError(ErrorCode.MFA_NOT_ENROLLED,
                               "enroll not started")
            ok, reason, step = self._verify(user, code, now)
            if not ok:
                self.audit.record(
                    AuditEvent.MFA_ENROLL, user=user.username,
                    result="denied",
                    reason=_TOTP_REASON_TO_CODE[reason].value,
                    stage="confirm")
                raise AppError(_TOTP_REASON_TO_CODE[reason],
                               f"totp {reason}")
            user.totp_enrolled = True
            user.totp_last_step = step
            # 绑定即安全状态变化：纪元 +1，既有会话全部作废，需重新登录走 MFA
            user.session_epoch += 1
            self.store.put_user(user)
            n = self.store.invalidate_user_sessions(
                user.username, now, cause="invalidated")
        self.audit.record(AuditEvent.MFA_ENROLL, user=user.username,
                          result="ok", reason="enroll_confirmed",
                          consumed_step=step, sessions_invalidated=n)

    # ------------------------------------------------------------------ #
    # 登录第二步
    # ------------------------------------------------------------------ #
    def verify_for_login(self, principal: Principal, code: str) -> None:
        now = self._now()
        with self.store.transaction():
            if principal.mfa_verified:
                # 已完成 MFA，不允许再次"校验"来消费/探测验证码
                raise AppError(ErrorCode.MFA_NOT_VERIFIED,
                               "mfa already verified")
            user = self._get_user(principal.username)
            if not (user.totp_enrolled and user.totp_secret):
                raise AppError(ErrorCode.MFA_NOT_ENROLLED,
                               "user has no totp enrollment")
            sess = self.store.get_session(principal.session_id)
            if sess is None or sess.mfa_verified:
                raise AppError(ErrorCode.MFA_NOT_VERIFIED,
                               "session not awaiting mfa")

            ok, reason, step = self._verify(user, code, now)
            if not ok:
                self.audit.record(
                    AuditEvent.MFA_VERIFY, user=user.username,
                    result="denied",
                    reason=_TOTP_REASON_TO_CODE[reason].value,
                    stage="login")
                raise AppError(_TOTP_REASON_TO_CODE[reason],
                               f"totp {reason}")

            # 成功：消费该步 + 标记会话 + 轮换会话标识（登录态升级后再换一次）
            user.totp_last_step = step
            self.store.put_user(user)
            origin = "unknown"
            existing = self.store.get_csrf(principal.csrf_token or "")
            if existing is not None:
                origin = existing.origin
                self.store.delete_csrf(existing.token)
            new_sid, new_csrf = self._promote_session_locked(
                sess, now, origin=origin)
        self.audit.record(AuditEvent.MFA_VERIFY, user=user.username,
                          result="ok", reason="mfa_verified",
                          consumed_step=step)
        return {"session_id": new_sid, "csrf_token": new_csrf,
                "mfa_verified": True}

    # ------------------------------------------------------------------ #
    # 解绑（自服务）：口令 + 当前一次性码双确认
    # ------------------------------------------------------------------ #
    def unbind(self, principal: Principal, password: str, code: str) -> None:
        now = self._now()
        with self.store.transaction():
            user = self._get_user(principal.username)
            if not (user.totp_enrolled and user.totp_secret):
                raise AppError(ErrorCode.MFA_NOT_ENROLLED,
                               "not enrolled")
            if not verify_password(password, user.password_hash):
                self.audit.record(AuditEvent.MFA_UNBIND,
                                  user=user.username, result="denied",
                                  reason=ErrorCode.INVALID_CREDENTIALS.value)
                raise AppError(ErrorCode.INVALID_CREDENTIALS,
                               "password reconfirmation failed")
            ok, reason, step = self._verify(user, code, now)
            if not ok:
                self.audit.record(AuditEvent.MFA_UNBIND,
                                  user=user.username, result="denied",
                                  reason=_TOTP_REASON_TO_CODE[reason].value)
                raise AppError(_TOTP_REASON_TO_CODE[reason],
                               f"totp {reason}")
            user.totp_secret = None
            user.totp_enrolled = False
            user.totp_last_step = None
            self.store.put_user(user)
            # 安全状态变化：作废该用户既有会话
            user.session_epoch += 1
            self.store.put_user(user)
            n = self.store.invalidate_user_sessions(
                user.username, now, cause="invalidated")
        self.audit.record(AuditEvent.MFA_UNBIND, user=user.username,
                          result="ok", reason="unbound",
                          sessions_invalidated=n)

    # ------------------------------------------------------------------ #
    # 管理员重置：立即作废目标账号全部既有会话
    # ------------------------------------------------------------------ #
    def reset(self, actor: Principal, target_username: str) -> None:
        now = self._now()
        with self.store.transaction():
            target = self.store.get_user(target_username)
            if target is None:
                # 不泄漏目标是否存在：对管理员操作返回统一冲突/不存在语义
                raise AppError(ErrorCode.NOT_FOUND, "target not found")
            if not (target.totp_enrolled or target.totp_secret):
                raise AppError(ErrorCode.MFA_NOT_ENROLLED,
                               "target not enrolled")
            target.totp_secret = None
            target.totp_enrolled = False
            target.totp_last_step = None
            target.session_epoch += 1
            self.store.put_user(target)
            n = self.store.invalidate_user_sessions(
                target.username, now, cause="invalidated")
        self.audit.record(AuditEvent.MFA_RESET, user=target_username,
                          result="ok", reason="admin_reset",
                          actor=actor.username, sessions_invalidated=n)

    # ------------------------------------------------------------------ #
    # 辅助
    # ------------------------------------------------------------------ #
    def _verify(self, user, code: str, now: float):
        tc = self.config.totp
        # 时间漂移优先：若服务端时间允许窗口的"最新步"都 <= 已消费步，
        # 说明服务端/客户端时间已整体落后超过窗口，归一为时间漂移。
        if classify_window(user.totp_last_step, now,
                           period=tc.period,
                           drift_steps=tc.drift_steps) == "time_drift":
            return False, "time_drift", None
        return verify_code(
            user.totp_secret, code, now,
            period=tc.period, digits=tc.digits,
            drift_steps=tc.drift_steps,
            last_consumed_step=user.totp_last_step)

    def _promote_session_locked(self, sess: SessionRecord,
                                now: float, origin: str = "unknown"
                                ) -> tuple[str, str]:
        """MFA 验证成功后：会话升级 + 标识轮换 + 新 CSRF 落库。"""
        from app.security.csrf import issue_csrf_token
        from app.services.auth import new_session_id
        new_id = new_session_id()
        csrf = issue_csrf_token()
        promoted = SessionRecord(
            session_id=new_id, username=sess.username,
            created_at=sess.created_at, last_seen=now,
            absolute_expiry=sess.absolute_expiry,
            idle_expiry=now + self.config.session.idle_timeout_seconds,
            mfa_verified=True, epoch=sess.epoch, csrf_token=csrf)
        self.store.rotate_session(sess.session_id, promoted, now)
        self.store.put_csrf(CsrfTokenRecord(
            token=csrf, session_id=new_id, username=sess.username,
            origin=origin,
            expires_at=now + self.config.session.csrf_ttl_seconds))
        return new_id, csrf

    def _require_not_enrolled(self, user) -> None:
        if user.totp_enrolled:
            raise AppError(ErrorCode.MFA_ALREADY_ENROLLED,
                           "already enrolled")

    def _get_user(self, username: str):
        user = self.store.get_user(username)
        if user is None:  # pragma: no cover - 会话属主必然存在
            raise AppError(ErrorCode.NOT_FOUND, "user not found")
        return user

    def _now(self) -> float:
        return self.time.now()
