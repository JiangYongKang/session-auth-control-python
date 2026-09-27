"""认证核心服务：注册、登录（节流/锁定/统一失败）、会话生命周期。

关键不变量：
- 用户名不存在与口令错误对外完全不可区分（同一错误码、同一错误路径）；
  仅审计日志（受控）保留 failure_cause（user_not_found / bad_password）。
- 登录失败计数在单事务内读改写，并发失败不绕过计数、不重复锁定。
- 登录成功创建全新会话标识并绑定会话级 CSRF（会话固定防护）。
- 注销/过期/被纪元作废的标识进入墓碑，重放可区分且不复活。
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Any

from app.audit import AuditEvent, AuditLogger
from app.config import SecurityConfig
from app.errors import AppError, ErrorCode, StoreError, TimeSourceError
from app.security.csrf import issue_csrf_token
from app.security.passwords import hash_password, validate_password, verify_password
from app.storage.models import CsrfTokenRecord, SessionRecord, UserRecord
from app.storage.store import Store
from app.time_source import TimeSource

SID_BYTES = 32


def new_session_id() -> str:
    return secrets.token_hex(SID_BYTES)


@dataclass
class Principal:
    """解析后的会话主体（角色来自服务端记录，绝不来自客户端）。"""
    session_id: str
    username: str
    roles: tuple[str, ...]
    mfa_verified: bool
    csrf_token: str | None


class AuthService:
    def __init__(self, store: Store, time: TimeSource,
                 config: SecurityConfig, audit: AuditLogger) -> None:
        self.store = store
        self.time = time
        self.config = config
        self.audit = audit

    # ------------------------------------------------------------------ #
    # 注册
    # ------------------------------------------------------------------ #
    def register(self, username: str, password: str,
                 roles: tuple[str, ...] = ()) -> None:
        username = (username or "").strip()
        if not username:
            raise AppError(ErrorCode.VALIDATION_ERROR, "username is required")
        validate_password(password, self.config.password)
        requested = tuple(roles or ())
        for r in requested:
            if not isinstance(r, str) or not r:
                raise AppError(ErrorCode.VALIDATION_ERROR,
                               f"invalid role: {r!r}")
        # 自助注册只允许白名单角色；特权角色必须由管理员通过受控端点授予。
        # 服务端绝不因为客户端自报角色而提权。
        denied = sorted(set(requested) - self.config.self_service_roles)
        if denied:
            self.audit.record(
                AuditEvent.ACCESS_DENIED, user=username or None,
                result="denied", reason=ErrorCode.FORBIDDEN.value,
                decision_basis=f"self_service_role_denied roles={denied}")
            raise AppError(
                ErrorCode.FORBIDDEN,
                f"self-service registration cannot request role(s): {denied}")

        now = self._now()
        with self.store.transaction():
            if self.store.get_user(username) is not None:
                raise AppError(ErrorCode.CONFLICT, "username already taken")
            self.store.put_user(UserRecord(
                username=username,
                password_hash=hash_password(password),
                # 仅落库白名单内角色（此处 requested 已全部在白名单内）
                roles=requested,
            ))
        self.audit.record(AuditEvent.REGISTER, user=username, result="ok",
                          roles=",".join(requested) or "-")

    def provision_user(self, username: str, password: str,
                       roles: tuple[str, ...]) -> None:
        """受信引导（如初始管理员）：允许授予任意已配置角色。

        仅供服务端启动/受控脚本调用，不暴露为自助端点。
        """
        username = (username or "").strip()
        validate_password(password, self.config.password)
        for r in roles:
            if r not in self.config.role_permissions:
                raise AppError(ErrorCode.CONFIG_ERROR,
                               f"unknown role: {r}")
        now = self._now()
        with self.store.transaction():
            if self.store.get_user(username) is not None:
                raise AppError(ErrorCode.CONFLICT, "username already taken")
            self.store.put_user(UserRecord(
                username=username, password_hash=hash_password(password),
                roles=tuple(roles)))
        self.audit.record(AuditEvent.REGISTER, user=username, result="ok",
                          roles=",".join(roles), via="provisioned")

    def set_roles(self, actor: str, target_username: str,
                  roles: tuple[str, ...]) -> None:
        """管理员授予/变更角色（admin 动作）。"""
        roles = tuple(roles)
        for r in roles:
            if r not in self.config.role_permissions:
                raise AppError(ErrorCode.VALIDATION_ERROR,
                               f"unknown role: {r}")
        now = self._now()
        with self.store.transaction():
            target = self.store.get_user(target_username)
            if target is None:
                raise AppError(ErrorCode.NOT_FOUND, "target not found")
            target.roles = roles
            # 角色变更属安全状态变化：纪元 +1，立即失效其既有会话
            target.session_epoch += 1
            self.store.put_user(target)
            n = self.store.invalidate_user_sessions(
                target_username, now, cause="invalidated")
        self.audit.record(AuditEvent.ROLES_CHANGED,
                          user=target_username, result="ok",
                          reason="roles_changed", actor=actor,
                          roles=",".join(roles), sessions_invalidated=n)

    # ------------------------------------------------------------------ #
    # 登录
    # ------------------------------------------------------------------ #
    def login(self, username: str, password: str,
              *, origin: str = "unknown",
              remote: str | None = None) -> dict[str, Any]:
        username = (username or "").strip()
        now = self._now()
        audit_base = {"remote": remote or "?", "origin": origin}

        with self.store.transaction():
            user = self.store.get_user(username)

            # ---- 锁定期优先：锁定期内即使口令正确也拒绝（可区分） ----
            if user is not None and user.locked_until is not None:
                if user.locked_until > now:
                    remaining = max(0, int(user.locked_until - now))
                    self.audit.record(
                        AuditEvent.LOGIN_LOCKED, user=username,
                        result="denied", reason=ErrorCode.LOCKED.value,
                        lock_remaining_s=remaining, **audit_base)
                    raise AppError(
                        ErrorCode.LOCKED,
                        f"account locked; retry_after={remaining}s")
                user.locked_until = None
                user.fail_count = 0
                user.fail_window_start = None

            valid = user is not None and verify_password(
                password, user.password_hash)

            if not valid:
                # 若本事务登记失败时发现已被并发请求锁定，直接按锁定拒绝，
                # 不重复计数、不重复产生锁定事件。
                if user is not None and user.locked_until is not None \
                        and user.locked_until > now:
                    remaining = max(0, int(user.locked_until - now))
                    self.audit.record(
                        AuditEvent.LOGIN_LOCKED, user=username,
                        result="denied", reason=ErrorCode.LOCKED.value,
                        lock_remaining_s=remaining, **audit_base)
                    raise AppError(
                        ErrorCode.LOCKED,
                        f"account locked; retry_after={remaining}s")
                cause = "user_not_found" if user is None else "bad_password"
                user = self._register_failure_locked(user, username, now)
                just_locked = user.locked_until is not None
                # 真实用户才落库；不存在用户不落库（防账号枚举侧信道）
                if user.password_hash:
                    self.store.put_user(user)

                self.audit.record(
                    AuditEvent.LOGIN_LOCKED if just_locked
                    else AuditEvent.LOGIN_FAILURE,
                    user=username if user.password_hash else None,
                    result="denied",
                    reason=ErrorCode.LOCKED.value if just_locked
                    else ErrorCode.INVALID_CREDENTIALS.value,
                    failure_cause=cause, fail_count=user.fail_count,
                    lock_set=just_locked,
                    **audit_base)

                if just_locked:
                    raise AppError(
                        ErrorCode.LOCKED,
                        f"account locked after {user.fail_count} failures; "
                        f"retry_after={self.config.throttle.lock_seconds}s")
                raise AppError(ErrorCode.INVALID_CREDENTIALS,
                               "username or password is incorrect")

            assert user is not None
            user.fail_count = 0
            user.fail_window_start = None
            user.locked_until = None
            self.store.put_user(user)

            sid, csrf = self._create_session_locked(user, now, origin)
            evicted = self._enforce_capacity_locked(
                user.username, now, keep_session_id=sid)

        for ev in evicted:
            # 容量淘汰与逐条收回在审计上同构：每条一条 SESSION_REVOKED
            self.audit.record(
                AuditEvent.SESSION_REVOKED, user=user.username, result="ok",
                reason="capacity_evicted", cause="capacity_evicted",
                session_age_s=max(0, int(now - ev.created_at)))

        mfa_required = bool(user.totp_enrolled and user.totp_secret)
        self.audit.record(
            AuditEvent.LOGIN_SUCCESS, user=username, result="ok",
            reason=ErrorCode.MFA_REQUIRED.value if mfa_required else None,
            mfa_required=mfa_required, **audit_base)
        return {
            "session_id": sid,
            "csrf_token": csrf,
            "mfa_required": mfa_required,
            "mfa_verified": not mfa_required,
        }

    def _register_failure_locked(self, user: UserRecord | None,
                                 username: str, now: float) -> UserRecord:
        """原子地登记一次失败（调用方已持事务）。并发安全由单锁保证。"""
        thr = self.config.throttle
        if user is None:
            # 幻影记录：仅在事务内使用，不落库
            return UserRecord(username=username, password_hash="", roles=(),
                              fail_window_start=now, fail_count=1)

        if (user.fail_window_start is None
                or now - user.fail_window_start >= thr.window_seconds):
            user.fail_window_start = now
            user.fail_count = 1
        else:
            user.fail_count += 1

        if user.fail_count >= thr.max_failures and user.locked_until is None:
            # 仅在越过阈值的那一刻设置一次：并发失败不会重复锁定
            user.locked_until = now + thr.lock_seconds
        return user

    # ------------------------------------------------------------------ #
    # 登出
    # ------------------------------------------------------------------ #
    def logout(self, session_id: str, *, remote: str | None = None) -> None:
        now = self._now()
        with self.store.transaction():
            sess = self.store.get_session(session_id)
            if sess is None:
                if self.store.is_tombstoned(session_id, now):
                    self.audit.record(
                        AuditEvent.SESSION_REPLAYED, result="denied",
                        reason=ErrorCode.SESSION_REPLAYED.value,
                        remote=remote or "?")
                    raise AppError(ErrorCode.SESSION_REPLAYED,
                                   "session id has been revoked")
                raise AppError(ErrorCode.UNAUTHENTICATED,
                               "no active session")
            user = sess.username
            self.store.delete_session(session_id)
        self.audit.record(AuditEvent.LOGOUT, user=user, result="ok",
                          remote=remote or "?")

    def logout_all(self, username: str) -> int:
        """全量注销：纪元 +1 并使该用户所有会话原子失效。"""
        now = self._now()
        with self.store.transaction():
            user = self.store.get_user(username)
            if user is None:
                raise AppError(ErrorCode.NOT_FOUND, "user not found")
            user.session_epoch += 1
            self.store.put_user(user)
            return self.store.invalidate_user_sessions(username, now)

    def change_password(self, username: str, old_password: str,
                        new_password: str) -> int:
        """改密：旧口令重确认；成功后纪元 +1，原子失效全部既有会话。

        返回失效会话数。口令错误与"用户不存在"同样不可区分。
        """
        validate_password(new_password, self.config.password)
        if new_password == old_password:
            raise AppError(ErrorCode.VALIDATION_ERROR,
                           "new password must differ from old")
        now = self._now()
        with self.store.transaction():
            user = self.store.get_user(username)
            valid = user is not None and verify_password(
                old_password, user.password_hash)
            if not valid:
                cause = "user_not_found" if user is None else "bad_password"
                self.audit.record(
                    AuditEvent.PASSWORD_CHANGED,
                    user=username if user is not None else None,
                    result="denied",
                    reason=ErrorCode.INVALID_CREDENTIALS.value,
                    failure_cause=cause)
                raise AppError(ErrorCode.INVALID_CREDENTIALS,
                               "username or password is incorrect")
            assert user is not None
            user.password_hash = hash_password(new_password)
            user.fail_count = 0
            user.fail_window_start = None
            user.locked_until = None
            user.session_epoch += 1
            self.store.put_user(user)
            n = self.store.invalidate_user_sessions(
                username, now, cause="password_change")
        self.audit.record(AuditEvent.PASSWORD_CHANGED, user=username,
                          result="ok", reason="password_rotated",
                          sessions_invalidated=n)
        return n

    # ------------------------------------------------------------------ #
    # 会话解析
    # ------------------------------------------------------------------ #
    def resolve_session(self, session_id: str | None) -> Principal:
        if not session_id:
            raise AppError(ErrorCode.UNAUTHENTICATED, "missing session id")
        now = self._now()
        with self.store.transaction():
            sess = self.store.get_session(session_id)
            if sess is None:
                info = self.store.tombstone_info(session_id)
                if info is not None:
                    owner = self.store.get_user(info.get("username", ""))
                    tomb_epoch = info.get("epoch")
                    invalidated = (
                        info.get("cause") in ("invalidated", "password_change")
                        or (owner is not None and tomb_epoch is not None
                            and owner.session_epoch != tomb_epoch)
                    )
                    if invalidated:
                        self.audit.record(
                            AuditEvent.SESSION_REPLAYED,
                            user=info.get("username"), result="denied",
                            reason=ErrorCode.SESSION_INVALIDATED.value,
                            tombstone_cause=info.get("cause"))
                        raise AppError(
                            ErrorCode.SESSION_INVALIDATED,
                            "session invalidated by account change")
                    self.audit.record(
                        AuditEvent.SESSION_REPLAYED,
                        user=info.get("username"), result="denied",
                        reason=ErrorCode.SESSION_REPLAYED.value,
                        tombstone_cause=info.get("cause"))
                    raise AppError(ErrorCode.SESSION_REPLAYED,
                                   "revoked session id replayed")
                raise AppError(ErrorCode.UNAUTHENTICATED,
                               "unknown session id")

            if now >= sess.absolute_expiry or now >= sess.idle_expiry:
                self.store.delete_session(session_id, cause="expired")
                self.audit.record(
                    AuditEvent.SESSION_EXPIRED, user=sess.username,
                    result="denied",
                    reason=ErrorCode.SESSION_EXPIRED.value)
                raise AppError(ErrorCode.SESSION_EXPIRED, "session expired")

            user = self.store.get_user(sess.username)
            if user is None or user.session_epoch != sess.epoch:
                self.store.delete_session(session_id, cause="invalidated")
                self.audit.record(
                    AuditEvent.SESSION_REPLAYED, user=sess.username,
                    result="denied",
                    reason=ErrorCode.SESSION_INVALIDATED.value)
                raise AppError(ErrorCode.SESSION_INVALIDATED,
                               "session invalidated by account change")

            sess.last_seen = now
            sess.idle_expiry = now + self.config.session.idle_timeout_seconds
            self.store.put_session(sess)

            return Principal(
                session_id=session_id, username=sess.username,
                roles=tuple(user.roles),
                mfa_verified=sess.mfa_verified,
                csrf_token=sess.csrf_token)

    def rotate_session(self, old_session_id: str) -> tuple[str, str]:
        """显式轮换标识：旧的入墓碑，新的继承状态（防会话固定）。"""
        now = self._now()
        with self.store.transaction():
            old = self.store.get_session(old_session_id)
            if old is None:
                if self.store.is_tombstoned(old_session_id, now):
                    raise AppError(ErrorCode.SESSION_REPLAYED,
                                   "cannot rotate revoked session")
                raise AppError(ErrorCode.UNAUTHENTICATED, "no active session")
            user = self.store.get_user(old.username)
            if user is None or user.session_epoch != old.epoch:
                self.store.delete_session(old_session_id, cause="invalidated")
                raise AppError(ErrorCode.SESSION_INVALIDATED,
                               "session invalidated by account change")
            new_id = new_session_id()
            csrf = issue_csrf_token()
            # 旧 CSRF 与旧标识一并退役；新令牌必须服务端落库，
            # 否则旋转后的会话无法通过任何状态变更的 CSRF 校验。
            origin = "unknown"
            if old.csrf_token:
                prev_csrf = self.store.get_csrf(old.csrf_token)
                if prev_csrf is not None:
                    origin = prev_csrf.origin
                    self.store.delete_csrf(old.csrf_token)
            new = SessionRecord(
                session_id=new_id, username=old.username,
                created_at=old.created_at, last_seen=now,
                absolute_expiry=old.absolute_expiry,
                idle_expiry=now + self.config.session.idle_timeout_seconds,
                mfa_verified=old.mfa_verified, epoch=old.epoch,
                csrf_token=csrf)
            self.store.rotate_session(old_session_id, new, now)
            self.store.put_csrf(CsrfTokenRecord(
                token=csrf, session_id=new_id, username=old.username,
                origin=origin,
                expires_at=now + self.config.session.csrf_ttl_seconds))
        return new_id, csrf

    # ------------------------------------------------------------------ #
    # 辅助
    # ------------------------------------------------------------------ #
    def sweep_expired_user_sessions(self, username: str,
                                    now: float) -> list[SessionRecord]:
        """在调用方已持事务的前提下，原子清扫该用户已过期的活动会话。

        过期会话入墓碑（cause=expired），不再计入容量；返回被清扫记录副本。
        """
        swept: list[SessionRecord] = []
        for s in self.store.list_user_sessions(username):
            if now >= s.absolute_expiry or now >= s.idle_expiry:
                self.store.delete_session(s.session_id, cause="expired")
                swept.append(s)
        return swept

    def _enforce_capacity_locked(self, username: str, now: float, *,
                                 keep_session_id: str
                                 ) -> list[SessionRecord]:
        """每账号活动会话数上限（调用方已持事务）。

        1) 先清扫过期会话（它们不应占据名额）；
        2) 剩余活动会话超过上限时，按 (创建时间, 标识) 淘汰最旧的若干条；
        3) keep_session_id（本次新登录会话）永不被淘汰——新登录始终保留。
        整个过程与新会话创建处于同一把锁/同一事务，淘汰与插入原子，
        任何时刻该账号活动会话数都不会超过上限。
        """
        self.sweep_expired_user_sessions(username, now)
        limit = self.config.session.max_sessions_per_account
        active = self.store.list_user_sessions(username)
        keep = [s for s in active if s.session_id == keep_session_id]
        others = sorted(
            (s for s in active if s.session_id != keep_session_id),
            key=lambda s: (s.created_at, s.session_id))
        excess = len(active) - limit
        if excess <= 0:
            return []
        victims = others[:excess]
        for v in victims:
            # 与逐条收回同构：入墓碑，重放判定为 SESSION_REPLAYED
            self.store.delete_session(v.session_id, cause="capacity_evicted")
        # 防御性自检：新会话必须在场
        if not keep:  # pragma: no cover - 逻辑不变量
            raise StoreError("capacity enforcement lost the new session")
        return victims

    def _create_session_locked(self, user: UserRecord, now: float,
                               origin: str) -> tuple[str, str]:
        sid = new_session_id()
        csrf = issue_csrf_token()
        sess = SessionRecord(
            session_id=sid, username=user.username, created_at=now,
            last_seen=now,
            absolute_expiry=now + self.config.session.absolute_timeout_seconds,
            idle_expiry=now + self.config.session.idle_timeout_seconds,
            mfa_verified=not (user.totp_enrolled and user.totp_secret),
            epoch=user.session_epoch, csrf_token=csrf)
        self.store.put_session(sess)
        self.store.put_csrf(CsrfTokenRecord(
            token=csrf, session_id=sid, username=user.username,
            origin=origin or "unknown",
            expires_at=now + self.config.session.csrf_ttl_seconds))
        return sid, csrf

    def _now(self) -> float:
        try:
            return self.time.now()
        except TimeSourceError:
            self.audit.record(AuditEvent.INFRA_ERROR, result="error",
                              reason=ErrorCode.TIME_SOURCE_UNAVAILABLE.value)
            raise
