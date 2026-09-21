"""认证门面：注册、登录、MFA、会话、权限、节流的一致编排。

关键设计：
- 所有用例在单个存储临界区内完成“读-判定-写”，杜绝半更新/并发绕过；
- 用户名不存在与口令错误对外同为 invalid_credentials，差异只进受控审计；
- 登录成功创建会话；启用 MFA 时会话处于“待二因素”状态，通过后轮换标识；
- 任何存储/时钟异常向上归一化，绝不降级放行（fail_open 被配置层禁止）。
"""
from __future__ import annotations

from authapp.access import AccessController
from authapp.audit import AuditLogger
from authapp.clock import Clock, SystemClock
from authapp.config import AuthConfig
from authapp.csrf import CsrfManager
from authapp.errors import AuthError, ErrorCode, InternalReason
from authapp.mfa import MfaService
from authapp.security.passwords import hash_password, verify_password
from authapp.security.tokens import random_token
from authapp.sessions import SessionManager
from authapp.store.base import Store
from authapp.throttle import ThrottleController

SESSION_COOKIE = "sid"
CSRF_HEADER = "x-csrf-token"


class AuthService:
    def __init__(
        self,
        store: Store,
        config: AuthConfig | None = None,
        clock: Clock | None = None,
        audit: AuditLogger | None = None,
    ) -> None:
        self.config = config or AuthConfig()
        self.config.validate()
        self.store = store
        self.clock = clock or SystemClock()
        self.audit = audit or AuditLogger()
        self.sessions = SessionManager(store, self.config, self.clock)
        self.throttle = ThrottleController(store, self.config, self.clock)
        self.mfa = MfaService(store, self.config, self.clock)
        self.access = AccessController(store, self.config, self.clock)
        self.csrf = CsrfManager(self.config, self.clock)
        # 待确认绑定：session_id -> secret（不落库到用户，确认前不生效）
        self._pending_binds: dict[str, str] = {}

    # ------------------------------------------------------------------ #
    # 账号
    # ------------------------------------------------------------------ #
    def register(
        self,
        username: str,
        password: str,
        roles: list[str] | None = None,
    ) -> dict:
        self._validate_credentials_input(username, password)
        with self.store.lock():
            if self.store.get_user(username) is not None:
                self.audit.record(
                    "register", result="denied", reason="user_exists",
                    username_fp=self.audit.fingerprint(username),
                )
                raise AuthError(ErrorCode.USER_EXISTS, "用户名已被占用")
            user_id = random_token(16)
            # 注册接口不接受客户端提权：roles 仅允许服务端受控调用方传入，
            # HTTP 注册入口强制忽略请求中的 roles（见 api.py）。
            user = self._new_user(user_id, username, hash_password(password), roles)
            self.store.put_user(user)
            self.audit.record(
                "register", result="success",
                username_fp=self.audit.fingerprint(username),
                user_fp=self.audit.fingerprint(user_id), roles=list(user.roles),
            )
            return {"user_id": user_id, "username": username, "roles": list(user.roles)}

    def _new_user(self, user_id, username, password_hash, roles):
        from authapp.models import User

        return User(
            user_id=user_id,
            username=username,
            password_hash=password_hash,
            roles=list(roles or []),
        )

    def change_password(self, session_id: str, old_password: str, new_password: str) -> None:
        self._validate_credentials_input("__session__", new_password)
        with self.store.lock():
            record = self.sessions.resolve(session_id)
            user = self._require_user(record.user_id)
            if not verify_password(old_password, user.password_hash):
                self.audit.record(
                    "password_change", result="denied", reason="bad_password",
                    user_fp=self.audit.fingerprint(user.user_id),
                    session_fp=self.audit.fingerprint(session_id),
                )
                raise AuthError(ErrorCode.INVALID_CREDENTIALS, "原口令不正确")
            user.password_hash = hash_password(new_password)
            user.auth_epoch += 1
            self.store.put_user(user)
            # 立即且一致地失效该账号全部既有会话（含当前会话）。
            self.store.revoke_user_sessions(user.user_id, user.auth_epoch)
            self.csrf.drop_for_session(session_id)
            # 清理该用户全部待绑定 MFA 密钥。
            stale_binds = [
                sid
                for sid in list(self._pending_binds)
                if (rec0 := self.store.get_session(sid)) is not None
                and rec0.user_id == user.user_id
            ]
            for sid in stale_binds:
                self._pending_binds.pop(sid, None)
            self.audit.record(
                "password_change", result="success",
                user_fp=self.audit.fingerprint(user.user_id),
                session_fp=self.audit.fingerprint(session_id),
            )

    # ------------------------------------------------------------------ #
    # 登录 / MFA / 登出
    # ------------------------------------------------------------------ #
    def login(self, username: str, password: str) -> dict:
        """返回 {status, session?, mfa_required?}。失败统一为 invalid_credentials/locked。"""
        self._validate_login_input(username, password)
        fp = self.audit.fingerprint(username)
        with self.store.lock():
            # 锁判定先行：锁定期即便口令正确也拒绝且可区分。
            self.throttle.ensure_not_locked(username)
            user = self.store.get_user(username)
            dummy_ok = True
            if user is None:
                # 对不存在用户也做一次等成本哈希校验，消除用户枚举时序差。
                verify_password(password, _DUMMY_HASH)
                self.throttle.record_failure(username)
                self.audit.record(
                    "login", result="denied",
                    reason=InternalReason.USER_NOT_FOUND.value, username_fp=fp,
                )
                raise AuthError(
                    ErrorCode.INVALID_CREDENTIALS, "用户名或口令不正确"
                )
            if not verify_password(password, user.password_hash):
                newly_locked = self.throttle.record_failure(username)
                self.audit.record(
                    "login",
                    result="locked" if newly_locked else "denied",
                    reason=InternalReason.BAD_PASSWORD.value,
                    username_fp=fp, user_fp=self.audit.fingerprint(user.user_id),
                    fail_count=self.store.get_failure(username).count,
                )
                if newly_locked:
                    self.audit.record(
                        "account_locked", result="locked", username_fp=fp,
                        user_fp=self.audit.fingerprint(user.user_id),
                        lock_seconds=self.config.lock_seconds,
                        threshold=self.config.fail_threshold,
                    )
                    raise AuthError(ErrorCode.ACCOUNT_LOCKED, "失败次数过多，账号已临时锁定")
                raise AuthError(
                    ErrorCode.INVALID_CREDENTIALS, "用户名或口令不正确"
                )
            # 成功：清空计数。
            self.throttle.record_success(username)
            if user.mfa_enabled:
                # 只让此前遗留的“待二因素”会话失效（避免多个挂起的固定窗口）；
                # 其已认证会话保留，待本次 MFA 转正时随纪元递增统一吊销。
                stale_sessions = [
                    rec for rec in self.store.list_user_sessions(user.user_id)
                    if not rec.mfa_completed
                ]
            else:
                # 未启用 MFA：登录即轮换，该账号所有既有标识失效，登录后只持有新标识。
                stale_sessions = list(self.store.list_user_sessions(user.user_id))
            for existing in stale_sessions:
                self.csrf.drop_for_session(existing.session_id)
                self._pending_binds.pop(existing.session_id, None)
                self.sessions.logout(existing.session_id)
            # 清理该用户此前残留在其它会话上的待绑定密钥（未确认即失效）。
            stale = [
                sid for sid in self._pending_binds
                if (rec := self.store.get_session(sid)) is not None
                and rec.user_id == user.user_id
            ]
            for sid in stale:
                self._pending_binds.pop(sid, None)
            if user.mfa_enabled:
                # 待二因素会话：不可访问受保护资源，直到 MFA 通过并轮换。
                sid = self.sessions.create(
                    user.user_id, user.auth_epoch, mfa_completed=False
                )
                self.audit.record(
                    "login", result="mfa_required", username_fp=fp,
                    user_fp=self.audit.fingerprint(user.user_id),
                    session_fp=self.audit.fingerprint(sid),
                )
                return {"status": "mfa_required", "session": sid}
            sid = self.sessions.create(
                user.user_id, user.auth_epoch, mfa_completed=True
            )
            self.audit.record(
                "login", result="success", username_fp=fp,
                user_fp=self.audit.fingerprint(user.user_id),
                session_fp=self.audit.fingerprint(sid),
            )
            return {"status": "success", "session": sid}

    def mfa_login(self, session_id: str, code: str) -> str:
        """对“待二因素”会话校验一次性口令，通过后转正。

        通过的同一临界区内：纪元 +1、吊销该账号全部其它既有会话，
        再把当前待二因素会话标识轮换为已认证新标识。由此：
        - 会话固定攻击者持有的旧标识、以及绑定前建立的会话全部失效；
        - 吊销与轮换原子完成，不会出现只失效一部分的中间态。
        """
        with self.store.lock():
            record = self.sessions.resolve(session_id)
            user = self._require_user(record.user_id)
            self._check_epoch(record, user)
            self.mfa.verify(record, user, code)
            user.auth_epoch += 1
            self.store.put_user(user)
            # 吊销该账号除当前待二因素会话外的全部会话。
            for existing in self.store.list_user_sessions(user.user_id):
                if existing.session_id != record.session_id and not existing.revoked:
                    existing.revoked = True
                    self.store.put_session(existing)
            new_id = self.sessions.rotate(record, mfa_completed=True)
            # 轮换后新记录需携带新纪元。
            new_record = self.store.get_session(new_id)
            if new_record is not None:
                new_record.auth_epoch = user.auth_epoch
                self.store.put_session(new_record)
            self.csrf.drop_for_session(session_id)
            self.audit.record(
                "mfa_login", result="success",
                user_fp=self.audit.fingerprint(user.user_id),
                session_fp=self.audit.fingerprint(new_id),
            )
            return new_id

    def logout(self, session_id: str | None) -> None:
        with self.store.lock():
            if session_id:
                record = self.store.get_session(session_id)
                self.csrf.drop_for_session(session_id)
                self.sessions.logout(session_id)
                self._pending_binds.pop(session_id, None)
                self.audit.record(
                    "logout",
                    result="success" if record is not None else "idempotent",
                    session_fp=self.audit.fingerprint(session_id),
                    user_fp=(
                        self.audit.fingerprint(record.user_id) if record else None
                    ),
                )

    # ------------------------------------------------------------------ #
    # 会话与权限
    # ------------------------------------------------------------------ #
    def authenticate(self, session_id: str | None):
        """解析为已完成认证（含 MFA）的 (record, user)。"""
        with self.store.lock():
            record = self.sessions.resolve(session_id)
            user = self._require_user(record.user_id)
            self._check_epoch(record, user)
            if not record.mfa_completed:
                raise AuthError(ErrorCode.MFA_REQUIRED, "请先完成多因素校验")
            return record, user.snapshot()

    def authorize(self, session_id: str | None, action: str, resource: str):
        with self.store.lock():
            record, user = self.authenticate(session_id)
            try:
                self.access.check(user, action, resource)
            except AuthError as exc:
                self.audit.record(
                    "access_denied", result="denied", reason=exc.internal or "deny",
                    user_fp=self.audit.fingerprint(user.user_id),
                    session_fp=self.audit.fingerprint(session_id or ""),
                    action=action, resource=resource, roles=list(user.roles),
                )
                raise
            return record, user

    # ------------------------------------------------------------------ #
    # MFA 自助管理（均需已认证会话）
    # ------------------------------------------------------------------ #
    def begin_bind_mfa(self, session_id: str) -> tuple[str, str]:
        with self.store.lock():
            _, user = self.authenticate(session_id)
            secret, uri = self.mfa.begin_bind(user)
            self._pending_binds[session_id] = secret
            self.audit.record(
                "mfa_change", result="bind_begin",
                user_fp=self.audit.fingerprint(user.user_id),
                session_fp=self.audit.fingerprint(session_id),
            )
            return secret, uri

    def confirm_bind_mfa(self, session_id: str, code: str) -> None:
        with self.store.lock():
            record, user = self.authenticate(session_id)
            secret = self._pending_binds.get(session_id)
            if secret is None:
                raise AuthError(ErrorCode.INVALID_REQUEST, "尚未发起多因素绑定")
            self.mfa.confirm_bind(user, secret, code)
            self._pending_binds.pop(session_id, None)
            # 绑定成功后全部既有会话失效；当前会话也需重新登录。
            self.audit.record(
                "mfa_change", result="bind_confirmed",
                user_fp=self.audit.fingerprint(user.user_id),
                session_fp=self.audit.fingerprint(session_id),
            )

    def unbind_mfa(self, session_id: str, code: str) -> None:
        with self.store.lock():
            _, user = self.authenticate(session_id)
            self.mfa.unbind(user, code)
            self.audit.record(
                "mfa_change", result="unbound",
                user_fp=self.audit.fingerprint(user.user_id),
                session_fp=self.audit.fingerprint(session_id),
            )

    # ------------------------------------------------------------------ #
    # CSRF
    # ------------------------------------------------------------------ #
    def issue_csrf(self, session_id: str) -> str:
        with self.store.lock():
            self.sessions.resolve(session_id)
            return self.csrf.issue(session_id)

    def verify_csrf(self, session_id: str, token: str | None, origin: str | None) -> None:
        # 无存储临界需求，但统一入口便于审计与未来扩展。
        self.csrf.verify(token, session_id, origin)

    # ------------------------------------------------------------------ #
    # 内部辅助
    # ------------------------------------------------------------------ #
    def _require_user(self, user_id: str):
        user = self.store.get_user_by_id(user_id)
        if user is None:
            # 用户被删除但其会话还在：默认拒绝。
            raise AuthError(ErrorCode.UNAUTHENTICATED, "账号不存在")
        return user

    def _check_epoch(self, record, user) -> None:
        if record.auth_epoch != user.auth_epoch:
            # 改密/注销/MFA 重置后旧纪元会话立即失效。
            self.sessions.logout(record.session_id)
            raise AuthError(ErrorCode.SESSION_REVOKED, "会话已因账号变更而失效")

    def _validate_credentials_input(self, username: str, password: str) -> None:
        if not isinstance(username, str) or not username.strip():
            raise AuthError(ErrorCode.INVALID_REQUEST, "用户名不能为空")
        if not isinstance(password, str) or len(password) < self.config.min_password_length:
            raise AuthError(
                ErrorCode.INVALID_REQUEST,
                f"口令长度至少 {self.config.min_password_length} 位",
            )

    def _validate_login_input(self, username: str, password: str) -> None:
        # 登录只校验非空类型；长度/复杂度不在这里报错，以免借校验差异枚举用户。
        if not isinstance(username, str) or not username.strip():
            raise AuthError(ErrorCode.INVALID_REQUEST, "用户名不能为空")
        if not isinstance(password, str) or password == "":
            raise AuthError(ErrorCode.INVALID_REQUEST, "口令不能为空")


# 与 hash_password 同参数成本的占位哈希，用于不存在用户时等成本校验。
_DUMMY_HASH = hash_password("not-a-real-password-for-timing-equalization")
