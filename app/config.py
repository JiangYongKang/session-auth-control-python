"""可配置项：阈值、窗口、口令策略、TOTP 窗口等。

配置在构建期完成校验；非法配置 fail-closed（抛 ConfigError -> CONFIG_ERROR）。
"""
from __future__ import annotations

from dataclasses import dataclass, field

from app.errors import ConfigError


@dataclass(frozen=True)
class PasswordPolicy:
    min_length: int = 8
    require_digit: bool = True
    require_alpha: bool = True


@dataclass(frozen=True)
class ThrottleConfig:
    """登录失败节流：观察窗口内失败达到阈值则临时锁定。"""
    max_failures: int = 5
    window_seconds: int = 300
    lock_seconds: int = 900


@dataclass(frozen=True)
class TotpConfig:
    """RFC6238 TOTP。drift_steps 为允许的前后时间步偏移。"""
    period: int = 30
    digits: int = 6
    drift_steps: int = 1
    issuer: str = "session-auth-control"


@dataclass(frozen=True)
class SessionConfig:
    idle_timeout_seconds: int = 1800       # 无操作过期
    absolute_timeout_seconds: int = 28800  # 绝对过期
    csrf_ttl_seconds: int = 1800
    # 每账号活动会话数上限：达到上限再登录时原子淘汰最旧会话
    max_sessions_per_account: int = 10


@dataclass(frozen=True)
class SecurityConfig:
    password: PasswordPolicy = field(default_factory=PasswordPolicy)
    throttle: ThrottleConfig = field(default_factory=ThrottleConfig)
    totp: TotpConfig = field(default_factory=TotpConfig)
    session: SessionConfig = field(default_factory=SessionConfig)
    # 角色 -> {资源前缀: 动作集合}；默认拒绝
    role_permissions: dict[str, dict[str, frozenset[str]]] = field(
        default_factory=dict
    )
    # 自助注册允许请求的角色；特权角色（admin 等）必须由管理员授予
    self_service_roles: frozenset[str] = frozenset({"viewer", "editor"})

    def permissions_for(self, roles: tuple[str, ...]) -> list[dict[str, frozenset[str]]]:
        return [self.role_permissions[r] for r in roles if r in self.role_permissions]


_VALID_ACTIONS = frozenset({"read", "write", "admin"})


def _check_positive(name: str, value: int) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ConfigError(f"{name} must be a positive integer, got {value!r}")


def load_config(overrides: dict | None = None) -> SecurityConfig:
    """加载并校验配置。

    overrides 支持的键（均为可选）：
      password/min_length, password/require_digit, password/require_alpha,
      throttle/max_failures, throttle/window_seconds, throttle/lock_seconds,
      totp/period, totp/digits, totp/drift_steps, totp/issuer,
      session/idle_timeout_seconds, session/absolute_timeout_seconds,
      session/csrf_ttl_seconds, session/max_sessions_per_account,
      role_permissions
    """
    overrides = dict(overrides or {})
    try:
        pwd_in = dict(overrides.get("password") or {})
        thr_in = dict(overrides.get("throttle") or {})
        totp_in = dict(overrides.get("totp") or {})
        sess_in = dict(overrides.get("session") or {})

        pwd = PasswordPolicy(**{k: v for k, v in pwd_in.items()
                                if k in PasswordPolicy.__dataclass_fields__})
        if not isinstance(pwd.min_length, int) or isinstance(pwd.min_length, bool) \
                or pwd.min_length < 1:
            raise ConfigError("password.min_length must be >= 1")
        if not isinstance(pwd.require_digit, bool) or \
                not isinstance(pwd.require_alpha, bool):
            raise ConfigError("password flags must be bool")

        thr = ThrottleConfig(**{k: v for k, v in thr_in.items()
                                if k in ThrottleConfig.__dataclass_fields__})
        _check_positive("throttle.max_failures", thr.max_failures)
        _check_positive("throttle.window_seconds", thr.window_seconds)
        _check_positive("throttle.lock_seconds", thr.lock_seconds)

        totp = TotpConfig(**{k: v for k, v in totp_in.items()
                             if k in TotpConfig.__dataclass_fields__})
        _check_positive("totp.period", totp.period)
        if not 6 <= totp.digits <= 8:
            raise ConfigError("totp.digits must be between 6 and 8")
        if not 0 <= totp.drift_steps <= 5:
            raise ConfigError("totp.drift_steps must be between 0 and 5")
        if not totp.issuer or not isinstance(totp.issuer, str):
            raise ConfigError("totp.issuer must be non-empty string")

        sess = SessionConfig(**{k: v for k, v in sess_in.items()
                                if k in SessionConfig.__dataclass_fields__})
        _check_positive("session.idle_timeout_seconds",
                        sess.idle_timeout_seconds)
        _check_positive("session.absolute_timeout_seconds",
                        sess.absolute_timeout_seconds)
        _check_positive("session.csrf_ttl_seconds", sess.csrf_ttl_seconds)
        _check_positive("session.max_sessions_per_account",
                        sess.max_sessions_per_account)
        if sess.idle_timeout_seconds > sess.absolute_timeout_seconds:
            raise ConfigError("idle timeout cannot exceed absolute timeout")

        role_permissions = _validate_role_permissions(
            overrides.get("role_permissions"))
        if overrides.get("self_service_roles") is None:
            self_service_default = ("viewer", "editor")
        else:
            self_service_default = tuple(overrides["self_service_roles"])
        self_service_roles = _validate_self_service_roles(
            list(self_service_default), role_permissions,
            allow_unknown_when_matrix_empty=not role_permissions)

        cfg = SecurityConfig(password=pwd, throttle=thr, totp=totp,
                             session=sess, role_permissions=role_permissions,
                             self_service_roles=self_service_roles)
    except ConfigError:
        raise
    except TypeError as e:
        raise ConfigError(f"invalid config fields: {e}") from None
    return cfg


def _validate_self_service_roles(raw: object,
                                 role_permissions: dict,
                                 *, allow_unknown_when_matrix_empty: bool
                                 = False) -> frozenset[str]:
    if isinstance(raw, str) or not isinstance(
            raw, (list, tuple, set, frozenset)):
        raise ConfigError("self_service_roles must be a list of role names")
    roles = frozenset(raw)
    if not all(isinstance(r, str) and r for r in roles):
        raise ConfigError("self_service_roles entries must be non-empty strings")
    if allow_unknown_when_matrix_empty and not role_permissions:
        return roles
    unknown = roles - frozenset(role_permissions)
    if unknown:
        raise ConfigError(
            f"self_service_roles contains unknown roles: {sorted(unknown)}")
    return roles


def _validate_role_permissions(raw: object) -> dict[str, dict[str, frozenset[str]]]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ConfigError("role_permissions must be a mapping")
    out: dict[str, dict[str, frozenset[str]]] = {}
    for role, scopes in raw.items():
        if not isinstance(role, str) or not role or not isinstance(scopes, dict):
            raise ConfigError(f"bad role entry: {role!r}")
        scope_map: dict[str, frozenset[str]] = {}
        for prefix, actions in scopes.items():
            # 空前缀 "" 表示"匹配全部资源"（如 admin）
            if not isinstance(prefix, str):
                raise ConfigError(f"bad resource prefix for role {role!r}")
            if isinstance(actions, str) or not all(
                    isinstance(a, str) for a in actions):
                raise ConfigError(f"actions must be a list of strings "
                                  f"for {role!r}:{prefix!r}")
            action_set = frozenset(actions)
            bad = action_set - _VALID_ACTIONS
            if bad:
                raise ConfigError(f"unknown actions {sorted(bad)}; "
                                  f"allowed {sorted(_VALID_ACTIONS)}")
            if not action_set:
                raise ConfigError("empty action set")
            scope_map[prefix] = action_set
        out[role] = scope_map
    return out


DEFAULT_ROLE_PERMISSIONS: dict[str, dict[str, frozenset[str]]] = {
    "admin": {"": frozenset({"read", "write", "admin"})},
    "viewer": {"docs/": frozenset({"read"})},
    "editor": {"docs/": frozenset({"read", "write"})},
}


def default_config(overrides: dict | None = None) -> SecurityConfig:
    """默认配置：含 admin/viewer/editor 三组角色权限。"""
    merged = {"role_permissions": DEFAULT_ROLE_PERMISSIONS}
    if overrides:
        merged.update(overrides)
    return load_config(merged)
