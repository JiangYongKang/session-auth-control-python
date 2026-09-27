"""受控审计日志。

覆盖：登录、登出、权限拒绝、锁定、多因素变更。
记录中禁止出现口令、一次性验证码、会话标识等敏感明文。
同时写入标准 logging（受控日志）与内存缓冲（便于测试断言可复现判定）。
"""
from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any


class AuditEvent(str, Enum):
    REGISTER = "REGISTER"
    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_FAILURE = "LOGIN_FAILURE"
    LOGIN_LOCKED = "LOGIN_LOCKED"
    LOGOUT = "LOGOUT"
    SESSION_EXPIRED = "SESSION_EXPIRED"
    SESSION_REPLAYED = "SESSION_REPLAYED"
    SESSION_REVOKED = "SESSION_REVOKED"      # 定向收回或容量淘汰（cause 区分）
    MFA_ENROLL = "MFA_ENROLL"
    MFA_VERIFY = "MFA_VERIFY"
    MFA_UNBIND = "MFA_UNBIND"
    MFA_RESET = "MFA_RESET"
    PASSWORD_CHANGED = "PASSWORD_CHANGED"
    ROLES_CHANGED = "ROLES_CHANGED"
    ACCESS_DENIED = "ACCESS_DENIED"
    ACCESS_ALLOWED = "ACCESS_ALLOWED"
    CSRF_REJECTED = "CSRF_REJECTED"
    INFRA_ERROR = "INFRA_ERROR"


# 敏感字段：无论键名是否完全匹配，子串命中也脱敏（如 old_password_confirm）
SENSITIVE_FRAGMENTS = (
    "password", "passwd", "secret", "totp", "otp", "code",
    "session_id", "sid", "csrf", "token",
)

REDACTED = "<redacted>"


def _is_sensitive(key: str) -> bool:
    k = key.lower()
    return any(frag in k for frag in SENSITIVE_FRAGMENTS)


def redact(fields: dict[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in fields.items():
        if v is None:
            continue
        out[k] = REDACTED if _is_sensitive(k) else str(v)
    return out


@dataclass(frozen=True)
class AuditRecord:
    event: str
    user: str | None
    result: str
    reason: str | None
    fields: dict[str, str]

    def to_line(self) -> str:
        payload = asdict(self)
        return "AUDIT " + json.dumps(payload, sort_keys=True,
                                     ensure_ascii=False)


class AuditLogger:
    """审计记录器：敏感字段一律脱敏；内存缓冲 + logging 双通道。"""

    def __init__(self, logger: logging.Logger | None = None,
                 *, echo: bool = True) -> None:
        self._buf: list[AuditRecord] = []
        self._logger = logger or logging.getLogger("app.audit")
        self._echo = echo

    def record(self, event: AuditEvent, *, user: str | None = None,
               result: str = "ok", reason: str | None = None,
               **fields: Any) -> AuditRecord:
        rec = AuditRecord(
            event=event.value if isinstance(event, AuditEvent) else str(event),
            user=user,
            result=result,
            reason=reason,
            fields=redact(fields),
        )
        self._buf.append(rec)
        if self._echo:
            self._logger.warning(rec.to_line())
        return rec

    def records(self) -> list[AuditRecord]:
        return list(self._buf)

    def events(self) -> list[str]:
        return [r.event for r in self._buf]
