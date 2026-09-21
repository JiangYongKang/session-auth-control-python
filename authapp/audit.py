"""审计日志：覆盖登录/登出/权限拒绝/锁定/MFA 变更。

安全约束：
- 绝不记录口令、一次性验证码、会话标识、CSRF 令牌等敏感明文；
- 用户、会话以带密钥的 HMAC-SHA256 截断指纹呈现，可关联而不可还原；
- 调用方即便误传敏感字段，也会经白名单+脱敏兜底过滤。
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
from typing import Any

# 允许进入审计记录的字段白名单（其它字段一律丢弃）。
_ALLOWED_FIELDS = {
    "event",
    "result",
    "reason",
    "username_fp",
    "user_fp",
    "session_fp",
    "roles",
    "action",
    "resource",
    "lock_seconds",
    "fail_count",
    "threshold",
    "step_offset",
    "method",
    "path",
    "remote_addr",
}

_SENSITIVE_KEY_HINTS = ("password", "code", "secret", "session", "csrf", "token")


class AuditLogger:
    def __init__(
        self,
        logger: logging.Logger | None = None,
        *,
        fingerprint_key: bytes = b"local-audit-fingerprint-key",
    ) -> None:
        self._logger = logger or logging.getLogger("authapp.audit")
        self._key = fingerprint_key

    def fingerprint(self, value: str) -> str:
        """对标识做带密钥的不可逆指纹（前 16 位 hex）。"""
        digest = hmac.new(
            self._key, value.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        return digest[:16]

    def _sanitize(self, fields: dict[str, Any]) -> dict[str, Any]:
        clean: dict[str, Any] = {}
        for key, value in fields.items():
            if key not in _ALLOWED_FIELDS:
                continue
            if any(hint in key for hint in _SENSITIVE_KEY_HINTS) and not key.endswith(
                "_fp"
            ):
                # 双保险：疑似敏感且不是指纹字段，直接丢弃。
                continue
            clean[key] = value
        return clean

    def record(self, event: str, **fields: Any) -> None:
        payload = {"event": event}
        payload.update(self._sanitize(fields))
        # 单行 JSON，便于采集；不含任何敏感明文。
        line = json.dumps(payload, ensure_ascii=False, sort_keys=True)
        self._logger.info(line)
