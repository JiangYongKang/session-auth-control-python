"""对外可区分、但不泄漏敏感信息的归一化错误。

错误码（error.code）供调用方区分判定依据；detail 不得包含口令、
一次性验证码、会话标识等敏感明文。
"""
from __future__ import annotations

from enum import Enum


class ErrorCode(str, Enum):
    INVALID_CREDENTIALS = "invalid_credentials"
    ACCOUNT_LOCKED = "account_locked"
    MFA_REQUIRED = "mfa_required"
    MFA_NOT_BOUND = "mfa_not_bound"
    MFA_ALREADY_BOUND = "mfa_already_bound"
    MFA_INVALID_CODE = "mfa_invalid_code"
    MFA_REPLAYED_CODE = "mfa_replayed_code"
    MFA_TIME_SKEW = "mfa_time_skew"
    UNAUTHENTICATED = "unauthenticated"
    SESSION_EXPIRED = "session_expired"
    SESSION_REVOKED = "session_revoked"
    FORBIDDEN = "forbidden"
    CSRF_INVALID = "csrf_invalid"
    CSRF_MISSING = "csrf_missing"
    CSRF_EXPIRED = "csrf_expired"
    CSRF_SESSION_MISMATCH = "csrf_session_mismatch"
    CSRF_ORIGIN_MISMATCH = "csrf_origin_mismatch"
    USER_EXISTS = "user_exists"
    NOT_FOUND = "not_found"
    INVALID_REQUEST = "invalid_request"
    CONFIG_ERROR = "config_error"
    TIME_SOURCE_ERROR = "time_source_error"
    STORAGE_ERROR = "storage_error"
    RATE_LIMITED = "rate_limited"


# 仅用于受控日志区分“用户名不存在”与“口令错误”，禁止直接对外返回。
class InternalReason(str, Enum):
    USER_NOT_FOUND = "user_not_found"
    BAD_PASSWORD = "bad_password"


class AuthError(Exception):
    """所有认证/授权相关异常的基类：归一化后对外返回。"""

    def __init__(self, code: ErrorCode, message: str, *, internal: str | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.internal = internal
