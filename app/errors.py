"""统一的错误类型与对外可区分判定码。

所有内部异常在 API 边界被归一化为 AppError，绝不允许"异常即放行"。
"""
from __future__ import annotations

from enum import Enum


class ErrorCode(str, Enum):
    # 认证（用户名不存在 / 口令错误对外不可区分）
    INVALID_CREDENTIALS = "INVALID_CREDENTIALS"
    LOCKED = "ACCOUNT_LOCKED"
    MFA_REQUIRED = "MFA_REQUIRED"
    MFA_NOT_ENROLLED = "MFA_NOT_ENROLLED"
    MFA_ALREADY_ENROLLED = "MFA_ALREADY_ENROLLED"
    MFA_CODE_INVALID = "MFA_CODE_INVALID"        # 窗口内各步均不匹配（验证码错误）
    MFA_CODE_REUSED = "MFA_CODE_REUSED"          # 同一验证码重复使用
    MFA_TIME_DRIFT = "MFA_TIME_DRIFT"            # 时间偏移超出允许窗口
    MFA_NOT_VERIFIED = "MFA_NOT_VERIFIED"

    # 会话 / 状态
    UNAUTHENTICATED = "UNAUTHENTICATED"
    SESSION_EXPIRED = "SESSION_EXPIRED"
    SESSION_REPLAYED = "SESSION_REPLAYED"
    SESSION_INVALIDATED = "SESSION_INVALIDATED"
    SESSION_CONFIRMATION_PENDING = "SESSION_CONFIRMATION_PENDING"
    SESSION_ALREADY_REVOKED = "SESSION_ALREADY_REVOKED"  # 引用命中已撤销会话

    # 授权（默认拒绝；不泄漏资源是否存在）
    FORBIDDEN = "FORBIDDEN"
    NOT_FOUND = "NOT_FOUND"

    # CSRF
    CSRF_MISSING = "CSRF_MISSING"
    CSRF_INVALID = "CSRF_INVALID"
    CSRF_REVOKED = "CSRF_REVOKED"            # 令牌曾签发，但所属标识已轮换/撤销
    CSRF_EXPIRED = "CSRF_EXPIRED"
    CSRF_BOUND_SESSION = "CSRF_BOUND_SESSION"
    CSRF_BOUND_ORIGIN = "CSRF_BOUND_ORIGIN"

    # 请求语义
    CONFLICT = "CONFLICT"
    VALIDATION_ERROR = "VALIDATION_ERROR"

    # 基础设施异常归一化（不降级放行）
    STORE_UNAVAILABLE = "STORE_UNAVAILABLE"
    TIME_SOURCE_UNAVAILABLE = "TIME_SOURCE_UNAVAILABLE"
    CONFIG_ERROR = "CONFIG_ERROR"
    INTERNAL_ERROR = "INTERNAL_ERROR"


# 各错误码默认 HTTP 状态
_STATUS: dict[ErrorCode, int] = {
    ErrorCode.INVALID_CREDENTIALS: 401,
    ErrorCode.LOCKED: 423,
    ErrorCode.MFA_REQUIRED: 401,
    ErrorCode.MFA_NOT_ENROLLED: 409,
    ErrorCode.MFA_ALREADY_ENROLLED: 409,
    ErrorCode.MFA_CODE_INVALID: 401,
    ErrorCode.MFA_CODE_REUSED: 401,
    ErrorCode.MFA_TIME_DRIFT: 401,
    ErrorCode.MFA_NOT_VERIFIED: 401,
    ErrorCode.UNAUTHENTICATED: 401,
    ErrorCode.SESSION_EXPIRED: 401,
    ErrorCode.SESSION_REPLAYED: 401,
    ErrorCode.SESSION_INVALIDATED: 401,
    ErrorCode.SESSION_CONFIRMATION_PENDING: 403,
    ErrorCode.SESSION_ALREADY_REVOKED: 409,
    ErrorCode.FORBIDDEN: 403,
    ErrorCode.NOT_FOUND: 404,
    ErrorCode.CSRF_MISSING: 403,
    ErrorCode.CSRF_INVALID: 403,
    ErrorCode.CSRF_REVOKED: 403,
    ErrorCode.CSRF_EXPIRED: 403,
    ErrorCode.CSRF_BOUND_SESSION: 403,
    ErrorCode.CSRF_BOUND_ORIGIN: 403,
    ErrorCode.CONFLICT: 409,
    ErrorCode.VALIDATION_ERROR: 422,
    ErrorCode.STORE_UNAVAILABLE: 503,
    ErrorCode.TIME_SOURCE_UNAVAILABLE: 503,
    ErrorCode.CONFIG_ERROR: 500,
    ErrorCode.INTERNAL_ERROR: 500,
}


class StoreError(RuntimeError):
    """存储层异常的统一基类，归一化为 STORE_UNAVAILABLE。"""


class TimeSourceError(RuntimeError):
    """时间源异常基类，归一化为 TIME_SOURCE_UNAVAILABLE。"""


class ConfigError(RuntimeError):
    """配置异常基类，归一化为 CONFIG_ERROR。"""


class AppError(Exception):
    """对外错误。reason 是稳定的可区分判定码；detail 仅用于受控日志。"""

    def __init__(self, code: ErrorCode, detail: str | None = None,
                 *, status_code: int | None = None) -> None:
        self.code = code
        self.detail = detail
        self.status_code = (
            status_code if status_code is not None else _STATUS[code]
        )
        super().__init__(f"{code.value}: {detail or ''}")


def normalize(exc: BaseException) -> AppError:
    """把任意异常归一化为 AppError。

    - AppError 原样返回（判定码已确定）；
    - 存储/时间/配置异常归一化为各自可区分的 5xx 码；
    - 其余未知异常归一化为 INTERNAL_ERROR，绝不放行。
    """
    if isinstance(exc, AppError):
        return exc
    if isinstance(exc, ConfigError):
        return AppError(ErrorCode.CONFIG_ERROR, str(exc) or "config error")
    if isinstance(exc, TimeSourceError):
        return AppError(ErrorCode.TIME_SOURCE_UNAVAILABLE,
                        str(exc) or "time source unavailable")
    if isinstance(exc, StoreError):
        return AppError(ErrorCode.STORE_UNAVAILABLE,
                        str(exc) or "store unavailable")
    return AppError(ErrorCode.INTERNAL_ERROR,
                    f"{type(exc).__name__}: {exc}")
