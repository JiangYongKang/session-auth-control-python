"""口令哈希：不可逆（PBKDF2-HMAC-SHA256 + per-user 随机 salt）。"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os

from app.config import PasswordPolicy
from app.errors import AppError, ErrorCode

_ALGO = "pbkdf2_sha256"
_ITERATIONS = 200_000
_SALT_BYTES = 16


def hash_password(password: str, *, iterations: int = _ITERATIONS) -> str:
    """返回自描述编码：pbkdf2_sha256$iter$salt_b64$hash_b64"""
    if not isinstance(password, str):
        raise AppError(ErrorCode.VALIDATION_ERROR, "password must be string")
    salt = os.urandom(_SALT_BYTES)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                             salt, iterations)
    return "$".join((
        _ALGO, str(iterations),
        base64.b64encode(salt).decode("ascii"),
        base64.b64encode(dk).decode("ascii"),
    ))


def verify_password(password: str, encoded: str) -> bool:
    """解析编码并重算，hmac 恒时比较。解析失败一律 False（不放行）。"""
    try:
        algo, iter_s, salt_s, hash_s = encoded.split("$", 3)
        if algo != _ALGO:
            return False
        iterations = int(iter_s)
        salt = base64.b64decode(salt_s, validate=True)
        expected = base64.b64decode(hash_s, validate=True)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                                 salt, iterations)
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False


def validate_password(password: str, policy: PasswordPolicy) -> None:
    if not isinstance(password, str) or not password:
        raise AppError(ErrorCode.VALIDATION_ERROR, "password is required")
    if len(password) < policy.min_length:
        raise AppError(
            ErrorCode.VALIDATION_ERROR,
            f"password too short; min_length={policy.min_length}")
    if policy.require_digit and not any(c.isdigit() for c in password):
        raise AppError(ErrorCode.VALIDATION_ERROR,
                       "password must contain a digit")
    if policy.require_alpha and not any(c.isalpha() for c in password):
        raise AppError(ErrorCode.VALIDATION_ERROR,
                       "password must contain a letter")
