"""口令处理：不可逆哈希与校验。

使用 PBKDF2-HMAC-SHA256 + 每口令独立随机盐 + 高迭代次数；
校验使用恒定时间比较，避免时序侧信道。存储串自描述算法与参数。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os

_ALGO = "pbkdf2_sha256"
_ITERATIONS = 240_000
_SALT_BYTES = 16
_HASH_BYTES = 32


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"), validate=True)


def hash_password(password: str) -> str:
    """以不可逆方式存储口令，返回自描述哈希串。"""
    if not isinstance(password, str):
        raise TypeError("password 必须为字符串")
    salt = os.urandom(_SALT_BYTES)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, _ITERATIONS, dklen=_HASH_BYTES
    )
    return f"{_ALGO}${_ITERATIONS}${_b64e(salt)}${_b64e(digest)}"


def verify_password(password: str, password_hash: str) -> bool:
    """恒定时间校验。任何格式/算法异常均返回 False（默认拒绝）。"""
    if not isinstance(password, str) or not isinstance(password_hash, str):
        return False
    try:
        algo, iter_text, salt_text, digest_text = password_hash.split("$", 3)
        if algo != _ALGO:
            return False
        iterations = int(iter_text)
        salt = _b64d(salt_text)
        expected = _b64d(digest_text)
    except (ValueError, TypeError):
        return False
    candidate = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, iterations, dklen=len(expected)
    )
    return hmac.compare_digest(candidate, expected)
