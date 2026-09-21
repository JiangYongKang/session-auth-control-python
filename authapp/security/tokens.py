"""不可猜测的随机标识生成（会话标识、CSRF 令牌等）。"""
from __future__ import annotations

import base64
import hmac
import os


def random_token(nbytes: int = 32) -> str:
    """返回 URL 安全的高熵随机字符串（base64url，无填充）。"""
    if not isinstance(nbytes, int) or nbytes < 16:
        raise ValueError("token 熵长不足")
    return base64.urlsafe_b64encode(os.urandom(nbytes)).rstrip(b"=").decode("ascii")


def constant_time_equals(a: str, b: str) -> bool:
    """恒定时间字符串比较。"""
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))
