"""CSRF 令牌：服务端签发的高熵随机令牌。

令牌本身与会话、来源绑定（绑定关系存服务端）；
缺失/过期/跨会话/跨来源由 API 依赖统一区分拒绝。
"""
from __future__ import annotations

import hmac
import os


def issue_csrf_token() -> str:
    """256 位不可猜测随机令牌，hex 编码。"""
    return os.urandom(32).hex()


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)
