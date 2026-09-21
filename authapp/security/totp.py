"""基于时间的一次性口令（RFC 6238/4226）。

本模块只负责密码学计算；“时间偏移 vs 验证码错误 vs 重放”的策略判定
由上层 MfaService 结合 locate_code 的结果与已消费记录完成：
- locate_code 返回 None：窗口内无匹配 -> 验证码错误；
- 命中非当前时间步：时间偏移；
- 命中当前步但该码在本会话已消费：重复使用。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import struct
from dataclasses import dataclass
from urllib.parse import quote, urlencode

import os


@dataclass(frozen=True)
class TotpParams:
    secret: str
    period: int = 30
    digits: int = 6
    lookback: int = 1
    lookahead: int = 1
    algorithm: str = "sha1"

    def secret_bytes(self) -> bytes:
        return base64.b32decode(self.secret.upper(), casefold=True)


def generate_totp_secret(nbytes: int = 20) -> str:
    """生成 base32 编码随机密钥（RFC 推荐 >= 160 bit）。"""
    raw = os.urandom(nbytes)
    return base64.b32encode(raw).decode("ascii")


def provisioning_uri(secret: str, account: str, issuer: str) -> str:
    label = quote(f"{issuer}:{account}", safe=":")
    query = urlencode({"secret": secret, "issuer": issuer})
    return f"otpauth://totp/{label}?{query}"


def hotp(secret: str, counter: int, digits: int, algorithm: str = "sha1") -> str:
    key = base64.b32decode(secret.upper(), casefold=True)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, getattr(hashlib, algorithm)).digest()
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFF_FFFF
    return str(binary % (10**digits)).zfill(digits)


def current_step(now: float, period: int) -> int:
    return int(now // period)


def current_codes(secret: str, now: float, params: TotpParams) -> list[str]:
    """返回时间偏移窗口 [t-lookback, t+lookahead] 内的验证码。"""
    step = current_step(now, params.period)
    return [
        hotp(params.secret, step + off, params.digits, params.algorithm)
        for off in range(-params.lookback, params.lookahead + 1)
    ]


def locate_code(code: str, secret: str, now: float, params: TotpParams) -> int | None:
    """在窗口内定位验证码，返回命中的时间步；未命中返回 None。"""
    if not isinstance(code, str) or not code.isdigit() or len(code) != params.digits:
        return None
    step = current_step(now, params.period)
    for off in range(-params.lookback, params.lookahead + 1):
        candidate = hotp(params.secret, step + off, params.digits, params.algorithm)
        if hmac.compare_digest(candidate, code):
            return step + off
    return None


def code_matches(code: str, secret: str, now: float, params: TotpParams) -> bool:
    return locate_code(code, secret, now, params) is not None


# 便于测试：在指定时间点生成验证码。
def code_at(secret: str, at: float, period: int = 30, digits: int = 6) -> str:
    return hotp(secret, int(at // period), digits)
