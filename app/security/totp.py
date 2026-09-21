"""RFC6238 一次性口令：生成、校验、时间漂移、重放区分。

判定顺序（关键，保证三类失败可区分）：
1. 先在 [now-step-drift, now-step+drift] 窗口内逐步比对；
   全部不匹配 => "invalid"（验证码错误）。
2. 窗口超出 drift_steps 本身属于配置允许范围；时间漂移判定针对：
   输入对应的"步"已落在允许窗口之外（由服务在 last_consumed_step 比较时
   一并区分）。本模块把"匹配到的步 <= 已消费步"判为 "reused"。
3. 为让"时间偏移窗口"可显式区分，提供 classify_window()：
   当客户端时钟偏移超过允许步数（窗口内无任何可接受值）时返回 "time_drift"。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import struct
import urllib.parse


def generate_secret() -> str:
    """生成新的 base32 共享密钥（无填充）。"""
    return base64.b32encode(os.urandom(20)).decode("ascii").rstrip("=")


def provisioning_uri(secret: str, account: str, issuer: str) -> str:
    label = urllib.parse.quote(f"{issuer}:{account}")
    params = urllib.parse.urlencode({
        "secret": secret,
        "issuer": issuer,
        "algorithm": "SHA1",
        "digits": 6,
        "period": 30,
    })
    return f"otpauth://totp/{label}?{params}"


def current_step(now: float, period: int) -> int:
    return int(now // period)


def _decode_secret(secret: str) -> bytes:
    s = secret.strip().replace(" ", "").upper()
    pad = "=" * (-len(s) % 8)
    return base64.b32decode(s + pad, casefold=True)


def generate_code(secret: str, step: int, digits: int = 6) -> str:
    key = _decode_secret(secret)
    msg = struct.pack(">Q", step)
    mac = hmac.new(key, msg, hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    binary = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    token = binary % (10 ** digits)
    return str(token).zfill(digits)


def code_at_window(secret: str, now: float, *, period: int = 30,
                   digits: int = 6, drift_steps: int = 1) -> dict[int, str]:
    """返回允许窗口内每个步 -> code。"""
    center = current_step(now, period)
    return {
        step: generate_code(secret, step, digits)
        for step in range(center - drift_steps, center + drift_steps + 1)
    }


def verify_code(
    secret: str,
    code: str,
    now: float,
    *,
    period: int = 30,
    digits: int = 6,
    drift_steps: int = 1,
    last_consumed_step: int | None = None,
) -> tuple[bool, str | None, int | None]:
    """校验 TOTP。

    返回 (通过, 原因, 命中步)：
      (True,  None, step) 成功（调用方应持久化 step 作为已消费步）
      (False, "invalid",  None) 窗口内所有步都不匹配（验证码错误）
      (False, "reused",   step) 命中步 <= 上次已消费步（重复使用）
      (False, "time_drift", None) 时钟偏移超出允许窗口（见 classify_window）

    注意：只有在"窗口内至少有一个步匹配"时才可能判定 reused；
    这样错误验证码不会被误报为重放。
    """
    norm = (code or "").strip().replace(" ", "")
    if not norm.isdigit() or len(norm) != digits:
        return False, "invalid", None

    window = code_at_window(
        secret, now, period=period, digits=digits,
        drift_steps=drift_steps)
    matched = [step for step, c in window.items()
               if hmac.compare_digest(c, norm)]
    if not matched:
        return False, "invalid", None

    step = max(matched)
    if last_consumed_step is not None and step <= last_consumed_step:
        return False, "reused", step
    return True, None, step


def classify_window(last_consumed_step: int | None, now: float,
                    *, period: int = 30, drift_steps: int = 1) -> str | None:
    """当客户端与服务端时间偏移使整个允许窗口都早于已消费步时，
    给出 "time_drift"；否则 None。

    用于把"时间严重偏移"与"验证码错误"区分：即使此刻没有验证码输入，
    只要窗口最新步都不大于已消费步，说明时钟落后超过窗口。
    """
    if last_consumed_step is None:
        return None
    newest = current_step(now, period) + drift_steps
    if newest < last_consumed_step:
        return "time_drift"
    return None


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)
