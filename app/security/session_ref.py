"""会话稳定引用（session reference）。

安全性质：
- 不可反推原始标识：引用是对 (账号, 会话标识) 的密钥 HMAC，单向散列，
  服务端密钥为进程级随机值（或显式注入），拿到引用无法恢复会话标识；
- 不能跨账号使用：HMAC 消息把账号名作为绑定域，restrict() 必须用调用者
  本人账号重新计算比对，其他账号的引用在该账号域内永远匹配不上；
- 稳定：同一 (账号, 会话标识) 任意时刻得到同一引用，重复查看顺序/取值不变；
- 抗伪造：引用空间为 256 位，且不接受任何"看起来像"但校验失败的构造。

引用本身不携带会话标识明文，只在服务端持锁时通过逐用户枚举比对解析。
"""
from __future__ import annotations

import hashlib
import hmac
import secrets

REF_BYTES = 32  # HMAC-SHA256 输出长度


class SessionReferenceSigner:
    """会话引用签发/校验器。"""

    def __init__(self, secret: bytes | str | None = None) -> None:
        if secret is None:
            key = secrets.token_bytes(32)
        elif isinstance(secret, str):
            key = secret.encode("utf-8")
        else:
            key = bytes(secret)
        if not key:
            raise ValueError("session reference secret must not be empty")
        self._key = key

    def _digest(self, username: str, session_id: str) -> bytes:
        # 账号与会话标识以 NUL 分隔（NUL 不可能出现在二者字符集中），
        # 防止跨字段拼接混淆；账号绑定即"使用域"隔离。
        msg = b"session-ref-v1\x00" + username.encode("utf-8") \
            + b"\x00" + session_id.encode("utf-8")
        return hmac.new(self._key, msg, hashlib.sha256).digest()

    def sign(self, username: str, session_id: str) -> str:
        """为 (账号, 会话标识) 生成稳定且不可反推的引用。"""
        return self._digest(username, session_id).hex()

    def restrict(self, username: str, reference: str,
                 candidates: list[str]) -> str | None:
        """在该账号的候选会话标识集合内解析引用。

        只与属于该账号的候选逐一常量时间比对：
        - 命中 -> 返回对应会话标识；
        - 不命中（含其他账号的引用、伪造引用）-> None。
        调用方必须保证 candidates 全部属于 username，从而使跨账号引用
        在候选集合中无对应消息，无法借用本接口探测他人会话。
        """
        if not isinstance(reference, str) or len(reference) != REF_BYTES * 2:
            return None
        try:
            target = bytes.fromhex(reference)
        except ValueError:
            return None
        for sid in candidates:
            if hmac.compare_digest(self._digest(username, sid), target):
                return sid
        return None
