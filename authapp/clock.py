"""时间源抽象：便于测试控制与异常归一化。

- SystemClock：生产用，读取系统单调外的墙钟时间（Unix 秒）。
- 时间源本身异常时归一化为 AuthError(TIME_SOURCE_ERROR)，绝不允许
  上层因此降级为放行。
"""
from __future__ import annotations

import time
from typing import Protocol

from authapp.errors import AuthError, ErrorCode


class Clock(Protocol):
    def now(self) -> float:
        """返回当前 Unix 时间戳（秒）。时间源异常时抛 AuthError。"""
        ...


class SystemClock:
    """默认墙钟时间源。"""

    def now(self) -> float:
        try:
            value = time.time()
        except Exception as exc:  # pragma: no cover - 极端环境防御
            raise AuthError(
                ErrorCode.TIME_SOURCE_ERROR, "时间源不可用"
            ) from exc
        if not isinstance(value, (int, float)):  # pragma: no cover - 防御
            raise AuthError(ErrorCode.TIME_SOURCE_ERROR, "时间源返回非法值")
        return float(value)
