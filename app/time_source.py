"""时间源抽象，便于测试控制与异常注入。异常不得被吞掉降级。"""
from __future__ import annotations

import time

from app.errors import TimeSourceError


class TimeSource:
    """时间源协议基类。"""

    def now(self) -> float:
        """返回 UNIX 时间戳；失败必须抛 TimeSourceError。"""
        raise NotImplementedError


class SystemTimeSource(TimeSource):
    def now(self) -> float:
        try:
            return time.time()
        except Exception as e:  # pragma: no cover - 极端环境
            raise TimeSourceError(str(e)) from e


class ManualTimeSource(TimeSource):
    """测试用可控时间源。"""

    def __init__(self, start: float = 1_000_000.0) -> None:
        self._now = float(start)

    def now(self) -> float:
        return self._now

    def advance(self, seconds: float) -> None:
        if seconds < 0:
            raise ValueError("cannot advance backwards")
        self._now += seconds

    def set(self, value: float) -> None:
        self._now = float(value)


class FailingTimeSource(TimeSource):
    """始终抛异常的时间源，用于验证 fail-closed。"""

    def now(self) -> float:
        raise TimeSourceError("time source injected failure")
