"""可注入的时钟，保证测试可复现。

时间一律使用带时区的 UTC；审计时间戳采用固定格式字符串，
保证字节级确定、可排序、可复现。
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"


def format_ts(dt: datetime) -> str:
    """将时间统一格式化为 UTC 字符串（确定性输出）。"""
    return dt.astimezone(timezone.utc).strftime(TIMESTAMP_FORMAT)


def parse_ts(value: str) -> datetime:
    """解析 :func:`format_ts` 产生的时间戳。"""
    return datetime.strptime(value, TIMESTAMP_FORMAT).replace(tzinfo=timezone.utc)


class Clock:
    """时钟抽象。"""

    def now(self) -> datetime:
        raise NotImplementedError


class SystemClock(Clock):
    """系统 UTC 时钟。"""

    def now(self) -> datetime:
        return datetime.now(timezone.utc)


class FixedClock(Clock):
    """固定时钟，仅在显式 :meth:`advance` 时前进（供测试复现）。"""

    def __init__(self, current: datetime) -> None:
        if current.tzinfo is None:
            current = current.replace(tzinfo=timezone.utc)
        self._current = current.astimezone(timezone.utc)

    def now(self) -> datetime:
        return self._current

    def advance(self, seconds: int) -> None:
        self._current = self._current + timedelta(seconds=seconds)
