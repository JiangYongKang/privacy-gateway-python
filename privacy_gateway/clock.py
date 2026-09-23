"""Injectable clock so retention and decision timestamps are deterministic."""

from __future__ import annotations

from datetime import datetime, timezone


class Clock:
    def now_iso(self) -> str:
        ...

    def now(self) -> datetime:
        ...


class SystemClock(Clock):
    def now_iso(self) -> str:
        return self.now().strftime("%Y-%m-%dT%H:%M:%SZ")

    def now(self) -> datetime:
        return datetime.now(timezone.utc)


class FixedClock(Clock):
    def __init__(self, iso: str) -> None:
        self._iso = iso

    def now_iso(self) -> str:
        return self._iso

    def now(self) -> datetime:
        return datetime.strptime(self._iso, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
