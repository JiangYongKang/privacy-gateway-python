"""Incremental, cursor-based audit export.

Pages are keyed by the gap-free audit sequence, so paging while new entries
are appended concurrently can neither skip nor duplicate entries and the
order is stable. Cursors are opaque, resumable and idempotent: reusing a
cursor returns the same page again. Memory stays bounded — callers page (or
stream page-by-page) instead of materialising the whole history.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator

from .audit import AuditLog
from .errors import PrivacyError
from .models import AuditEntry

CURSOR_PREFIX = "pg1:"
DEFAULT_PAGE_SIZE = 100
MAX_PAGE_SIZE = 1000


class InvalidCursorError(PrivacyError):
    """An export cursor is malformed or from an incompatible exporter."""

    code = "INVALID_CURSOR"
    http_status = 400


@dataclass(frozen=True)
class ExportPage:
    entries: tuple[AuditEntry, ...]
    next_cursor: str | None          # None when the export has caught up
    has_more: bool

    def to_dict(self) -> dict:
        return {
            "entries": [e.to_dict() for e in self.entries],
            "next_cursor": self.next_cursor,
            "has_more": self.has_more,
        }


def encode_cursor(sequence: int) -> str:
    """Opaque cursor pointing *after* ``sequence``."""

    return f"{CURSOR_PREFIX}{sequence}"


def decode_cursor(cursor: str) -> int:
    """Parse a cursor back into a sequence number (0 = from the start)."""

    if not cursor.startswith(CURSOR_PREFIX):
        raise InvalidCursorError(f"unrecognised export cursor {cursor!r}")
    try:
        sequence = int(cursor[len(CURSOR_PREFIX):])
    except ValueError:
        raise InvalidCursorError(f"malformed export cursor {cursor!r}") from None
    if sequence < 0:
        raise InvalidCursorError(f"malformed export cursor {cursor!r}")
    return sequence


def export_page(
    audit: AuditLog, cursor: str | None = None, limit: int = DEFAULT_PAGE_SIZE,
) -> ExportPage:
    """One bounded page of entries after ``cursor``.

    ``limit`` is clamped to [1, MAX_PAGE_SIZE] so a single page can never
    grow unboundedly. The same cursor always yields the same page, so a
    retry or a resumed export never skips or duplicates entries.
    """

    after = decode_cursor(cursor) if cursor else 0
    limit = max(1, min(limit, MAX_PAGE_SIZE))
    batch = audit.entries_after(after, limit + 1)
    has_more = len(batch) > limit
    page = batch[:limit]
    next_cursor = encode_cursor(page[-1].sequence) if has_more else None
    return ExportPage(
        entries=tuple(page), next_cursor=next_cursor, has_more=has_more,
    )


def stream_entries(
    audit: AuditLog, cursor: str | None = None, page_size: int = DEFAULT_PAGE_SIZE,
) -> Iterator[AuditEntry]:
    """Yield all entries after ``cursor``, one bounded page at a time.

    Only one page is held in memory at any moment, so streaming the full
    history stays bounded regardless of how large the audit log grows.
    """

    next_cursor = cursor
    while True:
        page = export_page(audit, next_cursor, page_size)
        yield from page.entries
        if not page.has_more:
            return
        next_cursor = page.next_cursor
