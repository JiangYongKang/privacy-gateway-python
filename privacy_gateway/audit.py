"""Append-only, idempotent, concurrency-safe audit log.

Concurrency model: a single re-entrant lock makes "check request id -> assign
sequence -> append" atomic. Concurrent callers therefore interleave into one
total order with gap-free, deterministic sequence numbers, and retrying the
same ``request_id`` returns the original entry instead of writing a duplicate.

Only safe material is ever stored: the decision, deny code, rule-derived
masked values, and identifiers. Raw sensitive field values are never passed
in here by the decider.
"""

from __future__ import annotations

import threading

from .errors import IdempotencyConflictError
from .models import AuditEntry, DecisionResult


class AuditLog:
    def __init__(self) -> None:
        self._entries: list[AuditEntry] = []
        self._by_request: dict[str, AuditEntry] = {}
        self._lock = threading.RLock()
        self._seq = 0

    def append(
        self,
        result: DecisionResult,
        deny_code: str,
        request_fingerprint: str,
        decided_at: str,
        *,
        event_type: str = "access",
        basis: str = "",
    ) -> AuditEntry:
        """Record ``result`` once per request_id; return the stored entry.

        Replaying/retrying the same request id:
          * same payload  -> the original entry is returned, no new sequence;
          * different payload -> IdempotencyConflictError (rejected, audited
            via the caller's log stream without mutating state).
        """

        with self._lock:
            existing = self._by_request.get(result.request_id)
            if existing is not None:
                if existing.request_fingerprint != request_fingerprint:
                    raise IdempotencyConflictError(
                        f"request_id {result.request_id!r} was already used "
                        "with a different payload"
                    )
                return existing

            self._seq += 1
            entry = AuditEntry(
                sequence=self._seq,
                request_id=result.request_id,
                decision=result.decision,
                deny_code=deny_code,
                reason=result.reason,
                policy_version=result.policy_version,
                caller_id=result.caller_id,
                resource_id=result.resource_id,
                scope=result.scope,
                fields_snapshot={
                    name: {"action": fo.action.value, "value": fo.value}
                    for name, fo in sorted(result.fields.items())
                },
                request_fingerprint=request_fingerprint,
                decided_at=decided_at,
                event_type=event_type,
                basis=basis,
                expired=result.expired,
                hold_active=result.hold_active,
            )
            self._entries.append(entry)
            self._by_request[entry.request_id] = entry
            return entry

    def get_by_request(self, request_id: str) -> AuditEntry | None:
        with self._lock:
            return self._by_request.get(request_id)

    def entries(self) -> list[AuditEntry]:
        """Entries in deterministic append (sequence) order."""

        with self._lock:
            return list(self._entries)

    # ------------------------------------------------------------------
    # Incremental / batched export
    # ------------------------------------------------------------------
    MAX_PAGE_SIZE = 1000

    def page(
        self, after_sequence: int = 0, limit: int | None = None,
    ) -> tuple[list[AuditEntry], int, bool]:
        """One deterministic page of entries with ``sequence > after_sequence``.

        Returns ``(entries, next_cursor, has_more)`` where ``next_cursor`` is
        the sequence of the last entry in the page (or the input cursor when
        the page is empty). Feeding ``next_cursor`` back in resumes exactly
        where the previous page stopped; re-using the same cursor always
        yields the same page, so retries cannot skip or duplicate entries.

        The log is append-only with gap-free sequence numbers and the page is
        computed from a single locked snapshot, so concurrent appends during
        an export are simply picked up by later pages — never missed, never
        duplicated, and order is always ascending sequence.
        """

        if after_sequence < 0:
            after_sequence = 0
        if limit is None:
            limit = self.MAX_PAGE_SIZE
        limit = max(1, min(limit, self.MAX_PAGE_SIZE))

        with self._lock:
            start = min(after_sequence, len(self._entries))
            # sequence numbers are 1-based and gap-free, so the entry with
            # sequence s lives at index s-1 in the append-only list.
            page = self._entries[start:start + limit]
            has_more = start + limit < len(self._entries)

        next_cursor = page[-1].sequence if page else after_sequence
        return page, next_cursor, has_more

    def iter_pages(
        self, after_sequence: int = 0, limit: int | None = None,
    ):
        """Generator over successive pages; streams without materialising the
        whole history in the caller. Stops at the end of the log as observed
        by the final (empty) page."""

        cursor = after_sequence
        while True:
            page, cursor, has_more = self.page(cursor, limit)
            if page:
                yield page
            if not has_more:
                return
