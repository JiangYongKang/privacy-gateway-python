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
from .models import AuditEntry, Decision, DecisionResult


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
                retention_state=result.retention_state,
            )
            self._entries.append(entry)
            self._by_request[entry.request_id] = entry
            return entry

    def append_event(
        self,
        *,
        event_type: str,
        request_id: str,
        reason: str,
        caller_id: str,
        resource_id: str,
        hold_id: str,
        decided_at: str,
        request_fingerprint: str,
    ) -> AuditEntry:
        """Record a non-access lifecycle event (e.g. hold place/release).

        Shares the same idempotency and total-order guarantees as access
        decisions: one entry per ``request_id``, gap-free sequence.
        """

        with self._lock:
            existing = self._by_request.get(request_id)
            if existing is not None:
                if existing.request_fingerprint != request_fingerprint:
                    raise IdempotencyConflictError(
                        f"request_id {request_id!r} was already used "
                        "with a different payload"
                    )
                return existing

            self._seq += 1
            entry = AuditEntry(
                sequence=self._seq,
                request_id=request_id,
                decision=Decision.ALLOW,
                deny_code="",
                reason=reason,
                policy_version="-",
                caller_id=caller_id,
                resource_id=resource_id,
                scope="-",
                fields_snapshot={},
                request_fingerprint=request_fingerprint,
                decided_at=decided_at,
                event_type=event_type,
                hold_id=hold_id,
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

    def entries_after(self, sequence: int, limit: int) -> list[AuditEntry]:
        """Up to ``limit`` entries with sequence > ``sequence``, in order.

        Sequences are gap-free and append-only, so this is a bounded slice —
        safe to page while concurrent appends continue: entries already
        returned are never mutated or renumbered, and new entries simply
        become visible to later pages.
        """

        with self._lock:
            # sequence N lives at index N-1; the first entry after `sequence`
            # is at index `sequence`.
            return list(self._entries[sequence:sequence + max(0, limit)])
