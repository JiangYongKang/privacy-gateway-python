"""Retention holds: operator-driven retention extension / release.

A hold attached to a resource suspends the ordinary retention horizon for
reads (masking still applies); releasing it restores ordinary handling
immediately. Both actions are audited as first-class, replayable events with
their own distinguishable basis (``hold_place`` / ``hold_release``), separate
from read decisions and authorization denials.

Idempotency: placing a hold reuses ``hold_id`` as the idempotency key — the
same id with the same payload returns the original record without a new
audit entry; the same id with a different payload is a ``HOLD_CONFLICT``.
Releasing an already-released hold returns the stored release record.
"""

from __future__ import annotations

import hashlib
import json
import logging

from .audit import AuditLog
from .clock import Clock
from .errors import HoldNotFoundError, ResourceNotFoundError
from .models import AuditEventType, RetentionHold
from .store import LocalStore

logger = logging.getLogger("privacy_gateway.holds")


def _hold_fingerprint(payload: dict) -> str:
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


class HoldManager:
    """Places and releases retention holds; every action is audited."""

    def __init__(self, store: LocalStore, audit: AuditLog, clock: Clock) -> None:
        self.store = store
        self.audit = audit
        self.clock = clock

    # ------------------------------------------------------------------
    def place_hold(
        self, hold_id: str, resource_id: str, placed_by: str, reason: str,
    ) -> RetentionHold:
        """Attach a retention extension to ``resource_id`` (idempotent)."""

        if self.store.get_resource(resource_id) is None:
            raise ResourceNotFoundError(
                f"resource {resource_id!r} does not exist"
            )

        fingerprint = _hold_fingerprint({
            "action": "place",
            "hold_id": hold_id,
            "resource_id": resource_id,
            "placed_by": placed_by,
            "reason": reason,
        })
        # Idempotent retry: same hold_id + same payload -> original record.
        existing = self.store.get_hold(hold_id)
        if existing is not None:
            prior = self.audit.get_by_request(f"hold-place-{hold_id}")
            if prior is not None and prior.request_fingerprint == fingerprint:
                return existing
            # Different payload (or missing audit): store raises on conflict.
        hold = RetentionHold(
            hold_id=hold_id,
            resource_id=resource_id,
            placed_by=placed_by,
            reason=reason,
            placed_at=self.clock.now_iso(),
        )
        self.store.add_hold(hold)  # raises HoldConflictError on id reuse
        self.audit.append_event(
            event_type=AuditEventType.HOLD_PLACE.value,
            request_id=f"hold-place-{hold_id}",
            reason=(
                f"retention hold {hold_id!r} placed on resource "
                f"{resource_id!r} by {placed_by!r}: {reason}"
            ),
            caller_id=placed_by,
            resource_id=resource_id,
            hold_id=hold_id,
            decided_at=hold.placed_at,
            request_fingerprint=fingerprint,
        )
        logger.info(
            "hold-event place basis=hold-place hold_id=%s resource_id=%s "
            "placed_by=%s placed_at=%s",
            hold_id, resource_id, placed_by, hold.placed_at,
        )
        return hold

    # ------------------------------------------------------------------
    def release_hold(self, hold_id: str, released_by: str) -> RetentionHold:
        """Lift a retention extension (idempotent per hold)."""

        hold = self.store.get_hold(hold_id)
        if hold is None:
            raise HoldNotFoundError(f"hold {hold_id!r} does not exist")
        if not hold.active:
            # Releasing twice is a no-op that returns the original record.
            return hold

        released = RetentionHold(
            hold_id=hold.hold_id,
            resource_id=hold.resource_id,
            placed_by=hold.placed_by,
            reason=hold.reason,
            placed_at=hold.placed_at,
            released_at=self.clock.now_iso(),
            released_by=released_by,
        )
        self.store.replace_hold(released)
        self.audit.append_event(
            event_type=AuditEventType.HOLD_RELEASE.value,
            request_id=f"hold-release-{hold_id}",
            reason=(
                f"retention hold {hold_id!r} on resource "
                f"{hold.resource_id!r} released by {released_by!r}; "
                "ordinary retention handling restored"
            ),
            caller_id=released_by,
            resource_id=hold.resource_id,
            hold_id=hold_id,
            decided_at=released.released_at or "",
            request_fingerprint=_hold_fingerprint({
                "action": "release",
                "hold_id": hold_id,
                "released_by": released_by,
            }),
        )
        logger.info(
            "hold-event release basis=hold-release hold_id=%s resource_id=%s "
            "released_by=%s released_at=%s",
            hold_id, hold.resource_id, released_by, released.released_at,
        )
        return released

    # ------------------------------------------------------------------
    def active_hold_for(self, resource_id: str) -> RetentionHold | None:
        """The currently active hold for a resource, if any."""

        return self.store.active_hold_for(resource_id)
