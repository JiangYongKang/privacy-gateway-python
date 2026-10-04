"""Retention hold (legal-hold) placement and release.

A hold suspends the plain retention horizon for one resource: while active,
an otherwise-expired resource reads normally (masking unchanged); once
released, the plain horizon applies again immediately.

Both operations are themselves audited as first-class, replayable events
(``event_type`` = ``retention_hold`` / ``retention_release``) with their own
idempotency keys, so the audit trail explains *why* a read was or was not
considered expired at any point in time. Only safe identifiers and operator
free-text reasons are stored — never resource content.
"""

from __future__ import annotations

import logging

from .audit import AuditLog
from .clock import Clock
from .decider import _replay_result
from .errors import (
    HoldNotFoundError,
    IdempotencyConflictError,
    ResourceNotFoundError,
    UnauthorizedCallerError,
)
from .models import (
    Decision,
    DecisionResult,
    RetentionHold,
    fingerprint_payload,
)
from .store import LocalStore

logger = logging.getLogger("privacy_gateway.holds")


class HoldService:
    def __init__(self, store: LocalStore, audit: AuditLog, clock: Clock) -> None:
        self.store = store
        self.audit = audit
        self.clock = clock

    # ------------------------------------------------------------------
    def place_hold(
        self, hold_id: str, resource_id: str, operator_id: str, reason: str,
    ) -> DecisionResult:
        """Attach a retention hold to ``resource_id`` (idempotent by hold_id)."""

        fingerprint = fingerprint_payload({
            "op": "retention_hold",
            "hold_id": hold_id,
            "resource_id": resource_id,
            "operator_id": operator_id,
            "reason": reason,
        })
        prior = self.audit.get_by_request(hold_id)
        if prior is not None:
            if prior.request_fingerprint != fingerprint:
                raise IdempotencyConflictError(
                    f"hold id {hold_id!r} was already used with a different "
                    "payload"
                )
            self._log("replay-hit", hold_id, resource_id, operator_id)
            return _replay_result(prior)

        self._require_operator(operator_id)
        resource = self.store.get_resource(resource_id)
        if resource is None:
            raise ResourceNotFoundError(f"resource {resource_id!r} does not exist")

        hold = RetentionHold(
            hold_id=hold_id,
            resource_id=resource_id,
            created_by=operator_id,
            reason=reason,
            created_at=self.clock.now_iso(),
        )
        self.store.add_hold(hold)

        result = DecisionResult(
            request_id=hold_id,
            decision=Decision.RECORDED,
            policy_version=self.store.current_policy_version(),
            caller_id=operator_id,
            resource_id=resource_id,
            scope=resource.scope,
            reason=(
                f"retention hold {hold_id!r} placed on resource "
                f"{resource_id!r} by {operator_id!r}: {reason}"
            ),
            decided_at=hold.created_at,
            hold_active=True,
        )
        self.audit.append(result, "", fingerprint, result.decided_at,
                          event_type="retention_hold",
                          basis="retention-hold-placed")
        self._log("recorded", hold_id, resource_id, operator_id,
                  basis="retention-hold-placed")
        return result

    # ------------------------------------------------------------------
    def release_hold(
        self, release_id: str, resource_id: str, operator_id: str,
    ) -> DecisionResult:
        """Release the active hold on ``resource_id`` (idempotent by release_id)."""

        fingerprint = fingerprint_payload({
            "op": "retention_release",
            "release_id": release_id,
            "resource_id": resource_id,
            "operator_id": operator_id,
        })
        prior = self.audit.get_by_request(release_id)
        if prior is not None:
            if prior.request_fingerprint != fingerprint:
                raise IdempotencyConflictError(
                    f"release id {release_id!r} was already used with a "
                    "different payload"
                )
            self._log("replay-hit", release_id, resource_id, operator_id)
            return _replay_result(prior)

        self._require_operator(operator_id)
        resource = self.store.get_resource(resource_id)
        if resource is None:
            raise ResourceNotFoundError(f"resource {resource_id!r} does not exist")

        hold = self.store.active_hold_for(resource_id)
        if hold is None:
            raise HoldNotFoundError(
                f"no active retention hold on resource {resource_id!r}"
            )
        released = RetentionHold(
            hold_id=hold.hold_id,
            resource_id=hold.resource_id,
            created_by=hold.created_by,
            reason=hold.reason,
            created_at=hold.created_at,
            released_at=self.clock.now_iso(),
            released_by=operator_id,
        )
        self.store.update_hold(released)

        result = DecisionResult(
            request_id=release_id,
            decision=Decision.RECORDED,
            policy_version=self.store.current_policy_version(),
            caller_id=operator_id,
            resource_id=resource_id,
            scope=resource.scope,
            reason=(
                f"retention hold {hold.hold_id!r} on resource "
                f"{resource_id!r} released by {operator_id!r}"
            ),
            decided_at=released.released_at or "",
            hold_active=False,
        )
        self.audit.append(result, "", fingerprint, result.decided_at,
                          event_type="retention_release",
                          basis="retention-hold-released")
        self._log("recorded", release_id, resource_id, operator_id,
                  basis="retention-hold-released")
        return result

    # ------------------------------------------------------------------
    def _require_operator(self, operator_id: str) -> None:
        if self.store.get_caller(operator_id) is None:
            raise UnauthorizedCallerError(
                f"operator {operator_id!r} is not registered"
            )

    @staticmethod
    def _log(
        outcome: str, op_id: str, resource_id: str, operator_id: str,
        basis: str = "retention-hold",
    ) -> None:
        logger.info(
            "hold-event %s basis=%s op_id=%s resource_id=%s operator=%s",
            outcome, basis, op_id, resource_id, operator_id,
        )
