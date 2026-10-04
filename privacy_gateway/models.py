"""Core data types for the privacy gateway.

These are plain, serialisable dataclasses. None of them hold behaviour beyond
identity / canonicalisation helpers used for deterministic serialisation.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# Policy model
# ---------------------------------------------------------------------------

class MaskAction(str, Enum):
    """Deterministic field-level masking actions."""

    VISIBLE = "visible"        # explicit allow: value passes through unchanged
    REDACT = "redact"          # fixed token, no information about the value
    MASK = "mask"              # keep a fixed prefix, replace the rest with '*'
    HASH = "hash"              # stable SHA-256 fingerprint with fixed prefix


class ExpiryAction(str, Enum):
    """What a decision returns when a resource is past its retention horizon."""

    DENY = "deny"              # reject with RETENTION_EXPIRED (default)
    TOMBSTONE = "tombstone"    # return only {"resource_id": ..., "expired": true}
    PURGE = "purge"            # local data is erased, then DENY


@dataclass(frozen=True)
class FieldRule:
    """Masking rule for a single field within a scope."""

    field_name: str
    action: MaskAction
    keep_prefix: int = 0       # used by MASK
    hash_prefix: int = 8       # used by HASH (hex chars retained)


@dataclass(frozen=True)
class ScopePolicy:
    """Access + field rules for one resource scope in one policy version."""

    scope: str
    allowed_callers: frozenset[str]
    field_rules: dict[str, FieldRule]
    default_field_action: MaskAction = MaskAction.REDACT
    on_expiry: ExpiryAction = ExpiryAction.DENY
    retention_days: int | None = None  # scope-level override; None => global


@dataclass(frozen=True)
class Policy:
    """An immutable, versioned policy bundle."""

    version: str
    scope_policies: dict[str, ScopePolicy]
    default_retention_days: int = 90
    created_at: str = ""

    def scope(self, name: str) -> ScopePolicy | None:
        return self.scope_policies.get(name)


# ---------------------------------------------------------------------------
# Callers & resources (local storage fixtures)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Caller:
    caller_id: str
    display_name: str


@dataclass(frozen=True)
class Resource:
    """A stored resource. ``created_at`` anchors the retention window."""

    resource_id: str
    scope: str
    created_at: str                      # ISO-8601 UTC, e.g. 2026-01-01T00:00:00Z
    data: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Decisions & audit
# ---------------------------------------------------------------------------

class Decision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    TOMBSTONE = "tombstone"  # retention horizon passed: only a stub is emitted


class RetentionState(str, Enum):
    """Whether the resource was past its retention horizon *at decision time*.

    Recorded on every decision/audit entry so first evaluation, idempotent
    retry and later replay all report the same historical state.
    """

    WITHIN = "within_retention"
    EXPIRED = "past_retention"
    EXPIRED_HOLD = "past_retention_hold_active"  # past horizon, readable via hold


class AuditEventType(str, Enum):
    """Distinguishes what kind of action an audit entry records."""

    ACCESS = "access"                  # a read decision (allow/deny/tombstone)
    HOLD_PLACE = "hold_place"          # a retention extension was attached
    HOLD_RELEASE = "hold_release"      # a retention extension was lifted


# ---------------------------------------------------------------------------
# Retention holds (legal-hold style retention extension)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RetentionHold:
    """A retention extension attached to one specific resource.

    While ``released_at`` is None the hold is active: reads of a resource past
    its ordinary retention horizon proceed (with masking as usual). Releasing
    the hold immediately restores ordinary retention handling. The record
    itself is immutable; a release produces a new record value in the store.
    """

    hold_id: str
    resource_id: str
    placed_by: str
    reason: str
    placed_at: str
    released_at: str | None = None
    released_by: str | None = None

    @property
    def active(self) -> bool:
        return self.released_at is None

    def to_dict(self) -> dict[str, Any]:
        return {
            "hold_id": self.hold_id,
            "resource_id": self.resource_id,
            "placed_by": self.placed_by,
            "reason": self.reason,
            "placed_at": self.placed_at,
            "released_at": self.released_at,
            "released_by": self.released_by,
            "active": self.active,
        }


@dataclass(frozen=True)
class AccessRequest:
    """A single read attempt. ``request_id`` drives audit idempotency."""

    request_id: str
    caller_id: str
    resource_id: str
    policy_version: str | None = None   # None => current version
    fields: tuple[str, ...] | None = None  # projected fields; None => all
    submitted_at: str = ""


@dataclass(frozen=True)
class FieldOutcome:
    field_name: str
    action: MaskAction
    value: Any                           # already masked; never a raw secret


@dataclass(frozen=True)
class DecisionResult:
    request_id: str
    decision: Decision
    policy_version: str
    caller_id: str
    resource_id: str
    scope: str
    fields: dict[str, FieldOutcome] = field(default_factory=dict)
    reason: str = ""                     # human-readable, safe text only
    decided_at: str = ""
    expired: bool = False                # True when past the retention horizon
    retention_state: str = RetentionState.WITHIN.value

    def to_response(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "decision": self.decision.value,
            "policy_version": self.policy_version,
            "caller_id": self.caller_id,
            "resource_id": self.resource_id,
            "scope": self.scope,
            "reason": self.reason,
            "decided_at": self.decided_at,
            "expired": self.expired,
            "retention_state": self.retention_state,
            "fields": {
                name: {"action": fo.action.value, "value": fo.value}
                for name, fo in sorted(self.fields.items())
            },
        }


@dataclass(frozen=True)
class AuditEntry:
    """One idempotent, append-only audit record.

    Stores only the decision, the masked output and safe metadata — never raw
    field values.
    """

    sequence: int
    request_id: str
    decision: Decision
    deny_code: str                       # "" when allowed
    reason: str
    policy_version: str
    caller_id: str
    resource_id: str
    scope: str
    fields_snapshot: dict[str, Any]
    request_fingerprint: str
    decided_at: str
    event_type: str = AuditEventType.ACCESS.value
    retention_state: str = RetentionState.WITHIN.value
    hold_id: str = ""                    # set on hold_place / hold_release events

    def to_dict(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "request_id": self.request_id,
            "decision": self.decision.value,
            "deny_code": self.deny_code,
            "reason": self.reason,
            "policy_version": self.policy_version,
            "caller_id": self.caller_id,
            "resource_id": self.resource_id,
            "scope": self.scope,
            "fields_snapshot": self.fields_snapshot,
            "request_fingerprint": self.request_fingerprint,
            "decided_at": self.decided_at,
            "event_type": self.event_type,
            "retention_state": self.retention_state,
            "hold_id": self.hold_id,
        }


def fingerprint_request(req: AccessRequest) -> str:
    """Deterministic fingerprint of the *safe* parts of a request.

    Used to detect request-id reuse with a different payload. Raw resource
    values are not part of a request, so no secret can enter the digest.
    """

    payload = {
        "caller_id": req.caller_id,
        "resource_id": req.resource_id,
        "policy_version": req.policy_version,
        "fields": list(req.fields) if req.fields is not None else None,
    }
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()
