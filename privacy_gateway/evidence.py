"""Decision evidence export and offline verification.

``export_evidence`` renders one stored audit entry as a deterministic,
machine-readable document for compliance archival. The document contains
only safe material (identifiers, decision, basis, masked field snapshot,
expiry/hold state) — never raw sensitive values — plus a SHA-256 digest
over its canonical serialisation.

Determinism: canonical JSON (sorted keys, fixed separators, UTF-8) is a pure
function of the stored entry, so re-exporting the same historical decision
at any time, in any process, yields byte-identical output.

``verify_evidence`` re-derives the document from the live audit trail and
compares canonical bytes; any drift — tampering, truncation, or a state
mismatch (e.g. ``expired`` / ``hold_active`` / ``basis``) — is reported as
an explicit inconsistency, never silently passed.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from .audit import AuditLog
from .errors import PrivacyError
from .models import AuditEntry

EVIDENCE_FORMAT = "privacy-gateway-evidence/v1"


class EvidenceNotFoundError(PrivacyError):
    """No audit entry exists for the requested evidence export."""

    code = "EVIDENCE_NOT_FOUND"
    http_status = 404


@dataclass(frozen=True)
class VerificationResult:
    request_id: str
    consistent: bool
    mismatches: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "consistent": self.consistent,
            "mismatches": list(self.mismatches),
        }


def _document(entry: AuditEntry) -> dict[str, Any]:
    """The evidence document body (without its digest)."""

    return {
        "format": EVIDENCE_FORMAT,
        "request_id": entry.request_id,
        "event_type": entry.event_type,
        "decision": entry.decision.value,
        "deny_code": entry.deny_code,
        "basis": entry.basis,
        "reason": entry.reason,
        "policy_version": entry.policy_version,
        "caller_id": entry.caller_id,
        "resource_id": entry.resource_id,
        "scope": entry.scope,
        "expired": entry.expired,
        "hold_active": entry.hold_active,
        "fields_snapshot": entry.fields_snapshot,
        "request_fingerprint": entry.request_fingerprint,
        "decided_at": entry.decided_at,
    }


def canonical_bytes(document: dict[str, Any]) -> bytes:
    """Canonical serialisation: sorted keys, tight separators, UTF-8."""

    return json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")


def _digest(document: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_bytes(document)).hexdigest()


def export_evidence(audit: AuditLog, request_id: str) -> dict[str, Any]:
    """Export the evidence document for one historical decision."""

    entry = audit.get_by_request(request_id)
    if entry is None:
        raise EvidenceNotFoundError(
            f"no audit entry for request_id {request_id!r}"
        )
    doc = _document(entry)
    doc["digest"] = _digest(doc)
    return doc


def verify_evidence(audit: AuditLog, document: dict[str, Any]) -> VerificationResult:
    """Check an evidence document against the live audit trail.

    Verifies (a) the document's internal digest and (b) byte-equality with a
    fresh export of the same historical decision. Every discrepancy is
    reported; nothing is silently accepted.
    """

    request_id = str(document.get("request_id", ""))
    mismatches: list[str] = []

    if document.get("format") != EVIDENCE_FORMAT:
        mismatches.append(
            f"unsupported format {document.get('format')!r}; "
            f"expected {EVIDENCE_FORMAT!r}"
        )

    body = {k: v for k, v in document.items() if k != "digest"}
    if document.get("digest") != _digest(body):
        mismatches.append("document digest does not match its content")

    entry = audit.get_by_request(request_id) if request_id else None
    if entry is None:
        mismatches.append(f"no audit entry for request_id {request_id!r}")
    else:
        fresh = export_evidence(audit, request_id)
        if canonical_bytes(fresh) != canonical_bytes(document):
            for key in sorted(set(fresh) | set(document)):
                if fresh.get(key) != document.get(key):
                    mismatches.append(
                        f"field {key!r} differs from the stored decision"
                    )

    return VerificationResult(
        request_id=request_id,
        consistent=not mismatches,
        mismatches=mismatches,
    )
