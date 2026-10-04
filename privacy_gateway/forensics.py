"""Decision evidence export and offline verification.

``export_evidence`` renders a stored audit entry as a machine-readable,
byte-deterministic document (canonical JSON + SHA-256 checksum) containing
only safe material — never raw sensitive values. Re-exporting the same
historical conclusion at any time, in any process, yields byte-identical
output, so compliance can compare exports byte for byte.

``verify_evidence`` checks a previously exported document against the
authoritative audit log and reports an explicit CONSISTENT / INCONSISTENT
verdict. Tampering, or any drift from the historical conclusion — including
the retention state at decision time and how the request was handled
(decision / deny code) — yields INCONSISTENT, never a silent pass.

Compatibility scope: documents carry ``schema = privacy-gateway/evidence@1``;
verification accepts exactly that schema version and reports anything else
as INCONSISTENT.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from .audit import AuditLog
from .errors import AuditNotFoundError

EVIDENCE_SCHEMA = "privacy-gateway/evidence@1"


@dataclass(frozen=True)
class EvidenceVerdict:
    """Outcome of verifying an evidence document. Safe fields only."""

    status: str                      # "CONSISTENT" | "INCONSISTENT"
    request_id: str = ""
    mismatches: tuple[str, ...] = field(default_factory=tuple)

    @property
    def consistent(self) -> bool:
        return self.status == "CONSISTENT"

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "consistent": self.consistent,
            "request_id": self.request_id,
            "mismatches": list(self.mismatches),
        }


def _canonical(obj: Any) -> bytes:
    """Byte-deterministic JSON: sorted keys, tight separators, ASCII-only."""

    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("utf-8")


def _checksum(entry_dict: dict) -> str:
    return hashlib.sha256(_canonical(entry_dict)).hexdigest()


def export_evidence(audit: AuditLog, request_id: str) -> bytes:
    """Render the stored conclusion for ``request_id`` as canonical bytes.

    The document contains the audit entry as stored (decision, deny code,
    retention state, masked field snapshot, timestamps) plus a SHA-256
    checksum over the canonical entry encoding.
    """

    entry = audit.get_by_request(request_id)
    if entry is None:
        raise AuditNotFoundError(f"no audit entry for request {request_id!r}")
    entry_dict = entry.to_dict()
    document = {
        "schema": EVIDENCE_SCHEMA,
        "entry": entry_dict,
        "checksum": _checksum(entry_dict),
    }
    return _canonical(document)


def verify_evidence(blob: bytes, audit: AuditLog) -> EvidenceVerdict:
    """Check an exported document against the audit log; never raises."""

    try:
        document = json.loads(blob)
    except (ValueError, UnicodeDecodeError):
        return EvidenceVerdict(status="INCONSISTENT", mismatches=("unparseable",))
    if not isinstance(document, dict):
        return EvidenceVerdict(status="INCONSISTENT", mismatches=("unparseable",))

    if document.get("schema") != EVIDENCE_SCHEMA:
        return EvidenceVerdict(status="INCONSISTENT", mismatches=("schema",))

    entry_dict = document.get("entry")
    checksum = document.get("checksum")
    if not isinstance(entry_dict, dict) or not isinstance(checksum, str):
        return EvidenceVerdict(status="INCONSISTENT", mismatches=("structure",))

    request_id = str(entry_dict.get("request_id", ""))

    # 1. Self-integrity: the checksum must match the embedded entry.
    if _checksum(entry_dict) != checksum:
        return EvidenceVerdict(
            status="INCONSISTENT", request_id=request_id,
            mismatches=("checksum",),
        )

    # 2. Authority: the entry must match the stored historical conclusion
    #    exactly (decision, deny code, retention state, snapshot, ...).
    stored = audit.get_by_request(request_id)
    if stored is None:
        return EvidenceVerdict(
            status="INCONSISTENT", request_id=request_id,
            mismatches=("request_id",),
        )
    stored_dict = stored.to_dict()
    if stored_dict != entry_dict:
        mismatches = tuple(sorted(
            key for key in set(stored_dict) | set(entry_dict)
            if stored_dict.get(key) != entry_dict.get(key)
        ))
        return EvidenceVerdict(
            status="INCONSISTENT", request_id=request_id,
            mismatches=mismatches,
        )

    return EvidenceVerdict(status="CONSISTENT", request_id=request_id)
