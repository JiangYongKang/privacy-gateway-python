"""Replay historical decisions from the audit trail.

Replay never re-evaluates against live policy or data: it renders the stored
snapshot, so upgrading the current policy version cannot change a historical
conclusion. Output shape matches :meth:`DecisionResult.to_response`.
"""

from __future__ import annotations

from typing import Any

from .audit import AuditLog
from .decider import _replay_result
from .models import AuditEntry


def replay_entry(entry: AuditEntry) -> dict[str, Any]:
    """Re-express a stored audit entry as the response a caller would see."""

    return _replay_result(entry).to_response()


def replay_all(audit: AuditLog) -> list[dict[str, Any]]:
    """All decisions in deterministic append (sequence) order."""

    return [replay_entry(e) for e in audit.entries()]
