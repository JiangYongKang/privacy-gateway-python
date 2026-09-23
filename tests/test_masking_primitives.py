"""Pure masking determinism + replay rendering stability."""

from __future__ import annotations

from privacy_gateway.audit import AuditLog
from privacy_gateway.clock import FixedClock
from privacy_gateway.decider import Decider
from privacy_gateway.fixtures import build_seed_store
from privacy_gateway.masking import REDACT_TOKEN, hash_value, mask_value
from privacy_gateway.models import AccessRequest
from privacy_gateway.replay import replay_all


def test_mask_and_hash_are_deterministic():
    assert mask_value("13812345678", 3) == "138********"
    assert mask_value("13812345678", 3) == mask_value("13812345678", 3)
    assert mask_value("", 3) == REDACT_TOKEN
    assert mask_value("ab", 9) == "ab"  # prefix clamped to length
    assert hash_value("123-45-6789", 8) == hash_value("123-45-6789", 8)
    assert hash_value("123-45-6789", 8) != hash_value("987-65-4321", 8)
    assert hash_value("123-45-6789", 8).startswith("sha256:")


def test_replay_renders_stored_verdict_and_fields():
    store = build_seed_store()
    audit = AuditLog()
    clock = FixedClock("2026-09-23T12:00:00Z")
    d = Decider(store, audit, clock)
    d.decide(AccessRequest(request_id="rp1", caller_id="alice",
                           resource_id="r-patient-1"))
    d.decide(AccessRequest(request_id="rp2", caller_id="mallory",
                           resource_id="r-patient-1"))

    rows = replay_all(audit)
    assert [r["request_id"] for r in rows] == ["rp1", "rp2"]  # sequence order
    allow, deny = rows
    assert allow["decision"] == "allow" and deny["decision"] == "deny"
    assert allow["fields"]["ssn"]["value"].startswith("sha256:")
    assert deny["fields"] == {}

    # replay twice: fully stable
    assert replay_all(audit) == rows
