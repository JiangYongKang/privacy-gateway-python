"""Retention hold (legal hold) semantics: placement, release, auditability,
and cross-attempt consistency of the expired/hold state."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from privacy_gateway.audit import AuditLog
from privacy_gateway.clock import FixedClock
from privacy_gateway.decider import Decider
from privacy_gateway.fixtures import ANCHOR_NOW, V2, build_seed_store
from privacy_gateway.holds import HoldService
from privacy_gateway.models import AccessRequest, Decision
from privacy_gateway.replay import replay_all


def _req(rid, caller, res, version=V2, fields=None):
    return AccessRequest(
        request_id=rid, caller_id=caller, resource_id=res,
        policy_version=version,
        fields=tuple(fields) if fields is not None else None,
    )


@pytest.fixture()
def env():
    store = build_seed_store()
    audit = AuditLog()
    clock = FixedClock(ANCHOR_NOW)
    return store, audit, clock, Decider(store, audit, clock), HoldService(store, audit, clock)


def test_hold_makes_expired_resource_readable_with_masking(env):
    store, audit, clock, decider, holds = env
    # r-patient-old is >365d old: expired under v2 patient_health (365d).
    before = decider.decide(_req("h-pre", "alice", "r-patient-old"))
    assert before.decision is Decision.DENY and before.expired

    holds.place_hold("hold-1", "r-patient-old", "carol", "legal case 42")

    during = decider.decide(_req("h-during", "alice", "r-patient-old"))
    assert during.decision is Decision.ALLOW
    assert during.expired is True          # still past the plain horizon
    assert during.hold_active is True
    # masking is unchanged by the hold
    assert during.fields["ssn"].value.startswith("sha256:")
    assert during.fields["patient_name"].value == "李*"
    assert during.fields["diagnosis"].value == "migr****"


def test_release_restores_plain_retention_immediately(env):
    store, audit, clock, decider, holds = env
    holds.place_hold("hold-2", "r-patient-old", "carol", "legal case 42")
    assert decider.decide(_req("r-during", "alice", "r-patient-old")).decision is Decision.ALLOW

    holds.release_hold("rel-2", "r-patient-old", "carol")

    after = decider.decide(_req("r-after", "alice", "r-patient-old"))
    assert after.decision is Decision.DENY and after.expired
    assert after.hold_active is False
    entry = audit.get_by_request("r-after")
    assert entry.deny_code == "RETENTION_EXPIRED"


def test_hold_and_release_are_audited_with_distinguishable_basis(env):
    store, audit, clock, decider, holds = env
    holds.place_hold("hold-3", "r-patient-old", "carol", "case 7")
    holds.release_hold("rel-3", "r-patient-old", "carol")
    decider.decide(_req("x-allow", "alice", "r-patient-1"))   # plain allow
    decider.decide(_req("x-deny", "mallory", "r-patient-1"))  # access denied

    by_id = {e.request_id: e for e in audit.entries()}
    assert by_id["hold-3"].event_type == "retention_hold"
    assert by_id["hold-3"].basis == "retention-hold-placed"
    assert by_id["hold-3"].decision is Decision.RECORDED
    assert by_id["rel-3"].event_type == "retention_release"
    assert by_id["rel-3"].basis == "retention-hold-released"
    # bases are distinguishable from ordinary reads / denials
    bases = {e.basis for e in audit.entries()}
    assert {"retention-hold-placed", "retention-hold-released",
            "allow", "access-denied"} <= bases

    # hold/release events replay like any other decision
    replayed = {r["request_id"]: r for r in replay_all(audit)}
    assert replayed["hold-3"]["decision"] == "recorded"
    assert replayed["rel-3"]["decision"] == "recorded"


def test_same_request_consistent_first_retry_and_replay_under_hold(env):
    store, audit, clock, decider, holds = env
    holds.place_hold("hold-4", "r-patient-old", "carol", "case 8")

    first = decider.decide(_req("cons-1", "alice", "r-patient-old"))
    # hold released afterwards: the historical conclusion must not move
    holds.release_hold("rel-4", "r-patient-old", "carol")

    retry = decider.decide(_req("cons-1", "alice", "r-patient-old"))
    assert retry == first
    assert retry.expired is True and retry.hold_active is True

    replayed = [r for r in replay_all(audit) if r["request_id"] == "cons-1"][0]
    assert replayed == first.to_response()
    assert replayed["expired"] is True and replayed["hold_active"] is True
    # and the audit log still holds exactly one entry for the request
    assert sum(1 for e in audit.entries() if e.request_id == "cons-1") == 1


def test_hold_and_release_are_idempotent(env):
    store, audit, clock, decider, holds = env
    h1 = holds.place_hold("hold-5", "r-patient-old", "carol", "case 9")
    h2 = holds.place_hold("hold-5", "r-patient-old", "carol", "case 9")
    assert h1 == h2
    assert sum(1 for e in audit.entries() if e.request_id == "hold-5") == 1

    r1 = holds.release_hold("rel-5", "r-patient-old", "carol")
    r2 = holds.release_hold("rel-5", "r-patient-old", "carol")
    assert r1 == r2
    assert sum(1 for e in audit.entries() if e.request_id == "rel-5") == 1

    # same id, different payload -> conflict, state untouched
    with pytest.raises(Exception) as excinfo:
        holds.place_hold("hold-5", "r-patient-1", "carol", "different")
    assert getattr(excinfo.value, "code", "") == "IDEMPOTENCY_CONFLICT"


def test_release_without_active_hold_is_rejected(env):
    store, audit, clock, decider, holds = env
    with pytest.raises(Exception) as excinfo:
        holds.release_hold("rel-x", "r-patient-old", "carol")
    assert getattr(excinfo.value, "code", "") == "HOLD_NOT_FOUND"


def test_hold_prevents_purge_on_expiry(env):
    store, audit, clock, decider, holds = env
    from privacy_gateway.models import ExpiryAction, FieldRule, MaskAction, Policy, ScopePolicy
    purge_scope = ScopePolicy(
        scope="patient_health",
        allowed_callers=frozenset({"alice"}),
        field_rules={
            "record_id": FieldRule("record_id", MaskAction.VISIBLE),
            "patient_name": FieldRule("patient_name", MaskAction.REDACT),
            "ssn": FieldRule("ssn", MaskAction.HASH, hash_prefix=4),
            "phone": FieldRule("phone", MaskAction.REDACT),
            "diagnosis": FieldRule("diagnosis", MaskAction.REDACT),
        },
        retention_days=30,
        on_expiry=ExpiryAction.PURGE,
    )
    store.add_policy(Policy(version="policy-purge-hold",
                            scope_policies={"patient_health": purge_scope},
                            default_retention_days=30,
                            created_at="2026-09-01T00:00:00Z"))
    holds.place_hold("hold-6", "r-patient-old", "carol", "keep")
    res = decider.decide(_req("pp-1", "alice", "r-patient-old", "policy-purge-hold"))
    assert res.decision is Decision.ALLOW and res.hold_active
    assert store.get_resource("r-patient-old") is not None  # not purged


def test_hold_endpoints_over_http(engine_env):
    store, audit, clock, app = engine_env
    c = TestClient(app)
    r = c.post("/v1/holds", json={"hold_id": "http-h1", "resource_id": "r-patient-old",
                                  "operator_id": "carol", "reason": "case 11"})
    assert r.status_code == 200 and r.json()["decision"] == "recorded"

    r = c.post("/v1/access/decide", json={"request_id": "http-a1", "caller_id": "alice",
                                          "resource_id": "r-patient-old"})
    assert r.status_code == 200 and r.json()["hold_active"] is True

    r = c.post("/v1/holds/release", json={"release_id": "http-r1",
                                          "resource_id": "r-patient-old",
                                          "operator_id": "carol"})
    assert r.status_code == 200

    r = c.post("/v1/access/decide", json={"request_id": "http-a2", "caller_id": "alice",
                                          "resource_id": "r-patient-old"})
    assert r.status_code == 410 and r.json()["deny_code"] == "RETENTION_EXPIRED"

    # unknown operator / double release are distinguishable errors
    r = c.post("/v1/holds", json={"hold_id": "http-h2", "resource_id": "r-patient-old",
                                  "operator_id": "nobody", "reason": "x"})
    assert r.status_code == 401 and r.json()["error"]["code"] == "UNAUTHORIZED_CALLER"
    r = c.post("/v1/holds/release", json={"release_id": "http-r2",
                                          "resource_id": "r-patient-old",
                                          "operator_id": "carol"})
    assert r.status_code == 404 and r.json()["error"]["code"] == "HOLD_NOT_FOUND"
