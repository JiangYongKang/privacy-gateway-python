"""Policy versioning, retention semantics, replay stability."""

from __future__ import annotations

import pytest

from fastapi.testclient import TestClient

from privacy_gateway.clock import FixedClock
from privacy_gateway.decider import Decider
from privacy_gateway.errors import PolicyConflictError
from privacy_gateway.fixtures import V1, V2, build_seed_store
from privacy_gateway.audit import AuditLog
from privacy_gateway.models import AccessRequest
from privacy_gateway.models import (
    ExpiryAction,
    FieldRule,
    MaskAction,
    Policy,
    ScopePolicy,
)
from privacy_gateway.policies import validate_policy
from privacy_gateway.replay import replay_all


def _req(rid, caller, res, version=None, fields=None):
    return AccessRequest(
        request_id=rid, caller_id=caller, resource_id=res,
        policy_version=version,
        fields=tuple(fields) if fields is not None else None,
    )


def test_policy_upgrade_does_not_change_historical_decision(engine_env):
    store, audit, clock, app = engine_env
    c = TestClient(app)
    # Decide under v1 and capture the audit trail.
    r_v1 = c.post("/v1/access/decide", json={
        "request_id": "hist-1", "caller_id": "bob",
        "resource_id": "r-patient-1", "policy_version": V1})
    assert r_v1.status_code == 403  # bob not allowed in v1
    snapshot_before = [e.to_dict() for e in audit.entries()]

    # "Upgrade": v2 is current anyway; replay must render the stored v1 verdict.
    assert store.current_policy_version() == V2
    replay1 = c.get("/v1/replay").json()
    assert replay1[0]["decision"] == "deny"
    assert replay1[0]["policy_version"] == V1

    # A new request for the same subject under the new version is allowed...
    r_v2 = c.post("/v1/access/decide", json={
        "request_id": "hist-2", "caller_id": "bob",
        "resource_id": "r-patient-1", "policy_version": V2})
    assert r_v2.status_code == 200 and r_v2.json()["decision"] == "allow"

    # ...but the historical v1 record is byte-for-byte unchanged.
    snapshot_after = [e.to_dict() for e in audit.entries() if e.request_id == "hist-1"]
    assert snapshot_after == [snapshot_before[0]]
    replayed = [x for x in replay_all(audit) if x["request_id"] == "hist-1"][0]
    assert replayed["decision"] == "deny" and replayed["policy_version"] == V1


def test_retention_expired_deny_does_not_return_content(engine_env):
    store, audit, clock, _ = engine_env
    d = Decider(store, audit, clock)
    result = d.decide(_req("ret-1", "alice", "r-patient-old", V1))
    assert result.decision.value == "deny" and result.expired is True
    assert result.fields == {}
    entry = audit.get_by_request("ret-1")
    assert entry.deny_code == "RETENTION_EXPIRED"
    assert entry.fields_snapshot == {}


def test_retention_threshold_differs_between_versions(engine_env):
    store, audit, clock, _ = engine_env
    d = Decider(store, audit, clock)
    # r-bill-mid is 145d old: within v1's 180d, outside v2's 90d
    ok = d.decide(_req("ret-v1", "bob", "r-bill-mid", V1))
    assert ok.decision.value == "allow"
    assert ok.fields["card_number"].action is MaskAction.HASH

    tomb = d.decide(_req("ret-v2", "bob", "r-bill-mid", V2))
    assert tomb.decision.value == "tombstone" and tomb.expired is True
    assert tomb.fields == {}  # never silently returns full content
    assert "90" in tomb.reason


def test_purge_expiry_erases_then_denies_and_remains_auditable():
    store = build_seed_store()
    audit = AuditLog()
    clock = FixedClock("2026-09-23T12:00:00Z")
    # Craft a policy whose patient_health scope purges on expiry.
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
    p = Policy(version="policy-purge",
               scope_policies={"patient_health": purge_scope},
               default_retention_days=30,
               created_at="2026-09-01T00:00:00Z")
    validate_policy(p)
    store.add_policy(p)
    d = Decider(store, audit, clock)
    result = d.decide(_req("purge-1", "alice", "r-patient-old", "policy-purge"))
    assert result.decision.value == "deny"
    assert store.get_resource("r-patient-old") is None
    assert audit.get_by_request("purge-1").deny_code == "RETENTION_EXPIRED"
    # retry after purge stays a stable denial, still one audit row
    again = d.decide(_req("purge-1", "alice", "r-patient-old", "policy-purge"))
    assert again.decision.value == "deny" and len(audit.entries()) == 1


def test_missing_policy_version_is_rejected_not_defaulted(engine_env):
    store, audit, clock, app = engine_env
    c = TestClient(app)
    r = c.post("/v1/access/decide", json={
        "request_id": "nv", "caller_id": "alice",
        "resource_id": "r-patient-1", "policy_version": "nope"})
    assert r.status_code == 404 and r.json()["error"]["code"] == "POLICY_NOT_FOUND"


def test_policy_conflicts_are_rejected():
    bad_dup = ScopePolicy(
        scope="s", allowed_callers=frozenset({"u"}),
        field_rules={"f": FieldRule("x", MaskAction.MASK, keep_prefix=-1)})
    with pytest.raises(PolicyConflictError):
        validate_policy(Policy(version="bad", scope_policies={"s": bad_dup}))


def test_policy_version_immutable_in_store():
    store = build_seed_store()
    with pytest.raises(PolicyConflictError):
        store.add_policy(Policy(
            version=V1,
            scope_policies={},
            created_at="2026-09-01T00:00:00Z"))


def test_global_default_retention_applies_without_scope_override(engine_env):
    store, audit, clock, _ = engine_env
    # New policy: scope without retention override -> 90d global default.
    sp = ScopePolicy(
        scope="patient_health",
        allowed_callers=frozenset({"alice"}),
        field_rules={
            "record_id": FieldRule("record_id", MaskAction.VISIBLE),
            "patient_name": FieldRule("patient_name", MaskAction.REDACT),
            "ssn": FieldRule("ssn", MaskAction.REDACT),
            "phone": FieldRule("phone", MaskAction.REDACT),
            "diagnosis": FieldRule("diagnosis", MaskAction.REDACT),
        },
    )
    store.add_policy(Policy(version="policy-default-ret",
                            scope_policies={"patient_health": sp},
                            default_retention_days=90,
                            created_at="2026-09-01T00:00:00Z"))
    d = Decider(store, audit, clock)
    # r-bill style 145d resource not relevant; patient-old is ~621d old
    res = d.decide(_req("dr1", "alice", "r-patient-old", "policy-default-ret"))
    assert res.decision.value == "deny" and res.expired
    # patient-1 is 53d old -> allowed
    ok = d.decide(_req("dr2", "alice", "r-patient-1", "policy-default-ret"))
    assert ok.decision.value == "allow"
