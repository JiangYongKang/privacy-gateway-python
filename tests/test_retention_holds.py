"""Retention holds: extension makes expired data readable, release restores
ordinary retention, and both actions are audited/replayable with a
distinguishable basis."""

from __future__ import annotations

from fastapi.testclient import TestClient

from privacy_gateway.decider import Decider
from privacy_gateway.holds import HoldManager
from privacy_gateway.models import AccessRequest, AuditEventType
from privacy_gateway.replay import replay_all


def _req(rid, caller, res, version=None):
    return AccessRequest(request_id=rid, caller_id=caller,
                         resource_id=res, policy_version=version)


def test_hold_makes_expired_resource_readable_with_masking(engine_env):
    store, audit, clock, _ = engine_env
    holds = HoldManager(store, audit, clock)
    d = Decider(store, audit, clock)

    # Baseline: r-patient-old is past the 365d horizon -> RETENTION_EXPIRED.
    before = d.decide(_req("h-base", "alice", "r-patient-old"))
    assert before.decision.value == "deny"
    assert audit.get_by_request("h-base").deny_code == "RETENTION_EXPIRED"

    holds.place_hold("hold-1", "r-patient-old", "ops", "legal case LC-77")
    during = d.decide(_req("h-during", "alice", "r-patient-old"))
    assert during.decision.value == "allow"
    assert during.expired is True
    assert during.retention_state == "past_retention_hold_active"
    # Masking still applies exactly as for in-retention reads.
    assert during.fields["ssn"].value.startswith("sha256:")
    assert during.fields["patient_name"].value == "李*"
    assert during.fields["diagnosis"].value == "migr****"
    assert "hold-1" in during.reason


def test_release_restores_retention_immediately(engine_env):
    store, audit, clock, _ = engine_env
    holds = HoldManager(store, audit, clock)
    d = Decider(store, audit, clock)

    holds.place_hold("hold-2", "r-patient-old", "ops", "legal case LC-78")
    assert d.decide(_req("h2-a", "alice", "r-patient-old")).decision.value == "allow"

    holds.release_hold("hold-2", "ops")
    after = d.decide(_req("h2-b", "alice", "r-patient-old"))
    assert after.decision.value == "deny"
    assert after.retention_state == "past_retention"
    assert audit.get_by_request("h2-b").deny_code == "RETENTION_EXPIRED"


def test_hold_and_release_are_audited_with_distinguishable_basis(engine_env):
    store, audit, clock, _ = engine_env
    holds = HoldManager(store, audit, clock)

    holds.place_hold("hold-3", "r-patient-old", "ops", "legal case LC-79")
    holds.release_hold("hold-3", "ops")

    place = audit.get_by_request("hold-place-hold-3")
    release = audit.get_by_request("hold-release-hold-3")
    assert place is not None and release is not None
    # Basis distinguishable from access decisions / authorization denials.
    assert place.event_type == AuditEventType.HOLD_PLACE.value
    assert release.event_type == AuditEventType.HOLD_RELEASE.value
    assert place.hold_id == release.hold_id == "hold-3"
    assert place.resource_id == "r-patient-old"
    # Hold events carry no field content at all.
    assert place.fields_snapshot == {} and release.fields_snapshot == {}


def test_conclusion_stable_across_retry_and_replay(engine_env):
    """First evaluation, idempotent retry (even after release) and replay all
    report the same conclusion and the same was-expired state."""
    store, audit, clock, _ = engine_env
    holds = HoldManager(store, audit, clock)
    d = Decider(store, audit, clock)

    holds.place_hold("hold-4", "r-patient-old", "ops", "legal case LC-80")
    first = d.decide(_req("h4", "alice", "r-patient-old"))
    holds.release_hold("hold-4", "ops")

    # Retry after the release: the stored conclusion must not flip.
    retry = d.decide(_req("h4", "alice", "r-patient-old"))
    assert retry.decision == first.decision
    assert retry.retention_state == first.retention_state
    assert retry.expired == first.expired
    assert retry.fields == first.fields
    assert len([e for e in audit.entries() if e.request_id == "h4"]) == 1

    replayed = [r for r in replay_all(audit) if r["request_id"] == "h4"][0]
    assert replayed["decision"] == "allow"
    assert replayed["retention_state"] == "past_retention_hold_active"
    assert replayed["expired"] is True
    assert replayed["fields"]["ssn"]["value"] == first.fields["ssn"].value


def test_replayed_expired_deny_reports_past_retention(engine_env):
    """A retention denial replays with the same expired state it had live."""
    store, audit, clock, _ = engine_env
    d = Decider(store, audit, clock)
    live = d.decide(_req("h5", "alice", "r-patient-old"))
    assert live.expired is True
    replayed = [r for r in replay_all(audit) if r["request_id"] == "h5"][0]
    assert replayed["expired"] is True
    assert replayed["retention_state"] == "past_retention"


def test_hold_placement_is_idempotent_and_conflict_safe(engine_env):
    store, audit, clock, app = engine_env
    c = TestClient(app)
    body = {"hold_id": "hold-6", "resource_id": "r-patient-old",
            "placed_by": "ops", "reason": "legal case LC-81"}
    r1 = c.post("/v1/holds", json=body)
    r2 = c.post("/v1/holds", json=body)
    assert r1.status_code == r2.status_code == 200
    assert r1.json() == r2.json()
    # Exactly one hold_place audit event despite the retry.
    places = [e for e in audit.entries() if e.event_type == "hold_place"]
    assert len(places) == 1

    # Same hold id, different payload -> conflict, state untouched.
    r3 = c.post("/v1/holds", json={**body, "reason": "different case"})
    assert r3.status_code == 409
    assert r3.json()["error"]["code"] == "HOLD_CONFLICT"
    assert len([e for e in audit.entries() if e.event_type == "hold_place"]) == 1


def test_release_is_idempotent_and_unknown_hold_is_404(engine_env):
    store, audit, clock, app = engine_env
    c = TestClient(app)
    c.post("/v1/holds", json={"hold_id": "hold-7", "resource_id": "r-patient-old",
                              "placed_by": "ops", "reason": "LC-82"})
    r1 = c.post("/v1/holds/hold-7/release", json={"released_by": "ops"})
    r2 = c.post("/v1/holds/hold-7/release", json={"released_by": "ops"})
    assert r1.json() == r2.json()
    assert r2.json()["active"] is False
    releases = [e for e in audit.entries() if e.event_type == "hold_release"]
    assert len(releases) == 1

    missing = c.post("/v1/holds/nope/release", json={"released_by": "ops"})
    assert missing.status_code == 404
    assert missing.json()["error"]["code"] == "HOLD_NOT_FOUND"


def test_hold_on_missing_resource_rejected(engine_env):
    store, audit, clock, app = engine_env
    c = TestClient(app)
    r = c.post("/v1/holds", json={"hold_id": "hold-8", "resource_id": "ghost",
                                  "placed_by": "ops", "reason": "LC-83"})
    assert r.status_code == 404
    assert r.json()["error"]["code"] == "RESOURCE_NOT_FOUND"
    assert audit.entries() == []


def test_hold_does_not_widen_access_or_unmask(engine_env):
    """A hold only suspends the retention horizon; authorization and masking
    are untouched."""
    store, audit, clock, app = engine_env
    c = TestClient(app)
    c.post("/v1/holds", json={"hold_id": "hold-9", "resource_id": "r-patient-old",
                              "placed_by": "ops", "reason": "LC-84"})
    # mallory is not on the patient_health allow list: still denied.
    r = c.post("/v1/access/decide", json={
        "request_id": "h9", "caller_id": "mallory",
        "resource_id": "r-patient-old"})
    assert r.status_code == 403
    assert r.json()["deny_code"] == "ACCESS_DENIED"
