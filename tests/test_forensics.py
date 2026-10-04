"""Forensic evidence: byte-deterministic export, offline verification,
explicit INCONSISTENT verdicts on tampering, no raw secrets anywhere."""

from __future__ import annotations

import json

from fastapi.testclient import TestClient

from privacy_gateway.decider import Decider
from privacy_gateway.forensics import (
    EVIDENCE_SCHEMA,
    export_evidence,
    verify_evidence,
)
from privacy_gateway.holds import HoldManager
from privacy_gateway.models import AccessRequest


def _req(rid, caller, res, version=None):
    return AccessRequest(request_id=rid, caller_id=caller,
                         resource_id=res, policy_version=version)


def _make_history(engine_env):
    """One allow, one deny, one hold-covered allow: three handling styles."""
    store, audit, clock, _ = engine_env
    d = Decider(store, audit, clock)
    d.decide(_req("fx-allow", "alice", "r-patient-1"))
    d.decide(_req("fx-deny", "mallory", "r-patient-1"))
    HoldManager(store, audit, clock).place_hold(
        "fx-hold", "r-patient-old", "ops", "legal case LC-90")
    d.decide(_req("fx-hold-allow", "alice", "r-patient-old"))
    return audit


def test_export_is_byte_deterministic_across_exports(engine_env):
    audit = _make_history(engine_env)
    first = export_evidence(audit, "fx-allow")
    again = export_evidence(audit, "fx-allow")
    assert first == again  # byte-for-byte identical
    # Canonical form: sorted keys, tight separators, ASCII-only.
    assert first == json.dumps(
        json.loads(first), sort_keys=True, separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def test_verify_roundtrip_consistent_for_every_handling_style(engine_env):
    audit = _make_history(engine_env)
    for rid, state in [
        ("fx-allow", "within_retention"),
        ("fx-deny", "within_retention"),
        ("fx-hold-allow", "past_retention_hold_active"),
    ]:
        verdict = verify_evidence(export_evidence(audit, rid), audit)
        assert verdict.consistent, rid
        assert verdict.status == "CONSISTENT"
        assert json.loads(export_evidence(audit, rid))["entry"][
            "retention_state"] == state


def test_verify_via_http_endpoint(engine_env):
    audit = _make_history(engine_env)
    c = TestClient(engine_env[3])
    exported = c.get("/v1/forensics/fx-deny")
    assert exported.status_code == 200
    r = c.post("/v1/forensics/verify", json={"evidence": exported.json()})
    assert r.json()["status"] == "CONSISTENT"
    assert c.get("/v1/forensics/ghost").status_code == 404


def test_tampered_evidence_is_explicitly_inconsistent(engine_env):
    audit = _make_history(engine_env)
    good = json.loads(export_evidence(audit, "fx-hold-allow"))

    def tamper(mutate):
        doc = json.loads(json.dumps(good))
        mutate(doc)
        blob = json.dumps(doc, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True).encode()
        verdict = verify_evidence(blob, audit)
        assert not verdict.consistent
        assert verdict.status == "INCONSISTENT"
        return verdict

    # Flipped decision.
    v = tamper(lambda d: d["entry"].update(decision="deny"))
    assert "checksum" in v.mismatches
    # Flipped was-expired state.
    tamper(lambda d: d["entry"].update(retention_state="within_retention"))
    # Forged checksum that matches the entry but not the stored conclusion.
    def forge(d):
        import hashlib
        d["entry"]["deny_code"] = "RETENTION_EXPIRED"
        d["checksum"] = hashlib.sha256(json.dumps(
            d["entry"], sort_keys=True, separators=(",", ":"),
            ensure_ascii=True).encode()).hexdigest()
    v = tamper(forge)
    assert "deny_code" in v.mismatches
    # Unknown historical conclusion.
    tamper(lambda d: (d["entry"].update(request_id="never-happened"),
                      d.update(checksum="0" * 64)))
    # Wrong schema version.
    v = tamper(lambda d: d.update(schema="privacy-gateway/evidence@0"))
    assert "schema" in v.mismatches
    # Garbage bytes.
    assert not verify_evidence(b"{not json", audit).consistent


def test_verdict_never_raises_on_malformed_input(engine_env):
    audit = _make_history(engine_env)
    for blob in (b"", b"null", b"[]", b"{}", b'{"schema": 1}',
                 json.dumps({"schema": EVIDENCE_SCHEMA}).encode()):
        verdict = verify_evidence(blob, audit)
        assert verdict.status == "INCONSISTENT"


def test_evidence_and_verdict_contain_no_raw_secrets(engine_env):
    audit = _make_history(engine_env)
    blob = export_evidence(audit, "fx-allow")
    verdict = verify_evidence(blob, audit)
    combined = blob + json.dumps(verdict.to_dict()).encode()
    for secret in ("123-45-6789", "张三丰", "13812345678",
                   "hypertension stage 2"):
        assert secret not in combined.decode()


def test_exported_hold_events_verify_too(engine_env):
    """Hold place/release events are exportable, verifiable conclusions."""
    audit = _make_history(engine_env)
    for rid in ("hold-place-fx-hold",):
        blob = export_evidence(audit, rid)
        doc = json.loads(blob)
        assert doc["entry"]["event_type"] == "hold_place"
        assert verify_evidence(blob, audit).consistent
