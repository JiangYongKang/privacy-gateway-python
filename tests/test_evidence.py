"""Evidence export + offline verification: determinism, tamper detection,
state fidelity (expired / hold_active / basis), and value-freeness."""

from __future__ import annotations

import json
import subprocess
import sys

import pytest
from fastapi.testclient import TestClient

from privacy_gateway.audit import AuditLog
from privacy_gateway.clock import FixedClock
from privacy_gateway.decider import Decider
from privacy_gateway.evidence import (
    canonical_bytes,
    export_evidence,
    verify_evidence,
)
from privacy_gateway.fixtures import ANCHOR_NOW, V2, build_seed_store
from privacy_gateway.holds import HoldService
from privacy_gateway.models import AccessRequest


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
    decider = Decider(store, audit, clock)
    holds = HoldService(store, audit, clock)
    # One expired-but-held allow, one plain allow, one deny.
    holds.place_hold("ev-hold", "r-patient-old", "carol", "case 42")
    decider.decide(_req("ev-held", "alice", "r-patient-old"))
    decider.decide(_req("ev-allow", "alice", "r-patient-1"))
    decider.decide(_req("ev-deny", "mallory", "r-patient-1"))
    return store, audit, clock, decider, holds


def test_export_is_byte_identical_across_exports(env):
    _, audit, _, _, _ = env
    first = canonical_bytes(export_evidence(audit, "ev-held"))
    second = canonical_bytes(export_evidence(audit, "ev-held"))
    assert first == second
    # digest is stable
    assert export_evidence(audit, "ev-held")["digest"] == export_evidence(audit, "ev-held")["digest"]


def test_export_is_byte_identical_in_a_fresh_process(env):
    _, audit, _, _, _ = env
    doc = export_evidence(audit, "ev-held")
    expected = canonical_bytes(doc).decode("utf-8")

    # Rebuild the exact same world in a subprocess and export there.
    program = """
import json
from privacy_gateway.audit import AuditLog
from privacy_gateway.clock import FixedClock
from privacy_gateway.decider import Decider
from privacy_gateway.evidence import canonical_bytes, export_evidence
from privacy_gateway.fixtures import ANCHOR_NOW, V2, build_seed_store
from privacy_gateway.holds import HoldService
from privacy_gateway.models import AccessRequest

store = build_seed_store(); audit = AuditLog(); clock = FixedClock(ANCHOR_NOW)
d = Decider(store, audit, clock); h = HoldService(store, audit, clock)
h.place_hold("ev-hold", "r-patient-old", "carol", "case 42")
d.decide(AccessRequest(request_id="ev-held", caller_id="alice",
                       resource_id="r-patient-old", policy_version=V2))
print(canonical_bytes(export_evidence(audit, "ev-held")).decode("utf-8"))
"""
    out = subprocess.run(
        [sys.executable, "-c", program], capture_output=True, text=True, check=True,
    )
    assert out.stdout.strip() == expected


def test_verify_roundtrip_consistent(env):
    _, audit, _, _, _ = env
    for rid in ("ev-held", "ev-allow", "ev-deny", "ev-hold"):
        result = verify_evidence(audit, export_evidence(audit, rid))
        assert result.consistent, result.mismatches


def test_verify_repeatedly_consistent_over_time(env):
    _, audit, _, decider, _ = env
    doc = export_evidence(audit, "ev-held")
    # More activity happens afterwards; verification of the old document
    # must still match the historical conclusion.
    decider.decide(_req("ev-later", "alice", "r-patient-1"))
    for _ in range(3):
        result = verify_evidence(audit, doc)
        assert result.consistent, result.mismatches


def test_tampered_document_is_reported_inconsistent(env):
    _, audit, _, _, _ = env
    doc = export_evidence(audit, "ev-held")

    # Flip the expired state and fix up the digest so only the *content*
    # differs from the stored decision.
    tampered = dict(doc)
    tampered["expired"] = False
    body = {k: v for k, v in tampered.items() if k != "digest"}
    import hashlib
    tampered["digest"] = hashlib.sha256(canonical_bytes(body)).hexdigest()

    result = verify_evidence(audit, tampered)
    assert not result.consistent
    assert any("expired" in m for m in result.mismatches)


def test_corrupted_digest_is_reported_inconsistent(env):
    _, audit, _, _, _ = env
    doc = export_evidence(audit, "ev-allow")
    doc = dict(doc, digest="0" * 64)
    result = verify_evidence(audit, doc)
    assert not result.consistent
    assert any("digest" in m for m in result.mismatches)


def test_unknown_request_id_is_explicitly_inconsistent(env):
    _, audit, _, _, _ = env
    doc = export_evidence(audit, "ev-allow")
    doc = dict(doc, request_id="nope")
    result = verify_evidence(audit, doc)
    assert not result.consistent
    assert any("no audit entry" in m for m in result.mismatches)


def test_export_unknown_request_id_raises(env):
    _, audit, _, _, _ = env
    with pytest.raises(Exception) as excinfo:
        export_evidence(audit, "ghost")
    assert getattr(excinfo.value, "code", "") == "EVIDENCE_NOT_FOUND"


def test_evidence_records_expired_hold_and_basis_state(env):
    _, audit, _, _, _ = env
    held = export_evidence(audit, "ev-held")
    assert held["expired"] is True and held["hold_active"] is True
    assert held["basis"] == "allow-under-retention-hold"
    assert held["decision"] == "allow"

    deny = export_evidence(audit, "ev-deny")
    assert deny["decision"] == "deny" and deny["deny_code"] == "ACCESS_DENIED"
    assert deny["expired"] is False and deny["hold_active"] is False

    hold_evt = export_evidence(audit, "ev-hold")
    assert hold_evt["event_type"] == "retention_hold"
    assert hold_evt["basis"] == "retention-hold-placed"


def test_evidence_contains_no_raw_sensitive_values(env):
    _, audit, _, _, _ = env
    blob = json.dumps(
        [export_evidence(audit, rid) for rid in ("ev-held", "ev-allow", "ev-deny")],
        ensure_ascii=False,
    )
    for secret in ("123-45-6789", "987-65-4321", "张三丰", "李白",
                   "13812345678", "13987654321", "4111111111111111",
                   "hypertension", "migraine"):
        assert secret not in blob


def test_evidence_endpoints_over_http(engine_env):
    _, audit, _, app = engine_env
    c = TestClient(app)
    c.post("/v1/access/decide", json={"request_id": "http-ev1", "caller_id": "alice",
                                      "resource_id": "r-patient-1"})
    doc = c.get("/v1/evidence/http-ev1").json()
    assert doc["request_id"] == "http-ev1" and doc["decision"] == "allow"

    ok = c.post("/v1/evidence/verify", json=doc).json()
    assert ok["consistent"] is True and ok["mismatches"] == []

    bad = dict(doc, decision="deny")
    nok = c.post("/v1/evidence/verify", json=bad).json()
    assert nok["consistent"] is False and nok["mismatches"]

    missing = c.get("/v1/evidence/ghost")
    assert missing.status_code == 404
    assert missing.json()["error"]["code"] == "EVIDENCE_NOT_FOUND"
