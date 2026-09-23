"""Over-authorisation, distinguishable deny codes and deterministic masking."""

from __future__ import annotations

from fastapi.testclient import TestClient


def _post(client, **kw):
    body = {"request_id": kw.pop("request_id"), "caller_id": kw.pop("caller_id"),
            "resource_id": kw.pop("resource_id")}
    body.update(kw)
    return client.post("/v1/access/decide", json=body)


def test_distinct_deny_reasons(engine_env):
    _, _, _, app = engine_env
    c = TestClient(app)

    r = _post(c, request_id="t-unauth", caller_id="eve", resource_id="r-patient-1")
    assert r.status_code == 401 and r.json()["error"]["code"] == "UNAUTHORIZED_CALLER"

    r = _post(c, request_id="t-deny", caller_id="mallory", resource_id="r-patient-1")
    assert r.status_code == 403 and r.json()["deny_code"] == "ACCESS_DENIED"

    r = _post(c, request_id="t-field", caller_id="alice",
              resource_id="r-patient-1", fields=["record_id", "secret_note"])
    assert r.status_code == 403 and r.json()["deny_code"] == "FIELD_FORBIDDEN"

    r = _post(c, request_id="t-nopolicy", caller_id="carol",
              resource_id="r-audit-1", policy_version="policy-v1")
    # audit_logs scope exists only in v2 -> policy gap under v1
    assert r.status_code == 403 and r.json()["deny_code"] == "SCOPE_NOT_POLICIED"

    r = _post(c, request_id="t-nover", caller_id="alice",
              resource_id="r-patient-1", policy_version="policy-v9")
    assert r.status_code == 404 and r.json()["error"]["code"] == "POLICY_NOT_FOUND"

    r = _post(c, request_id="t-nores", caller_id="alice", resource_id="missing")
    assert r.status_code == 404 and r.json()["error"]["code"] == "RESOURCE_NOT_FOUND"


def test_allow_masking_is_deterministic_and_version_sensitive(engine_env):
    _, _, _, app = engine_env
    c = TestClient(app)

    r1 = _post(c, request_id="m1", caller_id="alice", resource_id="r-patient-1")
    r2 = _post(c, request_id="m2", caller_id="alice", resource_id="r-patient-1")
    a, b = r1.json(), r2.json()
    assert a["decision"] == b["decision"] == "allow"
    assert a["fields"] == b["fields"]  # deterministic across requests

    f = a["fields"]
    assert f["record_id"] == {"action": "visible", "value": "REC-1001"}
    assert f["patient_name"] == {"action": "mask", "value": "张**"}
    assert f["ssn"]["action"] == "hash" and f["ssn"]["value"].startswith("sha256:")
    assert f["phone"]["value"] == "138********"
    assert f["diagnosis"]["value"] == "hype****************"

    # same fields are masked differently -> actions remain distinguishable
    assert f["ssn"]["value"] != f["phone"]["value"]
    assert f["diagnosis"]["value"].count("*") == 16

    # pin v1: diagnosis must be fully redacted (different rule than v2)
    rv1 = _post(c, request_id="m3", caller_id="alice",
                resource_id="r-patient-1", policy_version="policy-v1")
    assert rv1.json()["policy_version"] == "policy-v1"
    assert rv1.json()["fields"]["diagnosis"] == {"action": "redact",
                                                 "value": "[REDACTED]"}
    assert rv1.json()["fields"] != a["fields"]


def test_billing_policy_tightening_is_observable(engine_env):
    _, _, _, app = engine_env
    c = TestClient(app)
    v1 = _post(c, request_id="b1", caller_id="bob",
               resource_id="r-bill-1", policy_version="policy-v1").json()
    v2 = _post(c, request_id="b2", caller_id="bob",
               resource_id="r-bill-1", policy_version="policy-v2").json()
    assert v1["fields"]["card_number"]["action"] == "hash"
    assert v2["fields"]["card_number"] == {"action": "redact",
                                           "value": "[REDACTED]"}
    # raw PAN nowhere
    assert "4111111111111111" not in str(v1) + str(v2)


def test_unit_log_prints_inputs_version_basis(engine_env, caplog):
    _, _, _, app = engine_env
    c = TestClient(app)
    import logging
    with caplog.at_level(logging.INFO, logger="privacy_gateway.decider"):
        _post(c, request_id="log1", caller_id="mallory", resource_id="r-patient-1")
        _post(c, request_id="log2", caller_id="alice", resource_id="r-patient-1")
    text = caplog.text
    assert "mallory" in text and "r-patient-1" in text          # inputs
    assert "policy-v2" in text                                  # hit version
    assert "access-denied" in text and "decision" in text       # basis
