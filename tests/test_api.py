"""HTTP 层：结构化响应、幂等、审计查询与回放。"""
from __future__ import annotations

from fastapi.testclient import TestClient

from privacy_gateway.clock import parse_ts
from privacy_gateway.seed import build_service


def _client():
    svc = build_service(parse_ts("2026-09-23T08:00:00.000000Z"))
    from privacy_gateway.api import create_app

    return TestClient(create_app(svc)), svc


def test_access_allowed_and_denied_payloads():
    client, _ = _client()
    ok = client.post(
        "/v1/access",
        json={
            "request_id": "w1", "principal_id": "alice",
            "resource_id": "patient-1", "fields": ["name", "phone"],
        },
    ).json()
    assert ok == {
        "allowed": True,
        "reason": None,
        "deny_detail": [],
        "policy_version": "v1",
        "matched_rule": "alice@patient:allow",
        "fields": {"name": "Alice Zhang", "phone": "1*********0"},
    }

    denied = client.post(
        "/v1/access",
        json={
            "request_id": "w2", "principal_id": "alice",
            "resource_id": "patient-1", "fields": ["ssn"],
        },
    ).json()
    assert denied["allowed"] is False
    assert denied["reason"] == "field_forbidden"
    assert denied["deny_detail"] == ["ssn"]
    assert denied["fields"] == {}


def test_audit_listing_and_replay_endpoint():
    client, svc = _client()
    client.post(
        "/v1/access",
        json={"request_id": "w3", "principal_id": "bob",
              "resource_id": "billing-1", "fields": ["invoice", "amount"]},
    )
    listing = client.get("/v1/audit").json()["entries"]
    assert len(listing) == 1 and listing[0]["seq"] == 1

    replay = client.post("/v1/replay/w3").json()
    assert replay["consistent"] is True
    assert replay["historical"]["policy_version"] == "v1"

    assert client.get("/v1/audit/w3").json()["request_id"] == "w3"
    assert client.get("/v1/audit/missing").status_code == 404


def test_policy_listing_and_switch():
    client, _ = _client()
    info = client.get("/v1/policies").json()
    assert info["current"] == "v1" and info["versions"] == ["v1", "v2"]
    assert client.put("/v1/policies/current", json={"version": "v2"}).status_code == 200
    assert client.get("/v1/policies").json()["current"] == "v2"
    assert client.put("/v1/policies/current", json={"version": "nope"}).status_code == 404
