"""Concurrent calls: deterministic ordering, no duplicate audit entries,
stable retries."""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor

from fastapi.testclient import TestClient

from privacy_gateway.models import AccessRequest
from privacy_gateway.models import fingerprint_request


def test_concurrent_distinct_requests_get_gapfree_sequence(engine_env):
    _, audit, _, app = engine_env
    c = TestClient(app)

    n = 30

    def fire(i: int):
        # Spread callers/resources so decisions are independent.
        caller = "alice" if i % 2 == 0 else "mallory"
        resource = "r-patient-1"
        return c.post("/v1/access/decide", json={
            "request_id": f"c-{i:03d}", "caller_id": caller,
            "resource_id": resource,
        })

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(fire, range(n)))
    assert all(r.status_code in (200, 403) for r in results)

    entries = audit.entries()
    assert len(entries) == n                       # exactly one entry each
    seqs = sorted(e.sequence for e in entries)
    assert seqs == list(range(1, n + 1))           # gap-free total order
    assert len({e.request_id for e in entries}) == n

    # Determinism: sequence order equals request-id lexical order only because
    # assignment is arbitrary under threads; assert the *content* keyed by id
    # is stable instead.
    by_id = {e.request_id: e for e in entries}
    for i in range(n):
        e = by_id[f"c-{i:03d}"]
        assert e.decision.value == ("allow" if i % 2 == 0 else "deny")
        assert e.policy_version == "policy-v2"


def test_duplicate_submission_is_idempotent(engine_env):
    _, audit, _, app = engine_env
    c = TestClient(app)
    payload = {"request_id": "dup-1", "caller_id": "alice",
               "resource_id": "r-patient-1"}

    with ThreadPoolExecutor(max_workers=4) as pool:
        rs = list(pool.map(lambda _: c.post("/v1/access/decide", json=payload),
                           range(10)))

    bodies = [r.json() for r in rs]
    assert all(b == bodies[0] for b in bodies)     # identical responses
    assert len(audit.entries()) == 1               # single audit entry
    assert audit.entries()[0].sequence == 1


def test_denial_retry_returns_same_denial_no_duplicate(engine_env):
    _, audit, _, app = engine_env
    c = TestClient(app)
    payload = {"request_id": "dup-deny", "caller_id": "mallory",
               "resource_id": "r-patient-1"}
    r1 = c.post("/v1/access/decide", json=payload)
    r2 = c.post("/v1/access/decide", json=payload)
    assert r1.json()["deny_code"] == r2.json()["deny_code"] == "ACCESS_DENIED"
    assert len(audit.entries()) == 1


def test_same_request_id_different_payload_rejected(engine_env):
    _, audit, _, app = engine_env
    c = TestClient(app)
    c.post("/v1/access/decide", json={"request_id": "k", "caller_id": "alice",
                                      "resource_id": "r-patient-1"})
    r = c.post("/v1/access/decide", json={
        "request_id": "k", "caller_id": "alice",
        "resource_id": "r-patient-1", "fields": ["ssn"]})
    assert r.status_code == 409
    assert r.json()["error"]["code"] == "IDEMPOTENCY_CONFLICT"
    # state untouched by the conflicting attempt
    assert len(audit.entries()) == 1


def test_fingerprint_ignores_safe_only_payload_stability():
    a = AccessRequest(request_id="x", caller_id="u", resource_id="r",
                      fields=("a", "b"))
    b = AccessRequest(request_id="x", caller_id="u", resource_id="r",
                      fields=("b", "a"))
    # field order is part of the request shape -> distinct fingerprints
    assert fingerprint_request(a) != fingerprint_request(b)
    c = AccessRequest(request_id="x", caller_id="u", resource_id="r",
                      fields=("a", "b"), submitted_at="2026-01-01T00:00:00Z")
    assert fingerprint_request(a) == fingerprint_request(c)  # timestamp ignored


def test_no_raw_secret_in_logs_or_audit(engine_env):
    _, audit, _, app = engine_env
    c = TestClient(app, raise_server_exceptions=True)
    c.post("/v1/access/decide", json={"request_id": "leak-1",
                                      "caller_id": "alice",
                                      "resource_id": "r-bill-1"})
    blob = json.dumps([e.to_dict() for e in audit.entries()])
    for secret in ("4111111111111111", "alice@example.com", "123-45-6789"):
        assert secret not in blob
