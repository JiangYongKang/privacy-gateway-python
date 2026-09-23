"""审计写入形态、指纹、回放一致性（含分歧检测）。"""
from __future__ import annotations

from privacy_gateway.audit import AuditLog, decision_fingerprint
from privacy_gateway.clock import FixedClock, parse_ts
from privacy_gateway.models import (
    AccessDecision,
    AccessRequest,
    DenyReason,
)


def _req(rid="a1", version="v1"):
    return AccessRequest(rid, "alice", frozenset(), "patient-1", ("phone",), version)


def test_audit_entry_never_contains_values():
    clk = FixedClock(parse_ts("2026-09-23T08:00:00.000000Z"))
    log = AuditLog(clk)
    decision = AccessDecision(
        True, None, "v1", "alice@patient:allow", {"phone": "1*********0"}
    )
    entry = log.append(_req(), decision)
    blob = repr(entry)
    assert "13800138000" not in blob          # 原始值
    assert "1*********0" not in blob          # 脱敏值也不入库
    assert entry.returned_fields == ("phone",)  # 只有字段名


def test_fingerprint_stable_and_sensitive():
    d1 = AccessDecision(True, None, "v1", "r", {"phone": "1*********0"})
    d2 = AccessDecision(True, None, "v1", "r", {"phone": "1*********0"})
    d3 = AccessDecision(True, None, "v2", "r", {"phone": "hmac:abc"})
    assert decision_fingerprint(d1) == decision_fingerprint(d2)
    assert decision_fingerprint(d1) != decision_fingerprint(d3)


def test_replay_detects_divergence(service):
    service.request_access(_req("h1"))
    entry = service.audit.get("h1")
    # 用一个被篡改的“重放结论”验证分歧会被发现
    tampered = AccessDecision(
        True, None, "v1", "alice@patient:allow", {"phone": "9*********9"}
    )
    result = AuditLog.replay(entry, tampered)
    assert result.consistent is False
    assert "diverges" in result.note


def test_replay_denied_decision_consistent(service):
    req = AccessRequest("h2", "bob", frozenset(), "patient-1", ("phone",))
    service.request_access(req)
    result = service.replay("h2")
    assert result.consistent
    assert result.entry.reason == "policy_default_deny"


def test_replay_unknown_request_raises(service):
    from privacy_gateway.errors import AccessDeniedError

    try:
        service.replay("ghost")
    except AccessDeniedError:
        pass
    else:  # pragma: no cover
        raise AssertionError("expected AccessDeniedError")
