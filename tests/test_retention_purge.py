"""保留期动作 purge：到期后落地清除并拒绝，绝不静默返回完整内容。"""
from __future__ import annotations

from privacy_gateway.clock import FixedClock, parse_ts
from privacy_gateway.models import (
    AccessRequest,
    DenyReason,
    FieldRule,
    MaskMode,
    PolicyVersion,
    RetentionAction,
    Rule,
)
from privacy_gateway.policy import PolicyStore
from privacy_gateway.seed import _resources, _principals
from privacy_gateway.audit import AuditLog
from privacy_gateway.service import PrivacyGatewayService
from privacy_gateway.store import Store


def _service_with_purge_policy():
    clock = FixedClock(parse_ts("2026-09-23T08:00:00.000000Z"))
    store = Store()
    for p in _principals():
        store.put_principal(p)
    for r in _resources():
        store.put_resource(r)
    policies = PolicyStore()
    policies.publish(
        PolicyVersion(
            version="p1",
            created_at="2026-01-01T00:00:00.000000Z",
            retention_action=RetentionAction.PURGE,
            rules=(
                Rule(
                    "alice", "patient", "allow",
                    frozenset({"name", "phone", "diagnosis"}),
                    {
                        "name": FieldRule("name", MaskMode.NONE),
                        "phone": FieldRule("phone", MaskMode.PARTIAL),
                        "diagnosis": FieldRule("diagnosis", MaskMode.FULL),
                    },
                ),
            ),
        )
    )
    policies.set_current("p1")
    return PrivacyGatewayService(store, policies, AuditLog(clock), clock), store


def test_purge_expired_resource_then_deny():
    svc, store = _service_with_purge_policy()
    d = svc.request_access(
        AccessRequest("pg-1", "alice", frozenset(), "patient-old", ("name",))
    )
    assert d.allowed is False
    assert d.reason == DenyReason.RETENTION_EXPIRED
    assert d.fields == {}
    # 存储层已被落地遮蔽，不残留完整内容
    purged = store.get_resource("patient-old")
    assert set(purged.fields.values()) == {"<REDACTED>"}
    # 回放：跳过副作用重新评估，仍为到期拒绝，历史结论一致
    replay = svc.replay("pg-1")
    assert replay.consistent
    assert replay.replayed_decision.reason == DenyReason.RETENTION_EXPIRED
