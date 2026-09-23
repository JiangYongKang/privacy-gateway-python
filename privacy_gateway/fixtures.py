"""Deterministic local seed data.

The demo "world" is anchored at 2026-09-23 (see README). All ids and values
are synthetic; nothing here is a real credential.

Policy evolution:
  * ``policy-v1`` (effective 2026-01-01): only ``alice`` may read
    ``patient_health``; billing retention 180d; card numbers are hashed.
  * ``policy-v2`` (effective 2026-06-01): adds ``bob`` to patient_health,
    reveals a masked diagnosis prefix, tightens billing retention to 90d and
    fully redacts card numbers. v1 remains stored and immutable, so old
    decisions are still replayable.
"""

from __future__ import annotations

from .models import (
    Caller,
    ExpiryAction,
    FieldRule,
    MaskAction,
    Policy,
    Resource,
    ScopePolicy,
)
from .policies import validate_policy
from .store import LocalStore

V1 = "policy-v1"
V2 = "policy-v2"
ANCHOR_NOW = "2026-09-23T12:00:00Z"


def _v1() -> Policy:
    patient = ScopePolicy(
        scope="patient_health",
        allowed_callers=frozenset({"alice"}),
        field_rules={
            "record_id": FieldRule("record_id", MaskAction.VISIBLE),
            "patient_name": FieldRule("patient_name", MaskAction.MASK, keep_prefix=1),
            "ssn": FieldRule("ssn", MaskAction.HASH, hash_prefix=8),
            "phone": FieldRule("phone", MaskAction.MASK, keep_prefix=3),
            "diagnosis": FieldRule("diagnosis", MaskAction.REDACT),
        },
        default_field_action=MaskAction.REDACT,
        retention_days=365,
    )
    billing = ScopePolicy(
        scope="billing",
        allowed_callers=frozenset({"bob"}),
        field_rules={
            "invoice_id": FieldRule("invoice_id", MaskAction.VISIBLE),
            "amount": FieldRule("amount", MaskAction.VISIBLE),
            "email": FieldRule("email", MaskAction.MASK, keep_prefix=2),
            "card_number": FieldRule("card_number", MaskAction.HASH, hash_prefix=8),
        },
        default_field_action=MaskAction.REDACT,
        retention_days=180,
    )
    return Policy(
        version=V1,
        scope_policies={"patient_health": patient, "billing": billing},
        default_retention_days=90,
        created_at="2026-01-01T00:00:00Z",
    )


def _v2() -> Policy:
    patient = ScopePolicy(
        scope="patient_health",
        allowed_callers=frozenset({"alice", "bob"}),  # bob added
        field_rules={
            "record_id": FieldRule("record_id", MaskAction.VISIBLE),
            "patient_name": FieldRule("patient_name", MaskAction.MASK, keep_prefix=1),
            "ssn": FieldRule("ssn", MaskAction.HASH, hash_prefix=8),
            "phone": FieldRule("phone", MaskAction.MASK, keep_prefix=3),
            # v2 reveals a fixed 4-char prefix instead of a full redaction
            "diagnosis": FieldRule("diagnosis", MaskAction.MASK, keep_prefix=4),
        },
        default_field_action=MaskAction.REDACT,
        retention_days=365,
    )
    billing = ScopePolicy(
        scope="billing",
        allowed_callers=frozenset({"bob"}),
        field_rules={
            "invoice_id": FieldRule("invoice_id", MaskAction.VISIBLE),
            "amount": FieldRule("amount", MaskAction.VISIBLE),
            "email": FieldRule("email", MaskAction.MASK, keep_prefix=2),
            "card_number": FieldRule("card_number", MaskAction.REDACT),  # tighter
        },
        default_field_action=MaskAction.REDACT,
        retention_days=90,  # tightened from 180
        on_expiry=ExpiryAction.TOMBSTONE,
    )
    # ``audit_logs`` exists in v2 only: a request for such a resource under v1
    # must fail with POLICY/SCOPE semantics, never default-allow.
    audit_logs = ScopePolicy(
        scope="audit_logs",
        allowed_callers=frozenset({"carol"}),
        field_rules={
            "log_id": FieldRule("log_id", MaskAction.VISIBLE),
            "body": FieldRule("body", MaskAction.REDACT),
        },
        default_field_action=MaskAction.REDACT,
        retention_days=30,
    )
    return Policy(
        version=V2,
        scope_policies={
            "patient_health": patient,
            "billing": billing,
            "audit_logs": audit_logs,
        },
        default_retention_days=90,
        created_at="2026-06-01T00:00:00Z",
    )


def build_seed_store() -> LocalStore:
    store = LocalStore()
    for cid, name in [
        ("alice", "Alice (analyst)"),
        ("bob", "Bob (support)"),
        ("carol", "Carol (auditor)"),
        ("mallory", "Mallory (untrusted)"),
    ]:
        store.add_caller(Caller(caller_id=cid, display_name=name))

    store.add_resource(Resource(
        resource_id="r-patient-1",
        scope="patient_health",
        created_at="2026-08-01T00:00:00Z",  # 53d old at the anchor
        data={
            "record_id": "REC-1001",
            "patient_name": "张三丰",
            "ssn": "123-45-6789",
            "phone": "13812345678",
            "diagnosis": "hypertension stage 2",
        },
    ))
    store.add_resource(Resource(
        resource_id="r-patient-old",
        scope="patient_health",
        created_at="2025-01-10T00:00:00Z",  # > 365d at the anchor
        data={
            "record_id": "REC-0002",
            "patient_name": "李白",
            "ssn": "987-65-4321",
            "phone": "13987654321",
            "diagnosis": "migraine",
        },
    ))
    store.add_resource(Resource(
        resource_id="r-bill-1",
        scope="billing",
        created_at="2026-08-15T00:00:00Z",  # 39d old at the anchor
        data={
            "invoice_id": "INV-7701",
            "amount": 428.50,
            "email": "alice@example.com",
            "card_number": "4111111111111111",
        },
    ))
    store.add_resource(Resource(
        resource_id="r-bill-mid",
        scope="billing",
        created_at="2026-05-01T00:00:00Z",  # 145d: alive in v1(180d),
                                           # expired in v2(90d)
        data={
            "invoice_id": "INV-7200",
            "amount": 99.0,
            "email": "bob@example.com",
            "card_number": "5500000000000004",
        },
    ))
    store.add_resource(Resource(
        resource_id="r-audit-1",
        scope="audit_logs",
        created_at="2026-09-20T00:00:00Z",
        data={"log_id": "LOG-1", "body": "raw audit body text"},
    ))

    p1, p2 = _v1(), _v2()
    validate_policy(p1)
    validate_policy(p2)
    store.add_policy(p1)
    store.add_policy(p2)
    store.set_current_policy_version(V2)
    return store
