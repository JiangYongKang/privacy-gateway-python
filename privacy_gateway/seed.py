"""本地示例数据与策略装载（确定性，无外部服务、无真实凭据）。

提供两个资源范围与三个调用方，以及两个不可变策略版本：

* ``v1``（2026-01-01）：alice 可读 patient 资源，phone 部分脱敏；
  bob 可读 billing 资源，amount 明文（策略显式授予）；
  carol 对 patient 显式 deny。保留期策略为 DENY。
* ``v2``（2026-06-01）：把 alice 的 phone 升级为 HMAC 假名，并新增
  carol 对 patient 诊断字段的只读（全遮蔽）授权；保留期策略改为 REDACT。

资源 ``patient-1`` 保留期 365 天（未到期），``patient-old`` 保留期 7 天
（种子时刻已到期，用于演示保留期拒绝/遮蔽），``billing-1`` 保留期 365 天。
"""
from __future__ import annotations

from .audit import AuditLog
from .clock import Clock, parse_ts
from .models import (
    FieldRule,
    MaskMode,
    PolicyVersion,
    Principal,
    Resource,
    RetentionAction,
    Rule,
)
from .policy import PolicyStore
from .service import PrivacyGatewayService
from .store import Store

SEED_TIME = "2026-09-23T08:00:00.000000Z"


def _principals() -> list[Principal]:
    return [
        Principal("alice", frozenset({"doctor"})),
        Principal("bob", frozenset({"cashier"})),
        Principal("carol", frozenset({"auditor"})),
    ]


def _resources() -> list[Resource]:
    return [
        Resource(
            id="patient-1",
            scope="patient",
            owner="alice",
            retention_days=365,
            created_at="2026-09-20T08:00:00.000000Z",
            fields={
                "name": "Alice Zhang",
                "phone": "13800138000",
                "diagnosis": "common-cold",
            },
        ),
        Resource(
            id="patient-old",
            scope="patient",
            owner="alice",
            retention_days=7,
            created_at="2026-01-01T08:00:00.000000Z",
            fields={
                "name": "Old Record",
                "phone": "13900139000",
                "diagnosis": "archived",
            },
        ),
        Resource(
            id="billing-1",
            scope="billing",
            owner="bob",
            retention_days=365,
            created_at="2026-09-20T08:00:00.000000Z",
            fields={"invoice": "INV-2026-0001", "amount": "128.50"},
        ),
    ]


def _policies() -> PolicyStore:
    ps = PolicyStore()

    v1 = PolicyVersion(
        version="v1",
        created_at="2026-01-01T00:00:00.000000Z",
        parent_version=None,
        retention_action=RetentionAction.DENY,
        rules=(
            Rule(
                principal_id="alice",
                scope="patient",
                effect="allow",
                allowed_fields=frozenset({"name", "phone", "diagnosis"}),
                field_rules={
                    "name": FieldRule("name", MaskMode.NONE),
                    "phone": FieldRule("phone", MaskMode.PARTIAL),
                    "diagnosis": FieldRule("diagnosis", MaskMode.FULL),
                },
            ),
            Rule(
                principal_id="bob",
                scope="billing",
                effect="allow",
                allowed_fields=frozenset({"invoice", "amount"}),
                field_rules={
                    "invoice": FieldRule("invoice", MaskMode.PARTIAL),
                    "amount": FieldRule("amount", MaskMode.NONE),
                },
            ),
            Rule(
                principal_id="carol",
                scope="patient",
                effect="deny",
                allowed_fields=frozenset(),
                field_rules={},
            ),
        ),
    )

    v2 = PolicyVersion(
        version="v2",
        created_at="2026-06-01T00:00:00.000000Z",
        parent_version="v1",
        retention_action=RetentionAction.REDACT,
        rules=(
            Rule(
                principal_id="alice",
                scope="patient",
                effect="allow",
                allowed_fields=frozenset({"name", "phone", "diagnosis"}),
                field_rules={
                    "name": FieldRule("name", MaskMode.NONE),
                    "phone": FieldRule("phone", MaskMode.HASH),
                    "diagnosis": FieldRule("diagnosis", MaskMode.FULL),
                },
            ),
            Rule(
                principal_id="carol",
                scope="patient",
                effect="allow",
                allowed_fields=frozenset({"diagnosis"}),
                field_rules={
                    "diagnosis": FieldRule("diagnosis", MaskMode.FULL),
                },
            ),
            Rule(
                principal_id="bob",
                scope="billing",
                effect="allow",
                allowed_fields=frozenset({"invoice", "amount"}),
                field_rules={
                    "invoice": FieldRule("invoice", MaskMode.PARTIAL),
                    "amount": FieldRule("amount", MaskMode.NONE),
                },
            ),
        ),
    )

    ps.publish(v1)
    ps.publish(v2)
    ps.set_current("v1")
    return ps


def build_service(
    clock: Clock,
    *,
    current_policy: str = "v1",
) -> PrivacyGatewayService:
    """组装本地网关：内存存储 + 两版策略 + 审计日志。"""
    store = Store()
    for p in _principals():
        store.put_principal(p)
    for r in _resources():
        store.put_resource(r)
    policies = _policies()
    policies.set_current(current_policy)
    audit = AuditLog(clock)
    return PrivacyGatewayService(store, policies, audit, clock)
