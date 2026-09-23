"""领域模型与枚举（仅类型定义）。"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class MaskMode(str, Enum):
    NONE = "none"
    FULL = "full"
    PARTIAL = "partial"
    HASH = "hash"


class DenyReason(str, Enum):
    UNAUTHORIZED = "unauthorized"
    FIELD_FORBIDDEN = "field_forbidden"
    POLICY_DEFAULT_DENY = "policy_default_deny"
    POLICY_MISSING = "policy_missing"
    POLICY_VERSION_NOT_FOUND = "policy_version_not_found"
    POLICY_CONFLICT = "policy_conflict"
    RETENTION_EXPIRED = "retention_expired"


class RetentionAction(str, Enum):
    DENY = "deny"
    PURGE = "purge"
    REDACT = "redact"


@dataclass(frozen=True)
class Principal:
    id: str
    roles: frozenset[str] = frozenset()


@dataclass(frozen=True)
class Resource:
    id: str
    scope: str
    owner: str
    retention_days: int
    created_at: str
    fields: dict[str, str]


@dataclass(frozen=True)
class FieldRule:
    field_name: str
    mask: MaskMode


@dataclass(frozen=True)
class Rule:
    principal_id: str
    scope: str
    effect: str  # "allow" | "deny"
    allowed_fields: frozenset[str]
    field_rules: dict[str, FieldRule]


@dataclass(frozen=True)
class PolicyVersion:
    version: str
    rules: tuple[Rule, ...]
    created_at: str
    parent_version: str | None = None
    retention_action: RetentionAction = RetentionAction.DENY


@dataclass(frozen=True)
class AccessRequest:
    request_id: str
    principal_id: str
    roles: frozenset[str]
    resource_id: str
    fields: tuple[str, ...]
    policy_version: str | None = None


@dataclass(frozen=True)
class AccessDecision:
    allowed: bool
    reason: DenyReason | None
    policy_version: str
    matched_rule: str | None
    fields: dict[str, str]
    deny_detail: tuple[str, ...] = ()


@dataclass(frozen=True)
class AuditEntry:
    seq: int
    request_id: str
    timestamp: str
    principal_id: str
    resource_id: str
    requested_fields: tuple[str, ...]
    policy_version: str
    allowed: bool
    reason: str | None
    matched_rule: str | None
    returned_fields: tuple[str, ...]
    idempotency_key: str
    decision_fingerprint: str
    deny_detail: tuple[str, ...] = ()


@dataclass(frozen=True)
class ReplayResult:
    entry: AuditEntry
    consistent: bool
    replayed_decision: AccessDecision | None
    note: str
