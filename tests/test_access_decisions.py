"""越权访问与可区分拒绝原因、确定性脱敏。

每条用例都通过 caplog 打印输入、命中策略版本与判定依据。
"""
from __future__ import annotations

import logging

from privacy_gateway.models import AccessRequest, DenyReason


def _log(caplog, text: str) -> None:
    """显式打印用例输入与期望，便于从单测日志复现判定依据。"""
    logging.getLogger("privacy_gateway.test").info(text)


def test_allowed_with_deterministic_masking(service, caplog):
    caplog.set_level(logging.INFO, logger="privacy_gateway")
    req = AccessRequest(
        "t-allow", "alice", frozenset(), "patient-1",
        ("name", "phone", "diagnosis"),
    )
    _log(caplog, f"INPUT {req} EXPECT allow v1: name=明文 phone=部分 diagnosis=全遮蔽")

    d = service.request_access(req)

    assert d.allowed is True
    assert d.policy_version == "v1"
    assert d.matched_rule == "alice@patient:allow"
    # 确定性脱敏结果逐字节固定
    assert d.fields == {
        "name": "Alice Zhang",
        "phone": "1*********0",
        "diagnosis": "<REDACTED>",
    }
    # 原始值绝不出现在结论中（name 是策略显式授予的明文非敏感字段）
    assert "13800138000" not in repr(d.fields)


def test_reason_unauthorized_unknown_principal(service, caplog):
    caplog.set_level(logging.INFO, logger="privacy_gateway")
    req = AccessRequest("t-unk", "zoe", frozenset(), "patient-1", ("name",))
    _log(caplog, f"INPUT {req} EXPECT unauthorized（主体不存在）")

    d = service.request_access(req)

    assert not d.allowed
    assert d.reason == DenyReason.UNAUTHORIZED


def test_reason_explicit_deny_rule(service, caplog):
    caplog.set_level(logging.INFO, logger="privacy_gateway")
    req = AccessRequest("t-deny", "carol", frozenset(), "patient-1", ("diagnosis",))
    _log(caplog, f"INPUT {req} EXPECT unauthorized（命中 carol@patient:deny）")

    d = service.request_access(req)

    assert not d.allowed
    assert d.reason == DenyReason.UNAUTHORIZED
    assert d.matched_rule == "carol@patient:deny"


def test_reason_policy_default_deny_cross_scope(service, caplog):
    caplog.set_level(logging.INFO, logger="privacy_gateway")
    # bob 只有 billing 授权，访问 patient 范围 => 无规则命中 => 缺省拒绝
    req = AccessRequest("t-default", "bob", frozenset(), "patient-1", ("name",))
    _log(caplog, f"INPUT {req} EXPECT policy_default_deny（跨范围无规则）")

    d = service.request_access(req)

    assert not d.allowed
    assert d.reason == DenyReason.POLICY_DEFAULT_DENY
    assert d.fields == {}


def test_reason_field_forbidden_is_distinguishable(service, caplog):
    caplog.set_level(logging.INFO, logger="privacy_gateway")
    req = AccessRequest(
        "t-field", "alice", frozenset(), "patient-1", ("phone", "ssn", "amount")
    )
    _log(caplog, f"INPUT {req} EXPECT field_forbidden 且详情列出越权字段")

    d = service.request_access(req)

    assert not d.allowed
    assert d.reason == DenyReason.FIELD_FORBIDDEN
    assert d.deny_detail == ("amount", "ssn")
    # 即使部分字段合法，也必须整单拒绝（不返回任何字段值）
    assert d.fields == {}


def test_reason_policy_version_not_found(service, caplog):
    caplog.set_level(logging.INFO, logger="privacy_gateway")
    req = AccessRequest(
        "t-nov", "alice", frozenset(), "patient-1", ("name",),
        policy_version="v42",
    )
    _log(caplog, f"INPUT {req} EXPECT policy_version_not_found（拒绝而非放行）")

    d = service.request_access(req)

    assert not d.allowed
    assert d.reason == DenyReason.POLICY_VERSION_NOT_FOUND


def test_retention_expired_denied_v1(service, caplog):
    caplog.set_level(logging.INFO, logger="privacy_gateway")
    req = AccessRequest("t-exp", "alice", frozenset(), "patient-old", ("name",))
    _log(caplog, f"INPUT {req} v1 保留期动作=deny EXPECT retention_expired")

    d = service.request_access(req)

    assert not d.allowed
    assert d.reason == DenyReason.RETENTION_EXPIRED
    assert d.fields == {}


def test_retention_expired_redacted_v2_not_silent(service_v2, caplog):
    caplog.set_level(logging.INFO, logger="privacy_gateway")
    req = AccessRequest(
        "t-exp2", "alice", frozenset(), "patient-old", ("name", "phone"),
        policy_version="v2",
    )
    _log(caplog, f"INPUT {req} v2 保留期动作=redact EXPECT 全遮蔽且不静默")

    d = service_v2.request_access(req)

    assert d.allowed is True
    assert d.fields == {"name": "<REDACTED>", "phone": "<REDACTED>"}
    assert "Old Record" not in repr(d.fields)
    assert "13900139000" not in repr(d.fields)


def test_policy_update_does_not_change_replayed_history(service, caplog):
    caplog.set_level(logging.INFO, logger="privacy_gateway")
    req = AccessRequest("t-hist", "alice", frozenset(), "patient-1", ("phone",))
    _log(caplog, f"INPUT {req} v1 下首次决策 phone=部分脱敏")
    first = service.request_access(req)
    assert first.fields == {"phone": "1*********0"}

    # 之后把当前策略升级到 v2（phone 变为 HMAC）
    service.policies.set_current("v2")
    _log(caplog, "当前策略已升级 v2；历史请求重放必须仍锁 v1 结论")

    replay = service.replay("t-hist")
    assert replay.consistent, replay.note
    assert replay.replayed_decision.policy_version == "v1"
    assert replay.replayed_decision.fields == {"phone": "1*********0"}

    # 同一 request_id 的重试直接返回首次结论，不受策略升级影响
    retry = service.request_access(req)
    assert retry.fields == {"phone": "1*********0"}
