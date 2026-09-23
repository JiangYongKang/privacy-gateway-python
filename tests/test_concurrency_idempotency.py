"""并发调用确定性 + 重复提交幂等 + 策略冲突拒绝。"""
from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier, Thread

import pytest

from privacy_gateway.errors import AccessDeniedError
from privacy_gateway.models import (
    AccessRequest,
    DenyReason,
    FieldRule,
    MaskMode,
    PolicyVersion,
    RetentionAction,
    Rule,
)


def _log(text: str) -> None:
    logging.getLogger("privacy_gateway.test").info(text)


# ---- 重复提交 / 重试幂等 -----------------------------------------------

def test_duplicate_submission_single_audit_entry(service, caplog):
    caplog.set_level(logging.INFO, logger="privacy_gateway")
    req = AccessRequest("dup-1", "alice", frozenset(), "patient-1", ("phone",))
    _log(f"INPUT 同一 request_id=dup-1 连续提交 3 次；期望 1 条审计、同一结论")

    results = [service.request_access(req) for _ in range(3)]

    assert all(r.fields == {"phone": "1*********0"} for r in results)
    entries = service.audit.all_entries()
    assert len(entries) == 1
    assert entries[0].request_id == "dup-1"
    assert entries[0].seq == 1


def test_concurrent_duplicate_submission_is_idempotent(service, caplog):
    caplog.set_level(logging.INFO, logger="privacy_gateway")
    req = AccessRequest("cd-1", "alice", frozenset(), "patient-1", ("phone",))
    barrier = Barrier(8)
    _log("INPUT 8 线程用同一 request_id 同时提交；期望恰好 1 条审计")

    def fire():
        barrier.wait()
        return service.request_access(req)

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: fire(), range(8)))

    assert all(r.fields == {"phone": "1*********0"} for r in results)
    assert len(service.audit.all_entries()) == 1


# ---- 并发不同请求：顺序与内容确定 --------------------------------------

def test_concurrent_distinct_requests_deterministic(service, clock, caplog):
    caplog.set_level(logging.INFO, logger="privacy_gateway")
    n = 12
    barrier = Barrier(n)
    _log(f"INPUT {n} 个不同 request_id 同时提交；期望 seq 连续 1..n 且内容可复现")

    def fire(i: int):
        barrier.wait()  # 尽量放大竞争：所有线程同时进入
        # 故意让请求到达顺序与编号顺序不同，证明结果不依赖调用方线程调度
        req = AccessRequest(
            f"c-{i:02d}", "alice", frozenset(), "patient-1", ("phone",)
        )
        decision = service.request_access(req)
        entry = service.audit.get(req.request_id)
        return i, entry.seq, decision.fields["phone"]

    # 以逆序提交线程任务
    with ThreadPoolExecutor(max_workers=n) as pool:
        outcomes = list(pool.map(fire, range(n - 1, -1, -1)))

    entries = service.audit.all_entries()
    # 无论线程如何调度，审计序号必须连续且唯一
    assert sorted(e.seq for e in entries) == list(range(1, n + 1))
    # 每个 request_id 都有且仅有一条；全部脱敏结果确定
    by_id = {e.request_id: e for e in entries}
    assert sorted(by_id) == [f"c-{i:02d}" for i in range(n)]
    assert all(out[2] == "1*********0" for out in outcomes)
    # 时间戳单调不减（同一固定时钟下全部相等，也是确定的）
    stamps = [e.timestamp for e in entries]
    assert stamps == sorted(stamps)
    _log(f"OUTPUT seq 集合={sorted(e.seq for e in entries)} 时间戳={stamps[0]}")


def test_concurrent_mixed_allow_and_deny(service, caplog):
    caplog.set_level(logging.INFO, logger="privacy_gateway")
    """并发混合：合法读、字段越权、跨范围缺省拒绝，各自原因可区分。"""
    barrier = Barrier(3)

    def fire(req: AccessRequest):
        barrier.wait()
        return service.request_access(req)

    reqs = [
        AccessRequest("m-0", "alice", frozenset(), "patient-1", ("phone",)),
        AccessRequest("m-1", "alice", frozenset(), "patient-1", ("ssn",)),
        AccessRequest("m-2", "bob", frozenset(), "patient-1", ("phone",)),
    ]
    with ThreadPoolExecutor(max_workers=3) as pool:
        decisions = list(pool.map(fire, reqs))

    by_id = {}
    for req, d in zip(reqs, decisions):
        by_id[req.request_id] = d
    assert by_id["m-0"].allowed is True
    assert by_id["m-1"].reason == DenyReason.FIELD_FORBIDDEN
    assert by_id["m-2"].reason == DenyReason.POLICY_DEFAULT_DENY
    assert len(service.audit.all_entries()) == 3


# ---- 策略发布冲突必须拒绝 ----------------------------------------------

def test_publish_overlapping_rules_rejected(service):
    overlap = PolicyVersion(
        version="bad",
        created_at="2026-09-23T00:00:00.000000Z",
        retention_action=RetentionAction.DENY,
        rules=(
            Rule("alice", "patient", "allow", frozenset({"name"}),
                 {"name": FieldRule("name", MaskMode.FULL)}),
            Rule("*", "patient", "allow", frozenset({"name"}),
                 {"name": FieldRule("name", MaskMode.FULL)}),
        ),
    )
    with pytest.raises(AccessDeniedError) as exc:
        service.policies.publish(overlap)
    assert exc.value.reason == DenyReason.POLICY_CONFLICT
    # 冲突版本不得入库
    assert not service.policies.exists("bad")


def test_republish_same_version_rejected_as_conflict(service):
    from privacy_gateway.seed import _resources  # noqa: F401
    existing = service.policies.get("v1")
    with pytest.raises(AccessDeniedError) as exc:
        service.policies.publish(existing)
    assert exc.value.reason == DenyReason.POLICY_CONFLICT


# ---- 并发回放与首次结论一致 --------------------------------------------

def test_replay_after_all_concurrent_requests(service):
    n = 6
    barrier = Barrier(n)

    def fire(i: int):
        barrier.wait()
        return service.request_access(
            AccessRequest(f"rr-{i}", "alice", frozenset(), "patient-1", ("phone",))
        )

    threads = [Thread(target=fire, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    for i in range(n):
        result = service.replay(f"rr-{i}")
        assert result.consistent, result.note
    assert len(service.audit.all_entries()) == n
