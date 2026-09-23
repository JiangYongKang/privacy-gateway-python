"""审计：幂等写入、确定性顺序与历史回放。

* 同一 ``request_id`` 的重复提交/重试只产生**一条**审计记录，
  重复调用直接返回首次记录（幂等键即请求 ID）。
* 所有写入在同一把锁内分配连续递增的 ``seq`` 与时间戳，
  因此并发调用下记录顺序也是确定的：先抢到锁的请求序号最小。
* 审计只记录“结论的形状”（允许与否、原因、策略版本、命中规则、
  返回字段名）以及对脱敏后结论的指纹；**不记录任何原始敏感值**。
* 回放时对历史决策重新求指纹，与历史指纹逐字节比对，
  从而证明“当时的结论”与“现在重放的结论”一致。
"""
from __future__ import annotations

import threading

from .clock import Clock, format_ts
from .masking import fingerprint
from .models import AccessDecision, AccessRequest, AuditEntry, ReplayResult


def decision_fingerprint(decision: AccessDecision) -> str:
    """对（脱敏后的）判定结论求确定性指纹。"""
    parts = [
        "allowed=" + ("1" if decision.allowed else "0"),
        "reason=" + (decision.reason.value if decision.reason else "-"),
        "policy=" + decision.policy_version,
        "rule=" + (decision.matched_rule or "-"),
        "fields="
        + ",".join(f"{k}={decision.fields[k]}" for k in sorted(decision.fields)),
        "detail=" + ",".join(decision.deny_detail),
    ]
    return fingerprint("|".join(parts))


class AuditLog:
    def __init__(self, clock: Clock) -> None:
        self._entries: list[AuditEntry] = []
        self._by_request: dict[str, AuditEntry] = {}
        self._lock = threading.RLock()
        self._seq = 0
        self._clock = clock

    def append(self, request: AccessRequest, decision: AccessDecision) -> AuditEntry:
        """幂等写入：相同 ``request_id`` 直接返回首条记录。"""
        with self._lock:
            existing = self._by_request.get(request.request_id)
            if existing is not None:
                return existing
            self._seq += 1
            entry = AuditEntry(
                seq=self._seq,
                request_id=request.request_id,
                timestamp=format_ts(self._clock.now()),
                principal_id=request.principal_id,
                resource_id=request.resource_id,
                requested_fields=tuple(request.fields),
                policy_version=decision.policy_version,
                allowed=decision.allowed,
                reason=decision.reason.value if decision.reason else None,
                matched_rule=decision.matched_rule,
                returned_fields=tuple(sorted(decision.fields)),
                idempotency_key=request.request_id,
                decision_fingerprint=decision_fingerprint(decision),
                deny_detail=tuple(decision.deny_detail),
            )
            self._entries.append(entry)
            self._by_request[request.request_id] = entry
            return entry

    def get(self, request_id: str) -> AuditEntry | None:
        with self._lock:
            return self._by_request.get(request_id)

    def all_entries(self) -> list[AuditEntry]:
        """按 seq 升序返回全部记录（确定顺序）。"""
        with self._lock:
            return list(self._entries)

    @staticmethod
    def replay(entry: AuditEntry, decision: AccessDecision) -> ReplayResult:
        """用重新评估得到的结论回放历史条目，比对指纹是否一致。"""
        current = decision_fingerprint(decision)
        consistent = (
            current == entry.decision_fingerprint
            and decision.allowed == entry.allowed
            and (decision.reason.value if decision.reason else None) == entry.reason
            and decision.policy_version == entry.policy_version
            and decision.matched_rule == entry.matched_rule
            and tuple(decision.deny_detail) == tuple(entry.deny_detail)
        )
        if consistent:
            note = "replayed decision matches historical fingerprint"
        else:
            note = (
                "replayed decision diverges from historical fingerprint: "
                f"historical={entry.decision_fingerprint[:12]} "
                f"replayed={current[:12]}"
            )
        return ReplayResult(
            entry=entry,
            consistent=consistent,
            replayed_decision=decision,
            note=note,
        )
