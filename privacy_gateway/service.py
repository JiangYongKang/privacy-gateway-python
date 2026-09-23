"""网关门面：访问判定 -> 确定性脱敏 -> 审计落盘。

判定顺序（每一步的拒绝原因彼此可区分）：

1. 策略版本：请求显式指定版本则必须存在，否则使用当前版本；
   没有任何可用版本 => ``POLICY_MISSING`` / ``POLICY_VERSION_NOT_FOUND``。
2. 主体/资源必须在本地存储中存在 => 否则 ``UNAUTHORIZED``。
3. 规则匹配：未命中任何规则 => ``POLICY_DEFAULT_DENY``；
   命中显式 ``deny`` 规则 => ``UNAUTHORIZED``（携带规则标签）。
4. 字段越权：请求字段不在规则允许集合内 => ``FIELD_FORBIDDEN``。
5. 保留期：已到期的资源按策略 ``retention_action`` 处理——
   ``deny``（``RETENTION_EXPIRED``）/ ``purge``（落地清除后拒绝）/
   ``redact``（所有字段强制全遮蔽，绝不静默返回完整内容）。
6. 通过后按字段规则逐个脱敏，只返回请求的字段。

任何拒绝都与允许一样写入审计；响应/异常/日志中均不出现原始敏感值。
整个“判定+审计”流程持同一把可重入锁串行化，
因此并发调用下结论、序号与写入内容完全确定。
"""
from __future__ import annotations

import threading

from .audit import AuditLog
from .clock import Clock
from .errors import AccessDeniedError
from .logging_utils import get_logger, log_decision
from .masking import REDACTED_PLACEHOLDER, mask_value
from .models import (
    AccessDecision,
    AccessRequest,
    DenyReason,
    MaskMode,
    ReplayResult,
    RetentionAction,
)
from .policy import PolicyStore
from .retention import is_expired
from .store import Store

_logger = get_logger("privacy_gateway.service")


class PrivacyGatewayService:
    def __init__(
        self,
        store: Store,
        policies: PolicyStore,
        audit: AuditLog,
        clock: Clock,
    ) -> None:
        self._store = store
        self._policies = policies
        self._audit = audit
        self._clock = clock
        self._lock = threading.RLock()
        # 进程内幂等缓存：保存首次的脱敏结论（不含原始值的再次拷贝，
        # 仅用于让重试得到字节级一致的响应）；审计记录本身仍不存任何值。
        self._decision_cache: dict[str, AccessDecision] = {}

    @property
    def audit(self) -> AuditLog:
        return self._audit

    @property
    def policies(self) -> PolicyStore:
        return self._policies

    @property
    def store(self) -> Store:
        return self._store

    # ---- 对外入口 -------------------------------------------------------

    def request_access(self, request: AccessRequest) -> AccessDecision:
        """提交一次访问请求（幂等：重复 request_id 返回首次结论）。"""
        with self._lock:
            existing = self._audit.get(request.request_id)
            if existing is not None:
                # 幂等重试：直接返回首次的完整（脱敏后）结论，
                # 不重新评估、不重复落盘，因此策略更新也不会改变历史响应。
                decision = self._decision_cache[request.request_id]
                log_decision(_logger, request, decision)
                return decision
            decision = self._evaluate(request)
            self._audit.append(request, decision)
            self._decision_cache[request.request_id] = decision
            log_decision(_logger, request, decision)
            return decision

    def replay(self, request_id: str) -> ReplayResult:
        """回放历史请求：用当时锁定的策略版本重新评估，并与历史指纹比对。"""
        with self._lock:
            entry = self._audit.get(request_id)
            if entry is None:
                raise AccessDeniedError(
                    DenyReason.POLICY_DEFAULT_DENY,
                    f"no audit entry for request_id: {request_id}",
                )
            request = AccessRequest(
                request_id=entry.request_id,
                principal_id=entry.principal_id,
                roles=frozenset(),
                resource_id=entry.resource_id,
                fields=entry.requested_fields,
                policy_version=entry.policy_version,
            )
            replayed = self._evaluate(request, skip_retention_side_effects=True)
            return AuditLog.replay(entry, replayed)

    # ---- 核心判定 -------------------------------------------------------

    def _evaluate(
        self, request: AccessRequest, *, skip_retention_side_effects: bool = False
    ) -> AccessDecision:
        # 1) 解析策略版本（版本不存在 / 无当前版本都明确拒绝）
        if request.policy_version is not None:
            version = request.policy_version
            if not self._policies.exists(version):
                return self._deny(
                    request, DenyReason.POLICY_VERSION_NOT_FOUND, version, None
                )
        else:
            try:
                version = self._policies.current_version()
            except AccessDeniedError:
                return self._deny(request, DenyReason.POLICY_MISSING, "-", None)

        # 2) 主体与资源
        principal = self._store.get_principal(request.principal_id)
        resource = self._store.get_resource(request.resource_id)
        if principal is None or resource is None:
            return self._deny(request, DenyReason.UNAUTHORIZED, version, None)

        # 3) 规则匹配
        rule = self._policies.match(version, principal, resource)
        if rule is None:
            return self._deny(request, DenyReason.POLICY_DEFAULT_DENY, version, None)
        rule_label = f"{rule.principal_id}@{rule.scope}:{rule.effect}"
        if rule.effect == "deny":
            return self._deny(request, DenyReason.UNAUTHORIZED, version, rule_label)

        # 4) 字段越权（一次性指出全部越权字段，原因可区分、可解释）
        forbidden = sorted(f for f in request.fields if f not in rule.allowed_fields)
        if forbidden:
            return self._deny(
                request, DenyReason.FIELD_FORBIDDEN, version, rule_label, forbidden
            )

        # 5) 保留期
        expired = is_expired(resource, self._clock.now())
        if expired:
            action = self._policies.get(version).retention_action
            if action == RetentionAction.DENY:
                return self._deny(
                    request, DenyReason.RETENTION_EXPIRED, version, rule_label
                )
            if action == RetentionAction.PURGE:
                if not skip_retention_side_effects:
                    self._store.update_resource_fields(
                        resource.id,
                        {k: REDACTED_PLACEHOLDER for k in resource.fields},
                    )
                return self._deny(
                    request, DenyReason.RETENTION_EXPIRED, version, rule_label
                )
            # REDACT：到期数据所有请求字段强制全遮蔽，绝不静默返回完整内容
            out = {f: REDACTED_PLACEHOLDER for f in request.fields}
            return AccessDecision(
                allowed=True,
                reason=None,
                policy_version=version,
                matched_rule=rule_label,
                fields=out,
            )

        # 6) 逐字段确定性脱敏（字段在资源中不存在同样视为越权）
        missing = sorted(f for f in request.fields if f not in resource.fields)
        if missing:
            return self._deny(
                request, DenyReason.FIELD_FORBIDDEN, version, rule_label, missing
            )
        out = {}
        for f in request.fields:
            field_rule = rule.field_rules.get(f)
            mode = field_rule.mask if field_rule is not None else MaskMode.FULL
            out[f] = mask_value(resource.fields[f], mode)
        return AccessDecision(
            allowed=True,
            reason=None,
            policy_version=version,
            matched_rule=rule_label,
            fields=out,
        )

    # ---- 辅助 -----------------------------------------------------------

    @staticmethod
    def _deny(
        request: AccessRequest,
        reason: DenyReason,
        version: str,
        rule_label: str | None,
        extra: list[str] | None = None,
    ) -> AccessDecision:
        # 统一由调用处的 log_decision 记录可解释信息；
        # 这里只构造拒绝结论，任何字段值都不进入异常/日志。
        return AccessDecision(
            allowed=False,
            reason=reason,
            policy_version=version,
            matched_rule=rule_label,
            fields={},
            deny_detail=tuple(extra) if extra else (),
        )
