"""策略版本仓库、发布期冲突校验与规则匹配。

设计要点（缺省/冲突一律拒绝，绝不默认放行）：

* 策略版本**不可变**：版本号一经发布即固化，重复发布同版本号 → 冲突拒绝；
  策略更新只能以新版本号发布，并通过 ``set_current`` 切换“当前版本”。
* 同一版本内，两条规则的“适用主体 × 资源范围”若存在交集 → 发布期冲突拒绝，
  避免运行期出现“到底命中哪条”的二义性。通配符 ``"*"`` 表示任意主体/范围。
* 规则的字段级配置必须自洽：``field_rules`` 的键必须包含在
  ``allowed_fields`` 内，否则发布期冲突拒绝。
* 命中的规则可以是 ``allow`` 或显式 ``deny``；完全没有命中规则时由上层
  按“策略缺省”拒绝（``POLICY_DEFAULT_DENY``）。
"""
from __future__ import annotations

import threading

from .errors import AccessDeniedError
from .models import DenyReason, PolicyVersion, Principal, Resource, Rule

_WILDCARD = "*"
_VALID_EFFECTS = frozenset({"allow", "deny"})


def _principal_overlap(a: str, b: str) -> bool:
    return a == b or a == _WILDCARD or b == _WILDCARD


def _scope_overlap(a: str, b: str) -> bool:
    return a == b or a == _WILDCARD or b == _WILDCARD


def rules_conflict(a: Rule, b: Rule) -> bool:
    """两条规则在主体与范围两个维度都有交集时视为冲突。"""
    if a is b:
        return False
    return _principal_overlap(a.principal_id, b.principal_id) and _scope_overlap(
        a.scope, b.scope
    )


class PolicyStore:
    def __init__(self) -> None:
        self._versions: dict[str, PolicyVersion] = {}
        self._current: str | None = None
        self._lock = threading.RLock()

    # ---- 发布与版本管理 -------------------------------------------------

    def publish(self, policy: PolicyVersion) -> None:
        """校验并固化一个策略版本。任何不自洽都抛 :class:`AccessDeniedError`。"""
        with self._lock:
            if policy.version in self._versions:
                raise AccessDeniedError(
                    DenyReason.POLICY_CONFLICT,
                    f"policy version already exists and is immutable: {policy.version}",
                )
            self._validate_rules(policy)
            self._versions[policy.version] = policy

    @staticmethod
    def _validate_rules(policy: PolicyVersion) -> None:
        rules = policy.rules
        for i, rule in enumerate(rules):
            if rule.effect not in _VALID_EFFECTS:
                raise AccessDeniedError(
                    DenyReason.POLICY_CONFLICT,
                    f"invalid rule effect {rule.effect!r} in policy {policy.version}",
                )
            for field_name, field_rule in rule.field_rules.items():
                if field_name not in rule.allowed_fields:
                    raise AccessDeniedError(
                        DenyReason.POLICY_CONFLICT,
                        "field rule references a field outside allowed_fields: "
                        f"{field_name} in {rule.principal_id}@{rule.scope}",
                    )
                if field_rule.field_name != field_name:
                    raise AccessDeniedError(
                        DenyReason.POLICY_CONFLICT,
                        f"field rule key/name mismatch for {field_name}",
                    )
            for j in range(i):
                if rules_conflict(rules[i], rules[j]):
                    raise AccessDeniedError(
                        DenyReason.POLICY_CONFLICT,
                        "overlapping rules in policy "
                        f"{policy.version}: {_label(rules[j])} vs {_label(rules[i])}",
                    )

    def set_current(self, version: str) -> None:
        with self._lock:
            if version not in self._versions:
                raise AccessDeniedError(
                    DenyReason.POLICY_VERSION_NOT_FOUND,
                    f"cannot set current policy; version not found: {version}",
                )
            self._current = version

    def current_version(self) -> str:
        with self._lock:
            if self._current is None:
                raise AccessDeniedError(
                    DenyReason.POLICY_MISSING,
                    "no current policy version has been published",
                )
            return self._current

    def exists(self, version: str) -> bool:
        with self._lock:
            return version in self._versions

    def get(self, version: str) -> PolicyVersion:
        with self._lock:
            policy = self._versions.get(version)
            if policy is None:
                raise AccessDeniedError(
                    DenyReason.POLICY_VERSION_NOT_FOUND,
                    f"policy version not found: {version}",
                )
            return policy

    def versions(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._versions))

    # ---- 匹配 -----------------------------------------------------------

    def match(
        self, version: str, principal: Principal, resource: Resource
    ) -> Rule | None:
        """返回唯一命中的规则；无命中返回 None（由上层按缺省拒绝处理）。"""
        policy = self.get(version)
        hits = [
            rule
            for rule in policy.rules
            if _principal_overlap(rule.principal_id, principal.id)
            and (rule.scope == resource.scope or rule.scope == _WILDCARD)
            and (
                rule.principal_id != _WILDCARD
                or _principal_overlap(rule.principal_id, principal.id)
            )
        ]
        # 发布期已保证至多一条命中；防御性断言，避免静默二义。
        if len(hits) > 1:
            raise AccessDeniedError(
                DenyReason.POLICY_CONFLICT,
                "multiple rules matched unexpectedly in policy " + version,
            )
        return hits[0] if hits else None


def _label(rule: Rule) -> str:
    return f"{rule.principal_id}@{rule.scope}:{rule.effect}"
