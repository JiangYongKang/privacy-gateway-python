"""Policy loading, validation and conflict detection.

Default posture is *deny*: anything ambiguous, duplicated or missing is a
rejection, never an implicit allow.
"""

from __future__ import annotations

from .errors import PolicyConflictError, PolicyNotFoundError
from .models import FieldRule, MaskAction, Policy, ScopePolicy
from .store import LocalStore


def validate_policy(policy: Policy) -> None:
    """Reject bundles that are internally inconsistent.

    Checks performed:
      * non-empty, unique version tag
      * unique scope names (guaranteed by dict, checked for defensive dupes
        through serialised input at load time)
      * no duplicate field names within a scope
      * MASK rules with negative prefixes, HASH rules with non-positive prefix
      * retention overrides that are negative
    """

    if not policy.version or not policy.version.strip():
        raise PolicyConflictError("policy version must be a non-empty string")
    if policy.default_retention_days is not None and policy.default_retention_days < 0:
        raise PolicyConflictError(
            f"policy {policy.version!r}: default_retention_days must be >= 0"
        )

    seen_scopes: set[str] = set()
    for scope in policy.scope_policies.values():
        if scope.scope in seen_scopes:
            raise PolicyConflictError(
                f"policy {policy.version!r}: duplicate scope {scope.scope!r}"
            )
        seen_scopes.add(scope.scope)
        _validate_scope(policy.version, scope)


def _validate_scope(version: str, scope: ScopePolicy) -> None:
    seen_fields: set[str] = set()
    for field_name, rule in scope.field_rules.items():
        if field_name in seen_fields:
            raise PolicyConflictError(
                f"policy {version!r} scope {scope.scope!r}: "
                f"duplicate field rule {field_name!r}"
            )
        seen_fields.add(field_name)
        if rule.field_name != field_name:
            raise PolicyConflictError(
                f"policy {version!r} scope {scope.scope!r}: field rule key "
                f"{field_name!r} does not match rule field {rule.field_name!r}"
            )
        if rule.action is MaskAction.MASK and rule.keep_prefix < 0:
            raise PolicyConflictError(
                f"policy {version!r} scope {scope.scope!r} field {field_name!r}: "
                "mask keep_prefix must be >= 0"
            )
        if rule.action is MaskAction.HASH and rule.hash_prefix <= 0:
            raise PolicyConflictError(
                f"policy {version!r} scope {scope.scope!r} field {field_name!r}: "
                "hash_prefix must be > 0"
            )
    if scope.retention_days is not None and scope.retention_days < 0:
        raise PolicyConflictError(
            f"policy {version!r} scope {scope.scope!r}: "
            "retention_days must be >= 0"
        )
    # Empty allow list is legal (scope exists but nobody may read it) and the
    # default field action must itself be a valid action.
    if not isinstance(scope.default_field_action, MaskAction):
        raise PolicyConflictError(
            f"policy {version!r} scope {scope.scope!r}: "
            "invalid default_field_action"
        )


def load_policy(store: LocalStore, version: str | None) -> Policy:
    """Resolve ``version`` (or the current version); never fall back to allow.

    An explicit unknown version -> POLICY_NOT_FOUND. A system with no policy
    loaded at all -> POLICY_NOT_FOUND as well.
    """

    if version is None:
        version = store.current_policy_version()
    policy = store.get_policy(version)
    if policy is None:
        raise PolicyNotFoundError(f"policy version {version!r} does not exist")
    return policy
