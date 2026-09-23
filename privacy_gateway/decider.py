"""The decision engine.

Pipeline (each stage has its own distinguishable deny code):

  1. idempotency / replay short-circuit (request_id)
  2. caller authentication            -> UNAUTHORIZED_CALLER
  3. policy version resolution        -> POLICY_NOT_FOUND / POLICY_CONFLICT
  4. resource lookup                  -> RESOURCE_NOT_FOUND
  5. scope coverage                   -> SCOPE_NOT_POLICIED
  6. scope authorization              -> ACCESS_DENIED
  7. field authorization              -> FIELD_FORBIDDEN
  8. retention horizon                -> RETENTION_EXPIRED / tombstone
  9. deterministic field masking
 10. append audit (exactly once per request_id)

DENY is represented as a ``DecisionResult`` (not an exception) so it can be
audited and replayed; structural failures (unknown caller/version/resource,
conflicts, idempotency reuse) raise typed ``PrivacyError`` s before a decision
is recorded. No stage logs or stores raw field values.
"""

from __future__ import annotations

import logging
from datetime import timedelta

from .audit import AuditLog
from .clock import Clock
from .errors import (
    AccessDeniedError,
    FieldForbiddenError,
    IdempotencyConflictError,
    ResourceNotFoundError,
    RetentionExpiredError,
    ScopeNotPoliciedError,
    UnauthorizedCallerError,
)
from .masking import apply_rule, mask_for_log
from .models import (
    AccessRequest,
    AuditEntry,
    Decision,
    DecisionResult,
    FieldOutcome,
    FieldRule,
    MaskAction,
)
from .policies import load_policy, validate_policy
from .store import LocalStore

logger = logging.getLogger("privacy_gateway.decider")


def _replay_result(entry: AuditEntry) -> DecisionResult:
    """Rebuild the exact DecisionResult that was originally stored."""

    return DecisionResult(
        request_id=entry.request_id,
        decision=entry.decision,
        policy_version=entry.policy_version,
        caller_id=entry.caller_id,
        resource_id=entry.resource_id,
        scope=entry.scope,
        fields={
            name: FieldOutcome(
                field_name=name,
                action=MaskAction(snap["action"]),
                value=snap["value"],
            )
            for name, snap in entry.fields_snapshot.items()
        },
        reason=entry.reason,
        decided_at=entry.decided_at,
        expired=entry.decision is Decision.TOMBSTONE,
    )


class Decider:
    def __init__(self, store: LocalStore, audit: AuditLog, clock: Clock) -> None:
        self.store = store
        self.audit = audit
        self.clock = clock

    # ------------------------------------------------------------------
    def decide(self, req: AccessRequest) -> DecisionResult:
        fingerprint = self._fingerprint(req)

        # Stage 1: idempotency / replay short-circuit ---------------------
        prior = self.audit.get_by_request(req.request_id)
        if prior is not None:
            if prior.request_fingerprint != fingerprint:
                self._log_event(
                    req, "reject", "idempotency-conflict",
                    version=prior.policy_version, scope=prior.scope,
                )
                raise IdempotencyConflictError(
                    f"request_id {req.request_id!r} was already used with a "
                    "different payload"
                )
            self._log_event(
                req, prior.decision.value, "replay-hit",
                version=prior.policy_version, scope=prior.scope,
            )
            return _replay_result(prior)

        # Stage 2: caller -------------------------------------------------
        caller = self.store.get_caller(req.caller_id)
        if caller is None:
            # Not a per-request decision (identity unknown); refuse loudly.
            self._log_event(req, "reject", "unauthorized-caller", version="-", scope="-")
            raise UnauthorizedCallerError(
                f"caller {req.caller_id!r} is not registered"
            )

        # Stage 3: policy -------------------------------------------------
        policy = load_policy(self.store, req.policy_version)
        validate_policy(policy)  # cheap; guarantees we never run a broken bundle
        version = policy.version

        # Stage 4: resource -----------------------------------------------
        resource = self.store.get_resource(req.resource_id)
        if resource is None:
            self._log_event(req, "reject", "resource-not-found", version=version, scope="-")
            raise ResourceNotFoundError(
                f"resource {req.resource_id!r} does not exist"
            )

        # Stage 5: scope coverage -----------------------------------------
        scope_policy = policy.scope(resource.scope)
        if scope_policy is None:
            return self._deny(
                req, version, resource.scope, "SCOPE_NOT_POLICIED",
                f"scope {resource.scope!r} has no rules under policy "
                f"{version!r}; default deny",
            )

        # Stage 6: scope authorization ------------------------------------
        if req.caller_id not in scope_policy.allowed_callers:
            return self._deny(
                req, version, resource.scope, "ACCESS_DENIED",
                f"caller {req.caller_id!r} is not in the allow list for "
                f"scope {resource.scope!r} under policy {version!r}",
            )

        # Stage 7: field authorization ------------------------------------
        requested = self._resolve_fields(req, resource)
        rules: dict[str, FieldRule] = scope_policy.field_rules
        for name in requested:
            if name not in rules:
                return self._deny(
                    req, version, resource.scope, "FIELD_FORBIDDEN",
                    f"field {name!r} is not governed by any rule for scope "
                    f"{resource.scope!r} under policy {version!r}",
                    field_names=requested,
                )

        # Stage 8: retention horizon --------------------------------------
        retention_days = (
            scope_policy.retention_days
            if scope_policy.retention_days is not None
            else policy.default_retention_days
        )
        age = self.clock.now() - _parse_iso(resource.created_at)
        expired = (
            retention_days is not None
            and age > timedelta(days=retention_days)
        )
        if expired:
            return self._handle_expired(
                req, version, resource.scope, requested, scope_policy.on_expiry.value,
                retention_days,
            )

        # Stage 9: deterministic masking ----------------------------------
        outcomes: dict[str, FieldOutcome] = {}
        rule_hits: list[str] = []
        for name in sorted(requested):
            rule = scope_policy.field_rules[name]
            outcomes[name] = FieldOutcome(
                field_name=name,
                action=rule.action,
                value=apply_rule(resource.data.get(name), rule),
            )
            rule_hits.append(f"{name}={mask_for_log(rule)}")

        result = DecisionResult(
            request_id=req.request_id,
            decision=Decision.ALLOW,
            policy_version=version,
            caller_id=req.caller_id,
            resource_id=req.resource_id,
            scope=resource.scope,
            fields=outcomes,
            reason=(
                f"allow: caller on allow list for scope {resource.scope!r}; "
                f"fields [{', '.join(rule_hits)}]; policy {version!r}"
            ),
            decided_at=self.clock.now_iso(),
        )

        # Stage 10: audit --------------------------------------------------
        self.audit.append(result, "", fingerprint, result.decided_at)
        self._log_event(req, "allow", "decision", version=version,
                        scope=resource.scope, rule_hits=rule_hits)
        return result

    # ------------------------------------------------------------------
    def _handle_expired(
        self, req: AccessRequest, version: str, scope: str,
        field_names: tuple[str, ...], on_expiry: str, retention_days: int | None,
    ) -> DecisionResult:
        from .models import ExpiryAction

        if on_expiry == ExpiryAction.PURGE.value:
            # Local, audited erasure; then deny. No content is ever emitted.
            self.store.delete_resource(req.resource_id)

        if on_expiry == ExpiryAction.TOMBSTONE.value:
            result = DecisionResult(
                request_id=req.request_id,
                decision=Decision.TOMBSTONE,
                policy_version=version,
                caller_id=req.caller_id,
                resource_id=req.resource_id,
                scope=scope,
                fields={},
                reason=(
                    f"resource past retention horizon "
                    f"({retention_days}d); tombstone returned per "
                    f"on_expiry={on_expiry} in policy {version!r}"
                ),
                decided_at=self.clock.now_iso(),
                expired=True,
            )
            self.audit.append(result, "", self._fingerprint(req), result.decided_at)
            self._log_event(req, "tombstone", "retention-expired",
                            version=version, scope=scope)
            return result

        # DENY (covers explicit DENY and PURGE-after-erasure)
        result = DecisionResult(
            request_id=req.request_id,
            decision=Decision.DENY,
            policy_version=version,
            caller_id=req.caller_id,
            resource_id=req.resource_id,
            scope=scope,
            fields={},
            reason=(
                f"resource past retention horizon ({retention_days}d); "
                f"content withheld per on_expiry={on_expiry} in policy "
                f"{version!r}"
            ),
            decided_at=self.clock.now_iso(),
            expired=True,
        )
        self.audit.append(result, "RETENTION_EXPIRED", self._fingerprint(req),
                          result.decided_at)
        self._log_event(req, "deny", "retention-expired",
                        version=version, scope=scope)
        return result

    # ------------------------------------------------------------------
    def _deny(
        self, req: AccessRequest, version: str, scope: str, code: str,
        reason: str, field_names: tuple[str, ...] = (),
    ) -> DecisionResult:
        result = DecisionResult(
            request_id=req.request_id,
            decision=Decision.DENY,
            policy_version=version,
            caller_id=req.caller_id,
            resource_id=req.resource_id,
            scope=scope,
            fields={},
            reason=reason,
            decided_at=self.clock.now_iso(),
        )
        self.audit.append(result, code, self._fingerprint(req), result.decided_at)
        self._log_event(req, "deny", code.lower().replace("_", "-"),
                        version=version, scope=scope)
        return result

    # ------------------------------------------------------------------
    @staticmethod
    def _resolve_fields(req: AccessRequest, resource) -> tuple[str, ...]:
        if req.fields is not None:
            return tuple(sorted(req.fields))
        return tuple(sorted(resource.data.keys()))

    @staticmethod
    def _fingerprint(req: AccessRequest) -> str:
        from .models import fingerprint_request

        return fingerprint_request(req)

    def _log_event(
        self, req: AccessRequest, outcome: str, basis: str, *,
        version: str, scope: str, rule_hits: list[str] | None = None,
    ) -> None:
        """Structured, value-free log line: inputs, policy version, basis."""

        safe = {
            "request_id": req.request_id,
            "caller_id": req.caller_id,
            "resource_id": req.resource_id,
            "requested_policy": req.policy_version or "<current>",
            "fields": list(req.fields) if req.fields is not None else "<all>",
        }
        logger.info(
            "decision-event %s basis=%s policy_version=%s scope=%s inputs=%s rules=%s",
            outcome, basis, version, scope, safe, rule_hits or [],
        )


def _parse_iso(ts: str):
    from datetime import datetime, timezone

    dt = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")
    return dt.replace(tzinfo=timezone.utc)
