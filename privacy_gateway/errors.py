"""Domain errors. Every error carries a stable machine-readable ``code`` so that
distinct rejection reasons remain distinguishable to callers, auditors and
tests. Error messages MUST only ever reference safe identifiers (caller id,
scope, field name, policy version) — never raw sensitive values."""

from __future__ import annotations


class PrivacyError(Exception):
    """Base class for all privacy-gateway rejections."""

    code: str = "PRIVACY_ERROR"
    http_status: int = 403

    def __init__(self, message: str, *, code: str | None = None) -> None:
        super().__init__(message)
        if code is not None:
            self.code = code


class UnauthorizedCallerError(PrivacyError):
    """The caller identity is unknown / not permitted to invoke the gateway."""

    code = "UNAUTHORIZED_CALLER"
    http_status = 401


class AccessDeniedError(PrivacyError):
    """Resource-scope access denied (caller known, but scope not granted)."""

    code = "ACCESS_DENIED"
    http_status = 403


class ScopeNotPoliciedError(AccessDeniedError):
    """The resource's scope has no rules in the resolved policy version
    (policy gap). Distinct from an authenticated-but-not-allowed access."""

    code = "SCOPE_NOT_POLICIED"
    http_status = 403


class FieldForbiddenError(PrivacyError):
    """The caller requested/accessed a field outside the policy field rules."""

    code = "FIELD_FORBIDDEN"
    http_status = 403


class PolicyNotFoundError(PrivacyError):
    """The requested policy version does not exist."""

    code = "POLICY_NOT_FOUND"
    http_status = 404


class PolicyConflictError(PrivacyError):
    """A policy bundle is internally inconsistent (duplicate/ambiguous rules)."""

    code = "POLICY_CONFLICT"
    http_status = 409


class RetentionExpiredError(PrivacyError):
    """The resource is past its retention horizon; full content is withheld."""

    code = "RETENTION_EXPIRED"
    http_status = 410


class ResourceNotFoundError(PrivacyError):
    """The requested resource does not exist in local storage."""

    code = "RESOURCE_NOT_FOUND"
    http_status = 404


class IdempotencyConflictError(PrivacyError):
    """A request id is being reused with a different payload."""

    code = "IDEMPOTENCY_CONFLICT"
    http_status = 409


class HoldNotFoundError(PrivacyError):
    """No active retention hold exists for the given resource."""

    code = "HOLD_NOT_FOUND"
    http_status = 404
