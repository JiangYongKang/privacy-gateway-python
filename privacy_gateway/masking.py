"""Deterministic field masking primitives.

Every transformation here is a pure, deterministic function of the value and
the rule: the same input under the same policy version always yields the same
output, which keeps reads reproducible and replayable.
"""

from __future__ import annotations

import hashlib
from typing import Any

from .errors import FieldForbiddenError
from .models import FieldRule, MaskAction

REDACT_TOKEN = "[REDACTED]"
MASK_FILLER = "*"
HASH_PREFIX_LITERAL = "sha256:"


def apply_rule(value: Any, rule: FieldRule) -> Any:
    """Apply a single field rule and return the safe-to-emit value."""

    match rule.action:
        case MaskAction.VISIBLE:
            return value
        case MaskAction.REDACT:
            return REDACT_TOKEN
        case MaskAction.MASK:
            return mask_value(value, rule.keep_prefix)
        case MaskAction.HASH:
            return hash_value(value, rule.hash_prefix)
        case _:  # pragma: no cover - exhaustive enum
            raise FieldForbiddenError(
                f"unsupported mask action {rule.action!r} for field "
                f"{rule.field_name!r}"
            )


def mask_value(value: Any, keep_prefix: int) -> str:
    """Keep the first ``keep_prefix`` characters; replace the rest with '*'.

    Non-string values are rendered via ``str`` first. Negative or oversized
    prefixes are clamped. Empty values render as the redact token.
    """

    text = "" if value is None else str(value)
    if text == "":
        return REDACT_TOKEN
    n = max(0, min(keep_prefix, len(text)))
    return text[:n] + MASK_FILLER * (len(text) - n)


def hash_value(value: Any, hash_prefix: int) -> str:
    """Stable SHA-256 fingerprint of the value with a fixed hex prefix."""

    if value is None:
        return HASH_PREFIX_LITERAL + "0" * max(0, hash_prefix)
    digest = hashlib.sha256(str(value).encode("utf-8")).hexdigest()
    n = max(0, min(hash_prefix, len(digest)))
    return HASH_PREFIX_LITERAL + digest[:n]


def mask_for_log(rule: FieldRule) -> str:
    """Safe, value-free description of a rule for structured logs."""

    match rule.action:
        case MaskAction.MASK:
            return f"mask(keep_prefix={rule.keep_prefix})"
        case MaskAction.HASH:
            return f"hash(prefix={rule.hash_prefix})"
        case other:
            return other.value
