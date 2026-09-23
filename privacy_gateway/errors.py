"""可区分原因的拒绝异常（异常消息中绝不包含原始敏感值）。"""
from __future__ import annotations

from .models import DenyReason


class GatewayError(Exception):
    """所有网关异常的基类。"""

    reason: DenyReason = DenyReason.POLICY_DEFAULT_DENY

    def __init__(self, message: str, *, reason: DenyReason | None = None) -> None:
        super().__init__(message)
        if reason is not None:
            self.reason = reason


class AccessDeniedError(GatewayError):
    """访问被拒绝；携带可区分的拒绝原因。"""

    def __init__(self, reason: DenyReason, message: str) -> None:
        super().__init__(message, reason=reason)
