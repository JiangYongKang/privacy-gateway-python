"""安全日志工具。

网关注册自定义 ``%`` 风格过滤器，任何日志记录中一旦出现资源字段值
（通过约定的 ``extra={"sensitive_fields": {...}}`` 传入），
都会被替换为只含长度的占位符 ``"<value:len=N>"``。

判定日志统一走 :func:`log_decision`，只打印：
输入（请求ID/主体/资源/请求字段名）、命中的策略版本、命中规则标签、
允许与否与**可区分的拒绝原因**，以及返回字段名；不打印任何字段值。
"""
from __future__ import annotations

import logging
from collections.abc import Mapping

from .models import AccessDecision, AccessRequest

_SENSITIVE_KEY = "sensitive_fields"


def safe_fields(fields: Mapping[str, str]) -> dict[str, str]:
    """把字段映射转为仅含长度信息的安全描述。"""
    return {k: f"<value:len={len(str(v))}>" for k, v in fields.items()}


class _RedactionFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        sensitive = getattr(record, _SENSITIVE_KEY, None)
        if isinstance(sensitive, Mapping):
            record.sensitive_fields = safe_fields(sensitive)
        if not hasattr(record, "policy_version"):
            record.policy_version = "-"
        return True


_CONFIGURED = False


def _configure_once() -> None:
    global _CONFIGURED
    if _CONFIGURED:
        return
    handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter(
            "%(asctime)s %(levelname)s %(name)s [%(policy_version)s] %(message)s"
        )
    )
    root = logging.getLogger("privacy_gateway")
    root.addHandler(handler)
    root.addFilter(_RedactionFilter())
    root.setLevel(logging.INFO)
    root.propagate = False
    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    _configure_once()
    logger = logging.getLogger(name)
    # 过滤器加在 logger 上，保证经该 logger 发出的记录都被净化。
    if not any(isinstance(f, _RedactionFilter) for f in logger.filters):
        logger.addFilter(_RedactionFilter())
    return logger


def log_decision(
    logger: logging.Logger,
    request: AccessRequest,
    decision: AccessDecision,
) -> None:
    """打印一条可解释、可复现且不含敏感值的判定日志。"""
    logger.info(
        "decision request_id=%s principal=%s resource=%s requested_fields=(%s) "
        "policy_version=%s matched_rule=%s allowed=%s reason=%s "
        "deny_detail=(%s) returned_fields=(%s)",
        request.request_id,
        request.principal_id,
        request.resource_id,
        ",".join(request.fields),
        decision.policy_version,
        decision.matched_rule or "-",
        decision.allowed,
        decision.reason.value if decision.reason else "-",
        ",".join(decision.deny_detail),
        ",".join(sorted(decision.fields)),
        extra={"policy_version": decision.policy_version},
    )
