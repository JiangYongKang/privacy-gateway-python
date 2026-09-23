"""确定性脱敏原语。

四种脱敏模式：

* ``none``    —— 原样返回（仅可用于非敏感字段，策略显式允许时）；
* ``full``    —— 完全遮蔽，输出固定占位 ``"<REDACTED>"``；
* ``partial`` —— 保留极少量结构信息（首尾各 1 个字符），其余以 ``*`` 替换；
                 长度 <=2 时整体替换，避免泄露；
* ``hash``    —— 以固定本地盐做 HMAC-SHA256，输出可跨请求比较、
                 但不可逆的确定性假名 ``"hmac:<hex16>"``。

所有输出都是输入的纯函数：同值同模式 => 同结果，便于复现与解释，
且任何输出都不包含原始敏感值（``none`` 除外，它只能由策略显式授予）。
"""
from __future__ import annotations

import hashlib
import hmac

from .models import MaskMode

REDACTED_PLACEHOLDER = "<REDACTED>"
# 本地固定“盐”（非真实凭据）：仅用于让假名在本地环境内稳定可复现。
_LOCAL_MASK_SALT = b"privacy-gateway/local-masking/v1"


def mask_value(value: str, mode: MaskMode) -> str:
    """按 ``mode`` 对单个值做确定性脱敏。"""
    if mode == MaskMode.NONE:
        return value
    if mode == MaskMode.FULL:
        return REDACTED_PLACEHOLDER
    if mode == MaskMode.PARTIAL:
        return _partial(value)
    if mode == MaskMode.HASH:
        return "hmac:" + hmac.new(
            _LOCAL_MASK_SALT, value.encode("utf-8"), hashlib.sha256
        ).hexdigest()[:16]
    raise ValueError(f"unknown mask mode: {mode!r}")


def _partial(value: str) -> str:
    n = len(value)
    if n <= 2:
        return "*" * n
    return value[0] + "*" * (n - 2) + value[-1]


def fingerprint(payload: str) -> str:
    """对判定结论做 SHA-256 指纹（不含密钥，用于一致性比对）。"""
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
