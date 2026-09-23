"""脱敏原语、保留期边界、时钟确定性。"""
from __future__ import annotations

from datetime import datetime, timezone

from privacy_gateway.clock import FixedClock, format_ts, parse_ts
from privacy_gateway.masking import mask_value
from privacy_gateway.models import MaskMode, Resource
from privacy_gateway.retention import is_expired


def test_mask_modes_are_deterministic_and_distinct():
    value = "13800138000"
    assert mask_value(value, MaskMode.FULL) == "<REDACTED>"
    assert mask_value(value, MaskMode.PARTIAL) == "1*********0"
    assert mask_value(value, MaskMode.HASH) == mask_value(value, MaskMode.HASH)
    assert mask_value(value, MaskMode.HASH).startswith("hmac:")
    assert value not in mask_value(value, MaskMode.HASH)
    assert mask_value("ab", MaskMode.PARTIAL) == "**"
    assert mask_value("x", MaskMode.NONE) == "x"


def test_clock_format_roundtrip_and_fixed_advance():
    ts = "2026-09-23T08:00:00.000000Z"
    assert format_ts(parse_ts(ts)) == ts
    c = FixedClock(parse_ts(ts))
    c.advance(60)
    assert format_ts(c.now()) == "2026-09-23T08:01:00.000000Z"


def test_retention_boundary_inclusive():
    r = Resource(
        "r", "patient", "u", retention_days=30,
        created_at="2026-08-01T00:00:00.000000Z", fields={},
    )
    # 第 29 天未到期，第 30 天 00:00 到期（>= 判定）
    assert is_expired(r, datetime(2026, 8, 30, 23, 59, tzinfo=timezone.utc)) is False
    assert is_expired(r, datetime(2026, 8, 31, 0, 0, tzinfo=timezone.utc)) is True
