"""数据保留期判定。

保留期从资源 ``created_at`` 起算（含时区的确定时间点）。
到期判定为：``now >= created_at + retention_days``。
保留期 <= 0 表示立即到期（便于测试 purge/redact 语义）。
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .clock import parse_ts
from .models import Resource


def is_expired(resource: Resource, at: datetime) -> bool:
    """判断资源在给定时刻是否已超出保留期。"""
    if at.tzinfo is None:
        at = at.replace(tzinfo=timezone.utc)
    created = parse_ts(resource.created_at)
    deadline = created + timedelta(days=resource.retention_days)
    return at.astimezone(timezone.utc) >= deadline.astimezone(timezone.utc)
