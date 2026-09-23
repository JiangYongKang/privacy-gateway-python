"""pytest 夹具：固定时钟 + 确定性种子数据（每个测试独立、互不污染）。"""
from __future__ import annotations

import pytest

from privacy_gateway.clock import FixedClock, parse_ts
from privacy_gateway.seed import SEED_TIME, build_service


@pytest.fixture
def fixed_now():
    return parse_ts(SEED_TIME)


@pytest.fixture
def clock(fixed_now):
    return FixedClock(fixed_now)


@pytest.fixture
def service(clock):
    # 种子默认当前策略为 v1。
    return build_service(clock, current_policy="v1")


@pytest.fixture
def service_v2(clock):
    return build_service(clock, current_policy="v2")
