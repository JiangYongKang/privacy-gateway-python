"""Shared fixtures: isolated store/audit, fixed clock, stdout decision logging.

The autouse ``decision_trace`` fixture makes the gateway emit each decision's
inputs, the policy version hit and the decision basis to stdout, so test runs
(``uv run pytest -s``) print an explainable trail.
"""

from __future__ import annotations

import logging
import sys

import pytest

from privacy_gateway.app import create_app
from privacy_gateway.audit import AuditLog
from privacy_gateway.clock import FixedClock
from privacy_gateway.fixtures import ANCHOR_NOW, build_seed_store


@pytest.fixture()
def engine_env():
    store = build_seed_store()
    audit = AuditLog()
    clock = FixedClock(ANCHOR_NOW)
    app = create_app(store, audit, clock)
    return store, audit, clock, app


@pytest.fixture(autouse=True)
def decision_trace():
    loggers = [
        logging.getLogger("privacy_gateway.decider"),
        logging.getLogger("privacy_gateway.holds"),
    ]
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("[trace] %(message)s"))
    old_levels = []
    for logger in loggers:
        logger.addHandler(handler)
        old_levels.append(logger.level)
        logger.setLevel(logging.INFO)
    yield
    for logger, old in zip(loggers, old_levels):
        logger.removeHandler(handler)
        logger.setLevel(old)
