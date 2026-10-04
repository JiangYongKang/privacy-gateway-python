"""Incremental / batched audit export: stable ordering, no gaps or
duplicates under concurrent writes, resumable cursors, bounded pages."""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

from fastapi.testclient import TestClient

from privacy_gateway.audit import AuditLog
from privacy_gateway.clock import FixedClock
from privacy_gateway.decider import Decider
from privacy_gateway.fixtures import ANCHOR_NOW, build_seed_store
from privacy_gateway.models import AccessRequest


def _req(rid, caller="alice", res="r-patient-1"):
    return AccessRequest(request_id=rid, caller_id=caller, resource_id=res)


def _fill(audit, decider, n, prefix="x"):
    for i in range(n):
        decider.decide(_req(f"{prefix}-{i:04d}"))


def _env():
    store = build_seed_store()
    audit = AuditLog()
    clock = FixedClock(ANCHOR_NOW)
    return store, audit, Decider(store, audit, clock)


def test_pagination_covers_everything_exactly_once_in_order():
    _, audit, decider = _env()
    _fill(audit, decider, 25)

    seen: list[int] = []
    cursor, pages = 0, 0
    while True:
        page, cursor, has_more = audit.page(cursor, limit=7)
        seen.extend(e.sequence for e in page)
        pages += 1
        if not has_more:
            break
        assert pages < 100  # safety: never loop forever

    assert seen == list(range(1, 26))       # complete, ordered, no dupes
    assert pages == 4                        # 7+7+7+4


def test_cursor_reuse_returns_the_same_page():
    _, audit, decider = _env()
    _fill(audit, decider, 10)
    p1, c1, _ = audit.page(3, limit=4)
    p2, c2, _ = audit.page(3, limit=4)
    assert [e.request_id for e in p1] == [e.request_id for e in p2]
    assert c1 == c2 == 7


def test_cursor_beyond_end_is_empty_and_stable():
    _, audit, decider = _env()
    _fill(audit, decider, 3)
    page, cursor, has_more = audit.page(999, limit=5)
    assert page == [] and cursor == 999 and has_more is False
    page, cursor, has_more = audit.page(3, limit=5)
    assert page == [] and cursor == 3 and has_more is False


def test_limit_is_clamped_to_max_page_size():
    _, audit, decider = _env()
    _fill(audit, decider, 5)
    page, _, _ = audit.page(0, limit=10**9)
    assert len(page) == 5
    page, _, _ = audit.page(0, limit=0)      # clamped up to 1
    assert len(page) == 1


def test_iter_pages_streams_without_materialising():
    _, audit, decider = _env()
    _fill(audit, decider, 10)
    gen = audit.iter_pages(0, limit=4)
    first = next(gen)
    assert len(first) == 4
    rest = [e for page in gen for e in page]
    assert [e.sequence for e in first] + [e.sequence for e in rest] == list(range(1, 11))


def test_export_under_concurrent_writes_no_miss_no_dup():
    """Writer appends while a reader pages through: the union of pages read
    up to any cursor is gap-free and duplicate-free, and a final drain
    catches every entry written before it."""
    _, audit, decider = _env()
    _fill(audit, decider, 20, prefix="pre")

    stop = threading.Event()
    written_after: list[str] = []

    def writer():
        i = 0
        while not stop.is_set():
            rid = f"live-{i:04d}"
            decider.decide(_req(rid))
            written_after.append(rid)
            i += 1

    t = threading.Thread(target=writer)
    t.start()
    collected: list[int] = []
    cursor = 0
    for _ in range(5):                        # export while writes continue
        page, cursor, _ = audit.page(cursor, limit=6)
        collected.extend(e.sequence for e in page)
    stop.set()
    t.join()

    # Drain to the end.
    while True:
        page, cursor, has_more = audit.page(cursor, limit=50)
        collected.extend(e.sequence for e in page)
        if not has_more:
            break

    assert collected == sorted(collected), "order must be ascending sequence"
    assert len(collected) == len(set(collected)), "no duplicates"
    total = len(audit.entries())
    assert collected == list(range(1, total + 1)), "gap-free: nothing missed"


def test_concurrent_readers_get_consistent_pages():
    _, audit, decider = _env()
    _fill(audit, decider, 40)

    def read_all():
        out, cursor = [], 0
        while True:
            page, cursor, has_more = audit.page(cursor, limit=3)
            out.extend(e.request_id for e in page)
            if not has_more:
                return out

    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(lambda _: read_all(), range(6)))
    assert all(r == results[0] for r in results)
    assert len(results[0]) == 40


def test_export_endpoint_paginates_and_resumes(engine_env):
    _, audit, _, app = engine_env
    c = TestClient(app)
    for i in range(9):
        c.post("/v1/access/decide", json={
            "request_id": f"ep-{i}", "caller_id": "alice",
            "resource_id": "r-patient-1"})

    r1 = c.get("/v1/audit/export", params={"after": 0, "limit": 4}).json()
    assert [e["request_id"] for e in r1["entries"]] == ["ep-0", "ep-1", "ep-2", "ep-3"]
    assert r1["has_more"] is True and r1["next_cursor"] == 4

    r2 = c.get("/v1/audit/export", params={"after": r1["next_cursor"], "limit": 4}).json()
    assert [e["request_id"] for e in r2["entries"]] == ["ep-4", "ep-5", "ep-6", "ep-7"]

    r3 = c.get("/v1/audit/export", params={"after": r2["next_cursor"], "limit": 4}).json()
    assert [e["request_id"] for e in r3["entries"]] == ["ep-8"]
    assert r3["has_more"] is False

    # Re-using an old cursor does not corrupt paging: same page again.
    again = c.get("/v1/audit/export", params={"after": 0, "limit": 4}).json()
    assert again == r1
