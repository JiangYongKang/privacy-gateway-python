"""Incremental audit export: paged, cursor-resumable, stable under
concurrent writes, bounded in memory."""

from __future__ import annotations

import types
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient

from privacy_gateway.decider import Decider
from privacy_gateway.export import (
    MAX_PAGE_SIZE,
    InvalidCursorError,
    decode_cursor,
    encode_cursor,
    export_page,
    stream_entries,
)
from privacy_gateway.models import AccessRequest


def _req(rid, caller="alice", res="r-patient-1"):
    return AccessRequest(request_id=rid, caller_id=caller, resource_id=res)


def _fill(engine_env, n, prefix="x"):
    store, audit, clock, _ = engine_env
    d = Decider(store, audit, clock)
    for i in range(n):
        d.decide(_req(f"{prefix}-{i:03d}"))
    return audit


def test_cursor_roundtrip():
    assert decode_cursor(encode_cursor(0)) == 0
    assert decode_cursor(encode_cursor(12345)) == 12345
    with pytest.raises(InvalidCursorError):
        decode_cursor("bogus")
    with pytest.raises(InvalidCursorError):
        decode_cursor("pg1:-1")
    with pytest.raises(InvalidCursorError):
        decode_cursor("pg1:abc")


def test_paging_covers_all_entries_in_order_without_gaps(engine_env):
    audit = _fill(engine_env, 25)
    seen, cursor, pages = [], None, 0
    while True:
        page = export_page(audit, cursor, limit=10)
        seen.extend(e.request_id for e in page.entries)
        pages += 1
        if not page.has_more:
            break
        cursor = page.next_cursor
    assert pages == 3  # 10 + 10 + 5
    assert seen == [f"x-{i:03d}" for i in range(25)]
    assert [e.sequence for e in audit.entries()] == list(range(1, 26))


def test_cursor_reuse_returns_same_page_and_resume_works(engine_env):
    audit = _fill(engine_env, 12)
    page1 = export_page(audit, None, limit=5)
    again = export_page(audit, None, limit=5)
    assert page1 == again  # idempotent: same cursor -> same page

    page2 = export_page(audit, page1.next_cursor, limit=5)
    page2_again = export_page(audit, page1.next_cursor, limit=5)
    assert page2 == page2_again
    assert [e.request_id for e in page2.entries] == [f"x-{i:03d}" for i in range(5, 10)]

    # Resume from the middle cursor: the rest arrives in order, no overlap.
    rest = list(stream_entries(audit, page1.next_cursor, page_size=4))
    assert [e.request_id for e in rest] == [f"x-{i:03d}" for i in range(5, 12)]


def test_limit_boundaries(engine_env):
    audit = _fill(engine_env, 3)
    page = export_page(audit, None, limit=1)
    assert len(page.entries) == 1 and page.has_more
    page = export_page(audit, None, limit=100)
    assert len(page.entries) == 3 and not page.has_more
    assert page.next_cursor is None
    # limit is clamped, never unbounded
    page = export_page(audit, None, limit=MAX_PAGE_SIZE * 10)
    assert len(page.entries) == 3
    # empty log -> empty first page, no cursor
    from privacy_gateway.audit import AuditLog
    empty = export_page(AuditLog(), None, limit=10)
    assert empty.entries == () and not empty.has_more


def test_stream_is_lazy_and_bounded(engine_env):
    audit = _fill(engine_env, 50)
    stream = stream_entries(audit, None, page_size=7)
    assert isinstance(stream, types.GeneratorType)  # nothing read yet
    collected = list(stream)
    assert [e.sequence for e in collected] == list(range(1, 51))


def test_export_during_concurrent_writes_loses_nothing_and_dups_nothing(engine_env):
    """New entries appended mid-export are picked up exactly once, in
    sequence order; entries already exported are never repeated."""
    store, audit, clock, _ = engine_env
    d = Decider(store, audit, clock)
    for i in range(20):
        d.decide(_req(f"pre-{i:03d}"))

    exported: list[int] = []

    def writer():
        for i in range(20):
            d.decide(_req(f"post-{i:03d}", caller="bob"))

    with ThreadPoolExecutor(max_workers=2) as pool:
        fut = pool.submit(writer)
        cursor = None
        while True:
            page = export_page(audit, cursor, limit=3)
            exported.extend(e.sequence for e in page.entries)
            if not page.has_more:
                break
            cursor = page.next_cursor
        fut.result()

    # Anything appended after our last page may not be included; drain again.
    cursor = encode_cursor(exported[-1]) if exported else None
    for e in stream_entries(audit, cursor, page_size=3):
        exported.append(e.sequence)

    assert len(exported) == len(set(exported))          # no duplicates
    assert exported == sorted(exported)                  # stable order
    assert exported == list(range(1, 41))                # nothing missing


def test_export_page_is_a_bounded_slice_not_a_full_copy(engine_env):
    """entries_after must never materialise more than the requested page."""
    audit = _fill(engine_env, 500)
    batch = audit.entries_after(0, 10)
    assert len(batch) == 10
    assert batch[-1].sequence == 10


def test_http_export_endpoint(engine_env):
    _fill(engine_env, 7)
    c = TestClient(engine_env[3])
    r = c.get("/v1/audit-export", params={"limit": 4})
    body = r.json()
    assert [e["request_id"] for e in body["entries"]] == [f"x-{i:03d}" for i in range(4)]
    assert body["has_more"] is True
    r2 = c.get("/v1/audit-export", params={"cursor": body["next_cursor"]})
    assert [e["request_id"] for e in r2.json()["entries"]] == [
        f"x-{i:03d}" for i in range(4, 7)]
    assert r2.json()["has_more"] is False
    bad = c.get("/v1/audit-export", params={"cursor": "garbage"})
    assert bad.status_code == 400
    assert bad.json()["error"]["code"] == "INVALID_CURSOR"
