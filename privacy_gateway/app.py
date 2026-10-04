"""FastAPI wiring for the privacy gateway.

``create_app`` accepts injected store/audit/clock so tests run against fixed
time and isolated storage. Error responses carry the stable deny ``code`` so
rejection reasons stay distinguishable over HTTP.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from fastapi import FastAPI, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from .audit import AuditLog
from .clock import Clock, SystemClock
from .decider import Decider
from .errors import PrivacyError
from .export import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE, export_page
from .fixtures import build_seed_store
from .forensics import export_evidence, verify_evidence
from .holds import HoldManager
from .models import AccessRequest, Decision
from .replay import replay_all
from .store import LocalStore


class DecideBody(BaseModel):
    request_id: str
    caller_id: str
    resource_id: str
    policy_version: str | None = None
    fields: list[str] | None = None


class HoldBody(BaseModel):
    hold_id: str
    resource_id: str
    placed_by: str
    reason: str = ""


class ReleaseBody(BaseModel):
    released_by: str


class VerifyBody(BaseModel):
    evidence: dict


def _error_classes_by_code() -> dict[str, type[PrivacyError]]:
    registry: dict[str, type[PrivacyError]] = {}
    for cls in PrivacyError.__subclasses__():
        registry[cls.code] = cls
        for sub in cls.__subclasses__():
            registry[sub.code] = sub
    return registry


def create_app(
    store: LocalStore | None = None,
    audit: AuditLog | None = None,
    clock: Clock | None = None,
) -> FastAPI:
    store = store or build_seed_store()
    audit = audit or AuditLog()
    clock = clock or SystemClock()
    engine = Decider(store, audit, clock)
    holds = HoldManager(store, audit, clock)
    error_registry = _error_classes_by_code()

    app = FastAPI(title="privacy-gateway", version="0.1.0")

    @app.exception_handler(PrivacyError)
    async def _on_privacy_error(_request, exc: PrivacyError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.http_status,
            content={"error": {"code": exc.code, "message": str(exc)}},
        )

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "current_policy": store.current_policy_version()}

    @app.post("/v1/access/decide")
    def decide(body: DecideBody) -> dict[str, Any]:
        req = AccessRequest(
            request_id=body.request_id,
            caller_id=body.caller_id,
            resource_id=body.resource_id,
            policy_version=body.policy_version,
            fields=tuple(body.fields) if body.fields is not None else None,
            submitted_at=clock.now_iso(),
        )
        result = engine.decide(req)
        payload = result.to_response()
        entry = audit.get_by_request(body.request_id)
        if entry is not None and entry.deny_code:
            payload["deny_code"] = entry.deny_code

        if result.decision is Decision.DENY:
            code = entry.deny_code if entry else "ACCESS_DENIED"
            cls = error_registry.get(code, PrivacyError)
            return JSONResponse(
                status_code=cls.http_status,
                content=payload,
            )
        return payload

    @app.get("/v1/audit")
    def list_audit() -> list[dict[str, Any]]:
        return [e.to_dict() for e in audit.entries()]

    @app.get("/v1/audit/{request_id}")
    def get_audit(request_id: str) -> dict[str, Any]:
        entry = audit.get_by_request(request_id)
        if entry is None:
            return JSONResponse(
                status_code=404,
                content={"error": {"code": "AUDIT_NOT_FOUND",
                                   "message": f"no audit for {request_id!r}"}},
            )
        return entry.to_dict()

    @app.get("/v1/replay")
    def replay() -> list[dict[str, Any]]:
        return replay_all(audit)

    @app.get("/v1/policies")
    def list_policies() -> dict[str, Any]:
        # Bounded reflection over the seeded store (store keeps them in a dict).
        versions = sorted(store._policies.keys())  # type: ignore[attr-defined]
        return {"current": store.current_policy_version(), "versions": versions}

    @app.post("/v1/policies/{version}/activate")
    def activate(version: str) -> dict[str, str]:
        store.set_current_policy_version(version)
        return {"current": store.current_policy_version()}

    # -- retention holds --------------------------------------------------
    @app.post("/v1/holds")
    def place_hold(body: HoldBody) -> dict[str, Any]:
        hold = holds.place_hold(
            body.hold_id, body.resource_id, body.placed_by, body.reason,
        )
        return hold.to_dict()

    @app.post("/v1/holds/{hold_id}/release")
    def release_hold(hold_id: str, body: ReleaseBody) -> dict[str, Any]:
        return holds.release_hold(hold_id, body.released_by).to_dict()

    @app.get("/v1/holds/{hold_id}")
    def get_hold(hold_id: str) -> dict[str, Any]:
        hold = store.get_hold(hold_id)
        if hold is None:
            return JSONResponse(
                status_code=404,
                content={"error": {"code": "HOLD_NOT_FOUND",
                                   "message": f"no hold {hold_id!r}"}},
            )
        return hold.to_dict()

    # -- incremental audit export -----------------------------------------
    @app.get("/v1/audit-export")
    def audit_export(
        cursor: str | None = None, limit: int = DEFAULT_PAGE_SIZE,
    ) -> dict[str, Any]:
        if limit > MAX_PAGE_SIZE:
            limit = MAX_PAGE_SIZE
        return export_page(audit, cursor, limit).to_dict()

    # -- decision forensics ------------------------------------------------
    @app.get("/v1/forensics/{request_id}")
    def forensics_export(request_id: str) -> Response:
        return Response(
            content=export_evidence(audit, request_id),
            media_type="application/json",
        )

    @app.post("/v1/forensics/verify")
    def forensics_verify(body: VerifyBody) -> dict[str, Any]:
        blob = json.dumps(
            body.evidence, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        return verify_evidence(blob, audit).to_dict()

    return app


logging.getLogger("privacy_gateway.decider").setLevel(logging.INFO)
app = create_app()
