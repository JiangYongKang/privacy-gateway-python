"""FastAPI HTTP 层。

对外端点（均只返回脱敏后的数据或结构化拒绝原因，绝不返回原始敏感值）：

* ``GET  /``                         服务信息
* ``POST /v1/access``                提交访问请求（按 request_id 幂等）
* ``GET  /v1/audit/{request_id}``    查询单条审计记录
* ``GET  /v1/audit``                 按 seq 升序列出审计记录
* ``POST /v1/replay/{request_id}``   回放历史决策并比对一致性
* ``GET  /v1/policies``              列出已发布策略版本与当前版本
* ``PUT  /v1/policies/current``      切换当前策略版本（不存在 -> 404）

注意：HTTP 层不提供写入原始资源/策略的接口，避免经网络暴露敏感面；
种子数据与策略在进程内装配。
"""
from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .errors import AccessDeniedError
from .models import AccessRequest
from .service import PrivacyGatewayService


class AccessRequestBody(BaseModel):
    request_id: str = Field(min_length=1)
    principal_id: str = Field(min_length=1)
    resource_id: str = Field(min_length=1)
    fields: list[str] = Field(default_factory=list)
    policy_version: str | None = None


class SetCurrentBody(BaseModel):
    version: str = Field(min_length=1)


def _decision_to_json(decision) -> dict:
    return {
        "allowed": decision.allowed,
        "reason": decision.reason.value if decision.reason else None,
        "deny_detail": list(decision.deny_detail),
        "policy_version": decision.policy_version,
        "matched_rule": decision.matched_rule,
        "fields": dict(decision.fields),
    }


def _entry_to_json(entry) -> dict:
    return {
        "seq": entry.seq,
        "request_id": entry.request_id,
        "timestamp": entry.timestamp,
        "principal_id": entry.principal_id,
        "resource_id": entry.resource_id,
        "requested_fields": list(entry.requested_fields),
        "policy_version": entry.policy_version,
        "allowed": entry.allowed,
        "reason": entry.reason,
        "matched_rule": entry.matched_rule,
        "returned_fields": list(entry.returned_fields),
        "deny_detail": list(entry.deny_detail),
        "decision_fingerprint": entry.decision_fingerprint,
    }


def create_app(service: PrivacyGatewayService) -> FastAPI:
    app = FastAPI(title="privacy-gateway", version="0.1.0")

    @app.exception_handler(AccessDeniedError)
    async def _denied_handler(_request, exc: AccessDeniedError) -> JSONResponse:
        # 异常转结构化响应：只暴露可区分的原因枚举与消息，不暴露任何值。
        status = 404 if exc.reason.value == "policy_version_not_found" else 403
        return JSONResponse(
            status_code=status,
            content={"allowed": False, "reason": exc.reason.value, "detail": str(exc)},
        )

    @app.get("/")
    def read_root() -> dict:
        return {"service": "privacy-gateway", "status": "ok"}

    @app.post("/v1/access")
    def access(body: AccessRequestBody) -> dict:
        request = AccessRequest(
            request_id=body.request_id,
            principal_id=body.principal_id,
            roles=frozenset(),
            resource_id=body.resource_id,
            fields=tuple(body.fields),
            policy_version=body.policy_version,
        )
        decision = service.request_access(request)
        return _decision_to_json(decision)

    @app.get("/v1/audit/{request_id}")
    def get_audit(request_id: str) -> dict:
        entry = service.audit.get(request_id)
        if entry is None:
            return JSONResponse(
                status_code=404, content={"reason": "audit_not_found"}
            )
        return _entry_to_json(entry)

    @app.get("/v1/audit")
    def list_audit() -> dict:
        return {"entries": [_entry_to_json(e) for e in service.audit.all_entries()]}

    @app.post("/v1/replay/{request_id}")
    def replay(request_id: str) -> dict:
        result = service.replay(request_id)
        return {
            "consistent": result.consistent,
            "note": result.note,
            "historical": _entry_to_json(result.entry),
            "replayed": _decision_to_json(result.replayed_decision),
        }

    @app.get("/v1/policies")
    def list_policies() -> dict:
        return {
            "current": service.policies.current_version(),
            "versions": list(service.policies.versions()),
        }

    @app.put("/v1/policies/current")
    def set_current(body: SetCurrentBody) -> dict:
        service.policies.set_current(body.version)
        return {"current": body.version}

    return app
