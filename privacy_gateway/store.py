"""本地存储：调用方与资源（纯内存，无外部服务、无真实凭据）。

写入/更新受同一把锁保护，保证并发下数据视图一致。
存储层不做任何权限判断，也不负责脱敏——它只是确定性的数据容器。
"""
from __future__ import annotations

import threading
from types import MappingProxyType

from .models import Principal, Resource


class Store:
    def __init__(self) -> None:
        self._principals: dict[str, Principal] = {}
        self._resources: dict[str, Resource] = {}
        self._lock = threading.RLock()

    def put_principal(self, principal: Principal) -> None:
        with self._lock:
            self._principals[principal.id] = principal

    def get_principal(self, principal_id: str) -> Principal | None:
        with self._lock:
            return self._principals.get(principal_id)

    def put_resource(self, resource: Resource) -> None:
        with self._lock:
            self._resources[resource.id] = resource

    def get_resource(self, resource_id: str) -> Resource | None:
        with self._lock:
            return self._resources.get(resource_id)

    def update_resource_fields(self, resource_id: str, fields: dict[str, str]) -> None:
        """整体替换资源字段（用于保留期到期后的清除/遮蔽落地）。"""
        with self._lock:
            current = self._resources.get(resource_id)
            if current is None:
                raise KeyError(resource_id)
            self._resources[resource_id] = Resource(
                id=current.id,
                scope=current.scope,
                owner=current.owner,
                retention_days=current.retention_days,
                created_at=current.created_at,
                fields=dict(fields),
            )

    def list_resources(self) -> tuple[Resource, ...]:
        with self._lock:
            return tuple(sorted(self._resources.values(), key=lambda r: r.id))
