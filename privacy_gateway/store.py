"""Local, in-process storage for callers, resources and policies.

Everything lives inside the process: no network, no real credentials. Policy
versions are immutable once stored; only the pointer to the "current" version
may move, so old decisions remain replayable against the version they used.
"""

from __future__ import annotations

from threading import RLock

from .errors import PolicyNotFoundError
from .models import Caller, Policy, Resource


class LocalStore:
    def __init__(self) -> None:
        self._callers: dict[str, Caller] = {}
        self._resources: dict[str, Resource] = {}
        self._policies: dict[str, Policy] = {}
        self._current_policy_version: str | None = None
        self._lock = RLock()

    # callers -------------------------------------------------------------
    def add_caller(self, caller: Caller) -> None:
        with self._lock:
            self._callers[caller.caller_id] = caller

    def get_caller(self, caller_id: str) -> Caller | None:
        with self._lock:
            return self._callers.get(caller_id)

    # resources -----------------------------------------------------------
    def add_resource(self, resource: Resource) -> None:
        with self._lock:
            self._resources[resource.resource_id] = resource

    def get_resource(self, resource_id: str) -> Resource | None:
        with self._lock:
            return self._resources.get(resource_id)

    def delete_resource(self, resource_id: str) -> bool:
        with self._lock:
            if resource_id in self._resources:
                del self._resources[resource_id]
                return True
            return False

    # policies ------------------------------------------------------------
    def add_policy(self, policy: Policy) -> None:
        with self._lock:
            # Versions are immutable: refuse to silently overwrite.
            if policy.version in self._policies:
                if self._policies[policy.version] != policy:
                    from .errors import PolicyConflictError

                    raise PolicyConflictError(
                        f"policy version {policy.version!r} already exists "
                        "with a different body; versions are immutable"
                    )
                return
            self._policies[policy.version] = policy
            if self._current_policy_version is None:
                self._current_policy_version = policy.version

    def get_policy(self, version: str) -> Policy | None:
        with self._lock:
            return self._policies.get(version)

    def current_policy_version(self) -> str:
        with self._lock:
            if self._current_policy_version is None:
                raise PolicyNotFoundError("no policy version has been loaded")
            return self._current_policy_version

    def set_current_policy_version(self, version: str) -> None:
        with self._lock:
            if version not in self._policies:
                raise PolicyNotFoundError(
                    f"cannot make {version!r} current: version does not exist"
                )
            self._current_policy_version = version
