"""Permission checking utilities."""

from __future__ import annotations

from typing import Iterable

from .rbac import RBAC


class PermissionManager:
    def __init__(self, rbac: RBAC | None = None) -> None:
        self.rbac = rbac or RBAC()

    def has_permissions(self, username: str, permissions: Iterable[str]) -> bool:
        user_permissions = self.rbac.permissions_for(username)
        return all(permission in user_permissions for permission in permissions)


if __name__ == "__main__":
    rbac = RBAC()
    rbac.define_role("admin", ["read", "write"])
    rbac.assign_role("demo", "admin")
    manager = PermissionManager(rbac)
    print(manager.has_permissions("demo", ["write"]))
