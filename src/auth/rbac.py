"""Role-based access control utilities."""

from __future__ import annotations

from typing import Dict, List, Set


class RBAC:
    def __init__(self) -> None:
        self.roles: Dict[str, Set[str]] = {}
        self.assignments: Dict[str, Set[str]] = {}

    def define_role(self, role: str, permissions: List[str]) -> None:
        self.roles[role] = set(permissions)

    def assign_role(self, username: str, role: str) -> None:
        self.assignments.setdefault(username, set()).add(role)

    def permissions_for(self, username: str) -> Set[str]:
        permissions: Set[str] = set()
        for role in self.assignments.get(username, set()):
            permissions.update(self.roles.get(role, set()))
        return permissions


if __name__ == "__main__":
    rbac = RBAC()
    rbac.define_role("admin", ["read", "write"])
    rbac.assign_role("demo", "admin")
    print(rbac.permissions_for("demo"))
