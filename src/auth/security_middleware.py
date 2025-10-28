"""Simple security middleware stub."""

from __future__ import annotations

from typing import Callable

from .permission_manager import PermissionManager


class SecurityMiddleware:
    def __init__(self, permission_manager: PermissionManager) -> None:
        self.permission_manager = permission_manager

    def require(self, *permissions: str) -> Callable[[Callable[..., object]], Callable[..., object]]:
        def decorator(func: Callable[..., object]) -> Callable[..., object]:
            def wrapper(username: str, *args, **kwargs):
                if not self.permission_manager.has_permissions(username, permissions):
                    raise PermissionError("insufficient permissions")
                return func(username, *args, **kwargs)

            return wrapper

        return decorator


if __name__ == "__main__":
    from .rbac import RBAC

    rbac = RBAC()
    rbac.define_role("admin", ["execute"])
    rbac.assign_role("demo", "admin")
    middleware = SecurityMiddleware(PermissionManager(rbac))

    @middleware.require("execute")
    def run(username: str) -> str:
        return f"Executed by {username}"

    print(run("demo"))
