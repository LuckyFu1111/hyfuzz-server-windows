"""Executes migrations."""

from __future__ import annotations

from typing import Callable, Dict


class MigrationExecutor:
    def __init__(self) -> None:
        self.handlers: Dict[str, Callable[[], None]] = {}

    def register(self, version: str, handler: Callable[[], None]) -> None:
        self.handlers[version] = handler

    def run(self, version: str) -> None:
        handler = self.handlers.get(version)
        if not handler:
            raise KeyError(f"Migration {version} not registered")
        handler()


if __name__ == "__main__":
    executor = MigrationExecutor()
    executor.register("v1", lambda: print("running v1"))
    executor.run("v1")
