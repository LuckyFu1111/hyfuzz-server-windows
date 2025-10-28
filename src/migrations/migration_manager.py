"""Tracks migrations."""

from __future__ import annotations

from typing import Dict, List


class MigrationManager:
    def __init__(self) -> None:
        self.migrations: Dict[str, str] = {}
        self.applied: List[str] = []

    def register(self, version: str, description: str) -> None:
        self.migrations[version] = description

    def mark_applied(self, version: str) -> None:
        if version not in self.applied:
            self.applied.append(version)

    def pending(self) -> List[str]:
        return [version for version in sorted(self.migrations) if version not in self.applied]


if __name__ == "__main__":
    manager = MigrationManager()
    manager.register("v1", "Initial schema")
    print(manager.pending())
