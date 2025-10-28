"""Quota management."""

from __future__ import annotations

from typing import Dict


class QuotaManager:
    def __init__(self) -> None:
        self.quotas: Dict[str, int] = {}

    def set_quota(self, name: str, quota: int) -> None:
        self.quotas[name] = quota

    def consume(self, name: str, amount: int = 1) -> bool:
        remaining = self.quotas.get(name, 0)
        if remaining < amount:
            return False
        self.quotas[name] = remaining - amount
        return True


if __name__ == "__main__":
    manager = QuotaManager()
    manager.set_quota("demo", 2)
    print(manager.consume("demo"))
    print(manager.consume("demo"))
    print(manager.consume("demo"))
