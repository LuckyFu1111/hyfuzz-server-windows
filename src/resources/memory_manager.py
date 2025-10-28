"""Memory manager stub."""

from __future__ import annotations

from typing import Dict


class MemoryManager:
    def __init__(self) -> None:
        self.allocations: Dict[str, int] = {}

    def allocate(self, name: str, size: int) -> None:
        self.allocations[name] = self.allocations.get(name, 0) + size

    def release(self, name: str, size: int) -> None:
        remaining = self.allocations.get(name, 0) - size
        if remaining <= 0:
            self.allocations.pop(name, None)
        else:
            self.allocations[name] = remaining


if __name__ == "__main__":
    manager = MemoryManager()
    manager.allocate("task", 100)
    manager.release("task", 50)
    print(manager.allocations)
