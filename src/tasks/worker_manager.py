"""Worker management utilities."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict


@dataclass
class WorkerStatus:
    name: str
    active: bool
    processed_tasks: int = 0


class WorkerManager:
    """Tracks worker status in memory."""

    def __init__(self) -> None:
        self.workers: Dict[str, WorkerStatus] = {}

    def register(self, name: str) -> None:
        self.workers[name] = WorkerStatus(name=name, active=True)

    def mark_inactive(self, name: str) -> None:
        if name in self.workers:
            self.workers[name].active = False

    def increment(self, name: str) -> None:
        if name not in self.workers:
            self.register(name)
        self.workers[name].processed_tasks += 1


if __name__ == "__main__":
    manager = WorkerManager()
    manager.register("worker-1")
    manager.increment("worker-1")
    manager.mark_inactive("worker-1")
    print(manager.workers["worker-1"])
