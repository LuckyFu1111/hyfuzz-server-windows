"""Coordinate distributed fuzzing workers."""

from __future__ import annotations

from typing import Iterable, List

from .task_models import FuzzTask
from .task_scheduler import TaskScheduler


class DistributedFuzzCoordinator:
    """Very small coordinator distributing tasks equally among nodes."""

    def __init__(self, scheduler: TaskScheduler) -> None:
        self.scheduler = scheduler

    def distribute(self, tasks: Iterable[FuzzTask], nodes: int) -> List[int]:
        counts = [0 for _ in range(nodes)]
        for index, task in enumerate(tasks):
            node = index % nodes
            counts[node] += 1
            self.scheduler.schedule(task)
        return counts


if __name__ == "__main__":  # pragma: no cover - sanity test
    from .task_queue import TaskQueue

    queue = TaskQueue()
    scheduler = TaskScheduler(queue)
    coordinator = DistributedFuzzCoordinator(scheduler)
    counts = coordinator.distribute(
        [FuzzTask(protocol="coap", parameters={}) for _ in range(5)],
        nodes=2,
    )
    assert counts == [3, 2]
    print("Distributed fuzzing self-test passed.")
