"""Schedule fuzzing tasks into the queue."""

from __future__ import annotations

from typing import Iterable

from .task_models import FuzzTask
from .task_queue import TaskQueue


class TaskScheduler:
    """Simple FIFO scheduler with priority support."""

    def __init__(self, queue: TaskQueue) -> None:
        self.queue = queue

    def schedule(self, task: FuzzTask) -> None:
        self.queue.put(task)

    def schedule_many(self, tasks: Iterable[FuzzTask]) -> None:
        for task in tasks:
            self.schedule(task)


if __name__ == "__main__":  # pragma: no cover - sanity test
    queue = TaskQueue()
    scheduler = TaskScheduler(queue)
    scheduler.schedule_many(
        [
            FuzzTask(protocol="coap", parameters={}, priority=2),
            FuzzTask(protocol="modbus", parameters={}, priority=1),
        ]
    )
    assert queue.get().protocol == "modbus"
    print("Task scheduler self-test passed.")
