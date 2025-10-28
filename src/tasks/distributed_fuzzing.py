"""Utilities for coordinating distributed fuzzing campaigns."""

from __future__ import annotations

from typing import Iterable, Mapping

from .task_models import FuzzTask
from .task_scheduler import TaskScheduler


class DistributedFuzzing:
    def __init__(self, scheduler: TaskScheduler) -> None:
        self.scheduler = scheduler

    def fan_out(self, protocol: str, payloads: Iterable[Mapping[str, object]]) -> list[FuzzTask]:
        tasks: list[FuzzTask] = []
        for idx, payload in enumerate(payloads):
            tasks.append(self.scheduler.schedule(protocol, payload, priority=idx))
        return tasks


if __name__ == "__main__":
    from .task_queue import TaskQueue

    queue = TaskQueue()
    scheduler = TaskScheduler(queue)
    distributed = DistributedFuzzing(scheduler)
    tasks = distributed.fan_out("coap", [{"payload": str(i)} for i in range(3)])
    assert len(tasks) == 3
    print("distributed_fuzzing self-test passed.")
