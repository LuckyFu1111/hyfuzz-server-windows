"""Schedules fuzzing tasks based on heuristics."""

from __future__ import annotations

from typing import Mapping

from .task_models import FuzzTask
from .task_queue import TaskQueue


class TaskScheduler:
    def __init__(self, queue: TaskQueue) -> None:
        self.queue = queue

    def schedule(self, protocol: str, payload: Mapping[str, object], priority: int = 0) -> FuzzTask:
        task = FuzzTask(protocol=protocol, payload=dict(payload), priority=priority)
        self.queue.put_nowait(task)
        return task


if __name__ == "__main__":
    scheduler = TaskScheduler(TaskQueue())
    task = scheduler.schedule("coap", {"payload": "hi"})
    assert task.payload["payload"] == "hi"
    print("task_scheduler self-test passed.")
