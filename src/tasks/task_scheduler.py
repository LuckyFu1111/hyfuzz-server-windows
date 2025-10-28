"""Task scheduling utilities."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Callable, Optional

from .task_models import TaskDefinition
from .task_queue import InMemoryTaskQueue


class TaskScheduler:
    """Schedules tasks into the queue."""

    def __init__(self, queue: InMemoryTaskQueue) -> None:
        self.queue = queue
        self.default_delay = timedelta(seconds=0)

    def schedule(self, task: TaskDefinition, delay: Optional[timedelta] = None) -> None:
        delay = delay or self.default_delay
        task.metadata = {"scheduled_for": datetime.utcnow() + delay}  # type: ignore[attr-defined]
        self.queue.enqueue(task)


if __name__ == "__main__":
    scheduler = TaskScheduler(InMemoryTaskQueue())
    definition = TaskDefinition(name="demo", payload={})
    scheduler.schedule(definition)
    print(definition)
