"""Simple in-memory task queue."""

from __future__ import annotations

from collections import deque
from typing import Deque, Optional

from .task_models import TaskDefinition, TaskStatus


class InMemoryTaskQueue:
    """A FIFO queue storing :class:`TaskDefinition` objects."""

    def __init__(self) -> None:
        self._queue: Deque[TaskDefinition] = deque()
        self._processed: int = 0

    def enqueue(self, task: TaskDefinition) -> None:
        self._queue.append(task)

    def dequeue(self) -> Optional[TaskDefinition]:
        if not self._queue:
            return None
        task = self._queue.popleft()
        task.mark_running()
        return task

    def mark_processed(self) -> None:
        self._processed += 1

    def stats(self) -> dict[str, int]:
        return {"queued": len(self._queue), "processed": self._processed}


if __name__ == "__main__":
    queue = InMemoryTaskQueue()
    queue.enqueue(TaskDefinition(name="one", payload={}))
    queue.enqueue(TaskDefinition(name="two", payload={}))
    while task := queue.dequeue():
        task.mark_completed({"ok": True})
        queue.mark_processed()
    print(queue.stats())
