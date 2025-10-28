"""Monitor task queue health."""

from __future__ import annotations

from typing import Mapping

from .task_queue import TaskQueue


class TaskMonitor:
    def __init__(self, queue: TaskQueue) -> None:
        self.queue = queue

    def snapshot(self) -> Mapping[str, int]:
        return {"queued": len(self.queue)}


if __name__ == "__main__":
    queue = TaskQueue()
    monitor = TaskMonitor(queue)
    queue.put_nowait(__import__("types"))
    queue._queue.clear()
    assert monitor.snapshot()["queued"] == 0
    print("task_monitor self-test passed.")
