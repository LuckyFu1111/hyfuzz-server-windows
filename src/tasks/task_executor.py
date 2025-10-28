"""Task execution helpers."""

from __future__ import annotations

from .task_queue import TaskQueue


class TaskExecutor:
    def __init__(self, queue: TaskQueue) -> None:
        self.queue = queue

    def fetch(self):
        return self.queue.get_nowait()


if __name__ == "__main__":
    from .task_scheduler import TaskScheduler

    queue = TaskQueue()
    scheduler = TaskScheduler(queue)
    scheduler.schedule("modbus", {"payload": "dead"})
    executor = TaskExecutor(queue)
    task = executor.fetch()
    assert task.protocol == "modbus"
    print("task_executor self-test passed.")
