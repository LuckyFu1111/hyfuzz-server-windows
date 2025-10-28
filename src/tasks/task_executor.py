"""Executes tasks pulled from the queue."""

from __future__ import annotations

from typing import Callable, Dict

from .task_models import TaskDefinition
from .task_queue import InMemoryTaskQueue


class TaskExecutor:
    """Simple executor dispatching tasks to registered handlers."""

    def __init__(self, queue: InMemoryTaskQueue) -> None:
        self.queue = queue
        self.handlers: Dict[str, Callable[[TaskDefinition], Dict[str, object]]] = {}

    def register(self, name: str, handler: Callable[[TaskDefinition], Dict[str, object]]) -> None:
        self.handlers[name] = handler

    def execute_once(self) -> None:
        task = self.queue.dequeue()
        if not task:
            return
        handler = self.handlers.get(task.name)
        if not handler:
            task.mark_failed("no handler registered")
            self.queue.mark_processed()
            return
        try:
            result = handler(task)
            task.mark_completed(result)
        except Exception as exc:  # pragma: no cover - demonstration only
            task.mark_failed(str(exc))
        finally:
            self.queue.mark_processed()


if __name__ == "__main__":
    queue = InMemoryTaskQueue()
    executor = TaskExecutor(queue)

    def handler(task: TaskDefinition) -> Dict[str, object]:
        return {"payload": task.payload}

    executor.register("demo", handler)
    queue.enqueue(TaskDefinition(name="demo", payload={"value": 5}))
    executor.execute_once()
    print(queue.stats())
