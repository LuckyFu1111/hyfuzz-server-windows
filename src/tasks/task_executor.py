"""Execute fuzzing tasks using the fuzzing engine."""

from __future__ import annotations

from typing import Optional

from ..fuzzing import FuzzEngine
from ..protocols import ProtocolFactory
from .task_models import FuzzTask, TaskResult
from .task_queue import TaskQueue


class TaskExecutor:
    """Pull tasks from the queue and execute them immediately."""

    def __init__(self, queue: TaskQueue, engine: Optional[FuzzEngine] = None) -> None:
        self.queue = queue
        self.engine = engine or FuzzEngine(ProtocolFactory())

    def execute_next(self) -> Optional[TaskResult]:
        task = self.queue.get()
        if task is None:
            return None
        try:
            payloads = self.engine.generate(task.protocol, task.parameters)
            return TaskResult(task=task, success=True, artifacts={"payload_count": len(payloads)})
        except Exception as exc:  # pragma: no cover - narrow scope
            return TaskResult(task=task, success=False, error=str(exc))


if __name__ == "__main__":  # pragma: no cover - sanity test
    queue = TaskQueue()
    executor = TaskExecutor(queue)
    queue.put(FuzzTask(protocol="coap", parameters={"path": "/"}))
    result = executor.execute_next()
    assert result and result.success
    print("Task executor self-test passed.")
