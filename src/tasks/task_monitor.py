"""Monitor progress of queued tasks."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict

from .task_models import TaskResult


@dataclass
class TaskMetrics:
    completed: int = 0
    failed: int = 0
    payloads_generated: int = 0


class TaskMonitor:
    """Track execution metrics."""

    def __init__(self) -> None:
        self.metrics = TaskMetrics()

    def record(self, result: TaskResult) -> None:
        if result.success:
            self.metrics.completed += 1
            self.metrics.payloads_generated += int(result.artifacts.get("payload_count", 0))
        else:
            self.metrics.failed += 1

    def snapshot(self) -> Dict[str, int]:
        return {
            "completed": self.metrics.completed,
            "failed": self.metrics.failed,
            "payloads_generated": self.metrics.payloads_generated,
        }


if __name__ == "__main__":  # pragma: no cover - sanity test
    from .task_models import FuzzTask

    monitor = TaskMonitor()
    task = FuzzTask(protocol="coap", parameters={})
    monitor.record(TaskResult(task=task, success=True, artifacts={"payload_count": 3}))
    monitor.record(TaskResult(task=task, success=False, error="boom"))
    assert monitor.snapshot()["completed"] == 1
    print("Task monitor self-test passed.")
