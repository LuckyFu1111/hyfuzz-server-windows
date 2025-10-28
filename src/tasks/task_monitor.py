"""Monitoring utilities for tasks."""

from __future__ import annotations

from typing import Iterable, List

from .task_models import TaskDefinition, TaskStatus


class TaskMonitor:
    """Provides helper methods to inspect tasks."""

    def pending(self, tasks: Iterable[TaskDefinition]) -> List[TaskDefinition]:
        return [task for task in tasks if task.status == TaskStatus.PENDING]

    def failed(self, tasks: Iterable[TaskDefinition]) -> List[TaskDefinition]:
        return [task for task in tasks if task.status == TaskStatus.FAILED]


if __name__ == "__main__":
    tasks = [
        TaskDefinition(name="one", payload={}),
        TaskDefinition(name="two", payload={}),
    ]
    tasks[1].mark_failed("error")
    monitor = TaskMonitor()
    print("Pending:", monitor.pending(tasks))
    print("Failed:", monitor.failed(tasks))
