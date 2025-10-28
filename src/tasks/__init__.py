"""Task orchestration utilities for HyFuzz server."""

from .task_models import TaskDefinition, TaskStatus
from .task_queue import InMemoryTaskQueue
from .task_scheduler import TaskScheduler
from .task_executor import TaskExecutor
from .task_monitor import TaskMonitor
from .worker_manager import WorkerManager

__all__ = [
    "TaskDefinition",
    "TaskStatus",
    "InMemoryTaskQueue",
    "TaskScheduler",
    "TaskExecutor",
    "TaskMonitor",
    "WorkerManager",
]


if __name__ == "__main__":
    queue = InMemoryTaskQueue()
    scheduler = TaskScheduler(queue)
    executor = TaskExecutor(queue)
    definition = TaskDefinition(name="demo", payload={"value": 1})
    scheduler.schedule(definition)
    executor.execute_once()
    print(queue.stats())
