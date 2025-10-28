"""Task scheduling utilities for HyFuzz Windows Server."""

from .task_models import FuzzTask, TaskResult
from .task_queue import TaskQueue
from .task_scheduler import TaskScheduler
from .task_executor import TaskExecutor
from .task_monitor import TaskMonitor
from .distributed_fuzzing import DistributedFuzzCoordinator

__all__ = [
    "FuzzTask",
    "TaskResult",
    "TaskQueue",
    "TaskScheduler",
    "TaskExecutor",
    "TaskMonitor",
    "DistributedFuzzCoordinator",
]


if __name__ == "__main__":  # pragma: no cover - sanity test
    queue = TaskQueue()
    scheduler = TaskScheduler(queue)
    executor = TaskExecutor(queue)
    task = FuzzTask(protocol="coap", parameters={"path": "/"})
    scheduler.schedule(task)
    result = executor.execute_next()
    assert result is not None and result.success
    print("Tasks package self-test passed.")
