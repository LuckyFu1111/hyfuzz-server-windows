"""Task orchestration package."""

from .task_queue import TaskQueue
from .task_scheduler import TaskScheduler
from .task_executor import TaskExecutor
from .task_models import FuzzTask

__all__ = ["TaskQueue", "TaskScheduler", "TaskExecutor", "FuzzTask"]


if __name__ == "__main__":
    queue = TaskQueue()
    scheduler = TaskScheduler(queue)
    executor = TaskExecutor(queue)
    scheduler.schedule("coap", {"payload": "test"})
    task = executor.fetch()
    assert task.protocol == "coap"
    print("tasks package self-test passed.")
