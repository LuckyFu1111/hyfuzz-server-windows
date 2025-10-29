import time

from src.tasks.task_models import TaskDefinition
from src.tasks.task_queue import InMemoryTaskQueue
from src.tasks.worker_manager import WorkerManager


def test_worker_distribution_speed() -> None:
    queue = InMemoryTaskQueue()
    manager = WorkerManager()
    manager.register("worker-1")

    for i in range(200):
        queue.enqueue(TaskDefinition(name=f"task-{i}", payload={"i": i}))

    start = time.perf_counter()
    while task := queue.dequeue():
        task.mark_completed({"ok": True})
        queue.mark_processed()
        manager.increment("worker-1")
    duration = time.perf_counter() - start

    assert manager.workers["worker-1"].processed_tasks == 200
    assert duration < 0.5


if __name__ == "__main__":
    test_worker_distribution_speed()
