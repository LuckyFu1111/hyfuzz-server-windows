import pytest

from src.tasks.task_models import TaskDefinition
from src.tasks.task_queue import InMemoryTaskQueue
from src.tasks.worker_manager import WorkerManager


def test_task_distribution_tracks_workers() -> None:
    queue = InMemoryTaskQueue()
    manager = WorkerManager()
    manager.register("worker-1")

    queue.enqueue(TaskDefinition(name="demo", payload={"id": 1}))
    task = queue.dequeue()
    assert task is not None

    task.mark_completed({"ok": True})
    queue.mark_processed()
    manager.increment("worker-1")

    assert manager.workers["worker-1"].processed_tasks == 1


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__])
