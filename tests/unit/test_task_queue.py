import pytest

from src.tasks.task_models import TaskDefinition
from src.tasks.task_queue import InMemoryTaskQueue


def test_task_queue_lifecycle() -> None:
    queue = InMemoryTaskQueue()
    task = TaskDefinition(name="demo", payload={"id": 1})

    queue.enqueue(task)
    retrieved = queue.dequeue()
    assert retrieved is not None
    assert retrieved.status.value == "running"

    retrieved.mark_completed({"ok": True})
    queue.mark_processed()

    stats = queue.stats()
    assert stats["queued"] == 0
    assert stats["processed"] == 1


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__])
