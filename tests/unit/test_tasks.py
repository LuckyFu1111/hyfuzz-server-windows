import pytest

from src.tasks import TaskQueue, TaskScheduler, TaskExecutor


def test_task_queue_roundtrip():
    queue = TaskQueue()
    scheduler = TaskScheduler(queue)
    scheduler.schedule("modbus", {"payload": "01"})
    executor = TaskExecutor(queue)
    task = executor.fetch()
    assert task.protocol == "modbus"


if __name__ == "__main__":
    pytest.main([__file__])
