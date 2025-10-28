"""Tests for task scheduling and execution."""

from src.tasks import FuzzTask, TaskExecutor, TaskMonitor, TaskQueue, TaskScheduler


def test_task_scheduler_prioritizes_tasks():
    queue = TaskQueue()
    scheduler = TaskScheduler(queue)
    scheduler.schedule(FuzzTask(protocol="coap", parameters={}, priority=5))
    scheduler.schedule(FuzzTask(protocol="modbus", parameters={}, priority=1))
    first = queue.get()
    assert first.protocol == "modbus"


def test_task_executor_returns_results():
    queue = TaskQueue()
    executor = TaskExecutor(queue)
    task = FuzzTask(protocol="coap", parameters={"path": "/"})
    queue.put(task)
    result = executor.execute_next()
    assert result and result.success and result.artifacts["payload_count"] >= 1


def test_task_monitor_tracks_metrics():
    queue = TaskQueue()
    executor = TaskExecutor(queue)
    monitor = TaskMonitor()
    queue.put(FuzzTask(protocol="coap", parameters={}))
    result = executor.execute_next()
    monitor.record(result)
    snapshot = monitor.snapshot()
    assert snapshot["completed"] == 1
