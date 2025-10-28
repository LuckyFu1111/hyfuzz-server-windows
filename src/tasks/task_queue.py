"""In-memory priority queue for fuzzing tasks."""

from __future__ import annotations

import heapq
from threading import Lock
from typing import List, Optional, Tuple

from .task_models import FuzzTask


class TaskQueue:
    """Thread-safe priority queue."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._items: List[Tuple[int, int, FuzzTask]] = []
        self._counter = 0

    def put(self, task: FuzzTask) -> None:
        with self._lock:
            heapq.heappush(self._items, (task.priority, self._counter, task))
            self._counter += 1

    def get(self) -> Optional[FuzzTask]:
        with self._lock:
            if not self._items:
                return None
            _, _, task = heapq.heappop(self._items)
            return task

    def __len__(self) -> int:  # pragma: no cover - trivial
        with self._lock:
            return len(self._items)


if __name__ == "__main__":  # pragma: no cover - sanity test
    queue = TaskQueue()
    queue.put(FuzzTask(protocol="coap", parameters={"path": "/"}, priority=2))
    queue.put(FuzzTask(protocol="modbus", parameters={"value": 1}, priority=1))
    assert queue.get().protocol == "modbus"
    print("Task queue self-test passed.")
