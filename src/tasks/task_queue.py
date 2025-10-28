"""Asynchronous aware task queue."""

from __future__ import annotations

import asyncio
from collections import deque
from typing import Deque, Optional

from .task_models import FuzzTask


class TaskQueue:
    def __init__(self) -> None:
        self._queue: Deque[FuzzTask] = deque()
        self._condition = asyncio.Condition()

    async def put(self, task: FuzzTask) -> None:
        async with self._condition:
            self._queue.append(task)
            self._condition.notify()

    async def get(self) -> FuzzTask:
        async with self._condition:
            while not self._queue:
                await self._condition.wait()
            return self._queue.popleft()

    def put_nowait(self, task: FuzzTask) -> None:
        self._queue.append(task)

    def get_nowait(self) -> Optional[FuzzTask]:
        return self._queue.popleft() if self._queue else None

    def __len__(self) -> int:
        return len(self._queue)


if __name__ == "__main__":
    queue = TaskQueue()
    queue.put_nowait(FuzzTask("coap", {"payload": "a"}))
    assert len(queue) == 1
    assert queue.get_nowait().payload["payload"] == "a"
    print("task_queue self-test passed.")
