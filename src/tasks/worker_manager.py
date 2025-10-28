"""Manage asynchronous workers consuming the task queue."""

from __future__ import annotations

import asyncio
from typing import Awaitable, Callable, Optional

from .task_queue import TaskQueue
from .task_models import FuzzTask


class WorkerManager:
    def __init__(self, queue: TaskQueue) -> None:
        self.queue = queue
        self._workers: list[asyncio.Task[None]] = []

    async def start_worker(self, handler: Callable[[FuzzTask], Awaitable[None]]) -> None:
        async def run() -> None:
            while True:
                task = await self.queue.get()
                await handler(task)

        self._workers.append(asyncio.create_task(run()))

    async def stop_all(self) -> None:
        for worker in self._workers:
            worker.cancel()
        await asyncio.gather(*self._workers, return_exceptions=True)
        self._workers.clear()


if __name__ == "__main__":
    async def main() -> None:
        queue = TaskQueue()
        manager = WorkerManager(queue)

        async def handler(task: FuzzTask) -> None:
            print("Handled", task.protocol)

        await manager.start_worker(handler)
        await queue.put(FuzzTask("coap", {"payload": "x"}))
        await asyncio.sleep(0.1)
        await manager.stop_all()

    asyncio.run(main())
