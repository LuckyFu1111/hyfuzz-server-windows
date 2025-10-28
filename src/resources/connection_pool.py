"""Connection pool stub."""

from __future__ import annotations

from queue import Queue
from typing import Any


class ConnectionPool:
    def __init__(self, size: int) -> None:
        self.pool: Queue[Any] = Queue(maxsize=size)
        for _ in range(size):
            self.pool.put(object())

    def acquire(self) -> Any:
        return self.pool.get()

    def release(self, connection: Any) -> None:
        self.pool.put(connection)


if __name__ == "__main__":
    pool = ConnectionPool(2)
    conn = pool.acquire()
    pool.release(conn)
    print("Pool size:", pool.pool.qsize())
