"""Celery-like interface without external dependency."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Iterable


class CeleryApp:
    """Minimal wrapper mimicking Celery apply_async for local execution."""

    def __init__(self, workers: int = 2) -> None:
        self.executor = ThreadPoolExecutor(max_workers=workers)

    def submit(self, func: Callable[..., object], *args, **kwargs) -> None:
        self.executor.submit(func, *args, **kwargs)

    def map(self, func: Callable[[object], object], iterable: Iterable[object]) -> list[object]:
        return list(self.executor.map(func, iterable))

    def shutdown(self) -> None:  # pragma: no cover - trivial
        self.executor.shutdown(wait=True)


if __name__ == "__main__":  # pragma: no cover - sanity test
    app = CeleryApp(workers=1)
    results = app.map(lambda x: x * 2, [1, 2, 3])
    assert results == [2, 4, 6]
    app.shutdown()
    print("Celery app stub self-test passed.")
