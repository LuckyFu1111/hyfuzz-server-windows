"""Performance monitoring helpers."""

from __future__ import annotations

import time
from contextlib import contextmanager
from typing import Generator

from .metrics_collector import MetricsCollector


class PerformanceMonitor:
    """Measures execution time of code blocks."""

    def __init__(self, collector: MetricsCollector | None = None) -> None:
        self.collector = collector or MetricsCollector()

    @contextmanager
    def timeit(self, name: str) -> Generator[None, None, None]:
        start = time.perf_counter()
        try:
            yield
        finally:
            duration = time.perf_counter() - start
            self.collector.observe(name, duration)


if __name__ == "__main__":
    monitor = PerformanceMonitor()
    with monitor.timeit("demo"):
        time.sleep(0.01)
    print(monitor.collector.export())
