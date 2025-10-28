"""Monitor server performance using metrics collector."""

from __future__ import annotations

import time
from typing import Mapping

from .metrics_collector import MetricsCollector


class PerformanceMonitor:
    def __init__(self, collector: MetricsCollector | None = None) -> None:
        self.collector = collector or MetricsCollector()

    def time_block(self, name: str):
        start = time.perf_counter()

        class _Timer:
            def __enter__(_self):
                return _self

            def __exit__(_self, exc_type, exc_val, exc_tb):
                elapsed = time.perf_counter() - start
                self.collector.observe(name, elapsed)

        return _Timer()

    def snapshot(self) -> Mapping[str, Mapping[str, float]]:
        return self.collector.snapshot()


if __name__ == "__main__":
    monitor = PerformanceMonitor()
    with monitor.time_block("op"):
        time.sleep(0.01)
    assert "op" in monitor.snapshot()
    print("performance_monitor self-test passed.")
