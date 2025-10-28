"""Track performance related metrics."""

from __future__ import annotations

from statistics import mean
from typing import List

from .metrics_collector import MetricsCollector


class PerformanceMonitor:
    """Monitor latency and throughput metrics."""

    def __init__(self, collector: MetricsCollector) -> None:
        self.collector = collector
        self._latencies: List[float] = []

    def track_latency(self, value: float) -> None:
        self._latencies.append(value)
        self.collector.record("latency_seconds", value)

    def average_latency(self) -> float:
        return mean(self._latencies) if self._latencies else 0.0


if __name__ == "__main__":  # pragma: no cover - sanity test
    monitor = PerformanceMonitor(MetricsCollector())
    monitor.track_latency(0.2)
    monitor.track_latency(0.4)
    assert abs(monitor.average_latency() - 0.3) < 1e-6
    print("Performance monitor self-test passed.")
