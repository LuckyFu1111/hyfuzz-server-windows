"""Determine server health based on collected metrics."""

from __future__ import annotations

from typing import Dict

from .metrics_collector import MetricsCollector


class HealthChecker:
    """Calculate health status using simple thresholds."""

    def __init__(self, collector: MetricsCollector, max_latency: float = 1.0) -> None:
        self.collector = collector
        self.max_latency = max_latency

    def status(self) -> Dict[str, object]:
        latency_sample = self.collector.latest("latency_seconds")
        latency = latency_sample.value if latency_sample else 0.0
        healthy = latency <= self.max_latency
        return {"healthy": healthy, "latency": latency, "threshold": self.max_latency}


if __name__ == "__main__":  # pragma: no cover - sanity test
    collector = MetricsCollector()
    collector.record("latency_seconds", 0.5)
    checker = HealthChecker(collector, max_latency=0.75)
    assert checker.status()["healthy"]
    print("Health checker self-test passed.")
