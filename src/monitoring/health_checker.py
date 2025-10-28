"""Health check utilities."""

from __future__ import annotations

from typing import Mapping

from .metrics_collector import MetricsCollector


class HealthChecker:
    def __init__(self, collector: MetricsCollector | None = None) -> None:
        self.collector = collector or MetricsCollector()

    def check(self) -> Mapping[str, object]:
        snapshot = self.collector.snapshot()
        return {
            "metrics_available": bool(snapshot),
            "metrics": snapshot,
        }


if __name__ == "__main__":
    checker = HealthChecker()
    checker.collector.observe("requests", 1.0)
    report = checker.check()
    assert report["metrics_available"] is True
    print("health_checker self-test passed.")
