"""Metrics collection utilities."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict


@dataclass
class Metric:
    count: int = 0
    total: float = 0.0

    def observe(self, value: float) -> None:
        self.count += 1
        self.total += value

    @property
    def average(self) -> float:
        return self.total / self.count if self.count else 0.0


class MetricsCollector:
    def __init__(self) -> None:
        self.metrics: Dict[str, Metric] = {}

    def observe(self, name: str, value: float) -> None:
        metric = self.metrics.setdefault(name, Metric())
        metric.observe(value)

    def snapshot(self) -> Dict[str, Dict[str, float]]:
        return {
            name: {"count": metric.count, "average": metric.average}
            for name, metric in self.metrics.items()
        }


if __name__ == "__main__":
    collector = MetricsCollector()
    collector.observe("requests", 1.0)
    collector.observe("requests", 3.0)
    snap = collector.snapshot()
    assert abs(snap["requests"]["average"] - 2.0) < 1e-6
    print("metrics_collector self-test passed.")
