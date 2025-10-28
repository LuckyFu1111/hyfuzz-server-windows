"""Dashboard API helpers for monitoring data."""

from __future__ import annotations

from typing import Dict

from .metrics_collector import MetricsCollector


class DashboardAPI:
    """Returns data formatted for dashboard consumption."""

    def __init__(self, collector: MetricsCollector) -> None:
        self.collector = collector

    def summary(self) -> Dict[str, float]:
        return {name: sum(values) for name, values in self.collector.export().items()}


if __name__ == "__main__":
    collector = MetricsCollector()
    collector.observe("requests", 1)
    collector.observe("requests", 2)
    api = DashboardAPI(collector)
    print(api.summary())
