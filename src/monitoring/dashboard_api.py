"""Mock dashboard API used by tests."""

from __future__ import annotations

from typing import Mapping

from .metrics_collector import MetricsCollector


class DashboardAPI:
    def __init__(self, collector: MetricsCollector | None = None) -> None:
        self.collector = collector or MetricsCollector()

    def get_metrics(self) -> Mapping[str, Mapping[str, float]]:
        return self.collector.snapshot()


if __name__ == "__main__":
    api = DashboardAPI()
    api.collector.observe("requests", 2.0)
    assert api.get_metrics()["requests"]["count"] == 1
    print("dashboard_api self-test passed.")
