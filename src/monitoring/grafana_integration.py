"""Helpers to provide Grafana dashboard ready data."""

from __future__ import annotations

from typing import Dict

from .metrics_collector import MetricsCollector


class GrafanaIntegration:
    """Produce JSON fragments usable by Grafana simple-json plugin."""

    def __init__(self, collector: MetricsCollector) -> None:
        self.collector = collector

    def query(self, metric: str) -> Dict[str, object]:
        samples = self.collector.export().get(metric, [])
        return {
            "target": metric,
            "datapoints": [[sample.value, int(sample.timestamp.timestamp() * 1000)] for sample in samples],
        }


if __name__ == "__main__":  # pragma: no cover - sanity test
    collector = MetricsCollector()
    collector.record("payloads", 1)
    integration = GrafanaIntegration(collector)
    data = integration.query("payloads")
    assert data["datapoints"]
    print("Grafana integration self-test passed.")
