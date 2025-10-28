"""REST-like helpers to expose monitoring data."""

from __future__ import annotations

from typing import Dict

from .grafana_integration import GrafanaIntegration
from .metrics_collector import MetricsCollector
from .prometheus_exporter import PrometheusExporter


class DashboardAPI:
    """Expose collected metrics to dashboards."""

    def __init__(self, collector: MetricsCollector) -> None:
        self.collector = collector
        self.prometheus = PrometheusExporter(collector)
        self.grafana = GrafanaIntegration(collector)

    def get_prometheus_metrics(self) -> str:
        return self.prometheus.render()

    def get_grafana_series(self, metric: str) -> Dict[str, object]:
        return self.grafana.query(metric)


if __name__ == "__main__":  # pragma: no cover - sanity test
    collector = MetricsCollector()
    collector.record("payloads", 2)
    api = DashboardAPI(collector)
    assert "payloads" in api.get_prometheus_metrics()
    assert api.get_grafana_series("payloads")["target"] == "payloads"
    print("Dashboard API self-test passed.")
