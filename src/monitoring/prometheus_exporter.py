"""Prometheus exporter stub."""

from __future__ import annotations

from typing import Dict

from .metrics_collector import MetricsCollector


class PrometheusExporter:
    """Formats metrics into Prometheus text format."""

    def __init__(self, collector: MetricsCollector) -> None:
        self.collector = collector

    def render(self) -> str:
        lines = []
        for name, values in self.collector.export().items():
            for value in values:
                lines.append(f"{name} {value}")
        return "\n".join(lines)


if __name__ == "__main__":
    collector = MetricsCollector()
    collector.observe("requests_total", 1)
    exporter = PrometheusExporter(collector)
    print(exporter.render())
