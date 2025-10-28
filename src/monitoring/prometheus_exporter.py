"""Expose metrics in a Prometheus friendly structure."""

from __future__ import annotations

from typing import Mapping

from .metrics_collector import MetricsCollector


class PrometheusExporter:
    def __init__(self, collector: MetricsCollector | None = None) -> None:
        self.collector = collector or MetricsCollector()

    def render(self) -> str:
        lines = []
        for name, data in self.collector.snapshot().items():
            lines.append(f"# HELP hyfuzz_{name}_average Average value for {name}")
            lines.append(f"# TYPE hyfuzz_{name}_average gauge")
            lines.append(f"hyfuzz_{name}_average {data['average']}")
        return "\n".join(lines)


if __name__ == "__main__":
    collector = MetricsCollector()
    collector.observe("requests", 1.0)
    exporter = PrometheusExporter(collector)
    rendered = exporter.render()
    assert "hyfuzz_requests_average" in rendered
    print("prometheus_exporter self-test passed.")
