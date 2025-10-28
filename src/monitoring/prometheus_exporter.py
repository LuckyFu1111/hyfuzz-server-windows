"""Expose metrics in Prometheus text format."""

from __future__ import annotations

from typing import Iterable

from .metrics_collector import MetricsCollector
from .monitoring_models import MetricSample


class PrometheusExporter:
    """Render metrics to Prometheus exposition format."""

    def __init__(self, collector: MetricsCollector) -> None:
        self.collector = collector

    def render(self) -> str:
        lines: list[str] = []
        for name, samples in self.collector.export().items():
            for sample in samples:
                label = ",".join(f"{key}='{value}'" for key, value in sample.labels.items())
                label_str = f"{{{label}}}" if label else ""
                lines.append(f"{name}{label_str} {sample.value}")
        return "\n".join(lines)


if __name__ == "__main__":  # pragma: no cover - sanity test
    collector = MetricsCollector()
    collector.record("payloads", 1, protocol="coap")
    exporter = PrometheusExporter(collector)
    text = exporter.render()
    assert "payloads" in text
    print("Prometheus exporter self-test passed.")
