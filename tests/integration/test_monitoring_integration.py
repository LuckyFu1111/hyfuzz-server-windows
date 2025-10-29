import pytest

from src.monitoring.metrics_collector import MetricsCollector
from src.monitoring.prometheus_exporter import PrometheusExporter


def test_prometheus_exporter_renders_metrics() -> None:
    collector = MetricsCollector()
    collector.observe("requests_total", 1.0)
    collector.observe("requests_total", 2.0)

    exporter = PrometheusExporter(collector)
    output = exporter.render()

    assert "requests_total 1.0" in output
    assert "requests_total 2.0" in output


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__])
