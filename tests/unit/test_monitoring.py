import pytest

from src.monitoring.health_checker import HealthChecker
from src.monitoring.metrics_collector import MetricsCollector
from src.monitoring.performance_monitor import PerformanceMonitor


def test_metrics_collector_records_values() -> None:
    collector = MetricsCollector()
    collector.observe("requests", 1.0)
    collector.observe("requests", 2.0)

    exported = collector.export()
    assert exported["requests"] == [1.0, 2.0]


def test_performance_monitor_times_block() -> None:
    collector = MetricsCollector()
    monitor = PerformanceMonitor(collector)

    with monitor.timeit("work"):
        sum(range(10))

    assert "work" in collector.export()


def test_health_checker_reports_status() -> None:
    checker = HealthChecker()
    checker.register("ok", lambda: True)
    checker.register("fail", lambda: False)

    results = checker.run()
    assert results["ok"].value == "healthy"
    assert results["fail"].value == "unhealthy"


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__])
