import pytest

from src.monitoring import MetricsCollector, PerformanceMonitor, HealthChecker


def test_metrics_collector_snapshot():
    collector = MetricsCollector()
    collector.observe("requests", 1.0)
    snapshot = collector.snapshot()
    assert snapshot["requests"]["count"] == 1


def test_performance_monitor_records_time():
    monitor = PerformanceMonitor()
    with monitor.time_block("operation"):
        pass
    assert "operation" in monitor.snapshot()


def test_health_checker_reports_metrics():
    checker = HealthChecker()
    checker.collector.observe("requests", 1.0)
    report = checker.check()
    assert report["metrics_available"] is True


if __name__ == "__main__":
    pytest.main([__file__])
