"""Tests for monitoring utilities."""

from src.monitoring import AlertManager, HealthChecker, MetricsCollector, PerformanceMonitor
from src.monitoring.dashboard_api import DashboardAPI


def test_metrics_collector_sum_and_latest():
    collector = MetricsCollector()
    collector.record("payloads", 5, protocol="coap")
    assert collector.sum("payloads") == 5
    assert collector.latest("payloads").labels["protocol"] == "coap"


def test_health_checker_uses_latest_latency():
    collector = MetricsCollector()
    collector.record("latency_seconds", 0.25)
    checker = HealthChecker(collector, max_latency=0.5)
    status = checker.status()
    assert status["healthy"]


def test_dashboard_prometheus_output():
    collector = MetricsCollector()
    collector.record("payloads", 1)
    api = DashboardAPI(collector)
    assert "payloads" in api.get_prometheus_metrics()


def test_performance_monitor_average_latency():
    collector = MetricsCollector()
    monitor = PerformanceMonitor(collector)
    monitor.track_latency(0.2)
    monitor.track_latency(0.4)
    assert abs(monitor.average_latency() - 0.3) < 1e-6


def test_alert_manager_notifies_subscribers():
    manager = AlertManager()
    messages = []
    manager.subscribe(messages.append)
    manager.notify("warning")
    assert messages == ["warning"]
