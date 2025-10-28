"""Monitoring utilities for HyFuzz Windows Server."""

from .metrics_collector import MetricsCollector
from .performance_monitor import PerformanceMonitor
from .health_checker import HealthChecker
from .alerting import AlertManager

__all__ = [
    "MetricsCollector",
    "PerformanceMonitor",
    "HealthChecker",
    "AlertManager",
]


if __name__ == "__main__":  # pragma: no cover - sanity test
    collector = MetricsCollector()
    collector.record("payloads", 5)
    monitor = PerformanceMonitor(collector)
    monitor.track_latency(0.2)
    health = HealthChecker(collector)
    assert health.status()["healthy"]
    print("Monitoring package self-test passed.")
