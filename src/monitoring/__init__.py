"""Monitoring utilities for HyFuzz server."""

from .monitoring_models import MetricSample, HealthStatus
from .metrics_collector import MetricsCollector
from .performance_monitor import PerformanceMonitor
from .health_checker import HealthChecker
from .alerting import AlertDispatcher

__all__ = [
    "MetricSample",
    "HealthStatus",
    "MetricsCollector",
    "PerformanceMonitor",
    "HealthChecker",
    "AlertDispatcher",
]


if __name__ == "__main__":
    collector = MetricsCollector()
    collector.observe("requests", 1)
    print(collector.export())
