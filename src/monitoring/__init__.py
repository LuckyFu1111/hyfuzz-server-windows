"""Monitoring package for HyFuzz."""

from .metrics_collector import MetricsCollector
from .performance_monitor import PerformanceMonitor
from .health_checker import HealthChecker

__all__ = ["MetricsCollector", "PerformanceMonitor", "HealthChecker"]


if __name__ == "__main__":
    collector = MetricsCollector()
    collector.observe("requests", 1.0)
    assert collector.snapshot()["requests"]["count"] == 1
    print("monitoring package self-test passed.")
