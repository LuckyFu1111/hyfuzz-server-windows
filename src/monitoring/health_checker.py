"""Health check utilities."""

from __future__ import annotations

from typing import Callable, Dict

from .monitoring_models import HealthStatus


class HealthChecker:
    """Runs registered health check callables."""

    def __init__(self) -> None:
        self.checks: Dict[str, Callable[[], bool]] = {}

    def register(self, name: str, check: Callable[[], bool]) -> None:
        self.checks[name] = check

    def run(self) -> Dict[str, HealthStatus]:
        results: Dict[str, HealthStatus] = {}
        for name, check in self.checks.items():
            status = HealthStatus.HEALTHY if check() else HealthStatus.UNHEALTHY
            results[name] = status
        return results


if __name__ == "__main__":
    checker = HealthChecker()
    checker.register("db", lambda: True)
    checker.register("cache", lambda: False)
    print(checker.run())
