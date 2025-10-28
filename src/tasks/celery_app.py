"""Celery application stub for distributed task execution."""

from __future__ import annotations

from typing import Any, Dict


class CeleryAppStub:
    """Minimal stub mimicking a Celery application."""

    def __init__(self) -> None:
        self.tasks: Dict[str, Any] = {}

    def task(self, name: str):
        def decorator(func):
            self.tasks[name] = func
            return func

        return decorator

    def delay(self, name: str, *args: Any, **kwargs: Any) -> Any:
        if name not in self.tasks:
            raise KeyError(f"Task '{name}' is not registered")
        return self.tasks[name](*args, **kwargs)


celery_app = CeleryAppStub()


if __name__ == "__main__":
    @celery_app.task("add")
    def add(x, y):
        return x + y

    print(celery_app.delay("add", 1, 2))
