"""Placeholder Celery application configuration."""

from __future__ import annotations

try:
    from celery import Celery
except Exception:  # pragma: no cover - optional dependency
    Celery = None  # type: ignore


def create_celery_app() -> Celery | None:
    if Celery is None:
        return None
    app = Celery("hyfuzz", broker="memory://", backend="rpc://")
    app.conf.task_serializer = "json"
    return app


if __name__ == "__main__":
    app = create_celery_app()
    if app:
        print("Celery broker:", app.conf.broker_url)
    else:
        print("Celery not installed; skipping test")
