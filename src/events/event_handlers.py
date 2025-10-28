"""Reusable event handlers."""

from __future__ import annotations

from typing import Callable

from .event_models import Event


def log_handler(event: Event) -> None:
    print(f"Event {event.name}: {event.payload}")


if __name__ == "__main__":
    log_handler(Event(name="demo", payload={"value": 1}))
