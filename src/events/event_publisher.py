"""Publishes events."""

from __future__ import annotations

from .event_bus import EventBus
from .event_models import Event


class EventPublisher:
    def __init__(self, bus: EventBus | None = None) -> None:
        self.bus = bus or EventBus()

    def publish(self, name: str, payload: dict) -> None:
        self.bus.publish(Event(name=name, payload=payload))


if __name__ == "__main__":
    publisher = EventPublisher()
    publisher.bus.subscribe("demo", lambda event: print(event))
    publisher.publish("demo", {"value": 1})
