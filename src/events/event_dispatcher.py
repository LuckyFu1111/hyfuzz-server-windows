"""Dispatches events to the bus."""

from __future__ import annotations

from .event_bus import EventBus
from .event_models import Event


class EventDispatcher:
    def __init__(self, bus: EventBus | None = None) -> None:
        self.bus = bus or EventBus()

    def dispatch(self, name: str, payload: dict) -> None:
        self.bus.publish(Event(name=name, payload=payload))


if __name__ == "__main__":
    dispatcher = EventDispatcher()
    dispatcher.bus.subscribe("demo", lambda event: print(event))
    dispatcher.dispatch("demo", {"value": 1})
