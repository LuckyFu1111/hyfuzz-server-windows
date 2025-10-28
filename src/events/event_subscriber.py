"""Event subscription helper."""

from __future__ import annotations

from typing import Callable

from .event_bus import EventBus
from .event_models import Event


class EventSubscriber:
    def __init__(self, bus: EventBus | None = None) -> None:
        self.bus = bus or EventBus()

    def subscribe(self, name: str, handler: Callable[[Event], None]) -> None:
        self.bus.subscribe(name, handler)


if __name__ == "__main__":
    subscriber = EventSubscriber()
    subscriber.subscribe("demo", lambda event: print(event))
    subscriber.bus.publish(Event(name="demo", payload={"value": 1}))
