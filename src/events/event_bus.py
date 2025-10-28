"""In-memory event bus."""

from __future__ import annotations

from collections import defaultdict
from typing import Callable, Dict, List

from .event_models import Event


class EventBus:
    def __init__(self) -> None:
        self.subscribers: Dict[str, List[Callable[[Event], None]]] = defaultdict(list)

    def subscribe(self, event_name: str, callback: Callable[[Event], None]) -> None:
        self.subscribers[event_name].append(callback)

    def publish(self, event: Event) -> None:
        for callback in self.subscribers.get(event.name, []):
            callback(event)


if __name__ == "__main__":
    bus = EventBus()
    bus.subscribe("demo", lambda event: print("Received", event))
    bus.publish(Event(name="demo", payload={"value": 1}))
