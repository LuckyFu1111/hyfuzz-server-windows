"""Event subsystem."""

from .event_bus import EventBus
from .event_dispatcher import EventDispatcher
from .event_models import Event

__all__ = ["EventBus", "EventDispatcher", "Event"]


if __name__ == "__main__":
    bus = EventBus()
    dispatcher = EventDispatcher(bus)
    bus.subscribe("demo", lambda event: print(event))
    dispatcher.dispatch("demo", {"value": 1})
