"""Event logger utility."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from .event_models import Event


@dataclass
class EventLogger:
    events: List[Event] = field(default_factory=list)

    def record(self, event: Event) -> None:
        self.events.append(event)


if __name__ == "__main__":
    logger = EventLogger()
    logger.record(Event(name="demo", payload={}))
    print(logger.events)
