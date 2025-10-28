"""Utility helpers for defense subsystem."""

from __future__ import annotations

from datetime import datetime
from typing import Iterable

from .defense_models import DefenseEvent


def filter_events_by_tag(events: Iterable[DefenseEvent], tag: str) -> list[DefenseEvent]:
    """Return events that contain the given tag."""

    return [event for event in events if tag in event.tags]


def format_event(event: DefenseEvent) -> str:
    """Format an event for logging output."""

    timestamp = event.created_at.isoformat()
    return f"[{timestamp}] {event.source}: {event.payload} (tags={event.tags})"


def utc_now() -> datetime:
    return datetime.utcnow()


if __name__ == "__main__":
    event = DefenseEvent(source="ids", payload={"alert": "demo"})
    event.tag("demo")
    print(format_event(event))
