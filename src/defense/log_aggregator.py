"""Aggregates defense logs from different systems."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from datetime import datetime
from typing import Deque, Dict, Iterable, List

from .defense_models import DefenseEvent


@dataclass
class AggregatedLog:
    source: str
    count: int
    last_seen: datetime
    tags: List[str]


class DefenseLogAggregator:
    """Maintain rolling windows of defense events."""

    def __init__(self, window: int = 1000) -> None:
        self.window = window
        self._events: Deque[DefenseEvent] = deque(maxlen=window)

    def ingest(self, event: DefenseEvent) -> None:
        self._events.append(event)

    def summary(self) -> List[AggregatedLog]:
        grouped: Dict[str, AggregatedLog] = {}
        for event in self._events:
            summary = grouped.setdefault(
                event.source,
                AggregatedLog(source=event.source, count=0, last_seen=event.created_at, tags=[]),
            )
            summary.count += 1
            summary.last_seen = max(summary.last_seen, event.created_at)
            for tag in event.tags:
                if tag not in summary.tags:
                    summary.tags.append(tag)
        return sorted(grouped.values(), key=lambda item: item.count, reverse=True)

    def recent(self, limit: int = 5) -> Iterable[DefenseEvent]:
        return list(self._events)[-limit:]


if __name__ == "__main__":
    aggregator = DefenseLogAggregator(window=3)
    for idx in range(5):
        event = DefenseEvent(source="waf", payload={"idx": idx})
        event.tag("demo")
        aggregator.ingest(event)
    for log in aggregator.summary():
        print(log)
