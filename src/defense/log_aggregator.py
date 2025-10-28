"""Aggregate defense telemetry for later analysis."""

from __future__ import annotations

from collections import deque
from typing import Deque, Iterable, Mapping

from .defense_models import DefenseEvent, DefenseRecommendation


class LogAggregator:
    def __init__(self, max_entries: int = 1000) -> None:
        self.events: Deque[DefenseEvent] = deque(maxlen=max_entries)
        self.recommendations: Deque[Iterable[DefenseRecommendation]] = deque(maxlen=max_entries)

    def store(
        self,
        event: DefenseEvent,
        analysis: Mapping[str, object],
        recommendations: Iterable[DefenseRecommendation],
    ) -> None:
        event.risk_score = analysis.get("risk", event.risk_score)
        self.events.append(event)
        self.recommendations.append(tuple(recommendations))

    def latest(self) -> Mapping[str, object]:
        if not self.events:
            return {"events": [], "recommendations": []}
        return {
            "events": list(self.events),
            "recommendations": [list(recs) for recs in self.recommendations],
        }


if __name__ == "__main__":
    aggregator = LogAggregator(max_entries=2)
    event = DefenseEvent(payload={"payload": "test"})
    aggregator.store(event, {"risk": 0.5}, [])
    assert aggregator.latest()["events"]
    print("log_aggregator self-test passed.")
