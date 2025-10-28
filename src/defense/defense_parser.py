"""Parse raw defense events into structured representations."""

from __future__ import annotations

from typing import Mapping

from .defense_models import DefenseEvent


class DefenseParser:
    def parse_event(self, event: DefenseEvent) -> Mapping[str, object]:
        return {
            "payload": event.payload,
            "detections": tuple(event.detections),
            "risk_score": float(event.risk_score),
            "timestamp": event.timestamp,
        }


if __name__ == "__main__":
    from datetime import datetime
    event = DefenseEvent(payload={"payload": "test"}, detections=["sql"], risk_score=0.5)
    parsed = DefenseParser().parse_event(event)
    assert parsed["risk_score"] == 0.5
    print("defense_parser self-test passed.")
