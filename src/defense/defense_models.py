"""Dataclasses representing defense insights."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List


@dataclass
class DefenseEvent:
    """Raw defense telemetry captured during fuzzing."""

    payload: Dict[str, Any]
    detections: List[str] = field(default_factory=list)
    risk_score: float = 0.0
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class DefenseInsight:
    """Aggregated insight produced by the defense analyser."""

    summary: str
    evidence: List[str]
    confidence: float


@dataclass
class DefenseRecommendation:
    """Actionable recommendation for the fuzzing engine."""

    action: str
    rationale: str
    priority: str = "medium"


if __name__ == "__main__":
    event = DefenseEvent(payload={"payload": "test"})
    assert event.payload["payload"] == "test"
    insight = DefenseInsight("Suspicious", ["SQL keyword"], 0.8)
    assert insight.summary == "Suspicious"
    recommendation = DefenseRecommendation("increase", "High risk")
    assert recommendation.action == "increase"
    print("defense_models self-test passed.")
