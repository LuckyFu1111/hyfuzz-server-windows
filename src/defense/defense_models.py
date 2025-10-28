"""Data models used by the defense integration layer."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class DefenseEvent:
    """Represents a raw event produced by a defense component."""

    source: str
    payload: Dict[str, Any]
    created_at: datetime = field(default_factory=datetime.utcnow)
    tags: List[str] = field(default_factory=list)

    def tag(self, *labels: str) -> None:
        """Attach labels to the event for later filtering."""

        self.tags.extend(label for label in labels if label not in self.tags)


@dataclass
class DefenseSignal:
    """Normalized signal passed across defense subsystems."""

    event: DefenseEvent
    severity: str = "info"
    confidence: float = 0.5
    notes: Optional[str] = None

    def escalate(self, new_severity: str, reason: str) -> None:
        """Escalate the severity of the signal with contextual notes."""

        self.severity = new_severity
        self.notes = reason


@dataclass
class DefenseAction:
    """Action taken by a defense system as a reaction to a signal."""

    name: str
    description: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_summary(self) -> str:
        """Create a human readable summary of the action."""

        return f"{self.name}: {self.description}"


@dataclass
class DefenseResult:
    """Result returned by the defense analyzer to the learning system."""

    signal: DefenseSignal
    actions: List[DefenseAction]
    verdict: str
    rationale: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert the result into a serializable dictionary."""

        return {
            "signal": {
                "source": self.signal.event.source,
                "severity": self.signal.severity,
                "confidence": self.signal.confidence,
                "tags": list(self.signal.event.tags),
                "notes": self.signal.notes,
            },
            "actions": [action.to_summary() for action in self.actions],
            "verdict": self.verdict,
            "rationale": self.rationale,
        }


if __name__ == "__main__":
    sample_event = DefenseEvent(source="ids", payload={"rule": "sql_injection"})
    sample_event.tag("critical", "sql")
    signal = DefenseSignal(event=sample_event, severity="high", confidence=0.8)
    result = DefenseResult(
        signal=signal,
        actions=[DefenseAction(name="alert", description="Notified SOC")],
        verdict="block",
        rationale="Matched SQLi signature with high confidence.",
    )
    print(result.to_dict())
