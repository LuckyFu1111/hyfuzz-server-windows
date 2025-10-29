"""Data models used by the defense integration layer."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

_SEVERITY_LEVELS = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


@dataclass
class DefenseEvent:
    """Represents a raw event produced by a defense component."""

    source: str
    payload: Dict[str, Any]
    created_at: datetime = field(default_factory=datetime.utcnow)
    tags: List[str] = field(default_factory=list)

    def tag(self, *labels: str) -> None:
        """Attach labels to the event for later filtering."""

        for label in labels:
            normalized = str(label)
            if normalized and normalized not in self.tags:
                self.tags.append(normalized)


@dataclass
class DefenseSignal:
    """Normalized signal passed across defense subsystems."""

    event: DefenseEvent
    severity: str = "info"
    confidence: float = 0.5
    notes: Optional[str] = None

    def escalate(self, new_severity: str, reason: str) -> None:
        """Escalate the severity of the signal with contextual *reason*."""

        current = _SEVERITY_LEVELS.get(self.severity.lower(), 0)
        incoming = _SEVERITY_LEVELS.get(new_severity.lower(), current)
        if incoming >= current:
            self.severity = new_severity.lower()
        self.notes = reason

    def clone(self) -> "DefenseSignal":
        """Return a shallow copy of the signal for isolated processing."""

        return DefenseSignal(
            event=self.event,
            severity=self.severity,
            confidence=self.confidence,
            notes=self.notes,
        )


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
    risk_score: float = 0.0
    context: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert the result into a serializable dictionary."""

        payload: Dict[str, Any] = {
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
            "risk_score": round(self.risk_score, 3),
        }
        if self.context:
            payload["context"] = self.context
        return payload


if __name__ == "__main__":  # pragma: no cover - illustrative example
    sample_event = DefenseEvent(source="ids", payload={"rule": "sql_injection"})
    sample_event.tag("critical", "sql")
    signal = DefenseSignal(event=sample_event, severity="high", confidence=0.8)
    result = DefenseResult(
        signal=signal,
        actions=[DefenseAction(name="alert", description="Notified SOC")],
        verdict="block",
        rationale="Matched SQLi signature with high confidence.",
        risk_score=0.92,
    )
    print(result.to_dict())
