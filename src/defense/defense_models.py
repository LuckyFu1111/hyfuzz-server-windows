"""Data models used by the defense analytics layer."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List


@dataclass
class DefenseFinding:
    """Represents a single defense finding entry."""

    source: str
    message: str
    confidence: float
    metadata: Dict[str, str] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class DefenseDecision:
    """Aggregated defense evaluation result."""

    findings: List[DefenseFinding]
    overall_score: float
    reasoning: str

    def as_dict(self) -> Dict[str, object]:
        return {
            "overall_score": self.overall_score,
            "reasoning": self.reasoning,
            "findings": [
                {
                    "source": finding.source,
                    "message": finding.message,
                    "confidence": finding.confidence,
                }
                for finding in self.findings
            ],
        }


if __name__ == "__main__":  # pragma: no cover - sanity check
    finding = DefenseFinding(source="ids", message="Suspicious payload", confidence=0.7)
    decision = DefenseDecision([finding], 0.65, "LLM judged payload as moderately risky")
    assert decision.as_dict()["overall_score"] == 0.65
    print("Defense models self-test passed.")
