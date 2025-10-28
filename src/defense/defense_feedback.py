"""Feedback generation from defense insights to fuzzing engine."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

from .defense_models import DefenseResult


@dataclass
class DefenseFeedback:
    """Structured feedback message for other subsystems."""

    category: str
    message: str
    metadata: Dict[str, str]


class DefenseFeedbackGenerator:
    """Creates actionable insights from defense results."""

    def generate(self, result: DefenseResult) -> List[DefenseFeedback]:
        feedback: List[DefenseFeedback] = []
        feedback.append(
            DefenseFeedback(
                category="verdict",
                message=f"Defense verdict: {result.verdict}",
                metadata={"rationale": result.rationale},
            )
        )
        if result.risk_score:
            feedback.append(
                DefenseFeedback(
                    category="risk",
                    message=f"Calculated defense risk score: {result.risk_score:.2f}",
                    metadata={"risk_score": f"{result.risk_score:.3f}"},
                )
            )
        for action in result.actions:
            feedback.append(
                DefenseFeedback(
                    category="action",
                    message=action.description,
                    metadata={"name": action.name, **{k: str(v) for k, v in action.metadata.items()}},
                )
            )
        return feedback


if __name__ == "__main__":
    from .defense_models import DefenseSignal, DefenseEvent, DefenseAction

    result = DefenseResult(
        signal=DefenseSignal(event=DefenseEvent(source="ids", payload={}), severity="high"),
        actions=[DefenseAction(name="block", description="Blocked malicious IP", metadata={"ip": "1.2.3.4"})],
        verdict="block",
        rationale="Repeated malicious attempts detected.",
    )
    generator = DefenseFeedbackGenerator()
    for feedback in generator.generate(result):
        print(feedback)
