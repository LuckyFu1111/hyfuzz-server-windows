"""Generate feedback for the fuzzing engine based on defense results."""

from __future__ import annotations

from typing import Iterable

from .defense_models import DefenseDecision


class DefenseFeedbackGenerator:
    """Produce feedback messages consumed by the learning pipeline."""

    def create_feedback(self, decision: DefenseDecision) -> str:
        indicator = "increase" if decision.overall_score > 0.6 else "decrease"
        return (
            f"Defense score {decision.overall_score:.2f} suggests to {indicator} payload aggressiveness."
            f" Findings: {len(decision.findings)}"
        )


if __name__ == "__main__":  # pragma: no cover - sanity test
    from .defense_models import DefenseFinding

    decision = DefenseDecision(
        findings=[DefenseFinding(source="ids", message="test", confidence=0.7)],
        overall_score=0.7,
        reasoning="LLM flagged suspicious behavior",
    )
    generator = DefenseFeedbackGenerator()
    message = generator.create_feedback(decision)
    assert "increase" in message
    print("Defense feedback self-test passed.")
