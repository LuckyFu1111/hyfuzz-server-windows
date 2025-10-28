"""Translate defence analysis into feedback for fuzzing."""

from __future__ import annotations

from typing import Iterable, Mapping

from .defense_models import DefenseRecommendation


class DefenseFeedback:
    def generate(self, analysis: Mapping[str, object], evasion: Mapping[str, float]) -> list[DefenseRecommendation]:
        recommendations: list[DefenseRecommendation] = []
        risk = analysis.get("risk", 0.0)
        if risk >= 0.6:
            recommendations.append(
                DefenseRecommendation(
                    action="increase_mutation",
                    rationale=f"Risk {risk:.2f} indicates payload effectiveness",
                    priority="high",
                )
            )
        else:
            recommendations.append(
                DefenseRecommendation(
                    action="diversify",
                    rationale="Low risk observed; explore new payload families",
                    priority="medium",
                )
            )
        if evasion.get("suspicious_overlap", 0.0) > 0.5:
            recommendations.append(
                DefenseRecommendation(
                    action="rotate_payload",
                    rationale="Potential evasion detected via repeated signatures",
                    priority="high",
                )
            )
        return recommendations


if __name__ == "__main__":
    feedback = DefenseFeedback()
    recs = feedback.generate({"risk": 0.7}, {"suspicious_overlap": 0.8})
    assert recs and recs[0].priority == "high"
    print("defense_feedback self-test passed.")
