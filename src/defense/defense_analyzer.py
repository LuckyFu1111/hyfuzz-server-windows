"""Combine defense findings and compute an overall score."""

from __future__ import annotations

from typing import Iterable

from .defense_models import DefenseDecision, DefenseFinding
from .evasion_detector import EvasionDetector


class DefenseAnalyzer:
    """Aggregate findings into a single decision."""

    def __init__(self, detector: EvasionDetector | None = None) -> None:
        self.detector = detector or EvasionDetector()

    def analyze(self, findings: Iterable[DefenseFinding]) -> DefenseDecision:
        findings_list = list(findings)
        if not findings_list:
            return DefenseDecision([], 0.0, "No findings available")
        avg_score = sum(f.confidence for f in findings_list) / len(findings_list)
        evasion_risk = self.detector.detect(findings_list)
        overall = max(0.0, min(1.0, avg_score * (1 + evasion_risk / 2)))
        reasoning = f"Average confidence {avg_score:.2f}, evasion risk {evasion_risk:.2f}"
        return DefenseDecision(findings_list, overall, reasoning)


if __name__ == "__main__":  # pragma: no cover - sanity test
    analyzer = DefenseAnalyzer()
    decision = analyzer.analyze([
        DefenseFinding(source="ids", message="alert", confidence=0.8),
        DefenseFinding(source="waf", message="rule hit", confidence=0.6),
    ])
    assert decision.overall_score > 0.6
    print("Defense analyzer self-test passed.")
