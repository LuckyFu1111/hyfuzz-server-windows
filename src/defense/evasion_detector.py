"""Detect potential defense evasion attempts."""

from __future__ import annotations

from statistics import mean
from typing import Iterable

from .defense_models import DefenseFinding


class EvasionDetector:
    """Simple heuristic to flag inconsistent defense findings."""

    def detect(self, findings: Iterable[DefenseFinding]) -> float:
        confidences = [finding.confidence for finding in findings]
        if not confidences:
            return 0.0
        avg = mean(confidences)
        anomalies = [abs(conf - avg) for conf in confidences]
        return min(1.0, sum(anomalies) / (len(confidences) or 1))


if __name__ == "__main__":  # pragma: no cover - sanity test
    detector = EvasionDetector()
    score = detector.detect([
        DefenseFinding(source="ids", message="a", confidence=0.2),
        DefenseFinding(source="waf", message="b", confidence=0.9),
    ])
    assert score > 0
    print("Evasion detector self-test passed.")
