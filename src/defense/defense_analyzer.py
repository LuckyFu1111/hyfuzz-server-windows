"""Analyse defense events to derive insights."""

from __future__ import annotations

from typing import Iterable, Mapping

from .defense_models import DefenseInsight


class DefenseAnalyzer:
    def analyse(self, parsed_event: Mapping[str, object], insights: Iterable[DefenseInsight]) -> Mapping[str, object]:
        insight_list = list(insights)
        avg_confidence = sum(insight.confidence for insight in insight_list) / max(len(insight_list), 1)
        return {
            "risk": parsed_event["risk_score"],
            "detections": parsed_event["detections"],
            "llm_confidence": avg_confidence,
        }


if __name__ == "__main__":
    dummy = DefenseAnalyzer().analyse({"risk_score": 0.5, "detections": ("sql",)}, [DefenseInsight("test", [], 0.5)])
    assert dummy["risk"] == 0.5
    print("defense_analyzer self-test passed.")
