"""Defense analytics for correlating signals and trends."""

from __future__ import annotations

from dataclasses import dataclass, field
from statistics import mean
from typing import Dict, Iterable, List

from .defense_models import DefenseResult, DefenseSignal


@dataclass
class AnalyzerReport:
    """Aggregated analytics describing defense posture."""

    severity_distribution: Dict[str, int] = field(default_factory=dict)
    average_confidence: float = 0.0
    verdict_counts: Dict[str, int] = field(default_factory=dict)
    average_risk: float = 0.0


class DefenseAnalyzer:
    """Produces summary analytics from defense results."""

    def build_report(self, results: Iterable[DefenseResult]) -> AnalyzerReport:
        report = AnalyzerReport()
        confidences: List[float] = []
        risks: List[float] = []

        for result in results:
            self._increment(report.severity_distribution, result.signal.severity)
            self._increment(report.verdict_counts, result.verdict)
            confidences.append(result.signal.confidence)
            risks.append(result.risk_score)

        report.average_confidence = mean(confidences) if confidences else 0.0
        report.average_risk = mean(risks) if risks else 0.0

        report.average_confidence = mean(confidences) if confidences else 0.0
        return report

    @staticmethod
    def _increment(counter: Dict[str, int], key: str) -> None:
        counter[key] = counter.get(key, 0) + 1

    def rank_signals(self, signals: Iterable[DefenseSignal]) -> List[DefenseSignal]:
        return sorted(signals, key=lambda signal: (signal.severity, signal.confidence), reverse=True)


if __name__ == "__main__":
    from .defense_models import DefenseEvent, DefenseAction

    analyzer = DefenseAnalyzer()
    signals = [
        DefenseResult(
            signal=DefenseSignal(event=DefenseEvent(source="ids", payload={}), severity="high", confidence=0.8),
            actions=[DefenseAction(name="block", description="Blocked IP")],
            verdict="block",
            rationale="High severity alert",
        ),
        DefenseResult(
            signal=DefenseSignal(event=DefenseEvent(source="waf", payload={}), severity="medium", confidence=0.6),
            actions=[DefenseAction(name="monitor", description="Monitoring")],
            verdict="monitor",
            rationale="WAF allowed but flagged",
        ),
    ]
    report = analyzer.build_report(signals)
    print(report)
