"""High level interface orchestrating defense telemetry."""

from __future__ import annotations

from typing import Iterable, List

from .defense_analyzer import DefenseAnalyzer
from .defense_feedback import DefenseFeedbackGenerator
from .defense_models import DefenseDecision, DefenseFinding
from .ids_integrator import IDSIntegrator
from .log_aggregator import LogAggregator
from .waf_integrator import WAFIntegrator


class DefenseIntegrator:
    """Combine WAF and IDS telemetry and produce actionable insights."""

    def __init__(
        self,
        waf: WAFIntegrator | None = None,
        ids: IDSIntegrator | None = None,
        analyzer: DefenseAnalyzer | None = None,
        feedback: DefenseFeedbackGenerator | None = None,
    ) -> None:
        self.waf = waf or WAFIntegrator()
        self.ids = ids or IDSIntegrator()
        self.analyzer = analyzer or DefenseAnalyzer()
        self.feedback = feedback or DefenseFeedbackGenerator()
        self.aggregator = LogAggregator()

    def evaluate(self, defense_events: Iterable[dict]) -> DefenseDecision:
        waf_logs = [event for event in defense_events if event.get("source") == "waf"]
        ids_logs = [event for event in defense_events if event.get("source") == "ids"]
        findings: List[DefenseFinding] = []
        if waf_logs:
            findings.extend(self.waf.parse_logs(waf_logs))
        if ids_logs:
            findings.extend(self.ids.analyze_events(ids_logs))
        decision = self.analyzer.analyze(findings)
        decision.reasoning += " | " + self.feedback.create_feedback(decision)
        return decision

    def summarize(self, decision: DefenseDecision) -> dict:
        grouped = self.aggregator.aggregate(decision.findings)
        return {
            "overall": decision.overall_score,
            "groups": {source: len(items) for source, items in grouped.items()},
            "reasoning": decision.reasoning,
        }


if __name__ == "__main__":  # pragma: no cover - sanity test
    integrator = DefenseIntegrator()
    decision = integrator.evaluate(
        [
            {"source": "waf", "message": "Rule triggered", "confidence": 0.7},
            {"source": "ids", "message": "Heap spray", "vector": [0.2, 0.8, 0.3], "confidence": 0.6},
        ]
    )
    summary = integrator.summarize(decision)
    assert summary["groups"]["waf"] == 1
    print("Defense integrator self-test passed.")
