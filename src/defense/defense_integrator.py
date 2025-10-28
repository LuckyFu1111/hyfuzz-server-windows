"""High level orchestration that combines WAF and IDS signals."""

from __future__ import annotations

from typing import Iterable, List, Mapping

from .defense_analyzer import DefenseAnalyzer
from .defense_models import DefenseEvent, DefenseInsight, DefenseRecommendation
from .defense_parser import DefenseParser
from .defense_feedback import DefenseFeedback
from .evasion_detector import EvasionDetector
from .ids_integrator import IDSIntegrator
from .log_aggregator import LogAggregator
from .waf_integrator import WAFIntegrator


class DefenseIntegrator:
    """Entry point consumed by the fuzzing pipeline."""

    def __init__(
        self,
        waf: WAFIntegrator | None = None,
        ids: IDSIntegrator | None = None,
    ) -> None:
        self.waf = waf or WAFIntegrator()
        self.ids = ids or IDSIntegrator()
        self.parser = DefenseParser()
        self.analyzer = DefenseAnalyzer()
        self.feedback = DefenseFeedback()
        self.evasion_detector = EvasionDetector()
        self.aggregator = LogAggregator()

    def assess_payload(self, payload: Mapping[str, object]) -> List[DefenseRecommendation]:
        event = self.waf.inspect(payload)
        insights = [self.ids.sync_score_payload(payload)]
        event.detections.extend([ins.summary for ins in insights])
        parsed = self.parser.parse_event(event)
        analysis = self.analyzer.analyse(parsed, insights)
        evasion = self.evasion_detector.detect(parsed)
        recommendations = self.feedback.generate(analysis, evasion)
        self.aggregator.store(event, analysis, recommendations)
        return recommendations

    def assess_batch(self, payloads: Iterable[Mapping[str, object]]) -> List[List[DefenseRecommendation]]:
        return [self.assess_payload(payload) for payload in payloads]


if __name__ == "__main__":
    integrator = DefenseIntegrator()
    recs = integrator.assess_payload({"payload": "../../etc/passwd"})
    assert recs
    print("defense_integrator self-test passed.")
