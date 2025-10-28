"""Coordinator for defense subsystems such as WAF and IDS."""

from __future__ import annotations

from collections import defaultdict
from typing import Callable, Dict, Iterable, List, Optional, Sequence
import logging

from .defense_models import DefenseEvent, DefenseResult, DefenseSignal, DefenseAction
from .log_aggregator import DefenseLogAggregator
from .evasion_detector import EvasionDetector
from .defense_analyzer import DefenseAnalyzer
from .defense_feedback import DefenseFeedbackGenerator
from .threat_context import ThreatContextBuilder


class DefenseIntegrator:
    """Integrates signals from different defense layers."""

    SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

    def __init__(
        self,
        *,
        log_aggregator: Optional[DefenseLogAggregator] = None,
        evasion_detector: Optional[EvasionDetector] = None,
        analyzer: Optional[DefenseAnalyzer] = None,
        feedback_generator: Optional[DefenseFeedbackGenerator] = None,
        context_builder: Optional[ThreatContextBuilder] = None,
    ) -> None:
        self._integrators: Dict[str, "BaseDefenseModule"] = {}
        self._history: Dict[str, List[DefenseSignal]] = defaultdict(list)
        self._result_history: List[DefenseResult] = []
        self._subscribers: List[Callable[[DefenseResult], None]] = []
        self.logger = logging.getLogger(__name__)
        self.log_aggregator = log_aggregator or DefenseLogAggregator()
        self.evasion_detector = evasion_detector or EvasionDetector()
        self.analyzer = analyzer or DefenseAnalyzer()
        self.feedback_generator = feedback_generator or DefenseFeedbackGenerator()
        self.context_builder = context_builder or ThreatContextBuilder()

    def register_integrator(self, name: str, integrator: "BaseDefenseModule") -> None:
        """Register a new defense module under a name."""

        self.logger.debug("Registering integrator %s", name)
        self._integrators[name] = integrator

    def list_integrators(self) -> List[str]:
        """List names of registered integrators."""

        return sorted(self._integrators)

    def subscribe(self, callback: Callable[[DefenseResult], None]) -> None:
        """Register a callback that receives aggregated defense results."""

        self._subscribers.append(callback)

    def process_signal(self, signal: DefenseSignal) -> Optional[DefenseResult]:
        """Dispatch the signal to all registered integrators."""

        self.logger.debug(
            "Processing signal from %s with severity %s",
            signal.event.source,
            signal.severity,
        )
        self._history[signal.event.source].append(signal)
        self.log_aggregator.ingest(signal.event)
        actions: List[DefenseAction] = []
        rationales: List[str] = []
        severity_scores: List[float] = [self._severity_to_score(signal.severity)]
        confidences: List[float] = [signal.confidence]
        contexts: List[Dict[str, object]] = []

        for name, integrator in self._integrators.items():
            module_signal = signal.clone()
            result = integrator.handle_signal(module_signal)
            if result:
                actions.extend(result.actions)
                rationales.append(f"{name}: {result.rationale}")
                severity_scores.append(self._severity_to_score(module_signal.severity))
                confidences.append(module_signal.confidence)
                context = self.context_builder.build_context(module_signal)
                if context:
                    contexts.append(context)
                signal.event.tag(*module_signal.event.tags)

        if not actions:
            self.logger.debug("No actions produced for signal from %s", signal.event.source)
            return None

        aggregated_signal = signal.clone()
        aggregated_signal.severity = self._score_to_severity(max(severity_scores))
        aggregated_signal.confidence = max(confidences)

        evasion_score = self.evasion_detector.score(aggregated_signal)
        merged_context = self.context_builder.merge_contexts(contexts)
        if evasion_score:
            merged_context.setdefault("analytics", {})["evasion_score"] = round(evasion_score, 3)

        knowledge_score = merged_context.get("analytics", {}).get("knowledge_risk", 0.0)
        risk_score = self._calculate_risk(max(severity_scores), knowledge_score, evasion_score)
        verdict = self._verdict_from_risk(risk_score)
        rationale_parts = rationales or ["Aggregated defense response."]
        if merged_context.get("cves"):
            tracked = ", ".join(item["cve_id"] for item in merged_context["cves"])
            rationale_parts.append(f"Related CVEs: {tracked}")
        rationale = " | ".join(rationale_parts)

        aggregated_result = DefenseResult(
            signal=aggregated_signal,
            actions=actions,
            verdict=verdict,
            rationale=rationale,
            risk_score=risk_score,
            context=merged_context,
        )
        self._result_history.append(aggregated_result)
        summary = self.analyzer.build_report(self._result_history[-20:])
        aggregated_result.context.setdefault("analytics", {})["average_risk_window"] = round(
            summary.average_risk, 3
        )
        aggregated_result.context["analytics"]["average_confidence_window"] = round(
            summary.average_confidence, 3
        )
        self.logger.debug("Aggregated result: %s", aggregated_result.to_dict())

        for callback in self._subscribers:
            try:
                callback(aggregated_result)
            except Exception:  # pragma: no cover - defensive logging
                self.logger.exception("Defense subscriber raised an exception")

        return aggregated_result

    def recent_signals(self, source: str, limit: int = 10) -> Iterable[DefenseSignal]:
        """Retrieve recent signals for a given source."""

        return self._history[source][-limit:]

    def recent_results(self, limit: int = 10) -> Sequence[DefenseResult]:
        """Return the most recent aggregated defense results."""

        if limit <= 0:
            return []
        return self._result_history[-limit:]

    def process_batch(self, signals: Iterable[DefenseSignal]) -> List[DefenseResult]:
        """Process a batch of signals and return aggregated results."""

        results: List[DefenseResult] = []
        for signal in signals:
            result = self.process_signal(signal)
            if result:
                results.append(result)
        return results

    @classmethod
    def _severity_to_score(cls, severity: str) -> float:
        try:
            index = cls.SEVERITY_ORDER.index(severity.lower())
        except ValueError:
            index = 0
        return index / (len(cls.SEVERITY_ORDER) - 1)

    @classmethod
    def _score_to_severity(cls, score: float) -> str:
        index = round(score * (len(cls.SEVERITY_ORDER) - 1))
        index = max(0, min(index, len(cls.SEVERITY_ORDER) - 1))
        return cls.SEVERITY_ORDER[index]

    def _calculate_risk(self, severity_score: float, knowledge_score: float, evasion_score: float) -> float:
        base = max(severity_score, knowledge_score)
        adjusted = min(1.0, base + evasion_score * 0.25)
        self.logger.debug(
            "Risk calculation - severity: %.3f, knowledge: %.3f, evasion: %.3f, final: %.3f",
            severity_score,
            knowledge_score,
            evasion_score,
            adjusted,
        )
        return adjusted

    @staticmethod
    def _verdict_from_risk(risk: float) -> str:
        if risk >= 0.85:
            return "block"
        if risk >= 0.6:
            return "investigate"
        return "monitor"


class BaseDefenseModule:
    """Interface that all defense modules should follow."""

    def handle_signal(self, signal: DefenseSignal) -> Optional[DefenseResult]:
        raise NotImplementedError


if __name__ == "__main__":
    class EchoModule(BaseDefenseModule):
        def handle_signal(self, signal: DefenseSignal) -> Optional[DefenseResult]:
            action = DefenseAction(name="echo", description=f"Received {signal.severity} event")
            return DefenseResult(signal=signal, actions=[action], verdict="log", rationale="Echo module test")

    integrator = DefenseIntegrator()
    integrator.register_integrator("echo", EchoModule())
    event = DefenseEvent(source="echo", payload={"demo": True, "cve_id": "CVE-2020-93810"})
    signal = DefenseSignal(event=event, severity="info", confidence=0.9)
    result = integrator.process_signal(signal)
    print(result.to_dict() if result else "No result")
