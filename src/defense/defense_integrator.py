"""Coordinator for defense subsystems such as WAF and IDS."""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Callable, Dict, Iterable, List, Optional, Sequence

from .defense_analyzer import DefenseAnalyzer
from .defense_feedback import DefenseFeedback, DefenseFeedbackGenerator
from .defense_models import DefenseAction, DefenseEvent, DefenseResult, DefenseSignal
from .evasion_detector import EvasionDetector
from .log_aggregator import DefenseLogAggregator
from .threat_context import ThreatContextBuilder


class DefenseIntegrator:
    """Integrates signals originating from multiple defense layers."""

    SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
    _MAX_HISTORY = 200
    _MAX_RESULTS = 1000

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

    # ------------------------------------------------------------------
    # Registration helpers
    # ------------------------------------------------------------------
    def register_integrator(self, name: str, integrator: "BaseDefenseModule") -> None:
        """Register a defense module under the supplied *name*."""

        self.logger.debug("Registering defense integrator: %s", name)
        self._integrators[name] = integrator

    def list_integrators(self) -> List[str]:
        """Return the names of the currently registered integrators."""

        return sorted(self._integrators)

    def subscribe(self, callback: Callable[[DefenseResult], None]) -> None:
        """Register a subscriber that will receive aggregated results."""

        self._subscribers.append(callback)

    # ------------------------------------------------------------------
    # Processing helpers
    # ------------------------------------------------------------------
    def process_signal(self, signal: DefenseSignal) -> Optional[DefenseResult]:
        """Dispatch *signal* to all integrators and aggregate their responses."""

        source = signal.event.source
        self.logger.debug("Processing defense signal from source %s", source)

        self._history[source].append(signal.clone())
        if len(self._history[source]) > self._MAX_HISTORY:
            self._history[source] = self._history[source][-self._MAX_HISTORY :]

        self.log_aggregator.ingest(signal.event)

        actions: List[DefenseAction] = []
        rationales: List[str] = []
        severity_scores: List[float] = [self._severity_to_score(signal.severity)]
        confidences: List[float] = [signal.confidence]
        contexts: List[Dict[str, object]] = []

        for name, integrator in self._integrators.items():
            module_signal = signal.clone()
            try:
                result = integrator.handle_signal(module_signal)
            except Exception:  # pragma: no cover - defensive logging
                self.logger.exception("Defense integrator '%s' raised an exception", name)
                continue

            if not result:
                continue

            actions.extend(result.actions)
            rationales.append(f"{name}: {result.rationale}")
            severity_scores.append(self._severity_to_score(module_signal.severity))
            confidences.append(module_signal.confidence)

            context = self.context_builder.build_context(module_signal)
            if context:
                contexts.append(context)

            if module_signal.event.tags:
                signal.event.tag(*module_signal.event.tags)

        if not actions:
            self.logger.debug("No defense actions produced for source %s", source)
            return None

        aggregated_signal = signal.clone()
        aggregated_signal.severity = self._score_to_severity(max(severity_scores))
        aggregated_signal.confidence = max(confidences)

        evasion_score = self.evasion_detector.score(aggregated_signal)
        merged_context = self.context_builder.merge_contexts(contexts) if contexts else {}
        if evasion_score:
            merged_context.setdefault("analytics", {})["evasion_score"] = round(evasion_score, 3)

        knowledge_score = float(merged_context.get("analytics", {}).get("knowledge_risk", 0.0))
        risk_score = self._calculate_risk(max(severity_scores), knowledge_score, evasion_score)
        verdict = self._verdict_from_risk(risk_score)

        rationale = " | ".join(rationales) if rationales else "Aggregated defense response."

        aggregated_result = DefenseResult(
            signal=aggregated_signal,
            actions=actions,
            verdict=verdict,
            rationale=rationale,
            risk_score=risk_score,
            context=merged_context or {},
        )

        self._result_history.append(aggregated_result)
        if len(self._result_history) > self._MAX_RESULTS:
            self._result_history = self._result_history[-self._MAX_RESULTS :]

        summary = self.analyzer.build_report(self._result_history[-50:])
        analytics = aggregated_result.context.setdefault("analytics", {})
        analytics["average_risk_window"] = round(summary.average_risk, 3)
        analytics["average_confidence_window"] = round(summary.average_confidence, 3)

        self.logger.debug("Aggregated defense result: %s", aggregated_result.to_dict())

        for callback in self._subscribers:
            try:
                callback(aggregated_result)
            except Exception:  # pragma: no cover - defensive logging
                self.logger.exception("Defense subscriber raised an exception")

        return aggregated_result

    def process_batch(self, signals: Iterable[DefenseSignal]) -> List[DefenseResult]:
        """Process a batch of *signals* and return all produced results."""

        results: List[DefenseResult] = []
        for signal in signals:
            result = self.process_signal(signal)
            if result:
                results.append(result)
        return results

    # ------------------------------------------------------------------
    # Introspection helpers
    # ------------------------------------------------------------------
    def recent_signals(self, source: str, limit: int = 10) -> Iterable[DefenseSignal]:
        """Return the most recent *limit* signals for *source*."""

        if limit <= 0:
            return []
        return self._history[source][-limit:]

    def recent_results(self, limit: int = 10) -> Sequence[DefenseResult]:
        """Return the latest *limit* aggregated results."""

        if limit <= 0:
            return []
        return self._result_history[-limit:]

    # ------------------------------------------------------------------
    # Feedback helpers
    # ------------------------------------------------------------------
    def generate_feedback(self, result: DefenseResult) -> List[DefenseFeedback]:
        """Generate high-level feedback for downstream systems."""

        return self.feedback_generator.generate(result)

    # ------------------------------------------------------------------
    # Utility helpers
    # ------------------------------------------------------------------
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
    """Interface implemented by all defense modules."""

    def handle_signal(self, signal: DefenseSignal) -> Optional[DefenseResult]:  # pragma: no cover - interface
        raise NotImplementedError


if __name__ == "__main__":  # pragma: no cover - simple smoke test
    class EchoModule(BaseDefenseModule):
        def handle_signal(self, signal: DefenseSignal) -> Optional[DefenseResult]:
            action = DefenseAction(name="echo", description=f"Received {signal.severity} event")
            return DefenseResult(
                signal=signal,
                actions=[action],
                verdict="log",
                rationale="Echo module test",
            )

    integrator = DefenseIntegrator()
    integrator.register_integrator("echo", EchoModule())
    demo_event = DefenseEvent(source="echo", payload={"demo": True})
    demo_signal = DefenseSignal(event=demo_event, severity="info", confidence=0.9)
    demo_result = integrator.process_signal(demo_signal)
    print(demo_result.to_dict() if demo_result else "No result")
