"""Coordinator for defense subsystems such as WAF and IDS."""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, Iterable, List, Optional
import logging

from .defense_models import DefenseEvent, DefenseResult, DefenseSignal, DefenseAction


class DefenseIntegrator:
    """Integrates signals from different defense layers."""

    def __init__(self) -> None:
        self._integrators: Dict[str, "BaseDefenseModule"] = {}
        self._history: Dict[str, List[DefenseSignal]] = defaultdict(list)
        self.logger = logging.getLogger(__name__)

    def register_integrator(self, name: str, integrator: "BaseDefenseModule") -> None:
        """Register a new defense module under a name."""

        self.logger.debug("Registering integrator %s", name)
        self._integrators[name] = integrator

    def list_integrators(self) -> List[str]:
        """List names of registered integrators."""

        return sorted(self._integrators)

    def process_signal(self, signal: DefenseSignal) -> Optional[DefenseResult]:
        """Dispatch the signal to all registered integrators."""

        self.logger.debug(
            "Processing signal from %s with severity %s",
            signal.event.source,
            signal.severity,
        )
        self._history[signal.event.source].append(signal)
        actions: List[DefenseAction] = []
        rationales: List[str] = []

        for name, integrator in self._integrators.items():
            result = integrator.handle_signal(signal)
            if result:
                actions.extend(result.actions)
                rationales.append(result.rationale)

        if not actions:
            self.logger.debug("No actions produced for signal from %s", signal.event.source)
            return None

        verdict = "monitor" if signal.severity == "info" else "investigate"
        rationale = " | ".join(rationales) if rationales else "Aggregated defense response."
        aggregated_result = DefenseResult(
            signal=signal,
            actions=actions,
            verdict=verdict,
            rationale=rationale,
        )
        self.logger.debug("Aggregated result: %s", aggregated_result.to_dict())
        return aggregated_result

    def recent_signals(self, source: str, limit: int = 10) -> Iterable[DefenseSignal]:
        """Retrieve recent signals for a given source."""

        return self._history[source][-limit:]


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
    event = DefenseEvent(source="echo", payload={"demo": True})
    signal = DefenseSignal(event=event, severity="info", confidence=0.9)
    result = integrator.process_signal(signal)
    print(result.to_dict() if result else "No result")
