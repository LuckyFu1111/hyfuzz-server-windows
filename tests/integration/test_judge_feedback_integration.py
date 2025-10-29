import pytest

from src.defense.defense_integrator import BaseDefenseModule, DefenseIntegrator
from src.defense.defense_models import DefenseAction, DefenseEvent, DefenseResult, DefenseSignal
from src.learning.feedback_loop import FeedbackLoop


class _FeedbackModule(BaseDefenseModule):
    def handle_signal(self, signal: DefenseSignal) -> DefenseResult | None:
        action = DefenseAction(name="record", description="store verdict")
        return DefenseResult(signal=signal, actions=[action], verdict="monitor", rationale="integration test")


def test_defense_feedback_flow() -> None:
    integrator = DefenseIntegrator()
    integrator.register_integrator("feedback", _FeedbackModule())

    event = DefenseEvent(source="ids", payload={"status": "blocked"})
    signal = DefenseSignal(event=event, severity="medium", confidence=0.7)
    result = integrator.process_signal(signal)

    loop = FeedbackLoop(history=[])
    loop.add_feedback(result.verdict if result else "none")

    assert loop.history[-1] == "monitor"


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__])
