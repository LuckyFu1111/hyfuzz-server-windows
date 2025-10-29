import pytest

from src.defense.defense_integrator import BaseDefenseModule, DefenseIntegrator
from src.defense.defense_models import DefenseAction, DefenseEvent, DefenseResult, DefenseSignal


class _EchoModule(BaseDefenseModule):
    def handle_signal(self, signal: DefenseSignal) -> DefenseResult | None:
        action = DefenseAction(name="echo", description="test action")
        return DefenseResult(signal=signal, actions=[action], verdict="monitor", rationale="ok")


def test_defense_integrator_dispatch() -> None:
    integrator = DefenseIntegrator()
    integrator.register_integrator("echo", _EchoModule())

    event = DefenseEvent(source="echo", payload={"status": "blocked"})
    signal = DefenseSignal(event=event, severity="medium", confidence=0.8)

    result = integrator.process_signal(signal)

    assert result is not None
    assert result.verdict in {"monitor", "investigate", "block"}
    assert result.actions, "at least one action should be aggregated"


def test_defense_integrator_batch_processing() -> None:
    integrator = DefenseIntegrator()
    integrator.register_integrator("echo", _EchoModule())

    event = DefenseEvent(source="echo", payload={"status": "blocked"})
    signals = [DefenseSignal(event=event, severity="low", confidence=0.5) for _ in range(3)]

    results = integrator.process_batch(signals)

    assert len(results) == 3


if __name__ == "__main__":  # pragma: no cover - quick smoke test
    pytest.main([__file__])
