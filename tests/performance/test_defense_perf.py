import time

from src.defense.defense_integrator import BaseDefenseModule, DefenseIntegrator
from src.defense.defense_models import DefenseAction, DefenseEvent, DefenseResult, DefenseSignal


class _FastModule(BaseDefenseModule):
    def handle_signal(self, signal: DefenseSignal) -> DefenseResult | None:
        action = DefenseAction(name="fast", description="perf")
        return DefenseResult(signal=signal, actions=[action], verdict="monitor", rationale="perf test")


def test_defense_integrator_throughput() -> None:
    integrator = DefenseIntegrator()
    integrator.register_integrator("fast", _FastModule())
    event = DefenseEvent(source="perf", payload={"status": "blocked"})

    signals = [DefenseSignal(event=event, severity="low", confidence=0.5) for _ in range(200)]
    start = time.perf_counter()
    results = integrator.process_batch(signals)
    duration = time.perf_counter() - start

    assert len(results) == 200
    assert duration < 0.5


if __name__ == "__main__":
    test_defense_integrator_throughput()
