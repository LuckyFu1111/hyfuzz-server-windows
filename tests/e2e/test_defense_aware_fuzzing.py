from src.defense.defense_integrator import BaseDefenseModule, DefenseIntegrator
from src.defense.defense_models import DefenseAction, DefenseEvent, DefenseResult, DefenseSignal
from src.llm.llm_judge import LLMJudge


class _E2EDefenseModule(BaseDefenseModule):
    def handle_signal(self, signal: DefenseSignal) -> DefenseResult | None:
        action = DefenseAction(name="e2e", description="simulate defense")
        return DefenseResult(signal=signal, actions=[action], verdict="monitor", rationale="e2e")


def test_defense_aware_fuzzing_flow() -> None:
    integrator = DefenseIntegrator()
    integrator.register_integrator("e2e", _E2EDefenseModule())

    event = DefenseEvent(source="ids", payload={"status": "blocked", "reason": "pattern"})
    signal = DefenseSignal(event=event, severity="medium", confidence=0.8)
    defense_result = integrator.process_signal(signal)

    judge = LLMJudge(model_name="mistral")
    judgment = judge.judge("demo payload")

    assert defense_result is not None
    assert 0.0 <= judgment.score <= 1.0


if __name__ == "__main__":
    test_defense_aware_fuzzing_flow()
