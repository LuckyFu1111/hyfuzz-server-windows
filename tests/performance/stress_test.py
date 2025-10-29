from src.defense.defense_integrator import BaseDefenseModule, DefenseIntegrator
from src.defense.defense_models import DefenseAction, DefenseEvent, DefenseResult, DefenseSignal
from src.llm.llm_judge import LLMJudge
from src.llm.payload_generator import PayloadGenerationRequest, PayloadGenerator


class _StressModule(BaseDefenseModule):
    def handle_signal(self, signal: DefenseSignal) -> DefenseResult | None:
        action = DefenseAction(name="stress", description="ok")
        return DefenseResult(signal=signal, actions=[action], verdict="monitor", rationale="stress")


def run_stress_iterations(iterations: int = 50) -> None:
    generator = PayloadGenerator(model_name="mistral")
    judge = LLMJudge(model_name="mistral")
    integrator = DefenseIntegrator()
    integrator.register_integrator("stress", _StressModule())

    event = DefenseEvent(source="stress", payload={"status": "blocked", "reason": "test"})

    for i in range(iterations):
        payload = generator.generate(PayloadGenerationRequest(prompt=f"payload-{i}"))
        signal = DefenseSignal(event=event, severity="low", confidence=0.5)
        integrator.process_signal(signal)
        judge.judge(payload)


def test_stress_iterations_runs_quickly() -> None:
    run_stress_iterations(iterations=10)


if __name__ == "__main__":
    run_stress_iterations()
