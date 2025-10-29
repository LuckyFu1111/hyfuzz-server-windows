import pytest

from src.defense.defense_integrator import BaseDefenseModule, DefenseIntegrator
from src.defense.defense_models import DefenseAction, DefenseEvent, DefenseResult, DefenseSignal
from src.learning.feedback_loop import FeedbackLoop
from src.llm.llm_judge import LLMJudge
from src.llm.payload_generator import PayloadGenerationRequest, PayloadGenerator
from src.protocols.base_protocol import ProtocolContext
from src.protocols.protocol_factory import ProtocolFactory
from src.protocols.protocol_registry import ProtocolRegistry


class _AllowAllModule(BaseDefenseModule):
    def handle_signal(self, signal: DefenseSignal) -> DefenseResult | None:
        action = DefenseAction(name="allow", description="monitor")
        return DefenseResult(signal=signal, actions=[action], verdict="monitor", rationale="integration")


def test_phase3_pipeline_runs_end_to_end() -> None:
    payload_generator = PayloadGenerator(model_name="mistral")
    payload = payload_generator.generate(PayloadGenerationRequest(prompt="demo payload"))

    factory = ProtocolFactory(ProtocolRegistry())
    handler = factory.create("coap")
    request = handler.prepare_request(ProtocolContext(target="coap://localhost"), {"payload": payload, "path": "/"})

    event = DefenseEvent(source="waf", payload={"status": "monitored", "reason": "test"})
    signal = DefenseSignal(event=event, severity="low", confidence=0.6)
    integrator = DefenseIntegrator()
    integrator.register_integrator("allow", _AllowAllModule())
    defense_result = integrator.process_signal(signal)

    judge = LLMJudge(model_name="mistral")
    judgment = judge.judge(request["payload"])

    feedback = FeedbackLoop(history=[])
    feedback.add_feedback(f"{judgment.score:.2f}:{defense_result.verdict if defense_result else 'none'}")

    assert feedback.history
    assert request["payload"].startswith("mistral")


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__])
