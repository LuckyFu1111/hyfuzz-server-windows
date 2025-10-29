"""Integration tests for lightweight LLM pipeline."""

from __future__ import annotations

from src.llm.payload_generator import PayloadGenerator, PayloadGenerationRequest
from src.llm.llm_judge import LLMJudge
from src.llm.prompt_builder import PromptBuilder, PromptTemplate
from src.models.llm_models import PayloadRequest, PayloadResponse


def test_payload_generation_and_judging() -> None:
    generator = PayloadGenerator(model_name="ollama-test")
    judge = LLMJudge(model_name="ollama-test")

    prompt = PromptBuilder().build("fuzz target")
    payload = generator.generate(PayloadGenerationRequest(prompt=prompt))
    judgment = judge.judge(payload)

    assert 0.0 <= judgment.score <= 1.0


def test_payload_models_roundtrip() -> None:
    request = PayloadRequest(prompt="hello")
    response = PayloadResponse(payload="data", reasoning="ok")

    assert request.temperature == 0.3
    assert response.reasoning == "ok"


def test_prompt_builder_custom_template() -> None:
    template = PromptTemplate(name="custom", prefix="[", suffix="]")
    builder = PromptBuilder(template=template)
    assert builder.build("payload") == "[payload]"
