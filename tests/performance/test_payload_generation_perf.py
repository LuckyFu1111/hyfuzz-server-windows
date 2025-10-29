import time

from src.llm.payload_generator import PayloadGenerationRequest, PayloadGenerator


def test_payload_generation_is_fast() -> None:
    generator = PayloadGenerator(model_name="mistral")
    start = time.perf_counter()
    for _ in range(100):
        generator.generate(PayloadGenerationRequest(prompt="ping"))
    duration = time.perf_counter() - start

    assert duration < 0.5


if __name__ == "__main__":
    test_payload_generation_is_fast()
