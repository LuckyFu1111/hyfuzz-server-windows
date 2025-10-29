from src.llm.payload_generator import PayloadGenerator, PayloadGenerationRequest

def test_payload_generator_self_test():
    generator = PayloadGenerator(model_name="ollama-test")
    request = PayloadGenerationRequest(prompt="hello")
    assert generator.generate(request).startswith("ollama-test")
