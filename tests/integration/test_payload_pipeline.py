import pytest

from src.llm.payload_generator import PayloadGenerationRequest, PayloadGenerator
from src.protocols.base_protocol import ProtocolContext
from src.protocols.protocol_factory import ProtocolFactory
from src.protocols.protocol_registry import ProtocolRegistry


def test_payload_pipeline_generates_protocol_request() -> None:
    generator = PayloadGenerator(model_name="mistral")
    request = PayloadGenerationRequest(prompt="generate coap payload")
    payload = generator.generate(request)

    registry = ProtocolRegistry()
    factory = ProtocolFactory(registry)

    handler = factory.create("coap")
    context = ProtocolContext(target="coap://localhost")
    prepared = handler.prepare_request(context, {"payload": payload, "path": "/demo"})

    assert prepared["payload"] == payload
    assert payload.startswith("mistral")


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__])
