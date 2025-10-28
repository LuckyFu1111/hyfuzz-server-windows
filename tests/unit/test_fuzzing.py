"""Tests for fuzzing engine components."""

from src.fuzzing import FuzzEngine
from src.fuzzing.fuzzing_strategies import PrefixMutationStrategy
from src.protocols import ProtocolFactory


def test_fuzz_engine_generates_mutations():
    engine = FuzzEngine(ProtocolFactory())
    payloads = engine.generate("coap", {"path": "/fuzz"})
    assert len(payloads) >= 1


def test_protocol_fuzzing_with_custom_strategy():
    engine = FuzzEngine(ProtocolFactory())
    strategy = PrefixMutationStrategy(prefix="x")
    payloads = engine.generate("modbus", {"value": 1}, strategy=strategy)
    assert any(payload.metadata.get("mutation") for payload in payloads if payload is not payloads[0])
