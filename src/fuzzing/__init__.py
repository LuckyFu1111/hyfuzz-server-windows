"""Fuzzing engine modules for HyFuzz Windows Server."""

from .fuzz_engine import FuzzEngine
from .payload_handler import PayloadHandler
from .protocol_fuzzing_engine import ProtocolFuzzingEngine
from .fuzzing_strategies import MutationStrategy

__all__ = [
    "FuzzEngine",
    "PayloadHandler",
    "ProtocolFuzzingEngine",
    "MutationStrategy",
]


if __name__ == "__main__":  # pragma: no cover - simple smoke test
    from .fuzzing_strategies import basic_mutations
    from ..protocols import ProtocolFactory

    engine = FuzzEngine(ProtocolFactory())
    payloads = engine.generate("coap", {"path": "/hello"}, mutations=basic_mutations("fuzz"))
    assert payloads
    print("Fuzzing package self-test passed.")
