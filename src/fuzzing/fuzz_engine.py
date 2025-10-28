"""Protocol aware fuzzing engine."""

from __future__ import annotations

from typing import Dict, Iterable, List, Optional

from ..protocols import ProtocolFactory, ProtocolPayload
from .payload_handler import PayloadHandler
from .fuzzing_strategies import MutationStrategy, basic_mutations


class FuzzEngine:
    """High level fuzzing engine orchestrating payload generation."""

    def __init__(self, protocol_factory: ProtocolFactory, handler: Optional[PayloadHandler] = None) -> None:
        self.protocol_factory = protocol_factory
        self.handler = handler or PayloadHandler()

    def generate(
        self,
        protocol_name: str,
        params: Dict[str, object],
        mutations: Optional[Iterable[str]] = None,
        strategy: Optional[MutationStrategy] = None,
    ) -> List[ProtocolPayload]:
        adapter = self.protocol_factory.get_protocol(protocol_name)
        base_payload = adapter.build_payload(params)
        if not adapter.validate_payload(base_payload):
            raise ValueError("Base payload failed validation")

        mutation_iterable = mutations or (strategy.generate(base_payload) if strategy else basic_mutations("default"))
        mutated = adapter.mutate(base_payload, mutation_iterable)
        return self.handler.handle(adapter, base_payload, mutated)


if __name__ == "__main__":  # pragma: no cover - sanity check
    factory = ProtocolFactory()
    engine = FuzzEngine(factory)
    payloads = engine.generate("modbus", {"value": 10})
    assert len(payloads) >= 1
    print("Fuzz engine self-test passed.")
