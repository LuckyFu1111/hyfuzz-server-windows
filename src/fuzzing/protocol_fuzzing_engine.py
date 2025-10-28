"""Per-protocol fuzzing orchestration."""

from __future__ import annotations

from typing import Dict, Iterable, List

from ..protocols import ProtocolAdapter, ProtocolFactory, ProtocolPayload
from .fuzzing_strategies import MutationStrategy


class ProtocolFuzzingEngine:
    """Manage fuzzing for a specific protocol instance."""

    def __init__(self, factory: ProtocolFactory) -> None:
        self.factory = factory

    def run(
        self,
        protocol_name: str,
        base_params: Dict[str, object],
        strategy: MutationStrategy,
    ) -> List[ProtocolPayload]:
        adapter = self.factory.get_protocol(protocol_name)
        base_payload = adapter.build_payload(base_params)
        mutations: Iterable[str] = strategy.generate(base_payload)
        return adapter.mutate(base_payload, mutations)


if __name__ == "__main__":  # pragma: no cover - sanity check
    from .fuzzing_strategies import PrefixMutationStrategy

    engine = ProtocolFuzzingEngine(ProtocolFactory())
    strategy = PrefixMutationStrategy(prefix="test-")
    payloads = engine.run("coap", {"path": "/"}, strategy)
    assert len(payloads) == 3
    print("Protocol fuzzing engine self-test passed.")
