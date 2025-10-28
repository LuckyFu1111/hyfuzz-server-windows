"""Payload post-processing utilities."""

from __future__ import annotations

from typing import Iterable, List

from ..protocols import ProtocolAdapter, ProtocolPayload


class PayloadHandler:
    """Apply additional processing to generated payloads."""

    def handle(
        self,
        adapter: ProtocolAdapter,
        base_payload: ProtocolPayload,
        mutated_payloads: Iterable[ProtocolPayload],
    ) -> List[ProtocolPayload]:
        results = [base_payload]
        for payload in mutated_payloads:
            if adapter.validate_payload(payload):
                results.append(payload)
        return results


if __name__ == "__main__":  # pragma: no cover - sanity test
    from ..protocols import CoAPProtocol

    handler = PayloadHandler()
    adapter = CoAPProtocol()
    base = adapter.build_payload({"path": "/"})
    mutated = adapter.mutate(base, ["-a"])
    assert len(handler.handle(adapter, base, mutated)) == 2
    print("Payload handler self-test passed.")
