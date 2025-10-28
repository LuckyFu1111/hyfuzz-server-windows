"""Simple protocol payload validator."""

from __future__ import annotations

from typing import Dict, Optional

from .base_protocol import ProtocolAdapter, ProtocolPayload


class ProtocolValidator:
    """Validate payloads before submission to clients."""

    def __init__(self, adapter: ProtocolAdapter) -> None:
        self.adapter = adapter

    def validate(self, payload: ProtocolPayload, constraints: Optional[Dict[str, int]] = None) -> bool:
        if not self.adapter.validate_payload(payload):
            return False
        if constraints and "max_length" in constraints:
            return len(payload.body) <= int(constraints["max_length"])
        return True


if __name__ == "__main__":  # pragma: no cover - sanity test
    from .coap_protocol import CoAPProtocol

    adapter = CoAPProtocol()
    validator = ProtocolValidator(adapter)
    payload = adapter.build_payload({"path": "/hello"})
    assert validator.validate(payload, {"max_length": 512})
    print("Protocol validator self-test passed.")
