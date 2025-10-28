"""CoAP protocol adapter used by the fuzzing engine."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict

from .base_protocol import ProtocolAdapter, ProtocolPayload


@dataclass
class CoAPMessage:
    """Simple representation of a CoAP message."""

    method: str
    path: str
    payload: Dict[str, Any]

    def to_bytes(self) -> bytes:
        return json.dumps({
            "method": self.method,
            "path": self.path,
            "payload": self.payload,
        }).encode("utf-8")


class CoAPProtocol(ProtocolAdapter):
    """Protocol adapter for Constrained Application Protocol."""

    def __init__(self) -> None:
        super().__init__("coap")

    def build_payload(self, params: Dict[str, Any]) -> ProtocolPayload:
        message = CoAPMessage(
            method=params.get("method", "GET"),
            path=params.get("path", "/"),
            payload=params.get("payload", {}),
        )
        return ProtocolPayload(body=message.to_bytes(), metadata={"coap": True})

    def validate_payload(self, payload: ProtocolPayload) -> bool:
        try:
            data = json.loads(payload.body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return False
        return "method" in data and "path" in data

    def parse_response(self, data: bytes) -> Dict[str, Any]:
        try:
            return json.loads(data.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return {"raw": data.hex()}


if __name__ == "__main__":  # pragma: no cover - sanity test
    adapter = CoAPProtocol()
    payload = adapter.build_payload({"path": "/status", "payload": {"q": 1}})
    assert adapter.validate_payload(payload)
    parsed = adapter.parse_response(payload.body)
    assert parsed["path"] == "/status"
    print("CoAP protocol adapter self-test passed.")
