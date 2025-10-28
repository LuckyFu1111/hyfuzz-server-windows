"""Base protocol adapter definitions for HyFuzz Windows Server."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List


@dataclass
class ProtocolPayload:
    """Representation of a protocol payload."""

    body: bytes
    metadata: Dict[str, Any] = field(default_factory=dict)

    def as_text(self) -> str:
        """Return a UTF-8 representation of the payload body."""

        try:
            return self.body.decode("utf-8", errors="replace")
        except AttributeError:
            return str(self.body)


class ProtocolAdapter(ABC):
    """Abstract base class for protocol fuzzing adapters."""

    name: str

    def __init__(self, name: str) -> None:
        self.name = name.lower()

    @abstractmethod
    def build_payload(self, params: Dict[str, Any]) -> ProtocolPayload:
        """Build a protocol specific payload."""

    @abstractmethod
    def validate_payload(self, payload: ProtocolPayload) -> bool:
        """Validate payload before execution."""

    @abstractmethod
    def parse_response(self, data: bytes) -> Dict[str, Any]:
        """Parse raw protocol response into structured data."""

    def mutate(self, payload: ProtocolPayload, mutations: Iterable[str]) -> List[ProtocolPayload]:
        """Apply simple string mutations to the payload body."""

        mutated: List[ProtocolPayload] = []
        base_text = payload.as_text()
        for mutation in mutations:
            mutated_body = (base_text + mutation).encode("utf-8")
            mutated.append(ProtocolPayload(body=mutated_body, metadata={"mutation": mutation}))
        return mutated


if __name__ == "__main__":  # pragma: no cover - smoke test
    class DummyProtocol(ProtocolAdapter):
        def build_payload(self, params: Dict[str, Any]) -> ProtocolPayload:
            return ProtocolPayload(body=str(params).encode())

        def validate_payload(self, payload: ProtocolPayload) -> bool:
            return bool(payload.body)

        def parse_response(self, data: bytes) -> Dict[str, Any]:
            return {"length": len(data)}

    dummy = DummyProtocol("dummy")
    payload = dummy.build_payload({"key": "value"})
    assert dummy.validate_payload(payload)
    mutated = dummy.mutate(payload, ["-test"])
    assert mutated and mutated[0].metadata["mutation"] == "-test"
    assert dummy.parse_response(b"ok") == {"length": 2}
    print("Base protocol module self-test passed.")
