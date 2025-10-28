"""Modbus protocol adapter implementation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List

from .base_protocol import ProtocolAdapter, ProtocolPayload


@dataclass
class ModbusFrame:
    """Represents a simplified Modbus TCP frame."""

    unit_id: int
    function_code: int
    address: int
    value: int

    def to_bytes(self) -> bytes:
        return bytes([
            self.unit_id & 0xFF,
            self.function_code & 0xFF,
            (self.address >> 8) & 0xFF,
            self.address & 0xFF,
            (self.value >> 8) & 0xFF,
            self.value & 0xFF,
        ])


class ModbusProtocol(ProtocolAdapter):
    """Protocol adapter for Modbus TCP fuzzing."""

    def __init__(self) -> None:
        super().__init__("modbus")

    def build_payload(self, params: Dict[str, Any]) -> ProtocolPayload:
        frame = ModbusFrame(
            unit_id=int(params.get("unit_id", 1)),
            function_code=int(params.get("function_code", 3)),
            address=int(params.get("address", 0)),
            value=int(params.get("value", 1)),
        )
        return ProtocolPayload(body=frame.to_bytes(), metadata={"modbus": True})

    def validate_payload(self, payload: ProtocolPayload) -> bool:
        return len(payload.body) == 6

    def parse_response(self, data: bytes) -> Dict[str, Any]:
        return {
            "length": len(data),
            "data": list(data),
        }

    def mutate(self, payload: ProtocolPayload, mutations: Iterable[str]) -> List[ProtocolPayload]:
        mutated = []
        base = list(payload.body)
        for idx, mutation in enumerate(mutations, start=1):
            frame = base.copy()
            frame[-1] = (frame[-1] + idx) & 0xFF
            mutated.append(ProtocolPayload(body=bytes(frame), metadata={"mutation": mutation, "delta": idx}))
        return mutated


if __name__ == "__main__":  # pragma: no cover - sanity test
    adapter = ModbusProtocol()
    payload = adapter.build_payload({"function_code": 4, "value": 5})
    assert adapter.validate_payload(payload)
    parsed = adapter.parse_response(payload.body)
    assert parsed["length"] == 6
    mutated = adapter.mutate(payload, ["-test"])
    assert mutated and mutated[0].metadata["mutation"] == "-test"
    print("Modbus protocol adapter self-test passed.")
