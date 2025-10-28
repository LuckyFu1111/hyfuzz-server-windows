"""Modbus/TCP protocol implementation for HyFuzz."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any, Iterable, List, Mapping, MutableMapping

import numpy as np

from .base_protocol import BaseProtocol, ProtocolMutation


@dataclass(frozen=True)
class ModbusFrame:
    transaction_id: int
    protocol_id: int
    unit_id: int
    function_code: int
    payload: bytes

    def to_dict(self) -> Mapping[str, Any]:
        return {
            "transaction_id": self.transaction_id,
            "protocol_id": self.protocol_id,
            "unit_id": self.unit_id,
            "function_code": self.function_code,
            "payload": self.payload.hex(),
        }


class ModbusProtocol(BaseProtocol):
    """Modbus protocol driver with focus on safe packet crafting."""

    name = "modbus"

    @property
    def default_port(self) -> int:  # pragma: no cover - simple getter
        return 502

    def generate_seed_payloads(self) -> Iterable[Mapping[str, Any]]:
        seeds = [
            ModbusFrame(1, 0, 1, 3, b"\x00\x10\x00\x02").to_dict(),  # Read Holding Registers
            ModbusFrame(2, 0, 1, 16, b"\x00\x64\x00\x01\x02\xff\x00").to_dict(),  # Write Multiple Registers
        ]
        return tuple(seeds)

    def mutate_payload(self, payload: Mapping[str, Any]) -> List[ProtocolMutation]:
        body = bytes.fromhex(payload.get("payload", ""))
        mutations: List[ProtocolMutation] = []
        if not body:
            body = b"\x00\x00"
        for idx, flip in enumerate((0x00, 0xff, 0x7f, 0x80)):
            mutated = bytearray(body)
            mutated[idx % len(mutated)] ^= flip
            mutations.append(
                ProtocolMutation("payload", body.hex(), bytes(mutated).hex(), float(np.clip(0.95 - idx * 0.2, 0.1, 0.95)))
            )
        return mutations

    def build_packet(self, payload: Mapping[str, Any]) -> bytes:
        pdu = bytes.fromhex(payload.get("payload", ""))
        length = len(pdu) + 1  # function code byte
        header = struct.pack(
            ">HHHB",
            payload.get("transaction_id", 0) & 0xFFFF,
            payload.get("protocol_id", 0) & 0xFFFF,
            length & 0xFFFF,
            payload.get("unit_id", 1) & 0xFF,
        )
        return header + bytes([payload.get("function_code", 3) & 0xFF]) + pdu

    def parse_response(self, packet: bytes) -> MutableMapping[str, Any]:
        if len(packet) < 9:
            raise ValueError("Invalid Modbus packet")
        transaction_id, protocol_id, length, unit_id = struct.unpack(">HHHB", packet[:7])
        function_code = packet[7]
        body = packet[8: 7 + length]
        return {
            "transaction_id": transaction_id,
            "protocol_id": protocol_id,
            "unit_id": unit_id,
            "function_code": function_code,
            "payload": body.hex(),
            "is_error": function_code & 0x80 != 0,
        }


if __name__ == "__main__":
    proto = ModbusProtocol()
    seeds = list(proto.generate_seed_payloads())
    assert seeds[0]["function_code"] == 3
    mutations = proto.mutate_payload(seeds[0])
    assert mutations
    packet = proto.build_packet(seeds[0])
    parsed = proto.parse_response(packet)
    assert parsed["transaction_id"] == 1
    print("ModbusProtocol self-test passed.")
