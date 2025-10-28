"""Base protocol abstractions for HyFuzz.

The protocol system standardises how protocol specific fuzzers interact with the rest
of the server.  Each protocol implementation should be deterministic, stateless and
side-effect free so it can safely run within the distributed task execution pipeline.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional


@dataclass(frozen=True)
class ProtocolMutation:
    """Description of a mutation generated for a protocol payload."""

    field: str
    original: Any
    mutated: Any
    confidence: float


class BaseProtocol(ABC):
    """Abstract base class for all HyFuzz protocol drivers."""

    name: str = "base"

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return f"{self.__class__.__name__}(name={self.name!r})"

    # ------------------------------------------------------------------
    # Metadata helpers
    # ------------------------------------------------------------------
    @property
    def default_port(self) -> int:
        """Return the default port used by the protocol."""

        return 0

    @property
    def handshake_timeout(self) -> float:
        """Return timeout used during protocol handshakes."""

        return 5.0

    # ------------------------------------------------------------------
    # Payload lifecycle
    # ------------------------------------------------------------------
    @abstractmethod
    def generate_seed_payloads(self) -> Iterable[Mapping[str, Any]]:
        """Return deterministic seed payloads.

        Seed payloads act as high quality starting points for the LLM payload
        generator.  Each payload is an immutable mapping describing protocol
        specific fields (e.g. headers, body, function codes).
        """

    @abstractmethod
    def mutate_payload(self, payload: Mapping[str, Any]) -> List[ProtocolMutation]:
        """Return a list of concrete mutations applied to *payload*."""

    @abstractmethod
    def build_packet(self, payload: Mapping[str, Any]) -> bytes:
        """Serialise *payload* into bytes ready to be transmitted."""

    @abstractmethod
    def parse_response(self, packet: bytes) -> MutableMapping[str, Any]:
        """Parse a response packet into a structured mapping."""

    # ------------------------------------------------------------------
    # Validation helpers
    # ------------------------------------------------------------------
    def validate_payload(self, payload: Mapping[str, Any]) -> None:
        """Perform lightweight validation on *payload*.

        Implementations may override this method to provide richer validation
        logic.  The default implementation performs basic type checks to help
        catch programming mistakes early.
        """

        if not isinstance(payload, Mapping):
            raise TypeError("Payload must be a mapping")

    def validate_response(self, response: Mapping[str, Any]) -> bool:
        """Return True if a parsed response is considered valid."""

        return bool(response)

    # ------------------------------------------------------------------
    # Convenience helpers
    # ------------------------------------------------------------------
    def normalise_field(self, name: str) -> str:
        """Normalise a field name for registry lookups."""

        return name.strip().lower()

    def get_field(self, payload: Mapping[str, Any], name: str, default: Optional[Any] = None) -> Any:
        """Helper to read a field from *payload* with a normalised name."""

        return payload.get(self.normalise_field(name), default)


if __name__ == "__main__":
    class DummyProtocol(BaseProtocol):
        name = "dummy"

        def generate_seed_payloads(self) -> Iterable[Mapping[str, Any]]:
            return [{"field": "value"}]

        def mutate_payload(self, payload: Mapping[str, Any]) -> List[ProtocolMutation]:
            return [ProtocolMutation("field", payload["field"], "mutated", 0.5)]

        def build_packet(self, payload: Mapping[str, Any]) -> bytes:
            return str(payload).encode()

        def parse_response(self, packet: bytes) -> MutableMapping[str, Any]:
            return {"raw": packet.decode()}

    proto = DummyProtocol()
    seeds = list(proto.generate_seed_payloads())
    assert seeds[0]["field"] == "value"
    mutations = proto.mutate_payload(seeds[0])
    assert mutations[0].mutated == "mutated"
    packet = proto.build_packet(seeds[0])
    parsed = proto.parse_response(packet)
    assert parsed["raw"]
    print("BaseProtocol self-test passed.")
