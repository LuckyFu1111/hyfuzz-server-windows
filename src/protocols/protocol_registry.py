"""Registry for protocol implementations."""

from __future__ import annotations

from typing import Dict, Iterable

from .base_protocol import BaseProtocol


class ProtocolRegistry:
    """In-memory registry storing protocol implementations."""

    def __init__(self) -> None:
        self._protocols: Dict[str, BaseProtocol] = {}

    def register(self, protocol: BaseProtocol) -> None:
        key = protocol.name.lower()
        self._protocols[key] = protocol

    def get(self, name: str) -> BaseProtocol:
        key = name.lower()
        if key not in self._protocols:
            raise KeyError(f"Protocol '{name}' is not registered")
        return self._protocols[key]

    def available(self) -> Iterable[str]:
        return tuple(sorted(self._protocols))

    def __contains__(self, item: str) -> bool:  # pragma: no cover - simple
        return item.lower() in self._protocols


if __name__ == "__main__":
    from .coap_protocol import CoAPProtocol

    registry = ProtocolRegistry()
    registry.register(CoAPProtocol())
    assert "coap" in registry
    assert registry.get("coap").name == "coap"
    print("ProtocolRegistry self-test passed.")
