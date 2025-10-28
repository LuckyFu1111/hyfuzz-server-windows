"""Factory for retrieving protocol adapters."""

from __future__ import annotations

from typing import Optional

from .base_protocol import ProtocolAdapter
from .protocol_registry import ProtocolRegistry


class ProtocolFactory:
    """Lightweight factory using :class:`ProtocolRegistry`."""

    def __init__(self, registry: Optional[ProtocolRegistry] = None) -> None:
        self.registry = registry or ProtocolRegistry()

    def get_protocol(self, name: str) -> ProtocolAdapter:
        return self.registry.get(name)


if __name__ == "__main__":  # pragma: no cover - sanity test
    factory = ProtocolFactory()
    adapter = factory.get_protocol("modbus")
    assert adapter.name == "modbus"
    print("Protocol factory self-test passed.")
