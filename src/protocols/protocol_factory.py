"""Factory for constructing protocol drivers from configuration."""

from __future__ import annotations

from typing import Optional

from .base_protocol import BaseProtocol
from .coap_protocol import CoAPProtocol
from .modbus_protocol import ModbusProtocol
from .protocol_registry import ProtocolRegistry


class ProtocolFactory:
    """Utility class wrapping :class:`ProtocolRegistry`."""

    def __init__(self, registry: Optional[ProtocolRegistry] = None) -> None:
        self.registry = registry or ProtocolRegistry()
        if "coap" not in self.registry.available():
            self.registry.register(CoAPProtocol())
        if "modbus" not in self.registry.available():
            self.registry.register(ModbusProtocol())

    def create(self, name: str) -> BaseProtocol:
        return self.registry.get(name)


if __name__ == "__main__":
    factory = ProtocolFactory()
    assert factory.create("coap").default_port == 5683
    assert factory.create("modbus").default_port == 502
    print("ProtocolFactory self-test passed.")
