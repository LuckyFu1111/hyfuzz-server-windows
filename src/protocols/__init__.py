"""Protocol handling package for HyFuzz."""

from .base_protocol import BaseProtocol
from .coap_protocol import CoAPProtocol
from .modbus_protocol import ModbusProtocol
from .protocol_factory import ProtocolFactory
from .protocol_registry import ProtocolRegistry

__all__ = [
    "BaseProtocol",
    "CoAPProtocol",
    "ModbusProtocol",
    "ProtocolFactory",
    "ProtocolRegistry",
]


if __name__ == "__main__":
    registry = ProtocolRegistry()
    factory = ProtocolFactory(registry)
    registry.register(CoAPProtocol())
    registry.register(ModbusProtocol())

    coap = factory.create("coap")
    modbus = factory.create("modbus")

    assert coap.name == "coap"
    assert modbus.name == "modbus"
    print("Protocol package smoke test passed.")
