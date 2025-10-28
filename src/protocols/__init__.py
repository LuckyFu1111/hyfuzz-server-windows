"""Protocol adapters for HyFuzz Windows Server.

This package provides protocol specific helpers used by the fuzzing
engine. Each adapter implements a minimal interface for building test
payloads and validating responses.
"""

from .base_protocol import ProtocolAdapter, ProtocolPayload
from .coap_protocol import CoAPProtocol
from .modbus_protocol import ModbusProtocol
from .protocol_registry import ProtocolRegistry
from .protocol_factory import ProtocolFactory

__all__ = [
    "ProtocolAdapter",
    "ProtocolPayload",
    "CoAPProtocol",
    "ModbusProtocol",
    "ProtocolRegistry",
    "ProtocolFactory",
]


if __name__ == "__main__":  # pragma: no cover - simple sanity check
    registry = ProtocolRegistry()
    factory = ProtocolFactory(registry)
    coap = factory.get_protocol("coap")
    modbus = factory.get_protocol("modbus")
    assert coap.name == "coap" and modbus.name == "modbus"
    sample = coap.build_payload({"path": "/test"})
    assert sample.body
    print("Protocol package self-test passed.")
