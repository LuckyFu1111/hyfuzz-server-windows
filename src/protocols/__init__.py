"""Protocol abstractions for HyFuzz server."""

from .protocol_registry import ProtocolRegistry
from .protocol_factory import ProtocolFactory
from .base_protocol import ProtocolHandler, ProtocolContext
from .coap_protocol import CoAPProtocolHandler
from .modbus_protocol import ModbusProtocolHandler
from .mqtt_protocol import MQTTProtocolHandler
from .http_protocol import HTTPProtocolHandler
from .grpc_protocol import GRPCProtocolHandler
from .jsonrpc_protocol import JSONRPCProtocolHandler

__all__ = [
    "ProtocolRegistry",
    "ProtocolFactory",
    "ProtocolHandler",
    "ProtocolContext",
    "CoAPProtocolHandler",
    "ModbusProtocolHandler",
    "MQTTProtocolHandler",
    "HTTPProtocolHandler",
    "GRPCProtocolHandler",
    "JSONRPCProtocolHandler",
]


if __name__ == "__main__":
    registry = ProtocolRegistry()
    factory = ProtocolFactory(registry)
    handler = factory.create("coap")
    context = ProtocolContext(target="coap://localhost", metadata={})
    response = handler.prepare_request(context, payload={"type": "ping"})
    print(response)
