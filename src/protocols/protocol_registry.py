"""Registry that keeps track of supported protocol handlers."""

from __future__ import annotations

from typing import Dict, Type

from .base_protocol import ProtocolHandler
from .coap_protocol import CoAPProtocolHandler
from .modbus_protocol import ModbusProtocolHandler
from .mqtt_protocol import MQTTProtocolHandler
from .http_protocol import HTTPProtocolHandler
from .grpc_protocol import GRPCProtocolHandler
from .jsonrpc_protocol import JSONRPCProtocolHandler


class ProtocolRegistry:
    """Registry mapping protocol identifiers to handlers."""

    def __init__(self) -> None:
        self._registry: Dict[str, Type[ProtocolHandler]] = {}
        self._register_defaults()

    def _register_defaults(self) -> None:
        self.register("coap", CoAPProtocolHandler)
        self.register("modbus", ModbusProtocolHandler)
        self.register("mqtt", MQTTProtocolHandler)
        self.register("http", HTTPProtocolHandler)
        self.register("grpc", GRPCProtocolHandler)
        self.register("jsonrpc", JSONRPCProtocolHandler)

    def register(self, name: str, handler_cls: Type[ProtocolHandler]) -> None:
        self._registry[name] = handler_cls

    def get(self, name: str) -> Type[ProtocolHandler]:
        if name not in self._registry:
            raise KeyError(f"Protocol '{name}' is not registered")
        return self._registry[name]

    def available_protocols(self) -> Dict[str, Type[ProtocolHandler]]:
        return dict(self._registry)


if __name__ == "__main__":
    registry = ProtocolRegistry()
    print(sorted(registry.available_protocols()))
