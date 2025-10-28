"""Registry for protocol adapters."""

from __future__ import annotations

from typing import Dict, Iterable, Type

from .base_protocol import ProtocolAdapter
from .coap_protocol import CoAPProtocol
from .modbus_protocol import ModbusProtocol


class ProtocolRegistry:
    """Simple registry storing protocol adapter factories."""

    def __init__(self) -> None:
        self._registry: Dict[str, Type[ProtocolAdapter]] = {}
        self.register("coap", CoAPProtocol)
        self.register("modbus", ModbusProtocol)

    def register(self, name: str, adapter_cls: Type[ProtocolAdapter]) -> None:
        self._registry[name.lower()] = adapter_cls

    def unregister(self, name: str) -> None:
        self._registry.pop(name.lower(), None)

    def get(self, name: str) -> ProtocolAdapter:
        try:
            adapter_cls = self._registry[name.lower()]
        except KeyError as exc:
            raise ValueError(f"Unknown protocol: {name}") from exc
        return adapter_cls()

    def available(self) -> Iterable[str]:
        return sorted(self._registry.keys())


if __name__ == "__main__":  # pragma: no cover - sanity test
    registry = ProtocolRegistry()
    assert "coap" in registry.available()
    adapter = registry.get("coap")
    assert adapter.name == "coap"
    print("Protocol registry self-test passed.")
