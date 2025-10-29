import pytest

from src.protocols.base_protocol import BaseProtocolHandler, ProtocolContext
from src.protocols.protocol_registry import ProtocolRegistry


def test_registry_lists_default_protocols() -> None:
    registry = ProtocolRegistry()
    available = registry.available_protocols()

    assert {"coap", "modbus"}.issubset(available.keys())


def test_base_handler_round_trip() -> None:
    handler = BaseProtocolHandler()
    context = ProtocolContext(target="coap://127.0.0.1")
    payload = {"method": "GET"}

    prepared = handler.prepare_request(context, payload)
    parsed = handler.parse_response(context, {"code": 205})

    assert prepared["payload"] == payload
    assert parsed["context"] == {}


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__])
