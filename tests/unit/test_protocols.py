"""Tests for protocol adapters."""

from src.protocols import CoAPProtocol, ModbusProtocol, ProtocolFactory, ProtocolRegistry
from src.protocols.protocol_validator import ProtocolValidator
from src.protocols.protocol_parser import parse_protocol_payload


def test_protocol_registry_roundtrip():
    registry = ProtocolRegistry()
    adapter = registry.get("coap")
    assert isinstance(adapter, CoAPProtocol)
    assert "modbus" in registry.available()


def test_coap_payload_validation():
    adapter = CoAPProtocol()
    payload = adapter.build_payload({"path": "/status"})
    validator = ProtocolValidator(adapter)
    assert validator.validate(payload, {"max_length": 1024})


def test_modbus_payload_and_parser():
    adapter = ModbusProtocol()
    payload = adapter.build_payload({"value": 2})
    assert adapter.validate_payload(payload)
    parsed = parse_protocol_payload(payload.body)
    assert parsed["format"] == "binary"
