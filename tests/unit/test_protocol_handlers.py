import pytest

from src.protocols import CoAPProtocol, ModbusProtocol, ProtocolFactory, ProtocolRegistry


def test_coap_protocol_mutations():
    protocol = CoAPProtocol()
    seed = next(iter(protocol.generate_seed_payloads()))
    mutations = protocol.mutate_payload(seed)
    assert mutations
    assert mutations[0].field == "payload"


def test_modbus_protocol_packet_roundtrip():
    protocol = ModbusProtocol()
    seed = next(iter(protocol.generate_seed_payloads()))
    packet = protocol.build_packet(seed)
    parsed = protocol.parse_response(packet)
    assert parsed["transaction_id"] == seed["transaction_id"]


def test_protocol_factory_registration():
    registry = ProtocolRegistry()
    factory = ProtocolFactory(registry)
    assert factory.create("coap").default_port == 5683


if __name__ == "__main__":
    pytest.main([__file__])
