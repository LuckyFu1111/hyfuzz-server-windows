import pytest

from src.protocols.protocol_factory import ProtocolFactory
from src.protocols.protocol_registry import ProtocolRegistry


def test_protocol_factory_creates_all_handlers() -> None:
    registry = ProtocolRegistry()
    factory = ProtocolFactory(registry)

    handlers = factory.create_all()

    assert "coap" in handlers
    assert "modbus" in handlers
    assert handlers["coap"].name == "coap"


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__])
