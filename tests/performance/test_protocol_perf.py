import time

from src.protocols.protocol_factory import ProtocolFactory
from src.protocols.protocol_registry import ProtocolRegistry


def test_protocol_factory_creation_speed() -> None:
    registry = ProtocolRegistry()
    factory = ProtocolFactory(registry)

    start = time.perf_counter()
    handlers = factory.create_all()
    duration = time.perf_counter() - start

    assert handlers
    assert duration < 0.5


if __name__ == "__main__":
    test_protocol_factory_creation_speed()
