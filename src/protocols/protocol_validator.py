"""Utility helpers for validating protocol payloads."""

from __future__ import annotations

from typing import Mapping

from .protocol_parser import ProtocolConfig


def ensure_supported_protocol(config: ProtocolConfig, registry) -> None:
    if config.name.lower() not in registry.available():
        raise ValueError(f"Unsupported protocol: {config.name}")


def ensure_target_uri(config: ProtocolConfig) -> None:
    if "//" not in config.target:
        raise ValueError("Target must be a URI")


def validate_config(config: Mapping[str, str], registry) -> ProtocolConfig:
    cfg = ProtocolConfig.model_validate(config)
    ensure_supported_protocol(cfg, registry)
    ensure_target_uri(cfg)
    return cfg


if __name__ == "__main__":
    from .protocol_registry import ProtocolRegistry
    from .coap_protocol import CoAPProtocol

    registry = ProtocolRegistry()
    registry.register(CoAPProtocol())
    config = validate_config({"name": "coap", "target": "coap://localhost"}, registry)
    assert config.name == "coap"
    print("protocol_validator self-test passed.")
