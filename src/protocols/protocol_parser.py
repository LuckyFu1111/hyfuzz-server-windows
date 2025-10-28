"""Parse protocol configuration payloads for the HyFuzz server."""

from __future__ import annotations

from typing import Any, Mapping

from pydantic import BaseModel, Field, ValidationError


class ProtocolConfig(BaseModel):
    name: str = Field(..., description="Protocol identifier")
    target: str = Field(..., description="Target endpoint")
    options: Mapping[str, Any] = Field(default_factory=dict)


def parse_protocol_config(config: Mapping[str, Any]) -> ProtocolConfig:
    try:
        return ProtocolConfig.model_validate(config)
    except ValidationError as exc:  # pragma: no cover - simple wrapper
        raise ValueError(str(exc)) from exc


if __name__ == "__main__":
    cfg = parse_protocol_config({"name": "coap", "target": "coap://127.0.0.1"})
    assert cfg.name == "coap"
    print("protocol_parser self-test passed.")
