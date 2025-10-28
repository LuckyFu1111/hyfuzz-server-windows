"""Base protocol handler definitions."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Protocol, runtime_checkable


@dataclass
class ProtocolContext:
    """Context describing the target under test."""

    target: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def with_metadata(self, **kwargs: Any) -> "ProtocolContext":
        merged = {**self.metadata, **kwargs}
        return ProtocolContext(target=self.target, metadata=merged)


@runtime_checkable
class ProtocolHandler(Protocol):
    """Protocol for protocol handlers."""

    name: str

    def prepare_request(self, context: ProtocolContext, payload: Dict[str, Any]) -> Dict[str, Any]:
        ...

    def parse_response(self, context: ProtocolContext, response: Dict[str, Any]) -> Dict[str, Any]:
        ...

    def validate(self, payload: Dict[str, Any]) -> bool:
        ...


class BaseProtocolHandler:
    """Concrete base class implementing default behaviors."""

    name: str = "base"

    def prepare_request(self, context: ProtocolContext, payload: Dict[str, Any]) -> Dict[str, Any]:
        return {"target": context.target, "payload": payload}

    def parse_response(self, context: ProtocolContext, response: Dict[str, Any]) -> Dict[str, Any]:
        return {"context": context.metadata, "response": response}

    def validate(self, payload: Dict[str, Any]) -> bool:
        return bool(payload)


if __name__ == "__main__":
    context = ProtocolContext(target="demo")
    handler = BaseProtocolHandler()
    prepared = handler.prepare_request(context, {"ping": True})
    print(prepared)
    print(handler.parse_response(context, {"pong": True}))
    print("Valid:", handler.validate({"ping": True}))
