"""gRPC protocol handler."""

from __future__ import annotations

from typing import Any, Dict

from .base_protocol import BaseProtocolHandler, ProtocolContext


class GRPCProtocolHandler(BaseProtocolHandler):
    name = "grpc"

    def prepare_request(self, context: ProtocolContext, payload: Dict[str, Any]) -> Dict[str, Any]:
        request = super().prepare_request(context, payload)
        request["service"] = payload.get("service", "TestService")
        request["method"] = payload.get("method", "Test")
        return request

    def validate(self, payload: Dict[str, Any]) -> bool:
        return "service" in payload and "method" in payload


if __name__ == "__main__":
    handler = GRPCProtocolHandler()
    ctx = ProtocolContext(target="grpc://localhost:50051")
    print(handler.prepare_request(ctx, {"service": "Example", "method": "Echo"}))
    print("Valid:", handler.validate({"service": "Example", "method": "Echo"}))
