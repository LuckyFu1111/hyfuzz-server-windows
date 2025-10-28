"""JSON-RPC protocol handler."""

from __future__ import annotations

from typing import Any, Dict

from .base_protocol import BaseProtocolHandler, ProtocolContext


class JSONRPCProtocolHandler(BaseProtocolHandler):
    name = "jsonrpc"

    def prepare_request(self, context: ProtocolContext, payload: Dict[str, Any]) -> Dict[str, Any]:
        request = super().prepare_request(context, payload)
        request.setdefault("jsonrpc", "2.0")
        request.setdefault("id", 1)
        return request

    def validate(self, payload: Dict[str, Any]) -> bool:
        return "method" in payload


if __name__ == "__main__":
    handler = JSONRPCProtocolHandler()
    ctx = ProtocolContext(target="http://localhost/jsonrpc")
    print(handler.prepare_request(ctx, {"method": "ping", "params": []}))
    print("Valid:", handler.validate({"method": "ping"}))
