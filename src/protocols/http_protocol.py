"""HTTP protocol handler."""

from __future__ import annotations

from typing import Any, Dict

from .base_protocol import BaseProtocolHandler, ProtocolContext


class HTTPProtocolHandler(BaseProtocolHandler):
    name = "http"

    def prepare_request(self, context: ProtocolContext, payload: Dict[str, Any]) -> Dict[str, Any]:
        request = super().prepare_request(context, payload)
        request.setdefault("method", "GET")
        request.setdefault("headers", {})
        return request

    def validate(self, payload: Dict[str, Any]) -> bool:
        return "method" in payload and "path" in payload


if __name__ == "__main__":
    handler = HTTPProtocolHandler()
    ctx = ProtocolContext(target="http://example.com")
    print(handler.prepare_request(ctx, {"method": "POST", "path": "/api"}))
    print("Valid:", handler.validate({"method": "GET", "path": "/"}))
