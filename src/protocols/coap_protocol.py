"""CoAP protocol handler."""

from __future__ import annotations

from typing import Any, Dict

from .base_protocol import BaseProtocolHandler, ProtocolContext


class CoAPProtocolHandler(BaseProtocolHandler):
    name = "coap"

    def prepare_request(self, context: ProtocolContext, payload: Dict[str, Any]) -> Dict[str, Any]:
        request = super().prepare_request(context, payload)
        request["method"] = payload.get("method", "GET")
        request["path"] = payload.get("path", "/")
        return request

    def validate(self, payload: Dict[str, Any]) -> bool:
        return "path" in payload


if __name__ == "__main__":
    handler = CoAPProtocolHandler()
    ctx = ProtocolContext(target="coap://demo")
    print(handler.prepare_request(ctx, {"path": "/ping"}))
    print("Valid:", handler.validate({"path": "/ping"}))
