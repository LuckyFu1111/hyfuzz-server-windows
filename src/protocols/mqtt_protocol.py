"""MQTT protocol handler."""

from __future__ import annotations

from typing import Any, Dict

from .base_protocol import BaseProtocolHandler, ProtocolContext


class MQTTProtocolHandler(BaseProtocolHandler):
    name = "mqtt"

    def prepare_request(self, context: ProtocolContext, payload: Dict[str, Any]) -> Dict[str, Any]:
        request = super().prepare_request(context, payload)
        request["topic"] = payload.get("topic", "test/topic")
        request["qos"] = payload.get("qos", 0)
        return request

    def validate(self, payload: Dict[str, Any]) -> bool:
        return "topic" in payload


if __name__ == "__main__":
    handler = MQTTProtocolHandler()
    ctx = ProtocolContext(target="mqtt://broker")
    print(handler.prepare_request(ctx, {"topic": "alerts"}))
    print("Valid:", handler.validate({"topic": "alerts"}))
