"""Utilities to parse protocol responses."""

from __future__ import annotations

import json
from typing import Any, Dict


def parse_protocol_payload(payload: bytes) -> Dict[str, Any]:
    """Attempt to parse payload as JSON, otherwise return metadata."""

    try:
        return {"format": "json", "data": json.loads(payload.decode("utf-8"))}
    except (json.JSONDecodeError, UnicodeDecodeError):
        return {"format": "binary", "length": len(payload), "preview": payload[:16].hex()}


if __name__ == "__main__":  # pragma: no cover - sanity test
    json_data = json.dumps({"value": 1}).encode()
    assert parse_protocol_payload(json_data)["format"] == "json"
    assert parse_protocol_payload(b"\x01\x02")["format"] == "binary"
    print("Protocol parser self-test passed.")
