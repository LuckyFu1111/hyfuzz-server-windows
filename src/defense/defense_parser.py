"""Parsers for translating raw defense logs into normalized events."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict

from .defense_models import DefenseEvent


@dataclass
class DefenseParser:
    """Simple parser for structured defense logs."""

    default_source: str = "defense"

    def parse(self, raw_entry: Dict[str, Any]) -> DefenseEvent:
        """Parse a dictionary into a :class:`DefenseEvent`."""

        source = raw_entry.get("source", self.default_source)
        payload = raw_entry.get("payload", {})
        timestamp = raw_entry.get("timestamp")
        event = DefenseEvent(source=source, payload=payload)
        if timestamp:
            event.created_at = self._parse_timestamp(timestamp)
        if raw_entry.get("tags"):
            event.tag(*raw_entry["tags"])
        return event

    def _parse_timestamp(self, timestamp: Any) -> datetime:
        if isinstance(timestamp, datetime):
            return timestamp
        if isinstance(timestamp, (int, float)):
            return datetime.fromtimestamp(timestamp)
        return datetime.fromisoformat(str(timestamp))


if __name__ == "__main__":
    parser = DefenseParser()
    entry = {
        "source": "ids",
        "payload": {"alert": {"severity": "medium", "signature_id": "123"}},
        "timestamp": datetime.utcnow().isoformat(),
        "tags": ["ids", "alert"],
    }
    event = parser.parse(entry)
    print(event)
