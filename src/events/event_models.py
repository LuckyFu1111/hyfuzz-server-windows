"""Event models."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Any


@dataclass
class Event:
    name: str
    payload: Dict[str, Any]
    timestamp: datetime = datetime.utcnow()


if __name__ == "__main__":
    print(Event(name="demo", payload={}))
