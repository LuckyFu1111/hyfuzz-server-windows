"""Dataclasses used by the task system."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict


@dataclass
class FuzzTask:
    protocol: str
    payload: Dict[str, Any]
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    priority: int = 0


if __name__ == "__main__":
    task = FuzzTask("coap", {"payload": "test"})
    assert task.protocol == "coap"
    print("task_models self-test passed.")
