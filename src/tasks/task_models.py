"""Dataclasses representing fuzzing tasks and results."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Optional


@dataclass
class FuzzTask:
    """Description of a single fuzzing task."""

    protocol: str
    parameters: Dict[str, object]
    created_at: datetime = field(default_factory=datetime.utcnow)
    priority: int = 0


@dataclass
class TaskResult:
    """Outcome of a fuzzing task."""

    task: FuzzTask
    success: bool
    artifacts: Dict[str, object] = field(default_factory=dict)
    error: Optional[str] = None


if __name__ == "__main__":  # pragma: no cover - sanity test
    task = FuzzTask(protocol="coap", parameters={"path": "/"})
    result = TaskResult(task=task, success=True, artifacts={"payloads": 5})
    assert result.success and result.artifacts["payloads"] == 5
    print("Task models self-test passed.")
