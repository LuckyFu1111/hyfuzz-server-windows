"""Dataclasses for monitoring metrics."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict


@dataclass
class MetricSample:
    name: str
    value: float
    timestamp: datetime = field(default_factory=datetime.utcnow)
    labels: Dict[str, str] = field(default_factory=dict)


if __name__ == "__main__":  # pragma: no cover - sanity test
    sample = MetricSample(name="payloads", value=10, labels={"protocol": "coap"})
    assert sample.labels["protocol"] == "coap"
    print("Monitoring models self-test passed.")
