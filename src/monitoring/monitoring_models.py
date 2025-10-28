"""Dataclasses for monitoring outputs."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class MetricSnapshot:
    name: str
    count: int
    average: float


if __name__ == "__main__":
    snap = MetricSnapshot("requests", 10, 1.2)
    assert snap.count == 10
    print("monitoring_models self-test passed.")
