"""Data models for monitoring subsystem."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum


@dataclass
class MetricSample:
    name: str
    value: float
    timestamp: datetime


class HealthStatus(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


if __name__ == "__main__":
    sample = MetricSample(name="requests", value=10, timestamp=datetime.utcnow())
    print(sample)
