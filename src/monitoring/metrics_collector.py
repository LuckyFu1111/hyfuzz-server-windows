"""Collects runtime metrics."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import Dict, List

from .monitoring_models import MetricSample


class MetricsCollector:
    """In-memory metric collector."""

    def __init__(self) -> None:
        self.samples: Dict[str, List[MetricSample]] = defaultdict(list)

    def observe(self, name: str, value: float) -> None:
        sample = MetricSample(name=name, value=value, timestamp=datetime.utcnow())
        self.samples[name].append(sample)

    def export(self) -> Dict[str, List[float]]:
        return {name: [sample.value for sample in samples] for name, samples in self.samples.items()}


if __name__ == "__main__":
    collector = MetricsCollector()
    collector.observe("requests", 1)
    collector.observe("requests", 2)
    print(collector.export())
