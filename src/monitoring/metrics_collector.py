"""In-memory metrics collector."""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, Iterable

from .monitoring_models import MetricSample


class MetricsCollector:
    """Collect numerical metrics and expose simple aggregates."""

    def __init__(self) -> None:
        self._metrics: Dict[str, list[MetricSample]] = defaultdict(list)

    def record(self, name: str, value: float, **labels: str) -> None:
        self._metrics[name].append(MetricSample(name=name, value=value, labels=labels))

    def sum(self, name: str) -> float:
        return sum(sample.value for sample in self._metrics.get(name, []))

    def latest(self, name: str) -> MetricSample | None:
        metrics = self._metrics.get(name)
        return metrics[-1] if metrics else None

    def export(self) -> Dict[str, Iterable[MetricSample]]:
        return {name: list(samples) for name, samples in self._metrics.items()}


if __name__ == "__main__":  # pragma: no cover - sanity test
    collector = MetricsCollector()
    collector.record("payloads", 5, protocol="coap")
    assert collector.sum("payloads") == 5
    assert collector.latest("payloads").labels["protocol"] == "coap"
    print("Metrics collector self-test passed.")
