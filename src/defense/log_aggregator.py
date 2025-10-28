"""Aggregate defense telemetry from multiple sources."""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, Iterable, List

from .defense_models import DefenseFinding


class LogAggregator:
    """Aggregate findings grouped by source."""

    def aggregate(self, findings: Iterable[DefenseFinding]) -> Dict[str, List[DefenseFinding]]:
        grouped: Dict[str, List[DefenseFinding]] = defaultdict(list)
        for finding in findings:
            grouped[finding.source].append(finding)
        return grouped


if __name__ == "__main__":  # pragma: no cover - sanity test
    aggregator = LogAggregator()
    grouped = aggregator.aggregate([
        DefenseFinding(source="waf", message="a", confidence=0.5),
        DefenseFinding(source="ids", message="b", confidence=0.7),
        DefenseFinding(source="waf", message="c", confidence=0.6),
    ])
    assert len(grouped["waf"]) == 2
    print("Defense log aggregator self-test passed.")
