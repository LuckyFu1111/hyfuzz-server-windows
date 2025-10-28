"""Aggregates campaign statistics for reports."""

from __future__ import annotations

from typing import Dict, Iterable


class StatisticsAggregator:
    def aggregate(self, campaign: Dict[str, object]) -> Dict[str, object]:
        findings = campaign.get("findings", [])
        summary = {
            "total_findings": len(findings),
            "high_severity": sum(1 for item in findings if item.get("severity") == "high"),
        }
        return {**campaign, **summary}


if __name__ == "__main__":
    aggregator = StatisticsAggregator()
    campaign = {"findings": [{"severity": "high"}, {"severity": "low"}]}
    print(aggregator.aggregate(campaign))
