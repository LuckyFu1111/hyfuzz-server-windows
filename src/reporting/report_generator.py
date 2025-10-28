"""Generates different report formats."""

from __future__ import annotations

from typing import Dict, List

from .template_engine import TemplateEngine
from .statistics_aggregator import StatisticsAggregator


class ReportGenerator:
    """High level report generator."""

    def __init__(self) -> None:
        self.templates = TemplateEngine()
        self.stats = StatisticsAggregator()

    def generate_summary(self, campaign: Dict[str, object]) -> str:
        context = self.stats.aggregate(campaign)
        return self.templates.render("executive_summary.html", context)

    def generate_findings(self, findings: List[Dict[str, object]]) -> str:
        return self.templates.render("technical_details.html", {"findings": findings})


if __name__ == "__main__":
    generator = ReportGenerator()
    html = generator.generate_summary({"findings": [{"id": "CVE-1", "severity": "high"}]})
    print(html[:80])
