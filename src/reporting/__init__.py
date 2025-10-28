"""Reporting utilities for HyFuzz server."""

from .report_generator import ReportGenerator
from .statistics_aggregator import StatisticsAggregator

__all__ = ["ReportGenerator", "StatisticsAggregator"]


if __name__ == "__main__":
    generator = ReportGenerator()
    report = generator.generate_summary({"findings": []})
    print(report[:60])
