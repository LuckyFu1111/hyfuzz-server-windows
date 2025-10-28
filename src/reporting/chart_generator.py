"""Generates simple chart structures."""

from __future__ import annotations

from typing import Dict, List


class ChartGenerator:
    """Produces chart configurations for the dashboard."""

    def bar_chart(self, title: str, labels: List[str], values: List[float]) -> Dict[str, object]:
        return {"type": "bar", "title": title, "labels": labels, "values": values}


if __name__ == "__main__":
    chart = ChartGenerator().bar_chart("Demo", ["A", "B"], [1, 2])
    print(chart)
