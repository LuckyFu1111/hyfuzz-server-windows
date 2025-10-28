"""Grafana dashboard integration helpers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict


@dataclass
class GrafanaPanel:
    title: str
    metric: str
    visualization: str = "graph"


class GrafanaIntegration:
    """Provides minimal Grafana dashboard definitions."""

    def build_dashboard(self, panels: Dict[str, GrafanaPanel]) -> Dict[str, object]:
        return {
            "panels": [
                {"title": panel.title, "target": panel.metric, "type": panel.visualization}
                for panel in panels.values()
            ]
        }


if __name__ == "__main__":
    integration = GrafanaIntegration()
    dashboard = integration.build_dashboard({"requests": GrafanaPanel("Requests", "requests_total")})
    print(dashboard)
