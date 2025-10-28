"""Helpers for Grafana dashboard integration."""

from __future__ import annotations

from typing import Mapping


class GrafanaIntegration:
    def __init__(self, datasource: str = "Prometheus") -> None:
        self.datasource = datasource

    def build_panel(self, metric: str) -> Mapping[str, object]:
        return {
            "datasource": self.datasource,
            "targets": [
                {
                    "expr": f"hyfuzz_{metric}_average",
                    "legendFormat": metric,
                }
            ],
        }


if __name__ == "__main__":
    panel = GrafanaIntegration().build_panel("requests")
    assert panel["targets"][0]["expr"] == "hyfuzz_requests_average"
    print("grafana_integration self-test passed.")
