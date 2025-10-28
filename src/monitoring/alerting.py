"""Simple alerting helpers."""

from __future__ import annotations

from typing import Iterable


class AlertingEngine:
    def __init__(self) -> None:
        self._alerts: list[str] = []

    def push(self, message: str) -> None:
        self._alerts.append(message)

    def drain(self) -> Iterable[str]:
        alerts = list(self._alerts)
        self._alerts.clear()
        return alerts


if __name__ == "__main__":
    engine = AlertingEngine()
    engine.push("High CPU usage")
    assert list(engine.drain()) == ["High CPU usage"]
    print("alerting self-test passed.")
