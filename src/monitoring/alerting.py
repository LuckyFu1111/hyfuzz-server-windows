"""Alert dispatching utilities."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, List

from .monitoring_models import HealthStatus


@dataclass
class Alert:
    channel: str
    message: str


class AlertDispatcher:
    """Dispatches alerts to registered channels."""

    def __init__(self) -> None:
        self.channels: Dict[str, Callable[[Alert], None]] = {}

    def register(self, name: str, callback: Callable[[Alert], None]) -> None:
        self.channels[name] = callback

    def dispatch(self, alert: Alert) -> None:
        for callback in self.channels.values():
            callback(alert)

    def notify_health(self, health: Dict[str, HealthStatus]) -> List[Alert]:
        alerts: List[Alert] = []
        for name, status in health.items():
            if status != HealthStatus.HEALTHY:
                alert = Alert(channel="health", message=f"{name} is {status.value}")
                alerts.append(alert)
                self.dispatch(alert)
        return alerts


if __name__ == "__main__":
    dispatcher = AlertDispatcher()
    dispatcher.register("print", lambda alert: print(f"Alert: {alert}"))
    alerts = dispatcher.notify_health({"db": HealthStatus.UNHEALTHY})
    print(alerts)
