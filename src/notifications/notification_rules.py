"""Notification rule evaluation."""

from __future__ import annotations

from typing import Callable, Dict

from .notification_models import NotificationMessage


class NotificationRules:
    def __init__(self) -> None:
        self.rules: Dict[str, Callable[[NotificationMessage], bool]] = {}

    def register(self, name: str, rule: Callable[[NotificationMessage], bool]) -> None:
        self.rules[name] = rule

    def should_send(self, message: NotificationMessage) -> bool:
        return all(rule(message) for rule in self.rules.values())


if __name__ == "__main__":
    rules = NotificationRules()
    rules.register("non_empty", lambda msg: bool(msg.body))
    print(rules.should_send(NotificationMessage(channel="console", subject="Demo", body="Test")))
