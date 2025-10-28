"""Slack notifier stub."""

from __future__ import annotations

from .notification_models import NotificationMessage


class SlackNotifier:
    def send(self, message: NotificationMessage) -> None:
        print(f"[SLACK] {message.subject}: {message.body}")


if __name__ == "__main__":
    SlackNotifier().send(NotificationMessage(channel="slack", subject="Demo", body="Test"))
