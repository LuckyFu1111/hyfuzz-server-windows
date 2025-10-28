"""Microsoft Teams notifier stub."""

from __future__ import annotations

from .notification_models import NotificationMessage


class TeamsNotifier:
    def send(self, message: NotificationMessage) -> None:
        print(f"[TEAMS] {message.subject}: {message.body}")


if __name__ == "__main__":
    TeamsNotifier().send(NotificationMessage(channel="teams", subject="Demo", body="Test"))
