"""Email notifier stub."""

from __future__ import annotations

from .notification_models import NotificationMessage


class EmailNotifier:
    def send(self, message: NotificationMessage) -> None:
        print(f"[EMAIL] {message.subject}: {message.body}")


if __name__ == "__main__":
    EmailNotifier().send(NotificationMessage(channel="email", subject="Demo", body="Test"))
