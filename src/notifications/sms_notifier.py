"""SMS notifier stub."""

from __future__ import annotations

from .notification_models import NotificationMessage


class SMSNotifier:
    def send(self, message: NotificationMessage) -> None:
        print(f"[SMS] {message.subject}: {message.body}")


if __name__ == "__main__":
    SMSNotifier().send(NotificationMessage(channel="sms", subject="Demo", body="Test"))
