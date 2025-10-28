"""Webhook notifier stub."""

from __future__ import annotations

from .notification_models import NotificationMessage


class WebhookNotifier:
    def send(self, message: NotificationMessage) -> None:
        print(f"[WEBHOOK] {message.subject}: {message.body}")


if __name__ == "__main__":
    WebhookNotifier().send(NotificationMessage(channel="webhook", subject="Demo", body="Test"))
