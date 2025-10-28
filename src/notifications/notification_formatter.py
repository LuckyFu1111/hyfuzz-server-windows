"""Formats notifications for output."""

from __future__ import annotations

from .notification_models import NotificationMessage


class NotificationFormatter:
    def format(self, message: NotificationMessage) -> str:
        return f"[{message.channel.upper()}] {message.subject}: {message.body}"

    def ensure_formatted(self, message: NotificationMessage) -> NotificationMessage:
        if not message.body:
            message.body = "(no content)"
        return message


if __name__ == "__main__":
    formatter = NotificationFormatter()
    message = NotificationMessage(channel="console", subject="Demo", body="")
    formatter.ensure_formatted(message)
    print(formatter.format(message))
