"""Notification service orchestrator."""

from __future__ import annotations

from typing import Dict

from .notification_models import NotificationMessage
from .email_notifier import EmailNotifier
from .slack_notifier import SlackNotifier
from .discord_notifier import DiscordNotifier
from .teams_notifier import TeamsNotifier
from .webhook_notifier import WebhookNotifier
from .sms_notifier import SMSNotifier
from .notification_formatter import NotificationFormatter


class NotificationService:
    """Routes notifications to specific channels."""

    def __init__(self) -> None:
        self.formatter = NotificationFormatter()
        self.channels: Dict[str, callable] = {
            "email": EmailNotifier().send,
            "slack": SlackNotifier().send,
            "discord": DiscordNotifier().send,
            "teams": TeamsNotifier().send,
            "webhook": WebhookNotifier().send,
            "sms": SMSNotifier().send,
            "console": lambda message: print(self.formatter.format(message)),
        }

    def send(self, message: NotificationMessage) -> None:
        handler = self.channels.get(message.channel)
        if not handler:
            raise KeyError(f"Channel '{message.channel}' not registered")
        handler(self.formatter.ensure_formatted(message))


if __name__ == "__main__":
    service = NotificationService()
    service.send(NotificationMessage(channel="console", subject="Demo", body="Test"))
