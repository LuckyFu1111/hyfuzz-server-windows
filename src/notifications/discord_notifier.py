"""Discord notifier stub."""

from __future__ import annotations

from .notification_models import NotificationMessage


class DiscordNotifier:
    def send(self, message: NotificationMessage) -> None:
        print(f"[DISCORD] {message.subject}: {message.body}")


if __name__ == "__main__":
    DiscordNotifier().send(NotificationMessage(channel="discord", subject="Demo", body="Test"))
