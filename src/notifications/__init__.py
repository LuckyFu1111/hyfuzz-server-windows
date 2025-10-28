"""Notification subsystem."""

from .notifier import NotificationService
from .notification_models import NotificationMessage

__all__ = ["NotificationService", "NotificationMessage"]


if __name__ == "__main__":
    service = NotificationService()
    service.send(NotificationMessage(channel="console", subject="Demo", body="Hello"))
