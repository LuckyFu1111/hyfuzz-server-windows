"""Data models for notifications."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass
class NotificationMessage:
    channel: str
    subject: str
    body: str
    created_at: datetime = datetime.utcnow()


if __name__ == "__main__":
    print(NotificationMessage(channel="console", subject="Demo", body="Test"))
