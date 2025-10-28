"""Cache models."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass
class CacheEntry:
    key: str
    value: object
    expires_at: datetime | None = None

    def is_expired(self) -> bool:
        return self.expires_at is not None and datetime.utcnow() >= self.expires_at


if __name__ == "__main__":
    entry = CacheEntry(key="demo", value="value")
    print(entry.is_expired())
