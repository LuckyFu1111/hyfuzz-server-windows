"""Simple in-memory cache."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Dict

from .cache_models import CacheEntry


class MemoryCache:
    def __init__(self) -> None:
        self.store: Dict[str, CacheEntry] = {}

    def set(self, key: str, value: object, ttl_seconds: int | None = None) -> None:
        expires_at = datetime.utcnow() + timedelta(seconds=ttl_seconds) if ttl_seconds else None
        self.store[key] = CacheEntry(key=key, value=value, expires_at=expires_at)

    def get(self, key: str) -> object | None:
        entry = self.store.get(key)
        if entry and entry.is_expired():
            self.store.pop(key, None)
            return None
        return entry.value if entry else None


if __name__ == "__main__":
    cache = MemoryCache()
    cache.set("demo", "value", ttl_seconds=1)
    print(cache.get("demo"))
