"""Redis cache stub."""

from __future__ import annotations

from typing import Dict


class RedisCache:
    def __init__(self) -> None:
        self.store: Dict[str, object] = {}

    def set(self, key: str, value: object) -> None:
        self.store[key] = value

    def get(self, key: str) -> object | None:
        return self.store.get(key)


if __name__ == "__main__":
    cache = RedisCache()
    cache.set("demo", "value")
    print(cache.get("demo"))
