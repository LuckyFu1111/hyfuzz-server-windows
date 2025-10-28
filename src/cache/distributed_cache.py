"""Distributed cache orchestrator."""

from __future__ import annotations

from typing import List

from .memory_cache import MemoryCache


class DistributedCache:
    def __init__(self, caches: List[MemoryCache] | None = None) -> None:
        self.caches = caches or [MemoryCache()]

    def set(self, key: str, value: object) -> None:
        for cache in self.caches:
            cache.set(key, value)

    def get(self, key: str) -> object | None:
        for cache in self.caches:
            value = cache.get(key)
            if value is not None:
                return value
        return None


if __name__ == "__main__":
    cache = DistributedCache()
    cache.set("demo", "value")
    print(cache.get("demo"))
