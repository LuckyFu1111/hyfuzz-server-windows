"""Cache invalidation helper."""

from __future__ import annotations

from typing import Iterable

from .memory_cache import MemoryCache


class CacheInvalidator:
    def __init__(self, caches: Iterable[MemoryCache]) -> None:
        self.caches = list(caches)

    def invalidate(self, key: str) -> None:
        for cache in self.caches:
            cache.store.pop(key, None)


if __name__ == "__main__":
    cache = MemoryCache()
    cache.set("demo", "value")
    invalidator = CacheInvalidator([cache])
    invalidator.invalidate("demo")
    print(cache.get("demo"))
