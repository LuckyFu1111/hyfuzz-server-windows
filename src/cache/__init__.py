"""Cache subsystem."""

from .memory_cache import MemoryCache
from .redis_cache import RedisCache

__all__ = ["MemoryCache", "RedisCache"]


if __name__ == "__main__":
    memory = MemoryCache()
    memory.set("demo", "value")
    print(memory.get("demo"))
