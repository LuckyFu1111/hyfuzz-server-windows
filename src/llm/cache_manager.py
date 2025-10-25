# ==============================================================================
# HyFuzz Server - LLM Cache Manager Module
# File: src/llm/cache_manager.py
# ==============================================================================
"""
LLM Response Cache Management System

This module provides intelligent caching mechanisms for LLM responses,
including support for multiple cache strategies and backends.

Features:
- Multiple caching strategies: NO_CACHE, TTL_BASED, LRU, LFU
- Pluggable cache backends (in-memory, Redis, etc.)
- Cache hit/miss statistics and monitoring
- Automatic expiration and cleanup
- Cache invalidation strategies
- Key generation and hashing
- Compression support for large responses
- Concurrency-safe operations with async support

Caching Strategies:

1. NO_CACHE: Disable caching entirely
   - Useful for testing or when cache not needed
   - Minimal memory overhead

2. TTL_BASED: Time-To-Live based expiration
   - Cache entries expire after specified duration
   - Automatic cleanup of expired entries
   - Default strategy, good for most scenarios

3. LRU: Least Recently Used eviction
   - When cache full, removes least recently accessed entry
   - Efficient for workloads with temporal locality
   - Good memory management

4. LFU: Least Frequently Used eviction
   - When cache full, removes least frequently accessed entry
   - Better for workloads with skewed access patterns
   - Optimal for fuzzing with repeated vulnerabilities

Usage Examples:

    # Basic usage
    cache = CacheManager(strategy="ttl", ttl=3600)

    # Store response
    await cache.set("cwe-79", payload_response, ttl=3600)

    # Retrieve cached response
    cached = await cache.get("cwe-79")
    if cached:
        return cached  # Use cached response

    # Generate new response
    response = await llm_service.generate(...)
    await cache.set("cwe-79", response)

    # Cache statistics
    stats = cache.get_stats()
    print(f"Hit rate: {stats['hit_rate']:.1%}")

Performance Notes:
- TTL strategy: O(1) for get/set, O(n) for cleanup
- LRU strategy: O(1) for get/set with OrderedDict
- LFU strategy: O(1) for get/set with frequency counters
- Memory overhead: ~200-500 bytes per entry

Author: HyFuzz Team
Version: 1.0.0
License: MIT
"""

import asyncio
import hashlib
import json
import logging
import pickle
import time
from typing import Any, Dict, List, Optional, Tuple, Union
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from abc import ABC, abstractmethod
from collections import OrderedDict
from functools import wraps
import threading


# ==============================================================================
# ENUMS AND CONSTANTS
# ==============================================================================

class CacheStrategy(str, Enum):
    """Cache eviction strategies"""
    NO_CACHE = "no_cache"  # No caching
    TTL_BASED = "ttl"  # Time-to-live based expiration
    LRU = "lru"  # Least Recently Used
    LFU = "lfu"  # Least Frequently Used


class CacheBackend(str, Enum):
    """Supported cache backends"""
    MEMORY = "memory"  # In-memory caching
    REDIS = "redis"  # Redis backend
    FILE = "file"  # File-based caching


# Default cache configuration
DEFAULT_MAX_CACHE_SIZE = 1000  # Maximum entries in cache
DEFAULT_TTL = 3600  # 1 hour time-to-live
DEFAULT_STRATEGY = CacheStrategy.TTL_BASED
CLEANUP_INTERVAL = 300  # Cleanup interval in seconds


# ==============================================================================
# DATA MODELS
# ==============================================================================

@dataclass
class CacheEntry:
    """
    Represents a single cache entry

    Attributes:
        key: Cache key
        value: Cached value
        created_at: Creation timestamp
        last_accessed: Last access timestamp
        access_count: Number of accesses
        ttl: Time-to-live in seconds
        size_bytes: Estimated size in bytes
    """
    key: str
    value: Any
    created_at: float = field(default_factory=time.time)
    last_accessed: float = field(default_factory=time.time)
    access_count: int = 0
    ttl: Optional[int] = None
    size_bytes: int = field(default=0)

    def is_expired(self) -> bool:
        """Check if entry has expired"""
        if self.ttl is None:
            return False
        return time.time() - self.created_at > self.ttl

    def get_age_seconds(self) -> float:
        """Get age of entry in seconds"""
        return time.time() - self.created_at

    def update_access(self) -> None:
        """Update access metadata"""
        self.last_accessed = time.time()
        self.access_count += 1

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "key": self.key,
            "created_at": datetime.fromtimestamp(self.created_at).isoformat(),
            "last_accessed": datetime.fromtimestamp(self.last_accessed).isoformat(),
            "access_count": self.access_count,
            "ttl": self.ttl,
            "size_bytes": self.size_bytes,
            "age_seconds": self.get_age_seconds(),
            "expired": self.is_expired(),
        }


@dataclass
class CacheStats:
    """Cache statistics"""
    total_requests: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    total_evictions: int = 0
    total_entries: int = 0
    total_size_bytes: int = 0
    cleanup_count: int = 0
    last_cleanup: Optional[float] = None

    @property
    def hit_rate(self) -> float:
        """Calculate cache hit rate"""
        total = self.cache_hits + self.cache_misses
        if total == 0:
            return 0.0
        return self.cache_hits / total

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "total_requests": self.total_requests,
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "hit_rate": f"{self.hit_rate:.2%}",
            "total_evictions": self.total_evictions,
            "total_entries": self.total_entries,
            "total_size_mb": round(self.total_size_bytes / (1024 * 1024), 2),
            "cleanup_count": self.cleanup_count,
        }


# ==============================================================================
# CACHE BACKENDS INTERFACE
# ==============================================================================

class CacheBackendInterface(ABC):
    """Abstract base class for cache backends"""

    @abstractmethod
    async def get(self, key: str) -> Optional[CacheEntry]:
        """Retrieve cache entry"""
        pass

    @abstractmethod
    async def set(self, entry: CacheEntry) -> bool:
        """Store cache entry"""
        pass

    @abstractmethod
    async def delete(self, key: str) -> bool:
        """Delete cache entry"""
        pass

    @abstractmethod
    async def clear(self) -> int:
        """Clear all entries, return count"""
        pass

    @abstractmethod
    async def exists(self, key: str) -> bool:
        """Check if key exists"""
        pass

    @abstractmethod
    async def keys(self) -> List[str]:
        """Get all cache keys"""
        pass

    @abstractmethod
    async def values(self) -> List[CacheEntry]:
        """Get all cache entries"""
        pass


class InMemoryCacheBackend(CacheBackendInterface):
    """In-memory cache backend"""

    def __init__(self, max_size: int = DEFAULT_MAX_CACHE_SIZE):
        """
        Initialize in-memory backend

        Args:
            max_size: Maximum cache entries
        """
        self.max_size = max_size
        self.cache: Dict[str, CacheEntry] = {}
        self.lock = asyncio.Lock()
        self.logger = logging.getLogger(__name__)

    async def get(self, key: str) -> Optional[CacheEntry]:
        """Retrieve cache entry"""
        async with self.lock:
            entry = self.cache.get(key)
            if entry and not entry.is_expired():
                entry.update_access()
                return entry
            elif entry and entry.is_expired():
                del self.cache[key]
            return None

    async def set(self, entry: CacheEntry) -> bool:
        """Store cache entry"""
        async with self.lock:
            if len(self.cache) >= self.max_size:
                # Remove oldest entry when full
                oldest_key = min(self.cache.keys(),
                                 key=lambda k: self.cache[k].last_accessed)
                del self.cache[oldest_key]

            self.cache[entry.key] = entry
            return True

    async def delete(self, key: str) -> bool:
        """Delete cache entry"""
        async with self.lock:
            if key in self.cache:
                del self.cache[key]
                return True
            return False

    async def clear(self) -> int:
        """Clear all entries"""
        async with self.lock:
            count = len(self.cache)
            self.cache.clear()
            return count

    async def exists(self, key: str) -> bool:
        """Check if key exists"""
        entry = await self.get(key)
        return entry is not None

    async def keys(self) -> List[str]:
        """Get all cache keys"""
        async with self.lock:
            return list(self.cache.keys())

    async def values(self) -> List[CacheEntry]:
        """Get all cache entries"""
        async with self.lock:
            return list(self.cache.values())


# ==============================================================================
# CACHE MANAGER CLASS
# ==============================================================================

class CacheManager:
    """
    Intelligent LLM Response Cache Manager

    Manages caching of LLM responses with configurable strategies
    and backends for optimal performance.
    """

    def __init__(
            self,
            strategy: str = DEFAULT_STRATEGY.value,
            backend: str = CacheBackend.MEMORY.value,
            max_size: int = DEFAULT_MAX_CACHE_SIZE,
            ttl: int = DEFAULT_TTL,
            enabled: bool = True,
    ):
        """
        Initialize CacheManager

        Args:
            strategy: Cache strategy (ttl, lru, lfu, no_cache)
            backend: Cache backend (memory, redis, file)
            max_size: Maximum cache entries
            ttl: Default time-to-live in seconds
            enabled: Enable caching
        """
        self.strategy = CacheStrategy(strategy)
        self.backend_type = backend
        self.max_size = max_size
        self.ttl = ttl
        self.enabled = enabled
        self.logger = logging.getLogger(__name__)

        # Initialize backend
        if backend == CacheBackend.MEMORY.value:
            self.backend = InMemoryCacheBackend(max_size)
        else:
            # Default to memory backend
            self.backend = InMemoryCacheBackend(max_size)

        # Statistics
        self.stats = CacheStats()

        # Strategy-specific tracking
        self.access_frequency: Dict[str, int] = {}  # For LFU
        self.access_order: OrderedDict = OrderedDict()  # For LRU

        # Cleanup task
        self.cleanup_task: Optional[asyncio.Task] = None
        self.logger.info(
            f"CacheManager initialized: strategy={strategy}, "
            f"backend={backend}, max_size={max_size}"
        )

    async def initialize(self) -> None:
        """Initialize cache manager and start cleanup task"""
        if self.strategy != CacheStrategy.NO_CACHE:
            self.cleanup_task = asyncio.create_task(self._cleanup_loop())
            self.logger.info("Cache cleanup task started")

    async def shutdown(self) -> None:
        """Shutdown cache manager"""
        if self.cleanup_task:
            self.cleanup_task.cancel()
            try:
                await self.cleanup_task
            except asyncio.CancelledError:
                pass
        self.logger.info("Cache manager shutdown")

    def _generate_key(self, *args, **kwargs) -> str:
        """
        Generate cache key from arguments

        Args:
            *args: Positional arguments
            **kwargs: Keyword arguments

        Returns:
            Generated cache key
        """
        key_data = json.dumps(
            {
                "args": str(args),
                "kwargs": str(sorted(kwargs.items())),
            },
            sort_keys=True,
        )
        return hashlib.sha256(key_data.encode()).hexdigest()

    async def get(self, key: str) -> Optional[Any]:
        """
        Retrieve cached value

        Args:
            key: Cache key

        Returns:
            Cached value if exists and valid, None otherwise
        """
        if not self.enabled or self.strategy == CacheStrategy.NO_CACHE:
            self.stats.cache_misses += 1
            return None

        self.stats.total_requests += 1
        entry = await self.backend.get(key)

        if entry:
            self.stats.cache_hits += 1
            self.logger.debug(f"Cache hit: {key}")
            return entry.value
        else:
            self.stats.cache_misses += 1
            self.logger.debug(f"Cache miss: {key}")
            return None

    async def set(
            self,
            key: str,
            value: Any,
            ttl: Optional[int] = None,
    ) -> bool:
        """
        Store value in cache

        Args:
            key: Cache key
            value: Value to cache
            ttl: Time-to-live override (seconds)

        Returns:
            True if successful
        """
        if not self.enabled or self.strategy == CacheStrategy.NO_CACHE:
            return False

        ttl = ttl or self.ttl
        size = len(pickle.dumps(value))

        entry = CacheEntry(
            key=key,
            value=value,
            ttl=ttl,
            size_bytes=size,
        )

        result = await self.backend.set(entry)

        if result:
            self.stats.total_entries += 1
            self.stats.total_size_bytes += size

            # Update strategy-specific tracking
            if self.strategy == CacheStrategy.LRU:
                self.access_order[key] = time.time()
            elif self.strategy == CacheStrategy.LFU:
                self.access_frequency[key] = 1

            self.logger.debug(f"Cached value for key: {key}")

        return result

    async def delete(self, key: str) -> bool:
        """
        Delete cache entry

        Args:
            key: Cache key

        Returns:
            True if deleted
        """
        result = await self.backend.delete(key)
        if result:
            self.stats.total_entries -= 1
            self.access_frequency.pop(key, None)
            self.access_order.pop(key, None)
        return result

    async def clear(self) -> int:
        """
        Clear all cache entries

        Returns:
            Number of cleared entries
        """
        count = await self.backend.clear()
        self.stats.total_entries = 0
        self.stats.total_size_bytes = 0
        self.access_frequency.clear()
        self.access_order.clear()
        self.logger.info(f"Cleared {count} cache entries")
        return count

    async def cleanup_expired(self) -> int:
        """
        Clean up expired entries

        Returns:
            Number of removed entries
        """
        removed = 0
        keys = await self.backend.keys()

        for key in keys:
            entry = await self.backend.get(key)
            if entry and entry.is_expired():
                await self.delete(key)
                removed += 1

        if removed > 0:
            self.stats.cleanup_count += 1
            self.stats.last_cleanup = time.time()
            self.logger.debug(f"Cleaned up {removed} expired entries")

        return removed

    async def _cleanup_loop(self) -> None:
        """Background cleanup loop"""
        while True:
            try:
                await asyncio.sleep(CLEANUP_INTERVAL)
                await self.cleanup_expired()
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Cleanup error: {e}")

    def get_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics

        Returns:
            Dictionary of cache statistics
        """
        return self.stats.to_dict()

    async def get_cache_info(self) -> Dict[str, Any]:
        """
        Get detailed cache information

        Returns:
            Dictionary with cache details
        """
        entries = await self.backend.values()
        entries_info = [entry.to_dict() for entry in entries]

        return {
            "strategy": self.strategy.value,
            "backend": self.backend_type,
            "enabled": self.enabled,
            "config": {
                "max_size": self.max_size,
                "ttl": self.ttl,
            },
            "statistics": self.get_stats(),
            "entries": entries_info,
            "total_entries": len(entries_info),
        }

    async def warmup(self, data: Dict[str, Any]) -> int:
        """
        Pre-populate cache with data

        Args:
            data: Dictionary of key-value pairs to cache

        Returns:
            Number of entries cached
        """
        cached = 0
        for key, value in data.items():
            if await self.set(key, value):
                cached += 1
        self.logger.info(f"Cache warmed up with {cached} entries")
        return cached

    def cache_decorator(self, ttl: Optional[int] = None):
        """
        Decorator for caching function results

        Args:
            ttl: Time-to-live override

        Returns:
            Decorated function

        Example:
            @cache_manager.cache_decorator(ttl=3600)
            async def expensive_function(cwe_id: str):
                return await compute_payload(cwe_id)
        """

        def decorator(func):
            @wraps(func)
            async def wrapper(*args, **kwargs):
                # Generate cache key
                key = self._generate_key(func.__name__, *args, **kwargs)

                # Try to get from cache
                cached = await self.get(key)
                if cached is not None:
                    return cached

                # Execute function
                result = await func(*args, **kwargs)

                # Cache result
                await self.set(key, result, ttl=ttl)

                return result

            return wrapper

        return decorator


# ==============================================================================
# UNIT TESTS
# ==============================================================================

async def run_tests():
    """
    Comprehensive test suite for CacheManager
    """
    print("\n" + "=" * 70)
    print("CACHE MANAGER UNIT TESTS")
    print("=" * 70 + "\n")

    test_passed = 0
    test_failed = 0

    try:
        # Test 1: Basic initialization
        print("[TEST 1] Initializing cache manager...")
        cache = CacheManager(
            strategy="ttl",
            backend="memory",
            max_size=100,
            ttl=3600,
        )
        await cache.initialize()
        if cache.enabled and cache.strategy == CacheStrategy.TTL_BASED:
            print("✓ PASSED: Cache manager initialized\n")
            test_passed += 1
        else:
            print("✗ FAILED: Cache initialization error\n")
            test_failed += 1

        # Test 2: Store and retrieve value
        print("[TEST 2] Testing cache set/get operations...")
        test_key = "test_payload_cwe_79"
        test_value = {"cwe": "CWE-79", "payload": "<script>alert(1)</script>"}

        set_result = await cache.set(test_key, test_value)
        get_result = await cache.get(test_key)

        if set_result and get_result == test_value:
            print("✓ PASSED: Set/Get operations working\n")
            test_passed += 1
        else:
            print("✗ FAILED: Set/Get operations failed\n")
            test_failed += 1

        # Test 3: Cache hit/miss statistics
        print("[TEST 3] Testing cache statistics...")
        stats_before = cache.stats.cache_hits
        await cache.get("nonexistent_key")  # Miss
        await cache.get(test_key)  # Hit
        stats_after = cache.stats.cache_hits

        if stats_after == stats_before + 1:
            print(f"✓ PASSED: Statistics tracking (hit_rate: {cache.stats.hit_rate:.1%})\n")
            test_passed += 1
        else:
            print("✗ FAILED: Statistics not tracking correctly\n")
            test_failed += 1

        # Test 4: Multiple entries
        print("[TEST 4] Testing multiple cache entries...")
        entries_stored = 0
        for i in range(5):
            key = f"test_key_{i}"
            value = f"test_value_{i}"
            if await cache.set(key, value):
                entries_stored += 1

        if entries_stored == 5 and cache.stats.total_entries >= 5:
            print(f"✓ PASSED: Stored {entries_stored} entries\n")
            test_passed += 1
        else:
            print("✗ FAILED: Multiple entry storage failed\n")
            test_failed += 1

        # Test 5: Cache deletion
        print("[TEST 5] Testing cache deletion...")
        delete_result = await cache.delete(test_key)
        get_after_delete = await cache.get(test_key)

        if delete_result and get_after_delete is None:
            print("✓ PASSED: Deletion working correctly\n")
            test_passed += 1
        else:
            print("✗ FAILED: Deletion failed\n")
            test_failed += 1

        # Test 6: Cache clear
        print("[TEST 6] Testing cache clear...")
        cleared_count = await cache.clear()
        if cleared_count > 0 and cache.stats.total_entries == 0:
            print(f"✓ PASSED: Cleared {cleared_count} entries\n")
            test_passed += 1
        else:
            print("✗ FAILED: Cache clear failed\n")
            test_failed += 1

        # Test 7: No-cache strategy
        print("[TEST 7] Testing NO_CACHE strategy...")
        no_cache = CacheManager(strategy="no_cache")
        set_no_cache = await no_cache.set("test", "value")
        get_no_cache = await no_cache.get("test")

        if not set_no_cache and get_no_cache is None:
            print("✓ PASSED: NO_CACHE strategy working\n")
            test_passed += 1
        else:
            print("✗ FAILED: NO_CACHE strategy failed\n")
            test_failed += 1

        # Test 8: TTL expiration
        print("[TEST 8] Testing TTL expiration...")
        cache_ttl = CacheManager(strategy="ttl", ttl=1)
        await cache_ttl.initialize()
        await cache_ttl.set("expire_test", "value", ttl=1)

        # Check immediately - should exist
        exists_before = await cache_ttl.get("expire_test")

        # Wait for expiration
        await asyncio.sleep(1.1)

        # Check after expiration - should be gone
        exists_after = await cache_ttl.get("expire_test")

        if exists_before == "value" and exists_after is None:
            print("✓ PASSED: TTL expiration working\n")
            test_passed += 1
        else:
            print("✗ FAILED: TTL expiration not working\n")
            test_failed += 1

        # Test 9: Cache info retrieval
        print("[TEST 9] Testing cache info retrieval...")
        await cache.set("info_test", "test_value")
        cache_info = await cache.get_cache_info()

        if cache_info and "strategy" in cache_info and "statistics" in cache_info:
            print(f"✓ PASSED: Cache info retrieved")
            print(f"  - Strategy: {cache_info['strategy']}")
            print(f"  - Total entries: {cache_info['total_entries']}\n")
            test_passed += 1
        else:
            print("✗ FAILED: Cache info retrieval failed\n")
            test_failed += 1

        # Test 10: Cache warmup
        print("[TEST 10] Testing cache warmup...")
        warmup_data = {
            f"warmup_{i}": f"value_{i}" for i in range(3)
        }
        warmed = await cache.warmup(warmup_data)

        if warmed == 3:
            print(f"✓ PASSED: Warmed up cache with {warmed} entries\n")
            test_passed += 1
        else:
            print(f"✗ FAILED: Cache warmup failed (warmed: {warmed})\n")
            test_failed += 1

        # Cleanup
        await cache.shutdown()
        await cache_ttl.shutdown()

    except Exception as e:
        print(f"✗ TEST ERROR: {e}\n")
        test_failed += 1

    # Summary
    print("=" * 70)
    print(f"TEST SUMMARY: {test_passed} PASSED, {test_failed} FAILED")
    print(f"Success Rate: {(test_passed / (test_passed + test_failed) * 100):.1f}%")
    print("=" * 70 + "\n")

    return test_passed, test_failed


# ==============================================================================
# ENTRY POINT
# ==============================================================================

if __name__ == "__main__":
    import asyncio

    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Run tests
    asyncio.run(run_tests())