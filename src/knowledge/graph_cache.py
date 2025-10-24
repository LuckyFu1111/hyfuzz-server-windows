"""
Graph Cache Module for HyFuzz MCP Server

This module provides the GraphCache class for caching CWE and CVE relationship graphs.
It supports multiple caching strategies (in-memory, disk, hybrid) with TTL support.

Features:
- Multi-strategy caching (in_memory, disk, hybrid)
- Time-to-live (TTL) support for cache entries
- LRU (Least Recently Used) eviction policy
- CWE and CVE graph caching
- Serialization/deserialization with pickle
- Cache statistics and monitoring
- Async support for I/O operations
- Comprehensive error handling and logging

Architecture:
- CacheEntry: Data structure for cached items with metadata
- GraphCache: Main cache manager supporting different strategies
- In-memory caching with LRU eviction
- Disk persistence with configurable cache directory
- Hybrid caching combining both strategies

Example Usage:
     cache = GraphCache(strategy="hybrid", max_size=10000, ttl=3600)
     await cache.initialize()
     await cache.set("CWE-79", cwe_graph_data)
     result = await cache.get("CWE-79")
     stats = cache.get_stats()

Author: HyFuzz Team
Version: 1.0.0
Date: 2025
"""

import asyncio
import json
import logging
import pickle
from typing import Dict, Any, Optional, List, Tuple
from pathlib import Path
from datetime import datetime, timedelta
from collections import OrderedDict
from dataclasses import dataclass, field, asdict
from enum import Enum
import hashlib
import os
from concurrent.futures import ThreadPoolExecutor

# ==============================================================================
# LOGGER SETUP
# ==============================================================================

logger = logging.getLogger(__name__)


# ==============================================================================
# ENUMERATIONS
# ==============================================================================


class CacheStrategy(str, Enum):
    """Cache strategy enumeration"""

    IN_MEMORY = "in_memory"
    DISK = "disk"
    HYBRID = "hybrid"

    def __str__(self):
        return self.value


class CacheType(str, Enum):
    """Cache entry type enumeration"""

    CWE_GRAPH = "cwe_graph"
    CVE_GRAPH = "cve_graph"
    RELATIONSHIP = "relationship"
    INDEX = "index"
    METADATA = "metadata"

    def __str__(self):
        return self.value


# ==============================================================================
# DATA CLASSES
# ==============================================================================


@dataclass
class CacheEntry:
    """Represents a single cache entry with metadata"""

    key: str
    value: Any
    cache_type: CacheType
    created_at: datetime = field(default_factory=datetime.now)
    accessed_at: datetime = field(default_factory=datetime.now)
    ttl_seconds: Optional[int] = None
    hit_count: int = 0
    size_bytes: int = 0

    def is_expired(self) -> bool:
        """Check if cache entry has expired based on TTL"""
        if self.ttl_seconds is None:
            return False

        elapsed = (datetime.now() - self.created_at).total_seconds()
        return elapsed > self.ttl_seconds

    def update_access_time(self):
        """Update access time for LRU tracking"""
        self.accessed_at = datetime.now()
        self.hit_count += 1

    def to_dict(self) -> Dict[str, Any]:
        """Convert cache entry to dictionary"""
        return {
            "key": self.key,
            "cache_type": self.cache_type.value,
            "created_at": self.created_at.isoformat(),
            "accessed_at": self.accessed_at.isoformat(),
            "ttl_seconds": self.ttl_seconds,
            "hit_count": self.hit_count,
            "size_bytes": self.size_bytes,
        }


@dataclass
class CacheStats:
    """Cache statistics and performance metrics"""

    total_entries: int = 0
    total_size_bytes: int = 0
    hit_count: int = 0
    miss_count: int = 0
    eviction_count: int = 0
    expired_count: int = 0
    memory_entries: int = 0
    disk_entries: int = 0
    cache_type_distribution: Dict[str, int] = field(default_factory=dict)

    @property
    def hit_rate(self) -> float:
        """Calculate cache hit rate"""
        total_accesses = self.hit_count + self.miss_count
        return self.hit_count / total_accesses if total_accesses > 0 else 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert stats to dictionary"""
        return {
            "total_entries": self.total_entries,
            "total_size_bytes": self.total_size_bytes,
            "hit_count": self.hit_count,
            "miss_count": self.miss_count,
            "eviction_count": self.eviction_count,
            "expired_count": self.expired_count,
            "hit_rate": f"{self.hit_rate:.2%}",
            "memory_entries": self.memory_entries,
            "disk_entries": self.disk_entries,
            "cache_type_distribution": self.cache_type_distribution,
        }


# ==============================================================================
# UTILITY FUNCTIONS FOR SYNCHRONOUS I/O
# ==============================================================================


def _save_entry_to_file(cache_file: Path, entry: CacheEntry):
    """
    Synchronously save cache entry to file.
    
    Args:
        cache_file: Path to cache file
        entry: Cache entry to save
    """
    with open(cache_file, "wb") as f:
        pickle.dump(entry, f)


def _load_entry_from_file(cache_file: Path) -> Optional[CacheEntry]:
    """
    Synchronously load cache entry from file.
    
    Args:
        cache_file: Path to cache file
        
    Returns:
        CacheEntry if successful, None otherwise
    """
    try:
        with open(cache_file, "rb") as f:
            return pickle.load(f)
    except Exception as e:
        logger.error(f"Failed to load from {cache_file}: {e}")
        return None


# ==============================================================================
# GRAPH CACHE CLASS
# ==============================================================================


class GraphCache:
    """
    Graph cache manager supporting multiple caching strategies.

    This class provides a unified interface for caching CWE and CVE graphs
    with support for different strategies: in-memory, disk-based, or hybrid.

    Attributes:
        strategy: Caching strategy to use
        max_size: Maximum number of entries in cache
        ttl: Default time-to-live for cache entries (seconds)
        cache_dir: Directory for disk cache storage
        initialized: Whether cache has been initialized
    """

    def __init__(
        self,
        strategy: str = "in_memory",
        max_size: int = 10000,
        ttl: Optional[int] = None,
        cache_dir: Optional[Path] = None,
    ):
        """
        Initialize graph cache.

        Args:
            strategy: Caching strategy ('in_memory', 'disk', 'hybrid')
            max_size: Maximum number of cache entries
            ttl: Default TTL for cache entries in seconds
            cache_dir: Directory for disk-based cache
        """
        self.strategy = CacheStrategy(strategy)
        self.max_size = max_size
        self.ttl = ttl
        self.cache_dir = Path(cache_dir) if cache_dir else Path.cwd() / "cache"
        self.initialized = False
        self._thread_pool = ThreadPoolExecutor(max_workers=4)

        # In-memory cache: LRU cache using OrderedDict
        self._memory_cache: OrderedDict[str, CacheEntry] = OrderedDict()

        # Metadata and statistics
        self._stats = CacheStats()
        self._lock = asyncio.Lock()

        logger.info(
            f"GraphCache initialized with strategy={self.strategy}, "
            f"max_size={max_size}, ttl={ttl}"
        )

    async def initialize(self) -> bool:
        """
        Initialize cache system.

        Creates cache directories and loads existing cache if present.

        Returns:
            True if initialization successful, False otherwise
        """
        try:
            async with self._lock:
                # Create cache directory
                if self.strategy in [CacheStrategy.DISK, CacheStrategy.HYBRID]:
                    self.cache_dir.mkdir(parents=True, exist_ok=True)
                    logger.info(f"Cache directory created: {self.cache_dir}")

                # Load existing cache from disk if available
                if self.strategy in [CacheStrategy.DISK, CacheStrategy.HYBRID]:
                    await self._load_from_disk()

                self.initialized = True
                logger.info("GraphCache initialization completed successfully")
                return True

        except Exception as e:
            logger.error(f"GraphCache initialization failed: {e}", exc_info=True)
            return False

    async def set(
        self,
        key: str,
        value: Any,
        cache_type: str = "index",
        ttl: Optional[int] = None,
    ) -> bool:
        """
        Set cache entry.

        Args:
            key: Cache key identifier
            value: Value to cache
            cache_type: Type of cached data
            ttl: Optional TTL override for this entry

        Returns:
            True if successfully cached, False otherwise
        """
        try:
            async with self._lock:
                cache_type_enum = CacheType(cache_type)
                entry_ttl = ttl or self.ttl

                # Calculate entry size
                try:
                    size_bytes = len(pickle.dumps(value))
                except Exception:
                    size_bytes = 0

                # Create cache entry
                entry = CacheEntry(
                    key=key,
                    value=value,
                    cache_type=cache_type_enum,
                    ttl_seconds=entry_ttl,
                    size_bytes=size_bytes,
                )

                # Handle size limit
                if self._should_evict():
                    await self._evict_lru()

                # Store in appropriate location(s)
                if self.strategy == CacheStrategy.IN_MEMORY:
                    self._memory_cache[key] = entry
                    self._memory_cache.move_to_end(key)

                elif self.strategy == CacheStrategy.DISK:
                    await self._save_to_disk(entry)

                elif self.strategy == CacheStrategy.HYBRID:
                    self._memory_cache[key] = entry
                    self._memory_cache.move_to_end(key)
                    await self._save_to_disk(entry)

                # Update statistics
                self._stats.total_entries = len(self._memory_cache)
                self._stats.total_size_bytes += size_bytes
                if cache_type in self._stats.cache_type_distribution:
                    self._stats.cache_type_distribution[cache_type] += 1
                else:
                    self._stats.cache_type_distribution[cache_type] = 1

                logger.debug(f"Cache set: key={key}, type={cache_type}, size={size_bytes}")
                return True

        except Exception as e:
            logger.error(f"Failed to set cache entry: {e}", exc_info=True)
            return False

    async def get(self, key: str) -> Optional[Any]:
        """
        Get cache entry.

        Args:
            key: Cache key identifier

        Returns:
            Cached value if found and not expired, None otherwise
        """
        try:
            async with self._lock:
                # Try memory cache first
                if key in self._memory_cache:
                    entry = self._memory_cache[key]

                    if entry.is_expired():
                        # Remove expired entry
                        del self._memory_cache[key]
                        self._stats.expired_count += 1
                        self._stats.miss_count += 1
                        logger.debug(f"Cache miss (expired): key={key}")
                        return None

                    # Update access information
                    entry.update_access_time()
                    self._memory_cache.move_to_end(key)
                    self._stats.hit_count += 1
                    logger.debug(f"Cache hit: key={key}")
                    return entry.value

                # Try disk cache if hybrid mode
                if self.strategy in [CacheStrategy.DISK, CacheStrategy.HYBRID]:
                    entry = await self._load_from_disk_by_key(key)
                    if entry:
                        if entry.is_expired():
                            # Remove expired entry
                            await self._delete_from_disk(key)
                            self._stats.expired_count += 1
                            self._stats.miss_count += 1
                            return None

                        # Store in memory for future access
                        if self.strategy == CacheStrategy.HYBRID:
                            self._memory_cache[key] = entry
                            self._memory_cache.move_to_end(key)

                        entry.update_access_time()
                        self._stats.hit_count += 1
                        logger.debug(f"Cache hit (disk): key={key}")
                        return entry.value

                self._stats.miss_count += 1
                logger.debug(f"Cache miss: key={key}")
                return None

        except Exception as e:
            logger.error(f"Failed to get cache entry: {e}", exc_info=True)
            self._stats.miss_count += 1
            return None

    async def delete(self, key: str) -> bool:
        """
        Delete cache entry.

        Args:
            key: Cache key identifier

        Returns:
            True if deletion successful, False otherwise
        """
        try:
            async with self._lock:
                # Delete from memory
                if key in self._memory_cache:
                    del self._memory_cache[key]

                # Delete from disk if applicable
                if self.strategy in [CacheStrategy.DISK, CacheStrategy.HYBRID]:
                    await self._delete_from_disk(key)

                logger.debug(f"Cache deleted: key={key}")
                return True

        except Exception as e:
            logger.error(f"Failed to delete cache entry: {e}", exc_info=True)
            return False

    async def clear(self) -> bool:
        """
        Clear all cache entries.

        Returns:
            True if successful, False otherwise
        """
        try:
            async with self._lock:
                self._memory_cache.clear()

                if self.strategy in [CacheStrategy.DISK, CacheStrategy.HYBRID]:
                    await self._clear_disk_cache()

                self._stats = CacheStats()
                logger.info("Cache cleared")
                return True

        except Exception as e:
            logger.error(f"Failed to clear cache: {e}", exc_info=True)
            return False

    async def build_cwe_graph(self, cwe_data: Dict[str, Any]) -> bool:
        """
        Build and cache CWE relationship graph.

        Args:
            cwe_data: CWE data dictionary

        Returns:
            True if successful, False otherwise
        """
        try:
            logger.info("Building CWE graph...")

            # Create graph structure
            cwe_graph = {
                "nodes": {},
                "edges": [],
                "metadata": {
                    "created_at": datetime.now().isoformat(),
                    "entry_count": len(cwe_data),
                },
            }

            # Build graph nodes and edges
            for cwe_id, cwe_info in cwe_data.items():
                cwe_graph["nodes"][cwe_id] = {
                    "id": cwe_id,
                    "name": cwe_info.get("name", ""),
                    "description": cwe_info.get("description", ""),
                    "severity": cwe_info.get("severity", "UNKNOWN"),
                }

                # Add parent relationships
                parent_ids = cwe_info.get("parent_cwe_ids", [])
                for parent_id in parent_ids:
                    cwe_graph["edges"].append({
                        "source": parent_id,
                        "target": cwe_id,
                        "type": "parent_of",
                    })

                # Add related relationships
                related_ids = cwe_info.get("related_cwe_ids", [])
                for related_id in related_ids:
                    cwe_graph["edges"].append({
                        "source": cwe_id,
                        "target": related_id,
                        "type": "related_to",
                    })

            # Cache the graph
            cache_key = "cwe_graph"
            success = await self.set(
                key=cache_key,
                value=cwe_graph,
                cache_type="cwe_graph",
            )

            if success:
                logger.info(
                    f"CWE graph built and cached: {len(cwe_graph['nodes'])} nodes, "
                    f"{len(cwe_graph['edges'])} edges"
                )

            return success

        except Exception as e:
            logger.error(f"Failed to build CWE graph: {e}", exc_info=True)
            return False

    async def build_cve_graph(self, cve_data: Dict[str, Any]) -> bool:
        """
        Build and cache CVE relationship graph.

        Args:
            cve_data: CVE data dictionary

        Returns:
            True if successful, False otherwise
        """
        try:
            logger.info("Building CVE graph...")

            # Create graph structure
            cve_graph = {
                "nodes": {},
                "edges": [],
                "metadata": {
                    "created_at": datetime.now().isoformat(),
                    "entry_count": len(cve_data),
                },
            }

            # Build graph nodes
            for cve_id, cve_info in cve_data.items():
                cve_graph["nodes"][cve_id] = {
                    "id": cve_id,
                    "title": cve_info.get("title", ""),
                    "description": cve_info.get("description", ""),
                    "severity": cve_info.get("severity", "UNKNOWN"),
                    "cvss_score": cve_info.get("cvss_v3_score", None),
                }

                # Add CWE relationships
                cwe_ids = cve_info.get("cwe_ids", [])
                for cwe_id in cwe_ids:
                    cve_graph["edges"].append({
                        "source": cve_id,
                        "target": cwe_id,
                        "type": "exploits",
                    })

            # Cache the graph
            cache_key = "cve_graph"
            success = await self.set(
                key=cache_key,
                value=cve_graph,
                cache_type="cve_graph",
            )

            if success:
                logger.info(
                    f"CVE graph built and cached: {len(cve_graph['nodes'])} nodes, "
                    f"{len(cve_graph['edges'])} edges"
                )

            return success

        except Exception as e:
            logger.error(f"Failed to build CVE graph: {e}", exc_info=True)
            return False

    def get_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics.

        Returns:
            Dictionary containing cache statistics
        """
        return self._stats.to_dict()

    # ==========================================================================
    # PRIVATE METHODS
    # ==========================================================================

    def _should_evict(self) -> bool:
        """Check if LRU eviction should occur"""
        return len(self._memory_cache) >= self.max_size

    async def _evict_lru(self) -> bool:
        """
        Evict least recently used entry from memory cache.

        Returns:
            True if eviction successful, False otherwise
        """
        try:
            if self._memory_cache:
                # Get least recently used item (first item in OrderedDict)
                key, entry = self._memory_cache.popitem(last=False)

                # Keep in disk cache if hybrid mode
                if self.strategy == CacheStrategy.HYBRID:
                    await self._save_to_disk(entry)

                self._stats.eviction_count += 1
                logger.debug(f"LRU eviction: key={key}")
                return True

            return False

        except Exception as e:
            logger.error(f"LRU eviction failed: {e}", exc_info=True)
            return False

    async def _save_to_disk(self, entry: CacheEntry) -> bool:
        """
        Save cache entry to disk asynchronously.

        Args:
            entry: Cache entry to save

        Returns:
            True if successful, False otherwise
        """
        try:
            cache_file = self.cache_dir / f"{entry.key}.pkl"

            # Run in thread pool to avoid blocking
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                self._thread_pool,
                _save_entry_to_file,
                cache_file,
                entry,
            )

            logger.debug(f"Saved to disk: {cache_file}")
            return True

        except Exception as e:
            logger.error(f"Failed to save to disk: {e}", exc_info=True)
            return False

    async def _load_from_disk(self) -> bool:
        """
        Load all cache entries from disk.

        Returns:
            True if successful, False otherwise
        """
        try:
            if not self.cache_dir.exists():
                return True

            cache_files = list(self.cache_dir.glob("*.pkl"))
            loaded_count = 0

            for cache_file in cache_files:
                try:
                    entry = await self._load_entry_from_file(cache_file)
                    if entry and not entry.is_expired():
                        self._memory_cache[entry.key] = entry
                        loaded_count += 1
                except Exception as e:
                    logger.warning(f"Failed to load cache file {cache_file}: {e}")

            if loaded_count > 0:
                logger.info(f"Loaded {loaded_count} entries from disk cache")

            return True

        except Exception as e:
            logger.error(f"Failed to load from disk: {e}", exc_info=True)
            return False

    async def _load_from_disk_by_key(self, key: str) -> Optional[CacheEntry]:
        """
        Load specific cache entry from disk.

        Args:
            key: Cache key to load

        Returns:
            CacheEntry if found, None otherwise
        """
        try:
            cache_file = self.cache_dir / f"{key}.pkl"

            if not cache_file.exists():
                return None

            return await self._load_entry_from_file(cache_file)

        except Exception as e:
            logger.error(f"Failed to load entry from disk: {e}", exc_info=True)
            return None

    async def _load_entry_from_file(self, cache_file: Path) -> Optional[CacheEntry]:
        """
        Load cache entry from file asynchronously.
        
        Args:
            cache_file: Path to cache file
            
        Returns:
            CacheEntry if successful, None otherwise
        """
        try:
            loop = asyncio.get_event_loop()
            entry = await loop.run_in_executor(
                self._thread_pool,
                _load_entry_from_file,
                cache_file,
            )
            return entry
        except Exception as e:
            logger.error(f"Failed to load entry: {e}", exc_info=True)
            return None

    async def _delete_from_disk(self, key: str) -> bool:
        """
        Delete cache entry from disk.

        Args:
            key: Cache key to delete

        Returns:
            True if successful, False otherwise
        """
        try:
            cache_file = self.cache_dir / f"{key}.pkl"

            if cache_file.exists():
                cache_file.unlink()
                logger.debug(f"Deleted from disk: {cache_file}")

            return True

        except Exception as e:
            logger.error(f"Failed to delete from disk: {e}", exc_info=True)
            return False

    async def _clear_disk_cache(self) -> bool:
        """
        Clear all disk cache files.

        Returns:
            True if successful, False otherwise
        """
        try:
            if self.cache_dir.exists():
                for cache_file in self.cache_dir.glob("*.pkl"):
                    cache_file.unlink()

            logger.info("Disk cache cleared")
            return True

        except Exception as e:
            logger.error(f"Failed to clear disk cache: {e}", exc_info=True)
            return False

    def __del__(self):
        """Cleanup thread pool on object destruction"""
        if hasattr(self, "_thread_pool"):
            self._thread_pool.shutdown(wait=False)


# ==============================================================================
# END OF MODULE
# ==============================================================================