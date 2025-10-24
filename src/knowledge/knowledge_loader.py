"""
Knowledge Loader Module for HyFuzz MCP Server

This module provides the KnowledgeLoader class for loading and managing
CWE and CVE data from various sources. It handles data loading, validation,
caching, and integration with knowledge base components.

Features:
- Load CWE and CVE data from JSON files and external sources
- Async data loading with progress tracking
- Data validation and integrity checking
- Cache management and persistence
- Graph building and indexing
- Lazy loading for performance
- Error handling and recovery
- Comprehensive logging and statistics

Architecture:
- Data source abstraction supporting multiple formats
- Pluggable data providers for extensibility
- Efficient indexing for quick lookups
- Integration with graph cache for relationship management
- Statistics tracking for performance monitoring

Example Usage:
     loader = KnowledgeLoader(data_dir="./data", cache_dir="./cache")
     await loader.initialize()
     cwe_data = await loader.load_cwe_data()
     cve_data = await loader.load_cve_data()
     stats = loader.get_statistics()

Author: HyFuzz Team
Version: 1.0.0
Date: 2025
"""

import asyncio
import json
import logging
import pickle
from typing import Dict, Any, Optional, List, Tuple, Set
from pathlib import Path
from datetime import datetime, timedelta
from dataclasses import dataclass, field, asdict
from enum import Enum
import hashlib
from concurrent.futures import ThreadPoolExecutor
import time

# ==============================================================================
# LOGGER SETUP
# ==============================================================================

logger = logging.getLogger(__name__)


# ==============================================================================
# ENUMERATIONS
# ==============================================================================


class DataSourceType(str, Enum):
    """Data source type enumeration"""

    JSON_FILE = "json_file"
    EXTERNAL_API = "external_api"
    DATABASE = "database"
    HYBRID = "hybrid"

    def __str__(self):
        return self.value


class LoadingStatus(str, Enum):
    """Loading status enumeration"""

    IDLE = "idle"
    LOADING = "loading"
    LOADED = "loaded"
    CACHED = "cached"
    FAILED = "failed"

    def __str__(self):
        return self.value


# ==============================================================================
# DATA CLASSES
# ==============================================================================


@dataclass
class LoadingStats:
    """Statistics for data loading operations"""

    total_entries: int = 0
    loaded_entries: int = 0
    failed_entries: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    loading_time_seconds: float = 0.0
    data_size_bytes: int = 0
    indexed_entries: int = 0
    validation_errors: int = 0

    @property
    def success_rate(self) -> float:
        """Calculate success rate"""
        if self.total_entries == 0:
            return 0.0
        return (self.loaded_entries / self.total_entries) * 100

    @property
    def cache_hit_rate(self) -> float:
        """Calculate cache hit rate"""
        total_accesses = self.cache_hits + self.cache_misses
        return (self.cache_hits / total_accesses * 100) if total_accesses > 0 else 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert stats to dictionary"""
        return {
            "total_entries": self.total_entries,
            "loaded_entries": self.loaded_entries,
            "failed_entries": self.failed_entries,
            "success_rate": f"{self.success_rate:.2f}%",
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "cache_hit_rate": f"{self.cache_hit_rate:.2f}%",
            "loading_time_seconds": f"{self.loading_time_seconds:.2f}",
            "data_size_bytes": self.data_size_bytes,
            "indexed_entries": self.indexed_entries,
            "validation_errors": self.validation_errors,
        }


@dataclass
class LoadingProgress:
    """Progress tracking for data loading"""

    total: int = 0
    current: int = 0
    status: LoadingStatus = LoadingStatus.IDLE
    current_item: str = ""
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    errors: List[str] = field(default_factory=list)

    @property
    def percentage(self) -> float:
        """Calculate completion percentage"""
        return (self.current / self.total * 100) if self.total > 0 else 0.0

    @property
    def elapsed_seconds(self) -> float:
        """Get elapsed time in seconds"""
        if self.start_time is None:
            return 0.0
        end = self.end_time or datetime.now()
        return (end - self.start_time).total_seconds()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "total": self.total,
            "current": self.current,
            "percentage": f"{self.percentage:.2f}%",
            "status": self.status.value,
            "current_item": self.current_item,
            "elapsed_seconds": f"{self.elapsed_seconds:.2f}",
            "errors": self.errors,
        }


# ==============================================================================
# UTILITY FUNCTIONS
# ==============================================================================


def _load_json_file(file_path: Path) -> Optional[Dict[str, Any]]:
    """
    Synchronously load JSON file.

    Args:
        file_path: Path to JSON file

    Returns:
        Loaded JSON data or None
    """
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Failed to load JSON file {file_path}: {e}")
        return None


def _save_json_file(file_path: Path, data: Dict[str, Any]) -> bool:
    """
    Synchronously save JSON file.

    Args:
        file_path: Path to JSON file
        data: Data to save

    Returns:
        True if successful, False otherwise
    """
    try:
        file_path.parent.mkdir(parents=True, exist_ok=True)
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return True
    except Exception as e:
        logger.error(f"Failed to save JSON file {file_path}: {e}")
        return False


# ==============================================================================
# KNOWLEDGE LOADER CLASS
# ==============================================================================


class KnowledgeLoader:
    """
    Knowledge loader for managing CWE and CVE data loading.

    This class provides a unified interface for loading knowledge base data
    from multiple sources, with support for caching, validation, and indexing.

    Attributes:
        data_dir: Directory containing knowledge data files
        cache_dir: Directory for caching loaded data
        is_initialized: Whether loader has been initialized
        cwe_data: Loaded CWE data dictionary
        cve_data: Loaded CVE data dictionary
    """

    def __init__(
            self,
            data_dir: Optional[Path] = None,
            cache_dir: Optional[Path] = None,
            enable_cache: bool = True,
            enable_indexing: bool = True,
    ):
        """
        Initialize knowledge loader.

        Args:
            data_dir: Directory containing data files
            cache_dir: Directory for cache storage
            enable_cache: Enable caching functionality
            enable_indexing: Enable data indexing
        """
        self.data_dir = Path(data_dir) if data_dir else Path.cwd() / "data"
        self.cache_dir = Path(cache_dir) if cache_dir else Path.cwd() / "cache"
        self.enable_cache = enable_cache
        self.enable_indexing = enable_indexing

        # Data storage
        self.cwe_data: Dict[str, Any] = {}
        self.cve_data: Dict[str, Any] = {}

        # Indexing structures
        self._cwe_index: Dict[str, List[str]] = {}  # For quick lookups
        self._cve_index: Dict[str, List[str]] = {}

        # Status tracking
        self.is_initialized = False
        self.load_time: Optional[datetime] = None
        self._progress = LoadingProgress()
        self._stats = LoadingStats()

        # Thread pool for I/O operations
        self._thread_pool = ThreadPoolExecutor(max_workers=4)
        self._lock = asyncio.Lock()

        logger.info(
            f"KnowledgeLoader initialized with data_dir={self.data_dir}, "
            f"cache_dir={self.cache_dir}"
        )

    async def initialize(self) -> bool:
        """
        Initialize knowledge loader.

        Creates necessary directories and loads cache if available.

        Returns:
            True if initialization successful, False otherwise
        """
        try:
            async with self._lock:
                # Create directories
                self.data_dir.mkdir(parents=True, exist_ok=True)
                if self.enable_cache:
                    self.cache_dir.mkdir(parents=True, exist_ok=True)

                logger.info(f"KnowledgeLoader directories created")

                # Try to load from cache
                if self.enable_cache:
                    cache_loaded = await self._load_from_cache()
                    if cache_loaded:
                        self._stats.cache_hits += 1
                        self.is_initialized = True
                        logger.info("Knowledge data loaded from cache")
                        return True

                self._stats.cache_misses += 1
                self.is_initialized = True
                logger.info("KnowledgeLoader initialization completed")
                return True

        except Exception as e:
            logger.error(f"KnowledgeLoader initialization failed: {e}", exc_info=True)
            return False

    async def load_cwe_data(
            self,
            force_reload: bool = False,
    ) -> Dict[str, Any]:
        """
        Load CWE data from sources.

        Args:
            force_reload: Force reload even if cached

        Returns:
            Dictionary of CWE data
        """
        try:
            async with self._lock:
                if self.cwe_data and not force_reload:
                    logger.debug("Using cached CWE data")
                    return self.cwe_data

                start_time = time.time()
                self._progress.status = LoadingStatus.LOADING
                self._progress.start_time = datetime.now()

                logger.info("Loading CWE data...")

                # Try loading from cache first
                if self.enable_cache and not force_reload:
                    cached_data = await self._load_cwe_from_cache()
                    if cached_data:
                        self.cwe_data = cached_data
                        self._stats.cache_hits += 1
                        self._progress.status = LoadingStatus.CACHED
                        logger.info(f"Loaded {len(self.cwe_data)} CWE entries from cache")
                        return self.cwe_data

                # Load from JSON file
                cwe_file = self.data_dir / "sample_cwe.json"
                if cwe_file.exists():
                    loop = asyncio.get_event_loop()
                    self.cwe_data = await loop.run_in_executor(
                        self._thread_pool,
                        _load_json_file,
                        cwe_file,
                    )

                    if not self.cwe_data:
                        self.cwe_data = {}

                    # Build index if enabled
                    if self.enable_indexing:
                        await self._build_cwe_index()

                    # Cache data if enabled
                    if self.enable_cache:
                        await self._save_cwe_to_cache()

                    # Update statistics
                    loading_time = time.time() - start_time
                    self._stats.total_entries += len(self.cwe_data)
                    self._stats.loaded_entries += len(self.cwe_data)
                    self._stats.loading_time_seconds += loading_time
                    self._progress.status = LoadingStatus.LOADED

                    logger.info(
                        f"Loaded {len(self.cwe_data)} CWE entries in {loading_time:.2f}s"
                    )

                return self.cwe_data

        except Exception as e:
            logger.error(f"Failed to load CWE data: {e}", exc_info=True)
            self._progress.status = LoadingStatus.FAILED
            self._progress.errors.append(str(e))
            return {}

    async def load_cve_data(
            self,
            force_reload: bool = False,
    ) -> Dict[str, Any]:
        """
        Load CVE data from sources.

        Args:
            force_reload: Force reload even if cached

        Returns:
            Dictionary of CVE data
        """
        try:
            async with self._lock:
                if self.cve_data and not force_reload:
                    logger.debug("Using cached CVE data")
                    return self.cve_data

                start_time = time.time()
                self._progress.status = LoadingStatus.LOADING
                self._progress.start_time = datetime.now()

                logger.info("Loading CVE data...")

                # Try loading from cache first
                if self.enable_cache and not force_reload:
                    cached_data = await self._load_cve_from_cache()
                    if cached_data:
                        self.cve_data = cached_data
                        self._stats.cache_hits += 1
                        self._progress.status = LoadingStatus.CACHED
                        logger.info(f"Loaded {len(self.cve_data)} CVE entries from cache")
                        return self.cve_data

                # Load from JSON file
                cve_file = self.data_dir / "sample_cve.json"
                if cve_file.exists():
                    loop = asyncio.get_event_loop()
                    self.cve_data = await loop.run_in_executor(
                        self._thread_pool,
                        _load_json_file,
                        cve_file,
                    )

                    if not self.cve_data:
                        self.cve_data = {}

                    # Build index if enabled
                    if self.enable_indexing:
                        await self._build_cve_index()

                    # Cache data if enabled
                    if self.enable_cache:
                        await self._save_cve_to_cache()

                    # Update statistics
                    loading_time = time.time() - start_time
                    self._stats.total_entries += len(self.cve_data)
                    self._stats.loaded_entries += len(self.cve_data)
                    self._stats.loading_time_seconds += loading_time
                    self._progress.status = LoadingStatus.LOADED

                    logger.info(
                        f"Loaded {len(self.cve_data)} CVE entries in {loading_time:.2f}s"
                    )

                return self.cve_data

        except Exception as e:
            logger.error(f"Failed to load CVE data: {e}", exc_info=True)
            self._progress.status = LoadingStatus.FAILED
            self._progress.errors.append(str(e))
            return {}

    async def preload_all(self, force_reload: bool = False) -> bool:
        """
        Preload all knowledge data.

        Args:
            force_reload: Force reload even if cached

        Returns:
            True if successful, False otherwise
        """
        try:
            logger.info("Preloading all knowledge data...")

            # Load CWE data
            cwe_result = await self.load_cwe_data(force_reload=force_reload)
            if not cwe_result:
                logger.warning("Failed to load CWE data during preload")

            # Load CVE data
            cve_result = await self.load_cve_data(force_reload=force_reload)
            if not cve_result:
                logger.warning("Failed to load CVE data during preload")

            self.load_time = datetime.now()
            logger.info(f"Preload completed: {len(cwe_result)} CWE, {len(cve_result)} CVE")
            return bool(cwe_result and cve_result)

        except Exception as e:
            logger.error(f"Preload failed: {e}", exc_info=True)
            return False

    def get_cwe_by_id(self, cwe_id: str) -> Optional[Dict[str, Any]]:
        """
        Get CWE entry by ID.

        Args:
            cwe_id: CWE identifier (e.g., "CWE-79")

        Returns:
            CWE data if found, None otherwise
        """
        return self.cwe_data.get(cwe_id)

    def get_cve_by_id(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Get CVE entry by ID.

        Args:
            cve_id: CVE identifier (e.g., "CVE-2021-1234")

        Returns:
            CVE data if found, None otherwise
        """
        return self.cve_data.get(cve_id)

    def search_cwe(self, query: str, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Search CWE data by query.

        Args:
            query: Search query
            limit: Maximum results to return

        Returns:
            List of matching CWE entries
        """
        try:
            results = []
            query_lower = query.lower()

            for cwe_id, cwe_info in self.cwe_data.items():
                if (query_lower in cwe_id.lower() or
                        query_lower in cwe_info.get("name", "").lower() or
                        query_lower in cwe_info.get("description", "").lower()):
                    results.append(cwe_info)
                    if len(results) >= limit:
                        break

            return results

        except Exception as e:
            logger.error(f"CWE search failed: {e}", exc_info=True)
            return []

    def search_cve(self, query: str, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Search CVE data by query.

        Args:
            query: Search query
            limit: Maximum results to return

        Returns:
            List of matching CVE entries
        """
        try:
            results = []
            query_lower = query.lower()

            for cve_id, cve_info in self.cve_data.items():
                if (query_lower in cve_id.lower() or
                        query_lower in cve_info.get("title", "").lower() or
                        query_lower in cve_info.get("description", "").lower()):
                    results.append(cve_info)
                    if len(results) >= limit:
                        break

            return results

        except Exception as e:
            logger.error(f"CVE search failed: {e}", exc_info=True)
            return []

    async def clear_cache(self) -> bool:
        """
        Clear all cached data.

        Returns:
            True if successful, False otherwise
        """
        try:
            async with self._lock:
                if not self.enable_cache:
                    return True

                cwe_cache_file = self.cache_dir / "cwe_data.pkl"
                cve_cache_file = self.cache_dir / "cve_data.pkl"

                if cwe_cache_file.exists():
                    cwe_cache_file.unlink()
                if cve_cache_file.exists():
                    cve_cache_file.unlink()

                logger.info("Cache cleared successfully")
                return True

        except Exception as e:
            logger.error(f"Failed to clear cache: {e}", exc_info=True)
            return False

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get loading statistics.

        Returns:
            Dictionary containing statistics
        """
        return self._stats.to_dict()

    def get_progress(self) -> Dict[str, Any]:
        """
        Get loading progress.

        Returns:
            Dictionary containing progress information
        """
        return self._progress.to_dict()

    # ==========================================================================
    # PRIVATE METHODS
    # ==========================================================================

    async def _build_cwe_index(self):
        """Build index for CWE data for faster lookups"""
        try:
            self._cwe_index.clear()

            for cwe_id, cwe_info in self.cwe_data.items():
                # Index by severity
                severity = cwe_info.get("severity", "UNKNOWN")
                if severity not in self._cwe_index:
                    self._cwe_index[severity] = []
                self._cwe_index[severity].append(cwe_id)

            logger.debug(f"Built CWE index with {len(self._cwe_index)} categories")
            self._stats.indexed_entries += len(self.cwe_data)

        except Exception as e:
            logger.error(f"Failed to build CWE index: {e}", exc_info=True)

    async def _build_cve_index(self):
        """Build index for CVE data for faster lookups"""
        try:
            self._cve_index.clear()

            for cve_id, cve_info in self.cve_data.items():
                # Index by severity
                severity = cve_info.get("severity", "UNKNOWN")
                if severity not in self._cve_index:
                    self._cve_index[severity] = []
                self._cve_index[severity].append(cve_id)

            logger.debug(f"Built CVE index with {len(self._cve_index)} categories")
            self._stats.indexed_entries += len(self.cve_data)

        except Exception as e:
            logger.error(f"Failed to build CVE index: {e}", exc_info=True)

    async def _load_from_cache(self) -> bool:
        """
        Load all data from cache.

        Returns:
            True if cache exists and is valid, False otherwise
        """
        try:
            cwe_cached = await self._load_cwe_from_cache()
            cve_cached = await self._load_cve_from_cache()

            if cwe_cached and cve_cached:
                self.cwe_data = cwe_cached
                self.cve_data = cve_cached
                return True

            return False

        except Exception as e:
            logger.error(f"Failed to load from cache: {e}", exc_info=True)
            return False

    async def _load_cwe_from_cache(self) -> Optional[Dict[str, Any]]:
        """Load CWE data from cache"""
        try:
            cache_file = self.cache_dir / "cwe_data.pkl"
            if not cache_file.exists():
                return None

            loop = asyncio.get_event_loop()
            data = await loop.run_in_executor(
                self._thread_pool,
                self._load_pkl_file,
                cache_file,
            )
            return data

        except Exception as e:
            logger.debug(f"Failed to load CWE from cache: {e}")
            return None

    async def _load_cve_from_cache(self) -> Optional[Dict[str, Any]]:
        """Load CVE data from cache"""
        try:
            cache_file = self.cache_dir / "cve_data.pkl"
            if not cache_file.exists():
                return None

            loop = asyncio.get_event_loop()
            data = await loop.run_in_executor(
                self._thread_pool,
                self._load_pkl_file,
                cache_file,
            )
            return data

        except Exception as e:
            logger.debug(f"Failed to load CVE from cache: {e}")
            return None

    async def _save_cwe_to_cache(self) -> bool:
        """Save CWE data to cache"""
        try:
            cache_file = self.cache_dir / "cwe_data.pkl"
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                self._thread_pool,
                self._save_pkl_file,
                cache_file,
                self.cwe_data,
            )
            logger.debug(f"CWE data cached to {cache_file}")
            return True

        except Exception as e:
            logger.error(f"Failed to save CWE to cache: {e}", exc_info=True)
            return False

    async def _save_cve_to_cache(self) -> bool:
        """Save CVE data to cache"""
        try:
            cache_file = self.cache_dir / "cve_data.pkl"
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                self._thread_pool,
                self._save_pkl_file,
                cache_file,
                self.cve_data,
            )
            logger.debug(f"CVE data cached to {cache_file}")
            return True

        except Exception as e:
            logger.error(f"Failed to save CVE to cache: {e}", exc_info=True)
            return False

    @staticmethod
    def _load_pkl_file(file_path: Path) -> Optional[Dict[str, Any]]:
        """Synchronously load pickle file"""
        try:
            with open(file_path, "rb") as f:
                return pickle.load(f)
        except Exception as e:
            logger.error(f"Failed to load pickle file {file_path}: {e}")
            return None

    @staticmethod
    def _save_pkl_file(file_path: Path, data: Dict[str, Any]) -> bool:
        """Synchronously save pickle file"""
        try:
            file_path.parent.mkdir(parents=True, exist_ok=True)
            with open(file_path, "wb") as f:
                pickle.dump(data, f)
            return True
        except Exception as e:
            logger.error(f"Failed to save pickle file {file_path}: {e}")
            return False

    def __del__(self):
        """Cleanup thread pool on object destruction"""
        if hasattr(self, "_thread_pool"):
            self._thread_pool.shutdown(wait=False)

# ==============================================================================
# END OF MODULE
# ==============================================================================