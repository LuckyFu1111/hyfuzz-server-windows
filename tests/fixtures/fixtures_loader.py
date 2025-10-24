"""
HyFuzz MCP Server - Test Fixtures Loader

This module provides comprehensive fixture loading and management for the test suite.
It handles loading test data from JSON/YAML files, managing fixture lifecycle,
caching, and integration with pytest.

Key Features:
- Load test data from JSON and YAML files
- Manage fixture lifecycle (setup, teardown)
- Cache loaded fixtures for performance
- Automatic discovery of fixture files
- Support for multiple data formats
- Comprehensive error handling and logging
- Integration with pytest fixtures

Usage:
    >>> from tests.fixtures.fixtures_loader import FixturesLoader
    >>> 
    >>> # Create loader
    >>> loader = FixturesLoader()
    >>> 
    >>> # Load all fixtures
    >>> fixtures = loader.load_all()
    >>> 
    >>> # Load specific fixture
    >>> cwe_data = loader.load("cwe")
    >>> 
    >>> # Clear cache
    >>> loader.clear_cache()

Author: HyFuzz Team
Version: 1.0.0
"""

import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timezone
import hashlib

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


# Initialize logger
logger = logging.getLogger(__name__)


# ==============================================================================
# Constants & Paths
# ==============================================================================

FIXTURES_DIR = Path(__file__).parent
PROJECT_ROOT = FIXTURES_DIR.parent.parent
DATA_DIR = FIXTURES_DIR / "data"

# Default fixture paths
FIXTURE_PATHS = {
    "cwe": DATA_DIR / "sample_cwe.json",
    "cve": DATA_DIR / "sample_cve.json",
    "payloads": DATA_DIR / "sample_payloads.json",
    "targets": DATA_DIR / "sample_targets.json",
    "requests": DATA_DIR / "sample_requests.json",
    "responses": DATA_DIR / "expected_responses.json",
    "vulnerabilities": DATA_DIR / "sample_vulnerabilities.json",
    "llm_responses": DATA_DIR / "llm_responses.json",
}


# ==============================================================================
# Enumerations
# ==============================================================================

class FileFormat(str, Enum):
    """Supported file formats for test data."""
    JSON = "json"
    YAML = "yaml"
    YML = "yml"


# ==============================================================================
# Data Classes
# ==============================================================================

@dataclass
class FixtureMetadata:
    """Metadata for loaded fixture."""
    name: str
    path: Path
    format: FileFormat
    loaded_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    size_bytes: int = 0
    checksum: Optional[str] = None
    entry_count: int = 0
    cached: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "path": str(self.path),
            "format": self.format.value,
            "loaded_at": self.loaded_at,
            "size_bytes": self.size_bytes,
            "checksum": self.checksum,
            "entry_count": self.entry_count,
            "cached": self.cached,
        }


@dataclass
class CachedFixture:
    """Cached fixture data."""
    metadata: FixtureMetadata
    data: Dict[str, Any]
    access_count: int = 0
    last_accessed: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def update_access(self) -> None:
        """Update access information."""
        self.access_count += 1
        self.last_accessed = datetime.now(timezone.utc).isoformat()


# ==============================================================================
# Fixtures Loader
# ==============================================================================

class FixturesLoader:
    """
    Comprehensive fixture loader and manager for the test suite.
    
    Handles loading, caching, and lifecycle management of test fixtures.
    Supports JSON and YAML formats with automatic discovery.
    """

    def __init__(
        self,
        fixtures_dir: Optional[Path] = None,
        enable_cache: bool = True,
        cache_size_limit: int = 100,
    ):
        """
        Initialize fixtures loader.
        
        Args:
            fixtures_dir: Directory containing fixture files (default: FIXTURES_DIR)
            enable_cache: Whether to cache loaded fixtures
            cache_size_limit: Maximum number of fixtures to cache
        """
        self.fixtures_dir = fixtures_dir or FIXTURES_DIR
        self.data_dir = self.fixtures_dir / "data"
        self.enable_cache = enable_cache
        self.cache_size_limit = cache_size_limit

        # Cache management
        self.cache: Dict[str, CachedFixture] = {}
        self.cache_hits = 0
        self.cache_misses = 0

        # Fixture discovery
        self.discovered_fixtures: Dict[str, Path] = {}
        self._discover_fixtures()

        logger.info(
            f"FixturesLoader initialized: "
            f"fixtures_dir={self.fixtures_dir}, "
            f"caching={'enabled' if enable_cache else 'disabled'}"
        )

    # ========================================================================
    # Discovery & Registration
    # ========================================================================

    def _discover_fixtures(self) -> None:
        """Discover all available fixture files."""
        if not self.data_dir.exists():
            logger.warning(f"Data directory not found: {self.data_dir}")
            return

        # Discover JSON files
        for json_file in self.data_dir.glob("*.json"):
            fixture_name = json_file.stem
            self.discovered_fixtures[fixture_name] = json_file

        # Discover YAML files if available
        if YAML_AVAILABLE:
            for yaml_file in self.data_dir.glob("*.yaml"):
                fixture_name = yaml_file.stem
                self.discovered_fixtures[fixture_name] = yaml_file

            for yml_file in self.data_dir.glob("*.yml"):
                fixture_name = yml_file.stem
                self.discovered_fixtures[fixture_name] = yml_file

        logger.debug(f"Discovered {len(self.discovered_fixtures)} fixture files")

    def register_fixture(self, name: str, path: Path) -> None:
        """
        Register a custom fixture location.
        
        Args:
            name: Fixture identifier
            path: Path to fixture file
            
        Raises:
            FileNotFoundError: If path doesn't exist
        """
        if not path.exists():
            raise FileNotFoundError(f"Fixture file not found: {path}")

        self.discovered_fixtures[name] = path
        logger.debug(f"Registered fixture: {name} -> {path}")

    def get_fixture_path(self, name: str) -> Optional[Path]:
        """
        Get path for a fixture by name.
        
        Args:
            name: Fixture identifier
            
        Returns:
            Path to fixture file or None if not found
        """
        # Check custom paths first
        if name in FIXTURE_PATHS and FIXTURE_PATHS[name].exists():
            return FIXTURE_PATHS[name]

        # Check discovered fixtures
        if name in self.discovered_fixtures:
            return self.discovered_fixtures[name]

        return None

    # ========================================================================
    # Loading & Caching
    # ========================================================================

    def load(
        self,
        name: str,
        use_cache: Optional[bool] = None,
        force_reload: bool = False,
    ) -> Dict[str, Any]:
        """
        Load a fixture by name.
        
        Args:
            name: Fixture identifier
            use_cache: Override cache setting (default: use instance setting)
            force_reload: Force reload even if cached
            
        Returns:
            Loaded fixture data
            
        Raises:
            FileNotFoundError: If fixture not found
            ValueError: If fixture format not supported
            
        Example:
            >>> loader = FixturesLoader()
            >>> cwe_data = loader.load("cwe")
            >>> assert "CWE-79" in cwe_data
        """
        # Determine cache preference
        use_cache_val = use_cache if use_cache is not None else self.enable_cache

        # Check cache first
        if use_cache_val and not force_reload and name in self.cache:
            self.cache_hits += 1
            cached = self.cache[name]
            cached.update_access()
            logger.debug(f"Cache hit for fixture: {name}")
            return cached.data

        # Load from file
        path = self.get_fixture_path(name)
        if not path:
            raise FileNotFoundError(f"Fixture not found: {name}")

        data = self._load_file(path)

        # Cache result
        if use_cache_val:
            self._cache_fixture(name, path, data)

        self.cache_misses += 1
        logger.debug(f"Loaded fixture: {name} from {path}")

        return data

    def load_all(
        self,
        use_cache: bool = True,
        exclude: Optional[Set[str]] = None,
    ) -> Dict[str, Dict[str, Any]]:
        """
        Load all discovered fixtures.
        
        Args:
            use_cache: Whether to use cache
            exclude: Set of fixture names to exclude
            
        Returns:
            Dictionary mapping fixture names to data
            
        Example:
            >>> loader = FixturesLoader()
            >>> all_fixtures = loader.load_all(exclude={"slow_fixture"})
            >>> assert "cwe" in all_fixtures
        """
        exclude = exclude or set()
        results: Dict[str, Dict[str, Any]] = {}

        for name in self.discovered_fixtures:
            if name in exclude:
                logger.debug(f"Skipping excluded fixture: {name}")
                continue

            try:
                results[name] = self.load(name, use_cache=use_cache)
            except Exception as e:
                logger.warning(f"Failed to load fixture '{name}': {e}")

        logger.info(f"Loaded {len(results)} fixtures")
        return results

    def _load_file(self, path: Path) -> Dict[str, Any]:
        """
        Load data from file.
        
        Args:
            path: Path to file
            
        Returns:
            Loaded data
            
        Raises:
            ValueError: If format not supported
        """
        suffix = path.suffix.lower()

        if suffix == ".json":
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)

        elif suffix in [".yaml", ".yml"]:
            if not YAML_AVAILABLE:
                raise ValueError("YAML support requires pyyaml package")

            with open(path, "r", encoding="utf-8") as f:
                loaded = yaml.safe_load(f)
                return loaded if loaded else {}

        else:
            raise ValueError(f"Unsupported file format: {suffix}")

    def _cache_fixture(
        self,
        name: str,
        path: Path,
        data: Dict[str, Any],
    ) -> None:
        """
        Cache a loaded fixture.
        
        Args:
            name: Fixture identifier
            path: Path to fixture file
            data: Loaded data
        """
        # Evict old entries if cache is full
        if len(self.cache) >= self.cache_size_limit:
            self._evict_cache_entry()

        # Create metadata
        metadata = FixtureMetadata(
            name=name,
            path=path,
            format=self._detect_format(path),
            size_bytes=path.stat().st_size,
            checksum=self._calculate_checksum(path),
            entry_count=len(data),
            cached=True,
        )

        # Cache the fixture
        self.cache[name] = CachedFixture(metadata=metadata, data=data)
        logger.debug(f"Cached fixture: {name}")

    def _evict_cache_entry(self) -> None:
        """Evict least recently used cache entry."""
        if not self.cache:
            return

        # Find least recently accessed entry
        lru_entry = min(
            self.cache.items(),
            key=lambda x: x[1].last_accessed
        )
        name, _ = lru_entry
        del self.cache[name]
        logger.debug(f"Evicted cache entry: {name}")

    # ========================================================================
    # Cache Management
    # ========================================================================

    def clear_cache(self) -> None:
        """Clear all cached fixtures."""
        count = len(self.cache)
        self.cache.clear()
        logger.info(f"Cleared cache: {count} entries removed")

    def remove_from_cache(self, name: str) -> bool:
        """
        Remove specific fixture from cache.
        
        Args:
            name: Fixture identifier
            
        Returns:
            True if removed, False if not found
        """
        if name in self.cache:
            del self.cache[name]
            logger.debug(f"Removed from cache: {name}")
            return True
        return False

    def get_cache_info(self) -> Dict[str, Any]:
        """
        Get cache statistics and information.
        
        Returns:
            Dictionary containing cache info
            
        Example:
            >>> loader = FixturesLoader()
            >>> _ = loader.load("cwe")
            >>> info = loader.get_cache_info()
            >>> assert info["cached_count"] == 1
        """
        total_requests = self.cache_hits + self.cache_misses
        hit_rate = (
            (self.cache_hits / total_requests * 100) if total_requests > 0 else 0
        )

        return {
            "cached_count": len(self.cache),
            "cache_limit": self.cache_size_limit,
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "hit_rate_percent": round(hit_rate, 2),
            "cached_fixtures": list(self.cache.keys()),
            "total_cached_size_bytes": sum(
                entry.metadata.size_bytes for entry in self.cache.values()
            ),
        }

    # ========================================================================
    # Utility Methods
    # ========================================================================

    def _detect_format(self, path: Path) -> FileFormat:
        """Detect file format from path."""
        suffix = path.suffix.lower()
        if suffix == ".json":
            return FileFormat.JSON
        elif suffix == ".yaml":
            return FileFormat.YAML
        elif suffix == ".yml":
            return FileFormat.YML
        else:
            return FileFormat.JSON

    @staticmethod
    def _calculate_checksum(path: Path) -> str:
        """Calculate MD5 checksum of file."""
        hash_md5 = hashlib.md5()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()

    def validate_fixture(self, name: str) -> Tuple[bool, List[str]]:
        """
        Validate a fixture file.
        
        Args:
            name: Fixture identifier
            
        Returns:
            Tuple of (is_valid, list of errors)
            
        Example:
            >>> loader = FixturesLoader()
            >>> valid, errors = loader.validate_fixture("cwe")
            >>> if not valid:
            ...     print("Errors:", errors)
        """
        errors: List[str] = []

        try:
            path = self.get_fixture_path(name)
            if not path:
                errors.append(f"Fixture not found: {name}")
                return False, errors

            if not path.exists():
                errors.append(f"File does not exist: {path}")
                return False, errors

            # Try to load
            data = self._load_file(path)

            # Basic validation
            if not isinstance(data, dict):
                errors.append("Fixture data is not a dictionary")
            elif not data:
                errors.append("Fixture data is empty")

            return len(errors) == 0, errors

        except Exception as e:
            errors.append(f"Load error: {str(e)}")
            return False, errors

    def validate_all(self) -> Dict[str, Tuple[bool, List[str]]]:
        """
        Validate all discovered fixtures.
        
        Returns:
            Dictionary mapping fixture names to validation results
        """
        results: Dict[str, Tuple[bool, List[str]]] = {}
        for name in self.discovered_fixtures:
            results[name] = self.validate_fixture(name)
        return results

    def get_discovery_info(self) -> Dict[str, Any]:
        """
        Get information about discovered fixtures.
        
        Returns:
            Dictionary containing discovery info
        """
        return {
            "fixtures_dir": str(self.fixtures_dir),
            "data_dir": str(self.data_dir),
            "discovered_count": len(self.discovered_fixtures),
            "discovered_fixtures": {
                name: str(path) for name, path in self.discovered_fixtures.items()
            },
            "registered_count": len(FIXTURE_PATHS),
            "data_dir_exists": self.data_dir.exists(),
        }

    def get_all_info(self) -> Dict[str, Any]:
        """
        Get comprehensive information about loader state.
        
        Returns:
            Dictionary containing all relevant information
        """
        return {
            "loader_config": {
                "fixtures_dir": str(self.fixtures_dir),
                "caching_enabled": self.enable_cache,
                "cache_size_limit": self.cache_size_limit,
            },
            "discovery": self.get_discovery_info(),
            "cache": self.get_cache_info(),
        }


# ==============================================================================
# Fixture Context Manager
# ==============================================================================

class FixtureContext:
    """Context manager for fixture loading and cleanup."""

    def __init__(
        self,
        loader: Optional[FixturesLoader] = None,
        fixtures_to_load: Optional[List[str]] = None,
    ):
        """
        Initialize fixture context.
        
        Args:
            loader: FixturesLoader instance (creates new if None)
            fixtures_to_load: List of fixture names to load
        """
        self.loader = loader or FixturesLoader()
        self.fixtures_to_load = fixtures_to_load or []
        self.loaded_fixtures: Dict[str, Dict[str, Any]] = {}

    def __enter__(self) -> Dict[str, Dict[str, Any]]:
        """Load fixtures on entry."""
        if self.fixtures_to_load:
            for name in self.fixtures_to_load:
                try:
                    self.loaded_fixtures[name] = self.loader.load(name)
                except Exception as e:
                    logger.error(f"Failed to load fixture '{name}': {e}")

        return self.loaded_fixtures

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Cleanup on exit."""
        self.loader.clear_cache()
        logger.debug("Fixture context exited, cache cleared")


# ==============================================================================
# Standalone Helper Functions
# ==============================================================================

def create_loader(
    enable_cache: bool = True,
    cache_size_limit: int = 100,
) -> FixturesLoader:
    """
    Create and return a FixturesLoader instance.
    
    Args:
        enable_cache: Enable fixture caching
        cache_size_limit: Maximum cache size
        
    Returns:
        FixturesLoader instance
    """
    return FixturesLoader(
        enable_cache=enable_cache,
        cache_size_limit=cache_size_limit,
    )


def load_fixture(name: str, use_cache: bool = True) -> Dict[str, Any]:
    """
    Load a single fixture using default loader.
    
    Args:
        name: Fixture identifier
        use_cache: Use cache
        
    Returns:
        Loaded fixture data
        
    Example:
        >>> cwe_data = load_fixture("cwe")
    """
    loader = FixturesLoader()
    return loader.load(name, use_cache=use_cache)


def load_all_fixtures(use_cache: bool = True) -> Dict[str, Dict[str, Any]]:
    """
    Load all fixtures using default loader.
    
    Args:
        use_cache: Use cache
        
    Returns:
        Dictionary of all loaded fixtures
    """
    loader = FixturesLoader()
    return loader.load_all(use_cache=use_cache)


# ==============================================================================
# Pytest Integration
# ==============================================================================

try:
    import pytest

    @pytest.fixture(scope="session")  # type: ignore
    def fixtures_loader():
        """Session-scoped fixture for FixturesLoader."""
        return FixturesLoader()

    @pytest.fixture  # type: ignore
    def fixture_context(fixtures_loader):
        """Fixture context for loading and cleanup."""
        return FixtureContext(fixtures_loader)

    @pytest.fixture  # type: ignore
    def cwe_fixtures(fixtures_loader):
        """Load CWE fixtures."""
        return fixtures_loader.load("cwe")

    @pytest.fixture  # type: ignore
    def cve_fixtures(fixtures_loader):
        """Load CVE fixtures."""
        return fixtures_loader.load("cve")

    @pytest.fixture  # type: ignore
    def payload_fixtures(fixtures_loader):
        """Load payload fixtures."""
        return fixtures_loader.load("payloads")

except ImportError:
    logger.debug("pytest not available, skipping pytest fixtures")


# ==============================================================================
# Exports
# ==============================================================================

__all__ = [
    # Main Classes
    "FixturesLoader",
    "FixtureContext",
    "FixtureMetadata",
    "CachedFixture",

    # Enumerations
    "FileFormat",

    # Helper Functions
    "create_loader",
    "load_fixture",
    "load_all_fixtures",

    # Constants
    "FIXTURES_DIR",
    "DATA_DIR",
    "FIXTURE_PATHS",
]