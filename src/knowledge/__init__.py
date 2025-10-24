"""
Knowledge Module for HyFuzz MCP Server

This module provides centralized management for vulnerability knowledge bases,
including CWE (Common Weakness Enumeration), CVE (Common Vulnerabilities and Exposures),
and semantic graph structures for intelligent vulnerability analysis.

Features:
- CWE and CVE repository management with caching
- Graph-based knowledge representation for protocol vulnerabilities
- Semantic vector embeddings for similarity-based retrieval
- Efficient knowledge loading and persistence
- Integration with LLM services for context-augmented prompting
- Memory-efficient caching strategies

Architecture:
- KnowledgeLoader: Central entry point for loading vulnerability knowledge
- GraphCache: In-memory caching for graph structures (CWE/CVE relationships)
- CWERepository: Management and querying of CWE entries
- CVERepository: Management and querying of CVE entries
- VulnerabilityDB: Unified interface for vulnerability data access
- Utils: Helper functions for knowledge processing

Example Usage:
    >>> from src.knowledge import KnowledgeManager
    >>> km = KnowledgeManager()
    >>> cwe_data = km.get_cwe(79)  # XSS vulnerability
    >>> similar_cves = km.find_similar_vulnerabilities(cve_id="CVE-2023-12345")
    >>> kb_graph = km.get_knowledge_graph()
"""

import os
import sys
import logging
from typing import Dict, Any, Optional, List, Set, Tuple
from pathlib import Path
from enum import Enum

# ==============================================================================
# VERSION AND METADATA
# ==============================================================================

__version__ = "1.0.0"
__author__ = "HyFuzz Team"
__description__ = "Knowledge management module for HyFuzz MCP Server"
__package__ = "hyfuzz.knowledge"

# ==============================================================================
# PATHS AND CONFIGURATION
# ==============================================================================

# Get the directory paths
MODULE_DIR = Path(__file__).parent
PROJECT_ROOT = MODULE_DIR.parent.parent
DATA_DIR = PROJECT_ROOT / "data"
KNOWLEDGE_CACHE_DIR = DATA_DIR / "knowledge_cache"
TEST_DATA_DIR = DATA_DIR / "test_data"

# Ensure cache directory exists
KNOWLEDGE_CACHE_DIR.mkdir(parents=True, exist_ok=True)

# ==============================================================================
# LOGGER SETUP
# ==============================================================================

logger = logging.getLogger(__name__)


# ==============================================================================
# ENUMERATIONS
# ==============================================================================


class KnowledgeSourceType(str, Enum):
    """Enumeration of knowledge source types"""

    CWE = "cwe"
    CVE = "cve"
    CAPEC = "capec"  # Common Attack Pattern Enumeration and Classification
    PROTOCOL = "protocol"
    CUSTOM = "custom"

    def __str__(self):
        return self.value


class VulnerabilityType(str, Enum):
    """Enumeration of vulnerability types"""

    WEAKNESS = "weakness"
    VULNERABILITY = "vulnerability"
    EXPOSURE = "exposure"
    ATTACK_PATTERN = "attack_pattern"

    def __str__(self):
        return self.value


class CacheStrategy(str, Enum):
    """Caching strategy enumeration"""

    IN_MEMORY = "in_memory"
    DISK = "disk"
    HYBRID = "hybrid"
    NONE = "none"

    def __str__(self):
        return self.value


# ==============================================================================
# LAZY IMPORTS - Core Classes
# ==============================================================================

_imported_classes = {}


def _lazy_import_knowledge_loader():
    """Lazy import KnowledgeLoader"""
    if "KnowledgeLoader" not in _imported_classes:
        from .knowledge_loader import KnowledgeLoader

        _imported_classes["KnowledgeLoader"] = KnowledgeLoader
    return _imported_classes["KnowledgeLoader"]


def _lazy_import_graph_cache():
    """Lazy import GraphCache"""
    if "GraphCache" not in _imported_classes:
        from .graph_cache import GraphCache

        _imported_classes["GraphCache"] = GraphCache
    return _imported_classes["GraphCache"]


def _lazy_import_cwe_repository():
    """Lazy import CWERepository"""
    if "CWERepository" not in _imported_classes:
        from .cwe_repository import CWERepository

        _imported_classes["CWERepository"] = CWERepository
    return _imported_classes["CWERepository"]


def _lazy_import_cve_repository():
    """Lazy import CVERepository"""
    if "CVERepository" not in _imported_classes:
        from .cve_repository import CVERepository

        _imported_classes["CVERepository"] = CVERepository
    return _imported_classes["CVERepository"]


def _lazy_import_vulnerability_db():
    """Lazy import VulnerabilityDB"""
    if "VulnerabilityDB" not in _imported_classes:
        from .vulnerability_db import VulnerabilityDB

        _imported_classes["VulnerabilityDB"] = VulnerabilityDB
    return _imported_classes["VulnerabilityDB"]


# ==============================================================================
# PROPERTY-BASED ACCESS TO LAZY IMPORTS
# ==============================================================================


def __getattr__(name):
    """Lazy loading of knowledge module components"""

    lazy_imports = {
        "KnowledgeLoader": _lazy_import_knowledge_loader,
        "GraphCache": _lazy_import_graph_cache,
        "CWERepository": _lazy_import_cwe_repository,
        "CVERepository": _lazy_import_cve_repository,
        "VulnerabilityDB": _lazy_import_vulnerability_db,
    }

    if name in lazy_imports:
        return lazy_imports[name]()

    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")


# ==============================================================================
# EAGERLY IMPORTED ITEMS FOR CONVENIENCE
# ==============================================================================

# These are imported at module initialization for immediate access
__all__ = [
    # Version and metadata
    "__version__",
    "__author__",
    "__description__",
    "__package__",
    # Core classes
    "KnowledgeLoader",
    "GraphCache",
    "CWERepository",
    "CVERepository",
    "VulnerabilityDB",
    # Enumerations
    "KnowledgeSourceType",
    "VulnerabilityType",
    "CacheStrategy",
    # Factory functions
    "create_knowledge_manager",
    "create_cwe_repository",
    "create_cve_repository",
    "create_vulnerability_db",
    "create_graph_cache",
    # Utility functions
    "initialize_knowledge_module",
    "preload_knowledge_cache",
    "get_knowledge_stats",
    "validate_knowledge_data",
    "clear_knowledge_cache",
    # Paths and constants
    "KNOWLEDGE_CACHE_DIR",
    "TEST_DATA_DIR",
    "DATA_DIR",
    # Helpers
    "is_knowledge_module_ready",
    "get_default_knowledge_config",
]

# ==============================================================================
# FACTORY FUNCTIONS
# ==============================================================================


def create_knowledge_manager(
    cache_strategy: str = "hybrid",
    preload: bool = False,
    config: Optional[Dict[str, Any]] = None,
) -> "VulnerabilityDB":
    """
    Factory function to create a unified knowledge manager.

    Args:
        cache_strategy: Caching strategy ("in_memory", "disk", "hybrid", "none")
        preload: Whether to preload knowledge data on initialization
        config: Additional configuration dictionary

    Returns:
        VulnerabilityDB: Initialized knowledge manager instance

    Example:
        >>> kb = create_knowledge_manager(cache_strategy="hybrid", preload=True)
        >>> cwe = kb.get_cwe(79)
    """
    config = config or {}
    config.update({"cache_strategy": cache_strategy, "preload": preload})

    VulnerabilityDB_class = _lazy_import_vulnerability_db()
    return VulnerabilityDB_class(**config)


def create_cwe_repository(
    cache_enabled: bool = True,
    cache_dir: Optional[Path] = None,
) -> "CWERepository":
    """
    Factory function to create a CWE repository.

    Args:
        cache_enabled: Whether to enable caching
        cache_dir: Custom cache directory path

    Returns:
        CWERepository: Initialized CWE repository instance
    """
    if cache_dir is None:
        cache_dir = KNOWLEDGE_CACHE_DIR

    CWERepository_class = _lazy_import_cwe_repository()
    return CWERepository_class(cache_enabled=cache_enabled, cache_dir=cache_dir)


def create_cve_repository(
    cache_enabled: bool = True,
    cache_dir: Optional[Path] = None,
) -> "CVERepository":
    """
    Factory function to create a CVE repository.

    Args:
        cache_enabled: Whether to enable caching
        cache_dir: Custom cache directory path

    Returns:
        CVERepository: Initialized CVE repository instance
    """
    if cache_dir is None:
        cache_dir = KNOWLEDGE_CACHE_DIR

    CVERepository_class = _lazy_import_cve_repository()
    return CVERepository_class(cache_enabled=cache_enabled, cache_dir=cache_dir)


def create_graph_cache(
    cache_strategy: str = "in_memory",
    max_size: int = 10000,
    ttl: Optional[int] = None,
) -> "GraphCache":
    """
    Factory function to create a graph cache.

    Args:
        cache_strategy: Caching strategy
        max_size: Maximum number of cached items
        ttl: Time-to-live for cache entries (in seconds)

    Returns:
        GraphCache: Initialized graph cache instance
    """
    GraphCache_class = _lazy_import_graph_cache()
    return GraphCache_class(
        strategy=cache_strategy,
        max_size=max_size,
        ttl=ttl,
    )


def create_vulnerability_db(
    config: Optional[Dict[str, Any]] = None,
) -> "VulnerabilityDB":
    """
    Factory function to create a vulnerability database.

    Args:
        config: Configuration dictionary

    Returns:
        VulnerabilityDB: Initialized vulnerability database instance
    """
    config = config or {}
    VulnerabilityDB_class = _lazy_import_vulnerability_db()
    return VulnerabilityDB_class(**config)


# ==============================================================================
# UTILITY FUNCTIONS
# ==============================================================================


def initialize_knowledge_module(config: Optional[Dict[str, Any]] = None) -> bool:
    """
    Initialize the knowledge module with configuration.

    Args:
        config: Configuration dictionary

    Returns:
        bool: True if initialization successful, False otherwise

    Example:
        >>> config = {"cache_strategy": "hybrid", "preload": True}
        >>> initialize_knowledge_module(config)
        True
    """
    try:
        config = config or get_default_knowledge_config()

        # Ensure cache directories exist
        KNOWLEDGE_CACHE_DIR.mkdir(parents=True, exist_ok=True)
        TEST_DATA_DIR.mkdir(parents=True, exist_ok=True)

        logger.info(
            f"Knowledge module initialized with config: {config}",
        )
        return True

    except Exception as e:
        logger.error(f"Failed to initialize knowledge module: {e}")
        return False


def preload_knowledge_cache(
    force_refresh: bool = False,
    include_cwe: bool = True,
    include_cve: bool = True,
) -> Dict[str, bool]:
    """
    Preload knowledge cache from data sources.

    Args:
        force_refresh: Force refresh of cache even if exists
        include_cwe: Whether to preload CWE data
        include_cve: Whether to preload CVE data

    Returns:
        Dict[str, bool]: Status of each preload operation

    Example:
        >>> result = preload_knowledge_cache(force_refresh=True)
        >>> print(result)
        {'cwe_preload': True, 'cve_preload': True}
    """
    result = {}

    try:
        if include_cwe:
            try:
                cwe_repo = create_cwe_repository()
                cwe_repo.preload(force_refresh=force_refresh)
                result["cwe_preload"] = True
                logger.info("CWE data preloaded successfully")
            except Exception as e:
                logger.warning(f"CWE preload failed: {e}")
                result["cwe_preload"] = False

        if include_cve:
            try:
                cve_repo = create_cve_repository()
                cve_repo.preload(force_refresh=force_refresh)
                result["cve_preload"] = True
                logger.info("CVE data preloaded successfully")
            except Exception as e:
                logger.warning(f"CVE preload failed: {e}")
                result["cve_preload"] = False

        return result

    except Exception as e:
        logger.error(f"Preload knowledge cache failed: {e}")
        return {
            "cwe_preload": False,
            "cve_preload": False,
            "error": str(e),
        }


def get_knowledge_stats() -> Dict[str, Any]:
    """
    Get statistics about the knowledge base.

    Returns:
        Dict[str, Any]: Statistics including counts, cache sizes, etc.

    Example:
        >>> stats = get_knowledge_stats()
        >>> print(stats['cwe_count'])
        1234
    """
    try:
        stats = {
            "cwe_count": 0,
            "cve_count": 0,
            "cache_size_mb": 0,
            "last_update": None,
            "status": "unknown",
        }

        cwe_repo = create_cwe_repository()
        cve_repo = create_cve_repository()

        stats["cwe_count"] = cwe_repo.get_total_count()
        stats["cve_count"] = cve_repo.get_total_count()

        # Calculate cache size
        cache_size = 0
        if KNOWLEDGE_CACHE_DIR.exists():
            for file in KNOWLEDGE_CACHE_DIR.rglob("*"):
                if file.is_file():
                    cache_size += file.stat().st_size
        stats["cache_size_mb"] = round(cache_size / (1024 * 1024), 2)

        stats["status"] = "ready"
        logger.info(f"Knowledge statistics: {stats}")
        return stats

    except Exception as e:
        logger.error(f"Failed to get knowledge stats: {e}")
        return {
            "status": "error",
            "error": str(e),
        }


def validate_knowledge_data() -> bool:
    """
    Validate integrity of knowledge data.

    Returns:
        bool: True if validation passes, False otherwise

    Example:
        >>> is_valid = validate_knowledge_data()
    """
    try:
        logger.info("Validating knowledge data...")

        # Validate CWE data
        cwe_repo = create_cwe_repository()
        if not cwe_repo.validate():
            logger.warning("CWE data validation failed")
            return False

        # Validate CVE data
        cve_repo = create_cve_repository()
        if not cve_repo.validate():
            logger.warning("CVE data validation failed")
            return False

        logger.info("Knowledge data validation passed")
        return True

    except Exception as e:
        logger.error(f"Knowledge data validation error: {e}")
        return False


def clear_knowledge_cache(include_cwe: bool = True, include_cve: bool = True) -> bool:
    """
    Clear knowledge cache.

    Args:
        include_cwe: Clear CWE cache
        include_cve: Clear CVE cache

    Returns:
        bool: True if cleared successfully

    Example:
        >>> clear_knowledge_cache()
        True
    """
    try:
        if include_cwe:
            cwe_repo = create_cwe_repository()
            cwe_repo.clear_cache()
            logger.info("CWE cache cleared")

        if include_cve:
            cve_repo = create_cve_repository()
            cve_repo.clear_cache()
            logger.info("CVE cache cleared")

        return True

    except Exception as e:
        logger.error(f"Failed to clear knowledge cache: {e}")
        return False


def is_knowledge_module_ready() -> bool:
    """
    Check if knowledge module is ready for use.

    Returns:
        bool: True if module is ready, False otherwise

    Example:
        >>> if is_knowledge_module_ready():
        ...     kb = create_knowledge_manager()
    """
    try:
        # Check if required directories exist
        if not DATA_DIR.exists() or not KNOWLEDGE_CACHE_DIR.exists():
            logger.warning("Required directories not found")
            return False

        # Try to create and use a knowledge manager
        kb = create_knowledge_manager()
        return kb is not None

    except Exception as e:
        logger.warning(f"Knowledge module readiness check failed: {e}")
        return False


def get_default_knowledge_config() -> Dict[str, Any]:
    """
    Get default configuration for knowledge module.

    Returns:
        Dict[str, Any]: Default configuration dictionary
    """
    return {
        "cache_strategy": "hybrid",
        "cache_dir": str(KNOWLEDGE_CACHE_DIR),
        "data_dir": str(DATA_DIR),
        "max_cache_size": 10000,
        "cache_ttl": 3600,  # 1 hour
        "preload": False,
        "validate_on_startup": True,
        "enable_logging": True,
        "log_level": "INFO",
    }


# ==============================================================================
# MODULE INITIALIZATION
# ==============================================================================


def _initialize_module():
    """Initialize knowledge module at import time"""
    try:
        # Create necessary directories
        KNOWLEDGE_CACHE_DIR.mkdir(parents=True, exist_ok=True)
        TEST_DATA_DIR.mkdir(parents=True, exist_ok=True)

        logger.debug(
            f"Knowledge module initialized - "
            f"Cache dir: {KNOWLEDGE_CACHE_DIR}, "
            f"Data dir: {DATA_DIR}"
        )

    except Exception as e:
        logger.warning(f"Knowledge module initialization warning: {e}")


# ==============================================================================
# MODULE-LEVEL METADATA
# ==============================================================================

__meta__ = {
    "name": "knowledge",
    "version": __version__,
    "description": __description__,
    "author": __author__,
    "python_requires": ">=3.9",
    "module_dir": str(MODULE_DIR),
    "cache_dir": str(KNOWLEDGE_CACHE_DIR),
    "data_dir": str(DATA_DIR),
    "capabilities": [
        "CWE management",
        "CVE management",
        "Graph-based knowledge representation",
        "Semantic similarity retrieval",
        "Efficient caching",
        "Vulnerability analysis support",
    ],
}

# ==============================================================================
# INITIALIZATION HOOK
# ==============================================================================

# Initialize module when imported
_initialize_module()


# ==============================================================================
# ADDITIONAL CONVENIENCE ALIASES
# ==============================================================================

# Shorter aliases for common factory functions
KnowledgeDB = create_knowledge_manager
CWERepo = create_cwe_repository
CVERepo = create_cve_repository
KBGraph = create_graph_cache

# Re-export these for convenience
__all__.extend(["KnowledgeDB", "CWERepo", "CVERepo", "KBGraph"])

# ==============================================================================
# END OF MODULE
# ==============================================================================