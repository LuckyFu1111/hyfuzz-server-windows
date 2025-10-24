"""
CVE Repository Module for HyFuzz MCP Server

This module provides the CVERepository class for managing and querying CVE
(Common Vulnerabilities and Exposures) data. It handles data loading, caching,
searching, and retrieval operations.

Features:
- CVE data loading from JSON files and external sources
- Efficient caching with multiple strategies
- Full-text search capabilities
- Query by CVE ID, year, severity, and affected component
- Severity scoring and CVSS calculations
- Batch operations and bulk import/export
- Data validation and integrity checking
- Performance monitoring and statistics

Architecture:
- Data persistence with configurable backends
- Lazy loading for performance
- LRU caching for frequently accessed items
- Async support for I/O operations
- Comprehensive logging and error handling

Example Usage:
    >>> from src.knowledge.cve_repository import CVERepository
    >>> repo = CVERepository(cache_enabled=True)
    >>> cve = repo.get_cve("CVE-2023-12345")
    >>> results = repo.search("XSS", top_k=10)
    >>> severity = repo.get_severity("CVE-2023-12345")
    >>> stats = repo.get_stats()

Author: HyFuzz Team
Version: 1.0.0
Date: 2024-10-24
"""

import json
import logging
from typing import Dict, Any, Optional, List, Tuple, Set
from pathlib import Path
from datetime import datetime, timedelta
import pickle
import hashlib
from collections import defaultdict, OrderedDict
from dataclasses import dataclass, asdict, field
from enum import Enum
import re
import asyncio
from concurrent.futures import ThreadPoolExecutor

# ==============================================================================
# LOGGER SETUP
# ==============================================================================

logger = logging.getLogger(__name__)


# ==============================================================================
# ENUMERATIONS AND DATA CLASSES
# ==============================================================================


class SeverityLevel(str, Enum):
    """CVE severity levels"""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    UNKNOWN = "UNKNOWN"

    def __lt__(self, other):
        """Allow severity comparison"""
        severity_order = {
            "CRITICAL": 5,
            "HIGH": 4,
            "MEDIUM": 3,
            "LOW": 2,
            "INFO": 1,
            "UNKNOWN": 0,
        }
        return severity_order.get(self.value, 0) < severity_order.get(
            other.value, 0
        )

    def __gt__(self, other):
        """Allow severity comparison"""
        return not (self < other or self == other)

    def __le__(self, other):
        """Allow severity comparison"""
        return self < other or self == other

    def __ge__(self, other):
        """Allow severity comparison"""
        return self > other or self == other


@dataclass
class CVERecord:
    """CVE data record"""

    id: str  # e.g., "CVE-2023-12345"
    title: str
    description: str
    severity: str = "UNKNOWN"
    cvss_v3_score: Optional[float] = None
    cvss_v2_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    published_date: Optional[str] = None
    updated_date: Optional[str] = None
    affected_product: Optional[str] = None
    affected_versions: List[str] = field(default_factory=list)
    affected_component: Optional[str] = None
    cwe_ids: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    remediation: Optional[str] = None
    exploit_available: bool = False
    exploit_urls: List[str] = field(default_factory=list)
    attack_vector: Optional[str] = None
    attack_complexity: Optional[str] = None
    privileges_required: Optional[str] = None
    user_interaction: Optional[str] = None
    scope: Optional[str] = None
    confidentiality_impact: Optional[str] = None
    integrity_impact: Optional[str] = None
    availability_impact: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    last_modified: Optional[datetime] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CVERecord":
        """Create CVERecord from dictionary"""
        # Extract only valid fields
        valid_fields = {f.name for f in cls.__dataclass_fields__.values()}
        filtered_data = {k: v for k, v in data.items() if k in valid_fields}
        return cls(**filtered_data)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)

    def matches_query(self, query: str) -> bool:
        """Check if CVE record matches search query"""
        query_lower = query.lower()
        search_fields = [
            self.id,
            self.title,
            self.description,
            self.affected_product,
            self.affected_component,
            self.remediation,
        ]
        return any(
            query_lower in (field or "").lower() for field in search_fields
        )


# ==============================================================================
# CVE REPOSITORY CLASS
# ==============================================================================


class CVERepository:
    """
    CVE Repository - Manages and queries CVE data

    Provides comprehensive CVE data management including loading, caching,
    searching, and retrieval operations.

    Attributes:
        cache_enabled: Whether caching is enabled
        cache_dir: Directory for cache storage
        cve_data: In-memory CVE data storage
        index: Search index for fast lookups
        stats: Repository statistics
    """

    def __init__(
        self,
        cache_enabled: bool = True,
        cache_dir: Optional[Path] = None,
        data_file: Optional[Path] = None,
        max_cache_items: int = 10000,
    ):
        """
        Initialize CVE Repository

        Args:
            cache_enabled: Whether to use caching
            cache_dir: Directory for cache storage
            data_file: Path to CVE data file (JSON)
            max_cache_items: Maximum items to keep in cache
        """
        self.cache_enabled = cache_enabled
        self.cache_dir = cache_dir or Path.cwd() / "cache"
        self.data_file = data_file or Path(__file__).parent.parent.parent / "data" / "sample_cve.json"
        self.max_cache_items = max_cache_items

        # Data storage
        self.cve_data: Dict[str, CVERecord] = OrderedDict()
        self.index: Dict[str, List[str]] = defaultdict(list)
        self.severity_index: Dict[str, List[str]] = defaultdict(list)
        self.year_index: Dict[int, List[str]] = defaultdict(list)
        self.component_index: Dict[str, List[str]] = defaultdict(list)

        # Statistics
        self.stats = {
            "total_cves": 0,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "last_loaded": None,
            "last_updated": None,
            "load_time_ms": 0,
        }

        # Initialize cache directory
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        # Load data
        self._load_data()

    def _get_cache_path(self) -> Path:
        """Get path to cache file"""
        return self.cache_dir / "cve_data.pkl"

    def _get_index_path(self) -> Path:
        """Get path to index file"""
        return self.cache_dir / "cve_index.pkl"

    def _load_data(self) -> None:
        """Load CVE data from cache or file"""
        start_time = datetime.now()

        try:
            # Try to load from cache first
            if self.cache_enabled and self._load_from_cache():
                logger.info("CVE data loaded from cache")
                self.stats["last_loaded"] = datetime.now().isoformat()
                return

            # Load from file
            if self._load_from_file():
                logger.info("CVE data loaded from file")
                if self.cache_enabled:
                    self._save_cache()
                self.stats["last_loaded"] = datetime.now().isoformat()
            else:
                logger.warning("Failed to load CVE data from file")

        except Exception as e:
            logger.error(f"Error loading CVE data: {e}")
        finally:
            # Record load time
            load_time = (datetime.now() - start_time).total_seconds() * 1000
            self.stats["load_time_ms"] = round(load_time, 2)

    def _load_from_cache(self) -> bool:
        """Load CVE data from cache file"""
        try:
            cache_path = self._get_cache_path()
            index_path = self._get_index_path()

            if not cache_path.exists() or not index_path.exists():
                return False

            with open(cache_path, "rb") as f:
                self.cve_data = pickle.load(f)

            with open(index_path, "rb") as f:
                self.index = pickle.load(f)

            self._rebuild_indices()
            self._update_stats()
            return True

        except Exception as e:
            logger.error(f"Failed to load cache: {e}")
            return False

    def _load_from_file(self) -> bool:
        """Load CVE data from JSON file"""
        try:
            if not self.data_file.exists():
                logger.warning(f"Data file not found: {self.data_file}")
                return False

            with open(self.data_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            # Handle both list and dict formats
            if isinstance(data, list):
                cve_list = data
            elif isinstance(data, dict):
                cve_list = data.values()
            else:
                logger.error(f"Unexpected data format: {type(data)}")
                return False

            # Parse CVE records
            for cve_data in cve_list:
                if isinstance(cve_data, dict):
                    cve_id = cve_data.get("id")
                    if cve_id:
                        record = CVERecord.from_dict(cve_data)
                        self.cve_data[cve_id] = record

            self._rebuild_indices()
            self._update_stats()
            logger.info(f"Loaded {len(self.cve_data)} CVE records from file")
            return True

        except Exception as e:
            logger.error(f"Error loading from file: {e}")
            return False

    def _rebuild_indices(self) -> None:
        """Rebuild search indices"""
        self.index.clear()
        self.severity_index.clear()
        self.year_index.clear()
        self.component_index.clear()

        for cve_id, record in self.cve_data.items():
            # Severity index
            if record.severity:
                self.severity_index[record.severity].append(cve_id)

            # Year index
            if record.published_date:
                try:
                    year = int(cve_id.split("-")[1])
                    self.year_index[year].append(cve_id)
                except (ValueError, IndexError):
                    pass

            # Component index
            if record.affected_component:
                component_lower = record.affected_component.lower()
                self.component_index[component_lower].append(cve_id)

            # Full-text index (create searchable text)
            searchable_text = " ".join(
                filter(
                    None,
                    [
                        record.id,
                        record.title,
                        record.description,
                        record.affected_product,
                        record.affected_component,
                        " ".join(record.cwe_ids),
                        " ".join(record.tags),
                    ],
                )
            ).lower()

            # Store words in index
            words = set(re.findall(r"\b\w+\b", searchable_text))
            for word in words:
                self.index[word].append(cve_id)

    def _update_stats(self) -> None:
        """Update repository statistics"""
        self.stats["total_cves"] = len(self.cve_data)
        self.stats["critical_count"] = len(self.severity_index.get("CRITICAL", []))
        self.stats["high_count"] = len(self.severity_index.get("HIGH", []))
        self.stats["medium_count"] = len(self.severity_index.get("MEDIUM", []))
        self.stats["low_count"] = len(self.severity_index.get("LOW", []))
        self.stats["last_updated"] = datetime.now().isoformat()

    def _save_cache(self) -> None:
        """Save CVE data and index to cache"""
        try:
            cache_path = self._get_cache_path()
            index_path = self._get_index_path()

            with open(cache_path, "wb") as f:
                pickle.dump(self.cve_data, f)

            with open(index_path, "wb") as f:
                pickle.dump(self.index, f)

            logger.debug("CVE cache saved")

        except Exception as e:
            logger.error(f"Failed to save cache: {e}")

    # ======================================================================
    # PUBLIC METHODS
    # ======================================================================

    def get_cve(self, cve_id: str) -> Optional[CVERecord]:
        """
        Get CVE by ID

        Args:
            cve_id: CVE identifier (e.g., "CVE-2023-12345")

        Returns:
            CVERecord if found, None otherwise
        """
        cve_id = cve_id.upper()
        if cve_id in self.cve_data:
            return self.cve_data[cve_id]
        return None

    def search(
        self,
        query: str,
        top_k: int = 10,
        severity_filter: Optional[str] = None,
        year_filter: Optional[int] = None,
    ) -> List[CVERecord]:
        """
        Search CVEs by query string

        Args:
            query: Search query string
            top_k: Maximum number of results
            severity_filter: Filter by severity level
            year_filter: Filter by year

        Returns:
            List of matching CVE records
        """
        results = []
        query_lower = query.lower()

        # Get matching CVE IDs from index
        matching_ids = set()
        words = re.findall(r"\b\w+\b", query_lower)

        for word in words:
            matching_ids.update(self.index.get(word, []))

        # Also do direct text search
        for cve_id, record in self.cve_data.items():
            if record.matches_query(query):
                matching_ids.add(cve_id)

        # Apply filters
        filtered_ids = []
        for cve_id in matching_ids:
            record = self.cve_data[cve_id]

            # Severity filter
            if severity_filter and record.severity != severity_filter.upper():
                continue

            # Year filter
            if year_filter:
                try:
                    cve_year = int(cve_id.split("-")[1])
                    if cve_year != year_filter:
                        continue
                except (ValueError, IndexError):
                    pass

            filtered_ids.append(cve_id)

        # Sort by relevance and return top results
        sorted_ids = sorted(
            filtered_ids,
            key=lambda x: (
                -(self.cve_data[x].cvss_v3_score or 0),
                -len(self.cve_data[x].description or ""),
            ),
        )

        for cve_id in sorted_ids[:top_k]:
            results.append(self.cve_data[cve_id])

        return results

    def get_cves_by_year(self, year: int) -> List[CVERecord]:
        """
        Get all CVEs published in a specific year

        Args:
            year: Year to filter by

        Returns:
            List of CVE records
        """
        cve_ids = self.year_index.get(year, [])
        return [self.cve_data[cve_id] for cve_id in cve_ids]

    def get_cves_by_severity(
        self,
        severity: str,
        exact: bool = True,
    ) -> List[CVERecord]:
        """
        Get CVEs by severity level

        Args:
            severity: Severity level (e.g., "CRITICAL", "HIGH")
            exact: If False, return severity and above

        Returns:
            List of CVE records
        """
        results = []
        severity_upper = severity.upper()

        if exact:
            cve_ids = self.severity_index.get(severity_upper, [])
            results = [self.cve_data[cve_id] for cve_id in cve_ids]
        else:
            # Return severity and higher
            severity_levels = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
            if severity_upper in severity_levels:
                idx = severity_levels.index(severity_upper)
                for level in severity_levels[idx:]:
                    cve_ids = self.severity_index.get(level, [])
                    results.extend(
                        [self.cve_data[cve_id] for cve_id in cve_ids]
                    )

        return results

    def get_cves_by_component(self, component: str) -> List[CVERecord]:
        """
        Get CVEs affecting a specific component

        Args:
            component: Component name

        Returns:
            List of CVE records
        """
        component_lower = component.lower()
        cve_ids = self.component_index.get(component_lower, [])
        return [self.cve_data[cve_id] for cve_id in cve_ids]

    def get_cves_by_cwe(self, cwe_id: str) -> List[CVERecord]:
        """
        Get CVEs associated with a specific CWE

        Args:
            cwe_id: CWE identifier (e.g., "CWE-79")

        Returns:
            List of CVE records
        """
        results = []
        for record in self.cve_data.values():
            if cwe_id in record.cwe_ids:
                results.append(record)
        return results

    def get_severity(self, cve_id: str) -> Optional[float]:
        """
        Get CVSS v3 score for a CVE

        Args:
            cve_id: CVE identifier

        Returns:
            CVSS v3 score or None
        """
        record = self.get_cve(cve_id)
        if record:
            return record.cvss_v3_score
        return None

    def get_severity_level(self, cve_id: str) -> Optional[str]:
        """
        Get severity level for a CVE

        Args:
            cve_id: CVE identifier

        Returns:
            Severity level string or None
        """
        record = self.get_cve(cve_id)
        if record:
            return record.severity
        return None

    def get_total_count(self) -> int:
        """Get total number of CVEs in repository"""
        return len(self.cve_data)

    def get_stats(self) -> Dict[str, Any]:
        """Get repository statistics"""
        return self.stats.copy()

    def preload(self, force_refresh: bool = False) -> bool:
        """
        Preload CVE data

        Args:
            force_refresh: Force reload even if cached

        Returns:
            True if successful
        """
        if force_refresh:
            self.cve_data.clear()
            self.index.clear()
            self.severity_index.clear()
            self.year_index.clear()
            self.component_index.clear()

        self._load_data()
        return len(self.cve_data) > 0

    def validate(self) -> bool:
        """
        Validate data integrity

        Returns:
            True if validation passes
        """
        try:
            # Check if data is loaded
            if not self.cve_data:
                logger.warning("No CVE data loaded")
                return False

            # Check index consistency
            all_indexed_ids = set()
            for ids in self.index.values():
                all_indexed_ids.update(ids)

            if not all_indexed_ids:
                logger.warning("Index is empty")
                return False

            # Check for required fields
            for cve_id, record in self.cve_data.items():
                if not record.id or not record.title:
                    logger.warning(f"Invalid CVE record: {cve_id}")
                    return False

            logger.info("CVE data validation passed")
            return True

        except Exception as e:
            logger.error(f"Validation error: {e}")
            return False

    def clear_cache(self) -> None:
        """Clear cache files"""
        try:
            cache_path = self._get_cache_path()
            index_path = self._get_index_path()

            if cache_path.exists():
                cache_path.unlink()
            if index_path.exists():
                index_path.unlink()

            logger.info("CVE cache cleared")

        except Exception as e:
            logger.error(f"Error clearing cache: {e}")

    def clear_data(self) -> None:
        """Clear all CVE data"""
        self.cve_data.clear()
        self.index.clear()
        self.severity_index.clear()
        self.year_index.clear()
        self.component_index.clear()
        self.clear_cache()
        logger.info("CVE data cleared")

    def get_related_cves(
        self,
        cve_id: str,
        max_results: int = 10,
    ) -> List[Tuple[CVERecord, float]]:
        """
        Get CVEs related to a given CVE

        Args:
            cve_id: CVE identifier
            max_results: Maximum number of results

        Returns:
            List of tuples (CVERecord, relevance_score)
        """
        source_cve = self.get_cve(cve_id)
        if not source_cve:
            return []

        results = []
        for other_cve_id, other_cve in self.cve_data.items():
            if other_cve_id == cve_id:
                continue

            # Calculate relevance score
            score = 0.0

            # Same CWE
            common_cwes = set(source_cve.cwe_ids) & set(other_cve.cwe_ids)
            score += len(common_cwes) * 0.3

            # Same severity
            if source_cve.severity == other_cve.severity:
                score += 0.2

            # Same product
            if (
                source_cve.affected_product
                and source_cve.affected_product == other_cve.affected_product
            ):
                score += 0.3

            # Same year
            try:
                source_year = int(cve_id.split("-")[1])
                other_year = int(other_cve_id.split("-")[1])
                if source_year == other_year:
                    score += 0.2
            except (ValueError, IndexError):
                pass

            if score > 0:
                results.append((other_cve, score))

        # Sort by relevance and return top results
        results.sort(key=lambda x: x[1], reverse=True)
        return results[:max_results]

    def export_to_json(self, output_path: Path) -> bool:
        """
        Export CVE data to JSON file

        Args:
            output_path: Path to output file

        Returns:
            True if successful
        """
        try:
            data = [record.to_dict() for record in self.cve_data.values()]
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, default=str)
            logger.info(f"Exported {len(data)} CVEs to {output_path}")
            return True
        except Exception as e:
            logger.error(f"Export error: {e}")
            return False

    def import_from_json(self, input_path: Path, merge: bool = False) -> int:
        """
        Import CVE data from JSON file

        Args:
            input_path: Path to input file
            merge: If True, merge with existing data; if False, replace

        Returns:
            Number of CVEs imported
        """
        try:
            if not merge:
                self.cve_data.clear()

            with open(input_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            count = 0
            if isinstance(data, list):
                for cve_data in data:
                    if isinstance(cve_data, dict):
                        cve_id = cve_data.get("id")
                        if cve_id:
                            record = CVERecord.from_dict(cve_data)
                            self.cve_data[cve_id] = record
                            count += 1

            self._rebuild_indices()
            self._update_stats()
            logger.info(f"Imported {count} CVEs from {input_path}")
            return count

        except Exception as e:
            logger.error(f"Import error: {e}")
            return 0

    def get_affected_versions(self, cve_id: str) -> List[str]:
        """
        Get affected versions for a CVE

        Args:
            cve_id: CVE identifier

        Returns:
            List of affected versions
        """
        record = self.get_cve(cve_id)
        if record:
            return record.affected_versions
        return []

    def is_critical(self, cve_id: str) -> bool:
        """
        Check if CVE has critical severity

        Args:
            cve_id: CVE identifier

        Returns:
            True if critical severity
        """
        record = self.get_cve(cve_id)
        if record:
            return record.severity == "CRITICAL"
        return False

    def has_exploit(self, cve_id: str) -> bool:
        """
        Check if CVE has known exploit

        Args:
            cve_id: CVE identifier

        Returns:
            True if exploit available
        """
        record = self.get_cve(cve_id)
        if record:
            return record.exploit_available
        return False


# ==============================================================================
# END OF MODULE
# ==============================================================================