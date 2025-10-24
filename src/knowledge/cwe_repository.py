"""
CWE Repository Module for HyFuzz MCP Server

This module provides the CWERepository class for managing and querying CWE
(Common Weakness Enumeration) data. It handles data loading, caching,
searching, and retrieval operations for vulnerability weaknesses.

Features:
- CWE data loading from JSON files and external sources
- Efficient caching with multiple strategies
- Full-text search capabilities
- Query by CWE ID, category, severity, and attack type
- Weakness hierarchy and parent-child relationships
- Related CVE tracking and association
- Remediation and guidance retrieval
- CAPEC attack pattern mapping
- Technology and protocol classification
- Data validation and integrity checking
- Performance monitoring and statistics

Architecture:
- Data persistence with configurable backends
- Lazy loading for performance
- LRU caching for frequently accessed items
- Hierarchical index for parent-child relationships
- Comprehensive logging and error handling

Example Usage:
    >>> from src.knowledge.cwe_repository import CWERepository
    >>> repo = CWERepository(cache_enabled=True)
    >>> cwe = repo.get_cwe(79)  # Cross-Site Scripting (XSS)
    >>> results = repo.search("injection", top_k=10)
    >>> parent = repo.get_parent_cwe(79)
    >>> children = repo.get_child_cwes(116)
    >>> stats = repo.get_stats()

Author: HyFuzz Team
Version: 1.0.0
Date: 2024-10-24
"""

import json
import logging
from typing import Dict, Any, Optional, List, Tuple, Set
from pathlib import Path
from datetime import datetime
import pickle
from collections import defaultdict, OrderedDict
from dataclasses import dataclass, asdict, field
from enum import Enum
import re

# ==============================================================================
# LOGGER SETUP
# ==============================================================================

logger = logging.getLogger(__name__)


# ==============================================================================
# ENUMERATIONS AND DATA CLASSES
# ==============================================================================


class CWEType(str, Enum):
    """CWE classification types"""

    WEAKNESS = "Weakness"
    CATEGORY = "Category"
    PILLAR = "Pillar"
    COMPOUND = "Compound"

    def __str__(self):
        return self.value


class SeverityLevel(str, Enum):
    """CWE severity/impact levels"""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"

    def __lt__(self, other):
        """Allow severity comparison"""
        severity_order = {
            "CRITICAL": 5,
            "HIGH": 4,
            "MEDIUM": 3,
            "LOW": 2,
            "UNKNOWN": 0,
        }
        return severity_order.get(self.value, 0) < severity_order.get(
            other.value, 0
        )


@dataclass
class CWERecord:
    """CWE weakness record"""

    id: int  # e.g., 79 (for CWE-79)
    name: str
    type: str = "Weakness"  # Weakness, Category, Pillar, Compound
    description: str = ""
    extended_description: Optional[str] = None
    severity: str = "UNKNOWN"
    likelihood_of_exploitation: Optional[str] = None
    affected_technologies: List[str] = field(default_factory=list)
    affected_protocols: List[str] = field(default_factory=list)
    affected_platforms: List[str] = field(default_factory=list)
    common_consequences: List[str] = field(default_factory=list)
    cvss_v3_score: Optional[float] = None
    parent_cwe_ids: List[int] = field(default_factory=list)
    child_cwe_ids: List[int] = field(default_factory=list)
    related_cwe_ids: List[int] = field(default_factory=list)
    capec_ids: List[str] = field(default_factory=list)
    related_cve_count: int = 0
    remediation_strategies: List[str] = field(default_factory=list)
    detection_methods: List[str] = field(default_factory=list)
    example_payloads: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    last_modified: Optional[datetime] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CWERecord":
        """Create CWERecord from dictionary"""
        valid_fields = {f.name for f in cls.__dataclass_fields__.values()}
        filtered_data = {k: v for k, v in data.items() if k in valid_fields}
        return cls(**filtered_data)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)

    def matches_query(self, query: str) -> bool:
        """Check if CWE record matches search query"""
        query_lower = query.lower()
        search_fields = [
            self.name,
            self.description,
            self.extended_description,
            " ".join(self.affected_technologies),
            " ".join(self.affected_protocols),
            " ".join(self.common_consequences),
            " ".join(self.tags),
        ]
        return any(
            query_lower in (field or "").lower() for field in search_fields
        )


# ==============================================================================
# CWE REPOSITORY CLASS
# ==============================================================================


class CWERepository:
    """
    CWE Repository - Manages and queries CWE weakness data

    Provides comprehensive CWE data management including loading, caching,
    searching, and retrieval operations with support for hierarchical
    relationships and related data.

    Attributes:
        cache_enabled: Whether caching is enabled
        cache_dir: Directory for cache storage
        cwe_data: In-memory CWE data storage
        index: Search index for fast lookups
        hierarchy_index: Parent-child relationships
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
        Initialize CWE Repository

        Args:
            cache_enabled: Whether to use caching
            cache_dir: Directory for cache storage
            data_file: Path to CWE data file (JSON)
            max_cache_items: Maximum items to keep in cache
        """
        self.cache_enabled = cache_enabled
        self.cache_dir = cache_dir or Path.cwd() / "cache"
        self.data_file = data_file or Path(__file__).parent.parent.parent / "data" / "sample_cwe.json"
        self.max_cache_items = max_cache_items

        # Data storage
        self.cwe_data: Dict[int, CWERecord] = OrderedDict()
        self.index: Dict[str, List[int]] = defaultdict(list)
        self.severity_index: Dict[str, List[int]] = defaultdict(list)
        self.technology_index: Dict[str, List[int]] = defaultdict(list)
        self.protocol_index: Dict[str, List[int]] = defaultdict(list)
        self.hierarchy_index: Dict[str, List[int]] = defaultdict(list)  # parent_id -> [child_ids]

        # Statistics
        self.stats = {
            "total_cwes": 0,
            "weaknesses": 0,
            "categories": 0,
            "pillars": 0,
            "compounds": 0,
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
        return self.cache_dir / "cwe_data.pkl"

    def _get_index_path(self) -> Path:
        """Get path to index file"""
        return self.cache_dir / "cwe_index.pkl"

    def _load_data(self) -> None:
        """Load CWE data from cache or file"""
        start_time = datetime.now()

        try:
            # Try to load from cache first
            if self.cache_enabled and self._load_from_cache():
                logger.info("CWE data loaded from cache")
                self.stats["last_loaded"] = datetime.now().isoformat()
                return

            # Load from file
            if self._load_from_file():
                logger.info("CWE data loaded from file")
                if self.cache_enabled:
                    self._save_cache()
                self.stats["last_loaded"] = datetime.now().isoformat()
            else:
                logger.warning("Failed to load CWE data from file")

        except Exception as e:
            logger.error(f"Error loading CWE data: {e}")
        finally:
            # Record load time
            load_time = (datetime.now() - start_time).total_seconds() * 1000
            self.stats["load_time_ms"] = round(load_time, 2)

    def _load_from_cache(self) -> bool:
        """Load CWE data from cache file"""
        try:
            cache_path = self._get_cache_path()
            index_path = self._get_index_path()

            if not cache_path.exists() or not index_path.exists():
                return False

            with open(cache_path, "rb") as f:
                self.cwe_data = pickle.load(f)

            with open(index_path, "rb") as f:
                self.index = pickle.load(f)

            self._rebuild_indices()
            self._update_stats()
            return True

        except Exception as e:
            logger.error(f"Failed to load cache: {e}")
            return False

    def _load_from_file(self) -> bool:
        """Load CWE data from JSON file"""
        try:
            if not self.data_file.exists():
                logger.warning(f"Data file not found: {self.data_file}")
                return False

            with open(self.data_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            # Handle both list and dict formats
            if isinstance(data, list):
                cwe_list = data
            elif isinstance(data, dict):
                cwe_list = data.values()
            else:
                logger.error(f"Unexpected data format: {type(data)}")
                return False

            # Parse CWE records
            for cwe_data in cwe_list:
                if isinstance(cwe_data, dict):
                    cwe_id = cwe_data.get("id")
                    if cwe_id:
                        # Convert string ID to int if needed
                        if isinstance(cwe_id, str):
                            cwe_id = int(cwe_id.replace("CWE-", ""))
                        record = CWERecord.from_dict(cwe_data)
                        self.cwe_data[cwe_id] = record

            self._rebuild_indices()
            self._update_stats()
            logger.info(f"Loaded {len(self.cwe_data)} CWE records from file")
            return True

        except Exception as e:
            logger.error(f"Error loading from file: {e}")
            return False

    def _rebuild_indices(self) -> None:
        """Rebuild search indices"""
        self.index.clear()
        self.severity_index.clear()
        self.technology_index.clear()
        self.protocol_index.clear()
        self.hierarchy_index.clear()

        for cwe_id, record in self.cwe_data.items():
            # Severity index
            if record.severity:
                self.severity_index[record.severity].append(cwe_id)

            # Technology index
            for tech in record.affected_technologies:
                tech_lower = tech.lower()
                self.technology_index[tech_lower].append(cwe_id)

            # Protocol index
            for protocol in record.affected_protocols:
                protocol_lower = protocol.lower()
                self.protocol_index[protocol_lower].append(cwe_id)

            # Hierarchy index
            for parent_id in record.parent_cwe_ids:
                self.hierarchy_index[f"parent_{parent_id}"].append(cwe_id)

            # Full-text index
            searchable_text = " ".join(
                filter(
                    None,
                    [
                        f"CWE-{cwe_id}",
                        record.name,
                        record.description,
                        record.extended_description,
                        " ".join(record.affected_technologies),
                        " ".join(record.affected_protocols),
                        " ".join(record.common_consequences),
                        " ".join(record.tags),
                    ],
                )
            ).lower()

            # Store words in index
            words = set(re.findall(r"\b\w+\b", searchable_text))
            for word in words:
                self.index[word].append(cwe_id)

    def _update_stats(self) -> None:
        """Update repository statistics"""
        self.stats["total_cwes"] = len(self.cwe_data)
        self.stats["weaknesses"] = sum(
            1 for r in self.cwe_data.values() if r.type == "Weakness"
        )
        self.stats["categories"] = sum(
            1 for r in self.cwe_data.values() if r.type == "Category"
        )
        self.stats["pillars"] = sum(
            1 for r in self.cwe_data.values() if r.type == "Pillar"
        )
        self.stats["compounds"] = sum(
            1 for r in self.cwe_data.values() if r.type == "Compound"
        )
        self.stats["critical_count"] = len(self.severity_index.get("CRITICAL", []))
        self.stats["high_count"] = len(self.severity_index.get("HIGH", []))
        self.stats["medium_count"] = len(self.severity_index.get("MEDIUM", []))
        self.stats["low_count"] = len(self.severity_index.get("LOW", []))
        self.stats["last_updated"] = datetime.now().isoformat()

    def _save_cache(self) -> None:
        """Save CWE data and index to cache"""
        try:
            cache_path = self._get_cache_path()
            index_path = self._get_index_path()

            with open(cache_path, "wb") as f:
                pickle.dump(self.cwe_data, f)

            with open(index_path, "wb") as f:
                pickle.dump(self.index, f)

            logger.debug("CWE cache saved")

        except Exception as e:
            logger.error(f"Failed to save cache: {e}")

    # ======================================================================
    # PUBLIC METHODS - RETRIEVAL
    # ======================================================================

    def get_cwe(self, cwe_id: int) -> Optional[CWERecord]:
        """
        Get CWE by ID

        Args:
            cwe_id: CWE identifier (e.g., 79 for CWE-79)

        Returns:
            CWERecord if found, None otherwise
        """
        if cwe_id in self.cwe_data:
            return self.cwe_data[cwe_id]
        return None

    def search(
        self,
        query: str,
        top_k: int = 10,
        severity_filter: Optional[str] = None,
        technology_filter: Optional[str] = None,
        protocol_filter: Optional[str] = None,
    ) -> List[CWERecord]:
        """
        Search CWEs by query string

        Args:
            query: Search query string
            top_k: Maximum number of results
            severity_filter: Filter by severity level
            technology_filter: Filter by affected technology
            protocol_filter: Filter by affected protocol

        Returns:
            List of matching CWE records
        """
        results = []
        query_lower = query.lower()

        # Get matching CWE IDs from index
        matching_ids = set()
        words = re.findall(r"\b\w+\b", query_lower)

        for word in words:
            matching_ids.update(self.index.get(word, []))

        # Also do direct text search
        for cwe_id, record in self.cwe_data.items():
            if record.matches_query(query):
                matching_ids.add(cwe_id)

        # Apply filters
        filtered_ids = []
        for cwe_id in matching_ids:
            record = self.cwe_data[cwe_id]

            # Severity filter
            if severity_filter and record.severity != severity_filter.upper():
                continue

            # Technology filter
            if technology_filter:
                tech_lower = technology_filter.lower()
                if not any(tech_lower in t.lower() for t in record.affected_technologies):
                    continue

            # Protocol filter
            if protocol_filter:
                proto_lower = protocol_filter.lower()
                if not any(proto_lower in p.lower() for p in record.affected_protocols):
                    continue

            filtered_ids.append(cwe_id)

        # Sort by relevance and return top results
        sorted_ids = sorted(
            filtered_ids,
            key=lambda x: (
                -(self.cwe_data[x].cvss_v3_score or 0),
                -len(self.cwe_data[x].description or ""),
            ),
        )

        for cwe_id in sorted_ids[:top_k]:
            results.append(self.cwe_data[cwe_id])

        return results

    def get_cwes_by_type(self, cwe_type: str) -> List[CWERecord]:
        """
        Get CWEs by type

        Args:
            cwe_type: Type (Weakness, Category, Pillar, Compound)

        Returns:
            List of CWE records
        """
        results = []
        for record in self.cwe_data.values():
            if record.type == cwe_type:
                results.append(record)
        return results

    def get_cwes_by_severity(
        self,
        severity: str,
        exact: bool = True,
    ) -> List[CWERecord]:
        """
        Get CWEs by severity level

        Args:
            severity: Severity level
            exact: If False, return severity and above

        Returns:
            List of CWE records
        """
        results = []
        severity_upper = severity.upper()

        if exact:
            cwe_ids = self.severity_index.get(severity_upper, [])
            results = [self.cwe_data[cwe_id] for cwe_id in cwe_ids]
        else:
            severity_levels = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
            if severity_upper in severity_levels:
                idx = severity_levels.index(severity_upper)
                for level in severity_levels[idx:]:
                    cwe_ids = self.severity_index.get(level, [])
                    results.extend(
                        [self.cwe_data[cwe_id] for cwe_id in cwe_ids]
                    )

        return results

    def get_cwes_by_technology(self, technology: str) -> List[CWERecord]:
        """
        Get CWEs affecting a specific technology

        Args:
            technology: Technology name

        Returns:
            List of CWE records
        """
        tech_lower = technology.lower()
        cwe_ids = self.technology_index.get(tech_lower, [])
        return [self.cwe_data[cwe_id] for cwe_id in cwe_ids]

    def get_cwes_by_protocol(self, protocol: str) -> List[CWERecord]:
        """
        Get CWEs affecting a specific protocol

        Args:
            protocol: Protocol name

        Returns:
            List of CWE records
        """
        proto_lower = protocol.lower()
        cwe_ids = self.protocol_index.get(proto_lower, [])
        return [self.cwe_data[cwe_id] for cwe_id in cwe_ids]

    def get_parent_cwe(self, cwe_id: int) -> Optional[CWERecord]:
        """
        Get parent CWE

        Args:
            cwe_id: CWE identifier

        Returns:
            Parent CWE record or None
        """
        record = self.get_cwe(cwe_id)
        if record and record.parent_cwe_ids:
            parent_id = record.parent_cwe_ids[0]  # Get first parent
            return self.get_cwe(parent_id)
        return None

    def get_child_cwes(self, cwe_id: int) -> List[CWERecord]:
        """
        Get child CWEs

        Args:
            cwe_id: CWE identifier

        Returns:
            List of child CWE records
        """
        child_ids = self.hierarchy_index.get(f"parent_{cwe_id}", [])
        return [self.cwe_data[cid] for cid in child_ids if cid in self.cwe_data]

    def get_related_cwes(
        self,
        cwe_id: int,
        max_results: int = 10,
    ) -> List[Tuple[CWERecord, float]]:
        """
        Get related CWEs

        Args:
            cwe_id: CWE identifier
            max_results: Maximum number of results

        Returns:
            List of tuples (CWERecord, relevance_score)
        """
        source_cwe = self.get_cwe(cwe_id)
        if not source_cwe:
            return []

        results = []
        for other_cwe_id, other_cwe in self.cwe_data.items():
            if other_cwe_id == cwe_id:
                continue

            # Calculate relevance score
            score = 0.0

            # Same technology
            common_techs = set(source_cwe.affected_technologies) & set(
                other_cwe.affected_technologies
            )
            score += len(common_techs) * 0.3

            # Same protocol
            common_protos = set(source_cwe.affected_protocols) & set(
                other_cwe.affected_protocols
            )
            score += len(common_protos) * 0.3

            # Same severity
            if source_cwe.severity == other_cwe.severity:
                score += 0.2

            # Related by consequence
            common_consequences = set(source_cwe.common_consequences) & set(
                other_cwe.common_consequences
            )
            score += len(common_consequences) * 0.2

            if score > 0:
                results.append((other_cwe, score))

        # Sort by relevance and return top results
        results.sort(key=lambda x: x[1], reverse=True)
        return results[:max_results]

    # ======================================================================
    # PUBLIC METHODS - STATISTICS AND VALIDATION
    # ======================================================================

    def get_total_count(self) -> int:
        """Get total number of CWEs in repository"""
        return len(self.cwe_data)

    def get_stats(self) -> Dict[str, Any]:
        """Get repository statistics"""
        return self.stats.copy()

    def preload(self, force_refresh: bool = False) -> bool:
        """
        Preload CWE data

        Args:
            force_refresh: Force reload even if cached

        Returns:
            True if successful
        """
        if force_refresh:
            self.cwe_data.clear()
            self.index.clear()
            self.severity_index.clear()
            self.technology_index.clear()
            self.protocol_index.clear()
            self.hierarchy_index.clear()

        self._load_data()
        return len(self.cwe_data) > 0

    def validate(self) -> bool:
        """
        Validate data integrity

        Returns:
            True if validation passes
        """
        try:
            # Check if data is loaded
            if not self.cwe_data:
                logger.warning("No CWE data loaded")
                return False

            # Check for required fields
            for cwe_id, record in self.cwe_data.items():
                if not record.name:
                    logger.warning(f"Invalid CWE record: CWE-{cwe_id}")
                    return False

            logger.info("CWE data validation passed")
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

            logger.info("CWE cache cleared")

        except Exception as e:
            logger.error(f"Error clearing cache: {e}")

    def clear_data(self) -> None:
        """Clear all CWE data"""
        self.cwe_data.clear()
        self.index.clear()
        self.severity_index.clear()
        self.technology_index.clear()
        self.protocol_index.clear()
        self.hierarchy_index.clear()
        self.clear_cache()
        logger.info("CWE data cleared")

    # ======================================================================
    # PUBLIC METHODS - IMPORT/EXPORT
    # ======================================================================

    def export_to_json(self, output_path: Path) -> bool:
        """
        Export CWE data to JSON file

        Args:
            output_path: Path to output file

        Returns:
            True if successful
        """
        try:
            data = [record.to_dict() for record in self.cwe_data.values()]
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, default=str)
            logger.info(f"Exported {len(data)} CWEs to {output_path}")
            return True
        except Exception as e:
            logger.error(f"Export error: {e}")
            return False

    def import_from_json(self, input_path: Path, merge: bool = False) -> int:
        """
        Import CWE data from JSON file

        Args:
            input_path: Path to input file
            merge: If True, merge with existing data; if False, replace

        Returns:
            Number of CWEs imported
        """
        try:
            if not merge:
                self.cwe_data.clear()

            with open(input_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            count = 0
            if isinstance(data, list):
                for cwe_data in data:
                    if isinstance(cwe_data, dict):
                        cwe_id = cwe_data.get("id")
                        if cwe_id:
                            if isinstance(cwe_id, str):
                                cwe_id = int(cwe_id.replace("CWE-", ""))
                            record = CWERecord.from_dict(cwe_data)
                            self.cwe_data[cwe_id] = record
                            count += 1

            self._rebuild_indices()
            self._update_stats()
            logger.info(f"Imported {count} CWEs from {input_path}")
            return count

        except Exception as e:
            logger.error(f"Import error: {e}")
            return 0

    # ======================================================================
    # PUBLIC METHODS - ADVANCED QUERIES
    # ======================================================================

    def get_cwe_hierarchy(self, cwe_id: int, depth: int = 2) -> Dict[str, Any]:
        """
        Get CWE hierarchy (parents and children)

        Args:
            cwe_id: CWE identifier
            depth: Depth to traverse

        Returns:
            Dictionary containing hierarchy information
        """
        result = {
            "cwe_id": cwe_id,
            "parents": [],
            "children": [],
            "siblings": [],
        }

        # Get parents
        record = self.get_cwe(cwe_id)
        if record:
            for parent_id in record.parent_cwe_ids:
                parent = self.get_cwe(parent_id)
                if parent:
                    result["parents"].append({"id": parent_id, "name": parent.name})

            # Get children
            children = self.get_child_cwes(cwe_id)
            for child in children:
                result["children"].append({"id": child.id, "name": child.name})

            # Get siblings (same parent)
            if record.parent_cwe_ids:
                parent_id = record.parent_cwe_ids[0]
                siblings = self.get_child_cwes(parent_id)
                for sibling in siblings:
                    if sibling.id != cwe_id:
                        result["siblings"].append(
                            {"id": sibling.id, "name": sibling.name}
                        )

        return result

    def find_cwes_by_consequence(self, consequence: str) -> List[CWERecord]:
        """
        Find CWEs by common consequence

        Args:
            consequence: Consequence type

        Returns:
            List of CWE records
        """
        results = []
        consequence_lower = consequence.lower()
        for record in self.cwe_data.values():
            if any(
                consequence_lower in c.lower()
                for c in record.common_consequences
            ):
                results.append(record)
        return results

    def find_cwes_by_capec(self, capec_id: str) -> List[CWERecord]:
        """
        Find CWEs by CAPEC attack pattern

        Args:
            capec_id: CAPEC identifier

        Returns:
            List of CWE records
        """
        results = []
        for record in self.cwe_data.values():
            if capec_id in record.capec_ids:
                results.append(record)
        return results

    def get_exploitation_likelihood(self, cwe_id: int) -> Optional[str]:
        """
        Get exploitation likelihood for CWE

        Args:
            cwe_id: CWE identifier

        Returns:
            Likelihood string or None
        """
        record = self.get_cwe(cwe_id)
        if record:
            return record.likelihood_of_exploitation
        return None

    def get_remediation_strategies(self, cwe_id: int) -> List[str]:
        """
        Get remediation strategies for CWE

        Args:
            cwe_id: CWE identifier

        Returns:
            List of remediation strategies
        """
        record = self.get_cwe(cwe_id)
        if record:
            return record.remediation_strategies
        return []

    def get_detection_methods(self, cwe_id: int) -> List[str]:
        """
        Get detection methods for CWE

        Args:
            cwe_id: CWE identifier

        Returns:
            List of detection methods
        """
        record = self.get_cwe(cwe_id)
        if record:
            return record.detection_methods
        return []

    def get_example_payloads(self, cwe_id: int) -> List[str]:
        """
        Get example payloads for CWE

        Args:
            cwe_id: CWE identifier

        Returns:
            List of example payloads
        """
        record = self.get_cwe(cwe_id)
        if record:
            return record.example_payloads
        return []


# ==============================================================================
# END OF MODULE
# ==============================================================================