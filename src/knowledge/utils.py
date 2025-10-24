"""
Knowledge Module Utilities for HyFuzz MCP Server

This module provides utility functions for the knowledge base including:
- CWE/CVE ID validation and normalization
- Data parsing and transformation
- Search and indexing utilities
- Relationship mapping and traversal
- Performance optimization helpers
- Format conversion and data cleaning

Features:
- CWE and CVE identifier validation
- Severity level normalization and comparison
- Graph traversal and relationship extraction
- Full-text search helpers
- Data deduplication and merging
- Cache key generation
- Bulk operations support

Author: HyFuzz Team
Version: 1.0.0
Date: 2025
"""

import re
import logging
from typing import Dict, Any, List, Optional, Tuple, Set
from pathlib import Path
from datetime import datetime
import hashlib
from enum import Enum

# ==============================================================================
# LOGGER SETUP
# ==============================================================================

logger = logging.getLogger(__name__)


# ==============================================================================
# ENUMERATIONS
# ==============================================================================


class SeverityLevel(str, Enum):
    """Severity level enumeration with ordering"""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"

    @property
    def numeric_value(self) -> int:
        """Get numeric value for comparison"""
        severity_map = {
            "CRITICAL": 5,
            "HIGH": 4,
            "MEDIUM": 3,
            "LOW": 2,
            "UNKNOWN": 0,
        }
        return severity_map.get(self.value, 0)

    def __lt__(self, other):
        """Less than comparison"""
        if not isinstance(other, SeverityLevel):
            return NotImplemented
        return self.numeric_value < other.numeric_value

    def __le__(self, other):
        """Less than or equal comparison"""
        if not isinstance(other, SeverityLevel):
            return NotImplemented
        return self.numeric_value <= other.numeric_value

    def __gt__(self, other):
        """Greater than comparison"""
        if not isinstance(other, SeverityLevel):
            return NotImplemented
        return self.numeric_value > other.numeric_value

    def __ge__(self, other):
        """Greater than or equal comparison"""
        if not isinstance(other, SeverityLevel):
            return NotImplemented
        return self.numeric_value >= other.numeric_value


# ==============================================================================
# CONSTANTS
# ==============================================================================

# Regular expression patterns
CWE_PATTERN = re.compile(r"^CWE-?\d+$", re.IGNORECASE)
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
CVSS_PATTERN = re.compile(r"^CVSS:3\.\d/.*")

# Severity mappings
CVSS_TO_SEVERITY = {
    9.0: SeverityLevel.CRITICAL,
    7.0: SeverityLevel.HIGH,
    4.0: SeverityLevel.MEDIUM,
    0.1: SeverityLevel.LOW,
}


# ==============================================================================
# VALIDATION FUNCTIONS
# ==============================================================================


def is_valid_cwe_id(cwe_id: str) -> bool:
    """
    Validate CWE identifier format.
    
    Args:
        cwe_id: CWE identifier to validate
        
    Returns:
        True if valid format, False otherwise
        
    Example:
        >>> is_valid_cwe_id("CWE-79")
        True
        >>> is_valid_cwe_id("CWE79")
        True
        >>> is_valid_cwe_id("XSS")
        False
    """
    if not isinstance(cwe_id, str):
        return False
    return CWE_PATTERN.match(cwe_id.strip()) is not None


def is_valid_cve_id(cve_id: str) -> bool:
    """
    Validate CVE identifier format.
    
    Args:
        cve_id: CVE identifier to validate
        
    Returns:
        True if valid format, False otherwise
        
    Example:
        >>> is_valid_cve_id("CVE-2021-1234")
        True
        >>> is_valid_cve_id("CVE-2021-123")
        False
        >>> is_valid_cve_id("XSS")
        False
    """
    if not isinstance(cve_id, str):
        return False
    return CVE_PATTERN.match(cve_id.strip()) is not None


def is_valid_cvss_score(score: float) -> bool:
    """
    Validate CVSS score range.
    
    Args:
        score: CVSS score to validate
        
    Returns:
        True if score is between 0.0 and 10.0, False otherwise
    """
    try:
        score_float = float(score)
        return 0.0 <= score_float <= 10.0
    except (ValueError, TypeError):
        return False


def is_valid_severity(severity: str) -> bool:
    """
    Validate severity level.
    
    Args:
        severity: Severity level to validate
        
    Returns:
        True if valid severity level, False otherwise
    """
    try:
        SeverityLevel(severity.upper())
        return True
    except ValueError:
        return False


# ==============================================================================
# NORMALIZATION FUNCTIONS
# ==============================================================================


def normalize_cwe_id(cwe_id: str) -> Optional[str]:
    """
    Normalize CWE identifier to standard format.
    
    Args:
        cwe_id: CWE identifier to normalize
        
    Returns:
        Normalized CWE ID (e.g., "CWE-79") or None if invalid
        
    Example:
        >>> normalize_cwe_id("cwe-79")
        "CWE-79"
        >>> normalize_cwe_id("CWE79")
        "CWE-79"
    """
    if not isinstance(cwe_id, str):
        return None

    cwe_id = cwe_id.strip().upper()

    # Extract number
    match = re.search(r"\d+", cwe_id)
    if not match:
        return None

    number = match.group()
    return f"CWE-{number}"


def normalize_cve_id(cve_id: str) -> Optional[str]:
    """
    Normalize CVE identifier to standard format.
    
    Args:
        cve_id: CVE identifier to normalize
        
    Returns:
        Normalized CVE ID (e.g., "CVE-2021-1234") or None if invalid
        
    Example:
        >>> normalize_cve_id("cve-2021-1234")
        "CVE-2021-1234"
    """
    if not isinstance(cve_id, str):
        return None

    cve_id = cve_id.strip().upper()

    # Check format
    if CVE_PATTERN.match(cve_id):
        return cve_id

    return None


def normalize_severity(severity: str) -> Optional[SeverityLevel]:
    """
    Normalize severity level string to enum.
    
    Args:
        severity: Severity level string (e.g., "high", "CRITICAL")
        
    Returns:
        SeverityLevel enum or None if invalid
        
    Example:
        >>> normalize_severity("high")
        <SeverityLevel.HIGH: 'HIGH'>
        >>> normalize_severity("critical")
        <SeverityLevel.CRITICAL: 'CRITICAL'>
    """
    if not isinstance(severity, str):
        return None

    try:
        return SeverityLevel(severity.strip().upper())
    except ValueError:
        return None


def cvss_score_to_severity(score: float) -> SeverityLevel:
    """
    Convert CVSS score to severity level.
    
    Args:
        score: CVSS score (0.0-10.0)
        
    Returns:
        Corresponding SeverityLevel
        
    Example:
        >>> cvss_score_to_severity(9.8)
        <SeverityLevel.CRITICAL: 'CRITICAL'>
        >>> cvss_score_to_severity(5.5)
        <SeverityLevel.MEDIUM: 'MEDIUM'>
    """
    try:
        score_float = float(score)
        
        if score_float >= 9.0:
            return SeverityLevel.CRITICAL
        elif score_float >= 7.0:
            return SeverityLevel.HIGH
        elif score_float >= 4.0:
            return SeverityLevel.MEDIUM
        elif score_float > 0.0:
            return SeverityLevel.LOW
        else:
            return SeverityLevel.UNKNOWN
            
    except (ValueError, TypeError):
        return SeverityLevel.UNKNOWN


# ==============================================================================
# EXTRACTION AND PARSING FUNCTIONS
# ==============================================================================


def extract_cwe_ids(text: str) -> Set[str]:
    """
    Extract CWE IDs from text.
    
    Args:
        text: Text to search for CWE IDs
        
    Returns:
        Set of normalized CWE IDs found
        
    Example:
        >>> extract_cwe_ids("Related to CWE-79 and CWE-89")
        {'CWE-79', 'CWE-89'}
    """
    cwe_ids = set()
    
    # Find all CWE patterns
    matches = re.finditer(r"CWE-?\d+", text, re.IGNORECASE)
    for match in matches:
        normalized = normalize_cwe_id(match.group())
        if normalized:
            cwe_ids.add(normalized)
    
    return cwe_ids


def extract_cve_ids(text: str) -> Set[str]:
    """
    Extract CVE IDs from text.
    
    Args:
        text: Text to search for CVE IDs
        
    Returns:
        Set of normalized CVE IDs found
        
    Example:
        >>> extract_cve_ids("Affects CVE-2021-1234 and CVE-2020-5678")
        {'CVE-2021-1234', 'CVE-2020-5678'}
    """
    cve_ids = set()
    
    # Find all CVE patterns
    matches = re.finditer(r"CVE-\d{4}-\d{4,}", text, re.IGNORECASE)
    for match in matches:
        normalized = normalize_cve_id(match.group())
        if normalized:
            cve_ids.add(normalized)
    
    return cve_ids


def extract_severity(text: str) -> Optional[SeverityLevel]:
    """
    Extract severity level from text.
    
    Args:
        text: Text to search for severity level
        
    Returns:
        First severity level found or None
        
    Example:
        >>> extract_severity("CVSS:3.1/AV:N/AC:L - CRITICAL")
        <SeverityLevel.CRITICAL: 'CRITICAL'>
    """
    text_upper = text.upper()
    
    for severity in SeverityLevel:
        if severity.value in text_upper:
            return severity
    
    return None


# ==============================================================================
# SEARCH AND FILTERING FUNCTIONS
# ==============================================================================


def filter_by_severity(
    items: List[Dict[str, Any]],
    min_severity: SeverityLevel,
    severity_key: str = "severity",
) -> List[Dict[str, Any]]:
    """
    Filter items by minimum severity level.
    
    Args:
        items: List of dictionaries to filter
        min_severity: Minimum severity level
        severity_key: Key in dictionaries containing severity
        
    Returns:
        Filtered list of items
        
    Example:
        >>> items = [{"id": "CVE-1", "severity": "HIGH"}]
        >>> filter_by_severity(items, SeverityLevel.HIGH)
        [{"id": "CVE-1", "severity": "HIGH"}]
    """
    filtered = []
    
    for item in items:
        severity_str = item.get(severity_key, "UNKNOWN")
        severity = normalize_severity(severity_str)
        
        if severity and severity >= min_severity:
            filtered.append(item)
    
    return filtered


def search_text(
    items: List[Dict[str, Any]],
    query: str,
    search_fields: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    """
    Perform full-text search on items.
    
    Args:
        items: List of dictionaries to search
        query: Search query
        search_fields: Fields to search in (searches all if None)
        
    Returns:
        List of matching items
        
    Example:
        >>> items = [{"name": "XSS", "desc": "Cross-site scripting"}]
        >>> search_text(items, "XSS")
        [{"name": "XSS", "desc": "Cross-site scripting"}]
    """
    results = []
    query_lower = query.lower()
    
    for item in items:
        if search_fields:
            fields_to_search = search_fields
        else:
            fields_to_search = item.keys()
        
        match = False
        for field in fields_to_search:
            value = item.get(field, "")
            if isinstance(value, str) and query_lower in value.lower():
                match = True
                break
        
        if match:
            results.append(item)
    
    return results


# ==============================================================================
# RELATIONSHIP AND GRAPH FUNCTIONS
# ==============================================================================


def build_cwe_relationship_map(cwe_data: Dict[str, Any]) -> Dict[str, Set[str]]:
    """
    Build relationship map for CWE data.
    
    Args:
        cwe_data: Dictionary of CWE data
        
    Returns:
        Dictionary mapping CWE IDs to related CWE IDs
    """
    relationships = {}
    
    for cwe_id, cwe_info in cwe_data.items():
        related_ids = set()
        
        # Add parent relationships
        parent_ids = cwe_info.get("parent_cwe_ids", [])
        related_ids.update(parent_ids)
        
        # Add child relationships
        child_ids = cwe_info.get("child_cwe_ids", [])
        related_ids.update(child_ids)
        
        # Add related CWEs
        related_cwe = cwe_info.get("related_cwe_ids", [])
        related_ids.update(related_cwe)
        
        relationships[cwe_id] = related_ids
    
    return relationships


def get_related_cves_for_cwe(
    cwe_id: str,
    cve_data: Dict[str, Any],
) -> List[str]:
    """
    Get all CVEs related to a CWE.
    
    Args:
        cwe_id: CWE identifier
        cve_data: Dictionary of CVE data
        
    Returns:
        List of related CVE IDs
    """
    related_cves = []
    cwe_id_normalized = normalize_cwe_id(cwe_id)
    
    if not cwe_id_normalized:
        return related_cves
    
    for cve_id, cve_info in cve_data.items():
        cwe_ids = cve_info.get("cwe_ids", [])
        if cwe_id_normalized in cwe_ids:
            related_cves.append(cve_id)
    
    return related_cves


def get_cwe_chain(
    cwe_id: str,
    cwe_data: Dict[str, Any],
    max_depth: int = 5,
) -> List[str]:
    """
    Get CWE parent chain up to specified depth.
    
    Args:
        cwe_id: Starting CWE identifier
        cwe_data: Dictionary of CWE data
        max_depth: Maximum depth to traverse
        
    Returns:
        List of CWE IDs in parent chain
    """
    chain = []
    current_id = normalize_cwe_id(cwe_id)
    depth = 0
    visited = set()
    
    while current_id and depth < max_depth and current_id not in visited:
        visited.add(current_id)
        chain.append(current_id)
        
        # Get parent
        cwe_info = cwe_data.get(current_id, {})
        parent_ids = cwe_info.get("parent_cwe_ids", [])
        
        if parent_ids:
            current_id = parent_ids[0]  # Follow first parent
        else:
            break
        
        depth += 1
    
    return chain


# ==============================================================================
# CACHE AND HASHING FUNCTIONS
# ==============================================================================


def generate_cache_key(
    *args,
    prefix: str = "kb",
) -> str:
    """
    Generate cache key from arguments.
    
    Args:
        *args: Arguments to include in key
        prefix: Prefix for cache key
        
    Returns:
        Generated cache key
        
    Example:
        >>> generate_cache_key("CWE", "79", prefix="cwe")
        "cwe:abc123def456..."
    """
    key_parts = [str(arg) for arg in args]
    key_string = ":".join(key_parts)
    
    # Create hash
    hash_obj = hashlib.md5(key_string.encode())
    hash_hex = hash_obj.hexdigest()[:8]
    
    return f"{prefix}:{hash_hex}"


def compute_data_hash(data: Dict[str, Any]) -> str:
    """
    Compute hash for data dictionary.
    
    Args:
        data: Dictionary to hash
        
    Returns:
        Hash string
    """
    try:
        import json
        json_str = json.dumps(data, sort_keys=True)
        return hashlib.sha256(json_str.encode()).hexdigest()
    except Exception as e:
        logger.error(f"Failed to compute data hash: {e}")
        return ""


# ==============================================================================
# DEDUPLICATION AND MERGING FUNCTIONS
# ==============================================================================


def deduplicate_list(items: List[Dict[str, Any]], key_field: str) -> List[Dict[str, Any]]:
    """
    Deduplicate list of dictionaries by key field.
    
    Args:
        items: List of dictionaries
        key_field: Field to use as deduplication key
        
    Returns:
        Deduplicated list maintaining order
        
    Example:
        >>> items = [{"id": "A", "val": 1}, {"id": "A", "val": 2}]
        >>> deduplicate_list(items, "id")
        [{"id": "A", "val": 1}]
    """
    seen = set()
    deduplicated = []
    
    for item in items:
        key_value = item.get(key_field)
        if key_value and key_value not in seen:
            seen.add(key_value)
            deduplicated.append(item)
    
    return deduplicated


def merge_dicts(*dicts: Dict[str, Any]) -> Dict[str, Any]:
    """
    Merge multiple dictionaries, with later ones overriding earlier ones.
    
    Args:
        *dicts: Dictionaries to merge
        
    Returns:
        Merged dictionary
        
    Example:
        >>> merge_dicts({"a": 1}, {"b": 2}, {"a": 3})
        {"a": 3, "b": 2}
    """
    result = {}
    
    for d in dicts:
        if isinstance(d, dict):
            result.update(d)
    
    return result


def merge_lists_unique(*lists: List[str]) -> List[str]:
    """
    Merge lists maintaining unique values and order.
    
    Args:
        *lists: Lists to merge
        
    Returns:
        Merged list with unique values
    """
    seen = set()
    result = []
    
    for lst in lists:
        if isinstance(lst, list):
            for item in lst:
                if item not in seen:
                    seen.add(item)
                    result.append(item)
    
    return result


# ==============================================================================
# STATISTICS AND ANALYSIS FUNCTIONS
# ==============================================================================


def calculate_severity_distribution(
    items: List[Dict[str, Any]],
    severity_key: str = "severity",
) -> Dict[str, int]:
    """
    Calculate distribution of severity levels.
    
    Args:
        items: List of items to analyze
        severity_key: Key containing severity level
        
    Returns:
        Dictionary with severity counts
        
    Example:
        >>> items = [{"severity": "HIGH"}, {"severity": "CRITICAL"}]
        >>> calculate_severity_distribution(items)
        {"CRITICAL": 1, "HIGH": 1}
    """
    distribution = {}
    
    for item in items:
        severity_str = item.get(severity_key, "UNKNOWN")
        severity = normalize_severity(severity_str)
        
        if severity:
            key = severity.value
            distribution[key] = distribution.get(key, 0) + 1
    
    return distribution


def analyze_data_completeness(
    items: List[Dict[str, Any]],
    required_fields: List[str],
) -> Dict[str, float]:
    """
    Analyze data completeness for required fields.
    
    Args:
        items: List of items to analyze
        required_fields: Fields that should be present
        
    Returns:
        Dictionary with field completion percentages
    """
    completeness = {}
    
    if not items:
        return {field: 0.0 for field in required_fields}
    
    for field in required_fields:
        count = sum(1 for item in items if item.get(field))
        percentage = (count / len(items)) * 100
        completeness[field] = percentage
    
    return completeness


# ==============================================================================
# DATA CLEANING FUNCTIONS
# ==============================================================================


def clean_text(text: str) -> str:
    """
    Clean text by removing extra whitespace and normalizing.
    
    Args:
        text: Text to clean
        
    Returns:
        Cleaned text
    """
    if not isinstance(text, str):
        return ""
    
    # Remove extra whitespace
    cleaned = " ".join(text.split())
    
    # Remove special characters at start/end
    cleaned = cleaned.strip()
    
    return cleaned


def normalize_cwe_list(cwe_list: List[str]) -> List[str]:
    """
    Normalize and deduplicate CWE ID list.
    
    Args:
        cwe_list: List of CWE IDs
        
    Returns:
        Normalized list without duplicates
    """
    normalized = set()
    
    for cwe_id in cwe_list:
        normalized_id = normalize_cwe_id(cwe_id)
        if normalized_id:
            normalized.add(normalized_id)
    
    return sorted(list(normalized))


def normalize_cve_list(cve_list: List[str]) -> List[str]:
    """
    Normalize and deduplicate CVE ID list.
    
    Args:
        cve_list: List of CVE IDs
        
    Returns:
        Normalized list without duplicates
    """
    normalized = set()
    
    for cve_id in cve_list:
        normalized_id = normalize_cve_id(cve_id)
        if normalized_id:
            normalized.add(normalized_id)
    
    return sorted(list(normalized))


# ==============================================================================
# END OF MODULE
# ==============================================================================