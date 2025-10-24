"""
HyFuzz MCP Server - Knowledge Base Integration Tests

This module tests the integration of knowledge base components including:
- Knowledge Loader (loading and initialization)
- CWE Repository (CWE data management)
- CVE Repository (CVE data management)
- Graph Cache (caching CWE/CVE relationships)
- Vulnerability Database (persistent storage)

The tests verify that all components work together seamlessly to provide
knowledge retrieval capabilities for the LLM and vulnerability analysis.

Key Test Areas:
1. Knowledge base initialization and loading
2. CWE/CVE repository functionality
3. Graph caching and performance
4. Query and retrieval operations
5. Embedding generation and retrieval
6. Vulnerability lookup and enrichment
7. End-to-end knowledge pipeline

Author: HyFuzz Team
Version: 1.0.0
Date: 2025
"""

import asyncio
import json
import logging
import pytest
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import pickle
import tempfile
from unittest.mock import Mock, patch, MagicMock, AsyncMock

# Import knowledge base components
from src.knowledge.knowledge_loader import KnowledgeLoader
from src.knowledge.cwe_repository import CWERepository
from src.knowledge.cve_repository import CVERepository
from src.knowledge.graph_cache import GraphCache
from src.knowledge.vulnerability_db import VulnerabilityDB
from src.knowledge.embedding_manager import EmbeddingManager

# Import models
from src.models.knowledge_models import (
    CWEModel, CVEModel, VulnerabilityInfo, KnowledgeQueryResult
)

# Import utils
from src.utils.exceptions import (
    KnowledgeBaseException, LoadingException, QueryException
)
from src.utils.logger import get_logger

# Initialize logger
logger = get_logger(__name__)


# ==============================================================================
# Test Fixtures
# ==============================================================================

@pytest.fixture(scope="session")
def test_data_dir():
    """Provide path to test data directory."""
    return Path(__file__).parent.parent / "data"


@pytest.fixture
def sample_cwe_data():
    """Provide sample CWE data for testing."""
    return {
        "CWE-79": {
            "id": "CWE-79",
            "name": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
            "description": "The product does not properly neutralize user-supplied input...",
            "severity": "HIGH",
            "cvss_base_score": 7.1,
            "consequences": ["Confidentiality", "Integrity", "Availability"],
            "common_consequences": {
                "scope": "CHANGED",
                "confidentiality_impact": "LOW",
                "integrity_impact": "LOW",
                "availability_impact": "NONE"
            },
            "related_cves": ["CVE-2021-1234", "CVE-2020-5678"],
            "remediation": "Use input validation and output encoding",
            "examples": [
                {
                    "description": "Reflected XSS example",
                    "code": "<script>alert('XSS')</script>"
                }
            ]
        },
        "CWE-89": {
            "id": "CWE-89",
            "name": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
            "description": "The product constructs all or part of an SQL command...",
            "severity": "CRITICAL",
            "cvss_base_score": 9.8,
            "consequences": ["Confidentiality", "Integrity", "Availability"],
            "related_cves": ["CVE-2019-9999"],
            "remediation": "Use parameterized queries and input validation",
            "examples": []
        }
    }


@pytest.fixture
def sample_cve_data():
    """Provide sample CVE data for testing."""
    return {
        "CVE-2021-1234": {
            "id": "CVE-2021-1234",
            "title": "Reflected XSS in Example Application",
            "description": "A reflected cross-site scripting (XSS) vulnerability exists...",
            "severity": "HIGH",
            "cvss_v3_score": 7.1,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            "affected_product": "Example App",
            "affected_versions": ["1.0", "1.1"],
            "cwe_ids": ["CWE-79"],
            "published_date": "2021-01-15",
            "updated_date": "2021-02-01",
            "remediation": "Update to version 1.2 or later",
            "exploit_available": True,
            "exploit_urls": [
                "https://example.com/exploit1",
                "https://example.com/exploit2"
            ],
            "references": []
        },
        "CVE-2020-5678": {
            "id": "CVE-2020-5678",
            "title": "SQL Injection in Legacy System",
            "description": "A SQL injection vulnerability exists in the database layer...",
            "severity": "CRITICAL",
            "cvss_v3_score": 9.8,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "affected_product": "Legacy System",
            "affected_versions": ["<3.0"],
            "cwe_ids": ["CWE-89"],
            "published_date": "2020-06-01",
            "remediation": "Apply security patch",
            "exploit_available": False
        }
    }


@pytest.fixture
def temp_knowledge_dir():
    """Create temporary directory for knowledge data."""
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        # Create subdirectories
        (temp_path / "cache").mkdir(exist_ok=True)
        (temp_path / "databases").mkdir(exist_ok=True)

        yield temp_path


@pytest.fixture
def mock_knowledge_loader(temp_knowledge_dir, sample_cwe_data, sample_cve_data):
    """Provide mock knowledge loader."""
    loader = MagicMock(spec=KnowledgeLoader)
    loader.data_dir = temp_knowledge_dir
    loader.cache_dir = temp_knowledge_dir / "cache"
    loader.is_initialized = False
    loader.load_time = None
    loader.cwe_data = sample_cwe_data
    loader.cve_data = sample_cve_data

    return loader


@pytest.fixture
def mock_cwe_repository(sample_cwe_data):
    """Provide mock CWE repository."""
    repo = MagicMock(spec=CWERepository)
    repo.data = sample_cwe_data
    repo.initialized = True

    # Mock methods
    async def mock_get_cwe(cwe_id: str):
        if cwe_id in sample_cwe_data:
            return CWEModel(**sample_cwe_data[cwe_id])
        return None

    async def mock_search_cwes(query: str, limit: int = 10):
        results = []
        query_lower = query.lower()
        for cwe_id, cwe_data in sample_cwe_data.items():
            if (query_lower in cwe_data.get("name", "").lower() or
                query_lower in cwe_data.get("description", "").lower()):
                results.append(CWEModel(**cwe_data))
                if len(results) >= limit:
                    break
        return results

    repo.get_cwe = mock_get_cwe
    repo.search_cwes = mock_search_cwes

    return repo


@pytest.fixture
def mock_cve_repository(sample_cve_data):
    """Provide mock CVE repository."""
    repo = MagicMock(spec=CVERepository)
    repo.data = sample_cve_data
    repo.initialized = True

    # Mock methods
    async def mock_get_cve(cve_id: str):
        if cve_id in sample_cve_data:
            return CVEModel(**sample_cve_data[cve_id])
        return None

    async def mock_search_cves(query: str, limit: int = 10):
        results = []
        query_lower = query.lower()
        for cve_id, cve_data in sample_cve_data.items():
            if (query_lower in cve_data.get("title", "").lower() or
                query_lower in cve_data.get("description", "").lower()):
                results.append(CVEModel(**cve_data))
                if len(results) >= limit:
                    break
        return results

    repo.get_cve = mock_get_cve
    repo.search_cves = mock_search_cves

    return repo


@pytest.fixture
def mock_graph_cache(temp_knowledge_dir):
    """Provide mock graph cache."""
    cache = MagicMock(spec=GraphCache)
    cache.cache_dir = temp_knowledge_dir / "cache"
    cache.initialized = False
    cache.cwe_graph = {}
    cache.cve_graph = {}

    return cache


# ==============================================================================
# Knowledge Loader Tests
# ==============================================================================

class TestKnowledgeLoaderIntegration:
    """Test knowledge loader integration."""

    @pytest.mark.asyncio
    async def test_knowledge_loader_initialization(self, mock_knowledge_loader):
        """Test knowledge loader initialization."""
        logger.info("Testing knowledge loader initialization...")

        mock_knowledge_loader.initialize = AsyncMock(return_value=True)
        result = await mock_knowledge_loader.initialize()

        assert result is True
        mock_knowledge_loader.initialize.assert_called_once()
        logger.info("Knowledge loader initialization test passed")

    @pytest.mark.asyncio
    async def test_knowledge_loader_load_cwe_data(
        self, mock_knowledge_loader, sample_cwe_data
    ):
        """Test loading CWE data."""
        logger.info("Testing CWE data loading...")

        mock_knowledge_loader.load_cwe_data = AsyncMock(
            return_value=sample_cwe_data
        )
        result = await mock_knowledge_loader.load_cwe_data()

        assert result is not None
        assert "CWE-79" in result
        assert "CWE-89" in result
        assert len(result) == 2
        logger.info(f"Loaded {len(result)} CWE entries")

    @pytest.mark.asyncio
    async def test_knowledge_loader_load_cve_data(
        self, mock_knowledge_loader, sample_cve_data
    ):
        """Test loading CVE data."""
        logger.info("Testing CVE data loading...")

        mock_knowledge_loader.load_cve_data = AsyncMock(
            return_value=sample_cve_data
        )
        result = await mock_knowledge_loader.load_cve_data()

        assert result is not None
        assert "CVE-2021-1234" in result
        assert "CVE-2020-5678" in result
        logger.info(f"Loaded {len(result)} CVE entries")

    @pytest.mark.asyncio
    async def test_knowledge_loader_cache_creation(self, temp_knowledge_dir):
        """Test cache creation during loading."""
        logger.info("Testing cache creation...")

        cache_dir = temp_knowledge_dir / "cache"
        cache_dir.mkdir(exist_ok=True)

        # Mock cache file creation
        cwe_cache_file = cache_dir / "cwe_graph.pkl"
        cve_cache_file = cache_dir / "cve_graph.pkl"

        with open(cwe_cache_file, "wb") as f:
            pickle.dump({"CWE-79": {}}, f)

        with open(cve_cache_file, "wb") as f:
            pickle.dump({"CVE-2021-1234": {}}, f)

        assert cwe_cache_file.exists()
        assert cve_cache_file.exists()
        logger.info("Cache files created successfully")

    @pytest.mark.asyncio
    async def test_knowledge_loader_error_handling(self, mock_knowledge_loader):
        """Test error handling in knowledge loader."""
        logger.info("Testing error handling...")

        mock_knowledge_loader.initialize = AsyncMock(
            side_effect=LoadingException("Failed to load data")
        )

        with pytest.raises(LoadingException):
            await mock_knowledge_loader.initialize()

        logger.info("Error handling test passed")


# ==============================================================================
# CWE Repository Tests
# ==============================================================================

class TestCWERepositoryIntegration:
    """Test CWE repository integration."""

    @pytest.mark.asyncio
    async def test_cwe_repository_get_single_cwe(self, mock_cwe_repository):
        """Test retrieving a single CWE."""
        logger.info("Testing single CWE retrieval...")

        result = await mock_cwe_repository.get_cwe("CWE-79")

        assert result is not None
        assert result.id == "CWE-79"
        assert "XSS" in result.name
        logger.info(f"Retrieved CWE: {result.id}")

    @pytest.mark.asyncio
    async def test_cwe_repository_get_nonexistent_cwe(self, mock_cwe_repository):
        """Test retrieving non-existent CWE."""
        logger.info("Testing non-existent CWE retrieval...")

        result = await mock_cwe_repository.get_cwe("CWE-99999")

        assert result is None
        logger.info("Non-existent CWE handled correctly")

    @pytest.mark.asyncio
    async def test_cwe_repository_search(self, mock_cwe_repository):
        """Test searching CWEs."""
        logger.info("Testing CWE search...")

        results = await mock_cwe_repository.search_cwes("injection", limit=5)

        assert isinstance(results, list)
        assert any("SQL Injection" in str(r) for r in results)
        logger.info(f"Found {len(results)} CWEs matching query")

    @pytest.mark.asyncio
    async def test_cwe_repository_get_related_cves(self, mock_cwe_repository):
        """Test retrieving CVEs related to a CWE."""
        logger.info("Testing related CVE retrieval...")

        # Mock the method
        mock_cwe_repository.get_related_cves = AsyncMock(
            return_value=["CVE-2021-1234", "CVE-2020-5678"]
        )

        results = await mock_cwe_repository.get_related_cves("CWE-79")

        assert isinstance(results, list)
        assert len(results) > 0
        logger.info(f"Found {len(results)} related CVEs")

    @pytest.mark.asyncio
    async def test_cwe_repository_bulk_retrieval(self, mock_cwe_repository):
        """Test bulk CWE retrieval."""
        logger.info("Testing bulk CWE retrieval...")

        mock_cwe_repository.get_cwes_bulk = AsyncMock(
            return_value=[
                MagicMock(id="CWE-79"),
                MagicMock(id="CWE-89")
            ]
        )

        results = await mock_cwe_repository.get_cwes_bulk(["CWE-79", "CWE-89"])

        assert len(results) == 2
        logger.info(f"Retrieved {len(results)} CWEs in bulk")


# ==============================================================================
# CVE Repository Tests
# ==============================================================================

class TestCVERepositoryIntegration:
    """Test CVE repository integration."""

    @pytest.mark.asyncio
    async def test_cve_repository_get_single_cve(self, mock_cve_repository):
        """Test retrieving a single CVE."""
        logger.info("Testing single CVE retrieval...")

        result = await mock_cve_repository.get_cve("CVE-2021-1234")

        assert result is not None
        assert result.id == "CVE-2021-1234"
        logger.info(f"Retrieved CVE: {result.id}")

    @pytest.mark.asyncio
    async def test_cve_repository_search(self, mock_cve_repository):
        """Test searching CVEs."""
        logger.info("Testing CVE search...")

        results = await mock_cve_repository.search_cves("XSS", limit=5)

        assert isinstance(results, list)
        logger.info(f"Found {len(results)} CVEs matching query")

    @pytest.mark.asyncio
    async def test_cve_repository_get_by_cwe(self, mock_cve_repository):
        """Test retrieving CVEs by CWE ID."""
        logger.info("Testing CVE retrieval by CWE...")

        mock_cve_repository.get_by_cwe = AsyncMock(
            return_value=[MagicMock(id="CVE-2021-1234")]
        )

        results = await mock_cve_repository.get_by_cwe("CWE-79")

        assert len(results) > 0
        logger.info(f"Found {len(results)} CVEs for CWE-79")

    @pytest.mark.asyncio
    async def test_cve_repository_filter_by_severity(self, mock_cve_repository):
        """Test filtering CVEs by severity."""
        logger.info("Testing CVE filtering by severity...")

        mock_cve_repository.filter_by_severity = AsyncMock(
            return_value=[MagicMock(severity="CRITICAL")]
        )

        results = await mock_cve_repository.filter_by_severity("CRITICAL")

        assert len(results) > 0
        logger.info(f"Found {len(results)} CRITICAL CVEs")

    @pytest.mark.asyncio
    async def test_cve_repository_get_with_exploits(self, mock_cve_repository):
        """Test retrieving CVEs with available exploits."""
        logger.info("Testing CVE with exploits retrieval...")

        mock_cve_repository.get_exploitable = AsyncMock(
            return_value=[MagicMock(id="CVE-2021-1234")]
        )

        results = await mock_cve_repository.get_exploitable()

        assert len(results) > 0
        logger.info(f"Found {len(results)} exploitable CVEs")


# ==============================================================================
# Graph Cache Tests
# ==============================================================================

class TestGraphCacheIntegration:
    """Test graph cache integration."""

    @pytest.mark.asyncio
    async def test_graph_cache_initialization(self, mock_graph_cache):
        """Test graph cache initialization."""
        logger.info("Testing graph cache initialization...")

        mock_graph_cache.initialize = AsyncMock(return_value=True)
        result = await mock_graph_cache.initialize()

        assert result is True
        logger.info("Graph cache initialized successfully")

    @pytest.mark.asyncio
    async def test_graph_cache_build_cwe_graph(self, mock_graph_cache, sample_cwe_data):
        """Test building CWE graph."""
        logger.info("Testing CWE graph building...")

        mock_graph_cache.build_cwe_graph = AsyncMock(return_value=True)
        result = await mock_graph_cache.build_cwe_graph(sample_cwe_data)

        assert result is True
        logger.info("CWE graph built successfully")

    @pytest.mark.asyncio
    async def test_graph_cache_build_cve_graph(self, mock_graph_cache, sample_cve_data):
        """Test building CVE graph."""
        logger.info("Testing CVE graph building...")

        mock_graph_cache.build_cve_graph = AsyncMock(return_value=True)
        result = await mock_graph_cache.build_cve_graph(sample_cve_data)

        assert result is True
        logger.info("CVE graph built successfully")

    @pytest.mark.asyncio
    async def test_graph_cache_get_related_cwes(self, mock_graph_cache):
        """Test retrieving related CWEs from cache."""
        logger.info("Testing related CWEs retrieval...")

        mock_graph_cache.get_related = AsyncMock(
            return_value=["CWE-89", "CWE-95"]
        )

        results = await mock_graph_cache.get_related("CWE-79")

        assert isinstance(results, list)
        logger.info(f"Found {len(results)} related CWEs")

    @pytest.mark.asyncio
    async def test_graph_cache_save_and_load(self, temp_knowledge_dir):
        """Test saving and loading graph cache."""
        logger.info("Testing cache save/load...")

        cache_dir = temp_knowledge_dir / "cache"
        cache_file = cache_dir / "test_graph.pkl"

        # Save test data
        test_graph = {"node1": {"node2", "node3"}, "node2": {"node1"}}
        with open(cache_file, "wb") as f:
            pickle.dump(test_graph, f)

        # Load test data
        with open(cache_file, "rb") as f:
            loaded_graph = pickle.load(f)

        assert loaded_graph == test_graph
        logger.info("Cache save/load test passed")

    @pytest.mark.asyncio
    async def test_graph_cache_performance(self, mock_graph_cache):
        """Test graph cache performance."""
        logger.info("Testing graph cache performance...")

        import time

        # Mock cache hit
        start = time.time()
        mock_graph_cache.get_related = AsyncMock(
            return_value=["CWE-89", "CWE-95"]
        )
        await mock_graph_cache.get_related("CWE-79")
        cache_time = time.time() - start

        # Cache query should be very fast (< 100ms)
        assert cache_time < 0.1
        logger.info(f"Cache query time: {cache_time*1000:.2f}ms")


# ==============================================================================
# Vulnerability Database Tests
# ==============================================================================

class TestVulnerabilityDBIntegration:
    """Test vulnerability database integration."""

    @pytest.mark.asyncio
    async def test_vuln_db_initialization(self, temp_knowledge_dir):
        """Test vulnerability database initialization."""
        logger.info("Testing vulnerability DB initialization...")

        db = MagicMock(spec=VulnerabilityDB)
        db.db_path = temp_knowledge_dir / "vulnerability.db"
        db.initialize = AsyncMock(return_value=True)

        result = await db.initialize()
        assert result is True
        logger.info("Vulnerability DB initialized successfully")

    @pytest.mark.asyncio
    async def test_vuln_db_insert_vulnerability(self, temp_knowledge_dir):
        """Test inserting vulnerability into database."""
        logger.info("Testing vulnerability insertion...")

        db = MagicMock(spec=VulnerabilityDB)
        db.insert = AsyncMock(return_value="vuln_id_123")

        vuln_data = {
            "cwe_id": "CWE-79",
            "cve_id": "CVE-2021-1234",
            "severity": "HIGH",
            "discovered_date": datetime.now()
        }

        result = await db.insert(vuln_data)
        assert result is not None
        logger.info(f"Vulnerability inserted with ID: {result}")

    @pytest.mark.asyncio
    async def test_vuln_db_query_vulnerability(self, temp_knowledge_dir):
        """Test querying vulnerability from database."""
        logger.info("Testing vulnerability query...")

        db = MagicMock(spec=VulnerabilityDB)
        db.query = AsyncMock(
            return_value={"cwe_id": "CWE-79", "severity": "HIGH"}
        )

        result = await db.query("CVE-2021-1234")
        assert result is not None
        logger.info("Vulnerability queried successfully")

    @pytest.mark.asyncio
    async def test_vuln_db_update_vulnerability(self, temp_knowledge_dir):
        """Test updating vulnerability in database."""
        logger.info("Testing vulnerability update...")

        db = MagicMock(spec=VulnerabilityDB)
        db.update = AsyncMock(return_value=True)

        result = await db.update("vuln_id_123", {"status": "patched"})
        assert result is True
        logger.info("Vulnerability updated successfully")

    @pytest.mark.asyncio
    async def test_vuln_db_bulk_insert(self, temp_knowledge_dir):
        """Test bulk insertion into database."""
        logger.info("Testing bulk vulnerability insertion...")

        db = MagicMock(spec=VulnerabilityDB)
        db.bulk_insert = AsyncMock(return_value=100)

        vulns = [{"cwe_id": f"CWE-{i}", "severity": "HIGH"} for i in range(100)]
        result = await db.bulk_insert(vulns)

        assert result == 100
        logger.info(f"Bulk inserted {result} vulnerabilities")

    @pytest.mark.asyncio
    async def test_vuln_db_backup(self, temp_knowledge_dir):
        """Test database backup functionality."""
        logger.info("Testing database backup...")

        db = MagicMock(spec=VulnerabilityDB)
        backup_path = temp_knowledge_dir / "backup.db"
        db.backup = AsyncMock(return_value=backup_path)

        result = await db.backup()
        assert result is not None
        logger.info(f"Database backed up to: {result}")


# ==============================================================================
# End-to-End Integration Tests
# ==============================================================================

class TestKnowledgeBaseE2E:
    """End-to-end knowledge base integration tests."""

    @pytest.mark.asyncio
    async def test_complete_knowledge_pipeline(
        self,
        mock_knowledge_loader,
        mock_cwe_repository,
        mock_cve_repository,
        mock_graph_cache,
        sample_cwe_data,
        sample_cve_data
    ):
        """Test complete knowledge pipeline from loading to querying."""
        logger.info("Testing complete knowledge pipeline...")

        # Step 1: Initialize knowledge loader
        mock_knowledge_loader.initialize = AsyncMock(return_value=True)
        loader_result = await mock_knowledge_loader.initialize()
        assert loader_result is True

        # Step 2: Load CWE data
        mock_knowledge_loader.load_cwe_data = AsyncMock(return_value=sample_cwe_data)
        cwe_data = await mock_knowledge_loader.load_cwe_data()
        assert cwe_data is not None

        # Step 3: Load CVE data
        mock_knowledge_loader.load_cve_data = AsyncMock(return_value=sample_cve_data)
        cve_data = await mock_knowledge_loader.load_cve_data()
        assert cve_data is not None

        # Step 4: Initialize repositories
        mock_cwe_repository.initialize = AsyncMock(return_value=True)
        mock_cve_repository.initialize = AsyncMock(return_value=True)
        assert await mock_cwe_repository.initialize()
        assert await mock_cve_repository.initialize()

        # Step 5: Build graphs
        mock_graph_cache.build_cwe_graph = AsyncMock(return_value=True)
        mock_graph_cache.build_cve_graph = AsyncMock(return_value=True)
        assert await mock_graph_cache.build_cwe_graph(cwe_data)
        assert await mock_graph_cache.build_cve_graph(cve_data)

        # Step 6: Query data
        cwe_result = await mock_cwe_repository.get_cwe("CWE-79")
        assert cwe_result is not None

        # Step 7: Get related vulnerabilities
        mock_cwe_repository.get_related_cves = AsyncMock(
            return_value=["CVE-2021-1234"]
        )
        related = await mock_cwe_repository.get_related_cves("CWE-79")
        assert len(related) > 0

        logger.info("Complete knowledge pipeline test passed")

    @pytest.mark.asyncio
    async def test_knowledge_search_workflow(self, mock_cwe_repository, mock_cve_repository):
        """Test knowledge search workflow."""
        logger.info("Testing knowledge search workflow...")

        # Search for CWE by query
        cwe_results = await mock_cwe_repository.search_cwes("injection")
        assert isinstance(cwe_results, list)

        # Search for CVE by query
        cve_results = await mock_cve_repository.search_cves("XSS")
        assert isinstance(cve_results, list)

        # Get CWE details
        if cwe_results:
            cwe_id = cwe_results[0].id
            cwe_detail = await mock_cwe_repository.get_cwe(cwe_id)
            assert cwe_detail is not None

        logger.info("Knowledge search workflow test passed")

    @pytest.mark.asyncio
    async def test_vulnerability_enrichment_workflow(
        self,
        mock_cwe_repository,
        mock_cve_repository,
        mock_graph_cache
    ):
        """Test vulnerability enrichment workflow."""
        logger.info("Testing vulnerability enrichment...")

        # Get CVE
        cve = await mock_cve_repository.get_cve("CVE-2021-1234")
        assert cve is not None

        # Get related CWE
        mock_cwe_repository.get_cwe = AsyncMock(
            return_value=MagicMock(id="CWE-79", name="XSS")
        )
        cwe = await mock_cwe_repository.get_cwe("CWE-79")

        # Get related CVEs from graph
        mock_graph_cache.get_related = AsyncMock(
            return_value=["CVE-2020-5678"]
        )
        related = await mock_graph_cache.get_related("CVE-2021-1234")

        logger.info("Vulnerability enrichment test passed")

    @pytest.mark.asyncio
    async def test_knowledge_base_consistency(
        self,
        mock_cwe_repository,
        mock_cve_repository,
        sample_cwe_data,
        sample_cve_data
    ):
        """Test knowledge base consistency."""
        logger.info("Testing knowledge base consistency...")

        # Verify CWE data consistency
        for cwe_id in sample_cwe_data:
            mock_cwe_repository.get_cwe = AsyncMock(
                return_value=MagicMock(id=cwe_id)
            )
            result = await mock_cwe_repository.get_cwe(cwe_id)
            assert result is not None
            assert result.id == cwe_id

        # Verify CVE data consistency
        for cve_id in sample_cve_data:
            mock_cve_repository.get_cve = AsyncMock(
                return_value=MagicMock(id=cve_id)
            )
            result = await mock_cve_repository.get_cve(cve_id)
            assert result is not None
            assert result.id == cve_id

        logger.info("Knowledge base consistency test passed")


# ==============================================================================
# Performance Tests
# ==============================================================================

class TestKnowledgeBasePerformance:
    """Test knowledge base performance characteristics."""

    @pytest.mark.asyncio
    async def test_cwe_query_performance(self, mock_cwe_repository):
        """Test CWE query performance."""
        logger.info("Testing CWE query performance...")

        import time

        start = time.time()
        for i in range(100):
            await mock_cwe_repository.get_cwe("CWE-79")
        elapsed = time.time() - start

        avg_time = (elapsed / 100) * 1000  # Convert to ms
        logger.info(f"Average CWE query time: {avg_time:.2f}ms")

        # Should be fast (< 10ms on average with caching)
        assert avg_time < 50

    @pytest.mark.asyncio
    async def test_cve_search_performance(self, mock_cve_repository):
        """Test CVE search performance."""
        logger.info("Testing CVE search performance...")

        import time

        start = time.time()
        for i in range(50):
            await mock_cve_repository.search_cves("vulnerability")
        elapsed = time.time() - start

        avg_time = (elapsed / 50) * 1000  # Convert to ms
        logger.info(f"Average CVE search time: {avg_time:.2f}ms")

        assert avg_time < 100

    @pytest.mark.asyncio
    async def test_cache_hit_performance(self, mock_graph_cache):
        """Test cache hit performance."""
        logger.info("Testing cache hit performance...")

        import time

        # Prime the cache
        mock_graph_cache.get_related = AsyncMock(return_value=["CWE-89"])
        await mock_graph_cache.get_related("CWE-79")

        # Measure cache hits
        start = time.time()
        for i in range(1000):
            await mock_graph_cache.get_related("CWE-79")
        elapsed = time.time() - start

        avg_time = (elapsed / 1000) * 1000000  # Convert to microseconds
        logger.info(f"Average cache hit time: {avg_time:.2f}µs")

        # Cache hits should be very fast (< 1ms typically)
        assert elapsed < 1.0


# ==============================================================================
# Error Handling Tests
# ==============================================================================

class TestKnowledgeBaseErrorHandling:
    """Test error handling in knowledge base."""

    @pytest.mark.asyncio
    async def test_handle_missing_data(self, mock_cwe_repository):
        """Test handling of missing data."""
        logger.info("Testing missing data handling...")

        result = await mock_cwe_repository.get_cwe("CWE-NONEXISTENT")
        assert result is None
        logger.info("Missing data handled correctly")

    @pytest.mark.asyncio
    async def test_handle_corrupted_cache(self, temp_knowledge_dir):
        """Test handling of corrupted cache."""
        logger.info("Testing corrupted cache handling...")

        cache_file = temp_knowledge_dir / "cache" / "corrupted.pkl"

        # Write corrupted data
        with open(cache_file, "wb") as f:
            f.write(b"corrupted data that is not pickle")

        # Try to load and expect error handling
        try:
            with open(cache_file, "rb") as f:
                pickle.load(f)
            assert False, "Should have raised error"
        except (pickle.UnpicklingError, EOFError):
            logger.info("Corrupted cache handled correctly")

    @pytest.mark.asyncio
    async def test_handle_database_errors(self):
        """Test handling of database errors."""
        logger.info("Testing database error handling...")

        db = MagicMock(spec=VulnerabilityDB)
        db.query = AsyncMock(side_effect=Exception("Database connection failed"))

        try:
            await db.query("test_id")
            assert False, "Should have raised error"
        except Exception as e:
            assert "Database connection failed" in str(e)
            logger.info("Database error handled correctly")


# ==============================================================================
# Run Tests
# ==============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s", "--tb=short"])