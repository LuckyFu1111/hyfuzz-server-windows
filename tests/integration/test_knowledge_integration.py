"""Integration tests for lightweight knowledge components."""

from __future__ import annotations

from pathlib import Path

from src.knowledge.context_retrieval_layer import ContextRetrievalLayer
from src.knowledge.graph_db_manager import GraphDBManager
from src.knowledge.vector_db_manager import VectorDBManager
from src.knowledge.embedding_manager import EmbeddingManager
from src.models.knowledge_models import CWEModel, CVEModel, VulnerabilityInfo, KnowledgeQueryResult


def test_graph_and_vector_integration(tmp_path: Path) -> None:
    graph = GraphDBManager(nodes={})
    graph.add_node("CWE-79", {"name": "XSS"})

    vector = VectorDBManager(embeddings={})
    vector.add_embedding("CWE-79", [0.1, 0.2, 0.3])

    layer = ContextRetrievalLayer(vector_db=vector, graph_db=graph)
    result = layer.retrieve("CWE-79")

    assert result["graph"] is True
    assert result["vector"] is True


def test_embedding_manager_roundtrip() -> None:
    manager = EmbeddingManager()
    manager.add("CVE-2024-0001", [0.5, 0.5])
    assert manager.get("CVE-2024-0001") == [0.5, 0.5]


def test_knowledge_query_result() -> None:
    cwe = CWEModel(identifier="CWE-79", name="XSS")
    cve = CVEModel(identifier="CVE-2024-0001", severity="HIGH")
    info = VulnerabilityInfo(cwe=cwe, cve=cve, score=0.8)
    result = KnowledgeQueryResult(query="xss", results=[info])

    assert result.results[0].cve.identifier == "CVE-2024-0001"
