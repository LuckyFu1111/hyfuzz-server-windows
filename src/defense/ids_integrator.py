"""LLM assisted IDS integrator."""

from __future__ import annotations

import math
from types import SimpleNamespace
from typing import Iterable, List, Mapping, Sequence

import networkx as nx
import numpy as np

# LLM service is optional in lightweight environments
try:  # pragma: no cover - defensive import
    from ..llm.llm_service import LLMService  # type: ignore
except Exception:  # pragma: no cover - fallback stub
    LLMService = None  # type: ignore
# Prompt builder is optional because the full LLM pipeline may not be available
try:  # pragma: no cover - defensive import
    from ..llm.prompt_builder import PromptBuilder  # type: ignore
except Exception:  # pragma: no cover - fallback for lightweight environments
    class PromptBuilder:  # type: ignore
        """Minimal prompt builder used when the full implementation is unavailable."""

        def __init__(self, system_prompt: str = "") -> None:
            self.system_prompt = system_prompt

        def build_prompt(self, instruction: str, context: Mapping[str, object]) -> str:
            return f"SYSTEM: {self.system_prompt}\nINSTRUCTION: {instruction}\nCONTEXT: {context}"

try:  # pragma: no cover - optional utility
    from ..llm.utils import ensure_event_loop  # type: ignore
except Exception:  # pragma: no cover - provide local helper
    import asyncio

    def ensure_event_loop():
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        return loop
from .defense_models import DefenseEvent, DefenseInsight


class SimpleVectorStore:
    """Small in-memory vector store supporting cosine similarity."""

    def __init__(self) -> None:
        self._vectors: List[np.ndarray] = []
        self._payloads: List[Mapping[str, object]] = []

    def add(self, payload: Mapping[str, object]) -> None:
        vector = self._embed(payload)
        self._vectors.append(vector)
        self._payloads.append(dict(payload))

    def similar(self, payload: Mapping[str, object], top_k: int = 3) -> List[Mapping[str, object]]:
        if not self._vectors:
            return []
        query = self._embed(payload)
        scores = [self._cosine(query, vec) for vec in self._vectors]
        best = np.argsort(scores)[::-1][:top_k]
        return [self._payloads[idx] for idx in best]

    def _embed(self, payload: Mapping[str, object]) -> np.ndarray:
        joined = " ".join(str(v) for v in payload.values())
        bucket = np.zeros(16)
        for char in joined:
            bucket[hash(char) % len(bucket)] += 1
        norm = np.linalg.norm(bucket)
        return bucket if norm == 0 else bucket / norm

    @staticmethod
    def _cosine(a: np.ndarray, b: np.ndarray) -> float:
        denom = np.linalg.norm(a) * np.linalg.norm(b)
        return float(np.dot(a, b) / denom) if denom else 0.0


class IDSIntegrator:
    """Combines WAF style heuristics with LLM reasoning."""

    def __init__(self, llm_service: LLMService | None = None) -> None:
        if llm_service is not None:
            self.llm_service = llm_service
        elif LLMService is not None:
            try:
                self.llm_service = LLMService()  # type: ignore[arg-type]
            except TypeError:  # pragma: no cover - fallback if ctor requires args
                self.llm_service = self._build_mock_service()
        else:
            self.llm_service = self._build_mock_service()
        self.vector_store = SimpleVectorStore()
        self.graph = nx.Graph()
        self.builder = PromptBuilder(system_prompt="You are an IDS expert focusing on fuzzing payloads.")

    @staticmethod
    def _build_mock_service() -> SimpleNamespace:
        async def _generate_response(prompt: str):  # pragma: no cover - trivial
            return SimpleNamespace(summary="Mock analysis", highlights=[prompt[:32]], confidence=0.5)

        return SimpleNamespace(generate_response=_generate_response)

    async def score_payload(self, payload: Mapping[str, object]) -> DefenseInsight:
        self.vector_store.add(payload)
        related = self.vector_store.similar(payload)
        for related_payload in related:
            self._update_graph(payload, related_payload)

        prompt = self.builder.build_prompt(
            instruction="Assess the malicious potential of this payload.",
            context={
                "payload": payload,
                "related_payloads": related,
                "graph_stats": self._graph_summary(),
            },
        )

        response = await self.llm_service.generate_response(prompt)
        confidence = max(0.1, min(0.99, response.confidence or 0.5))
        return DefenseInsight(response.summary or "No summary", response.highlights or [], confidence)

    def _update_graph(self, payload: Mapping[str, object], related: Mapping[str, object]) -> None:
        a = hash(tuple(sorted(payload.items())))
        b = hash(tuple(sorted(related.items())))
        self.graph.add_node(a, payload=payload)
        self.graph.add_node(b, payload=related)
        weight = float(len(set(payload.values()) & set(related.values())) + 1)
        self.graph.add_edge(a, b, weight=weight)

    def _graph_summary(self) -> Mapping[str, float]:
        if not self.graph:
            return {"nodes": 0, "edges": 0, "density": 0.0}
        nodes = self.graph.number_of_nodes()
        edges = self.graph.number_of_edges()
        density = nx.density(self.graph)
        return {"nodes": nodes, "edges": edges, "density": float(density)}

    async def analyse_events(self, events: Iterable[DefenseEvent]) -> List[DefenseInsight]:
        results: List[DefenseInsight] = []
        for event in events:
            results.append(await self.score_payload(event.payload))
        return results

    def sync_score_payload(self, payload: Mapping[str, object]) -> DefenseInsight:
        loop = ensure_event_loop()
        return loop.run_until_complete(self.score_payload(payload))


if __name__ == "__main__":
    from ..llm.llm_client import LLMClient

    service = LLMService(client=LLMClient(base_url="http://localhost", model="mock"))
    integrator = IDSIntegrator(service)
    insight = integrator.sync_score_payload({"payload": "../../etc/passwd"})
    assert isinstance(insight.confidence, float)
    print("ids_integrator self-test passed.")
