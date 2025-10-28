"""LLM assisted Intrusion Detection System (IDS) integrator."""

from __future__ import annotations

from math import exp
from typing import Iterable, List

from .defense_models import DefenseFinding
from .utils import cosine_similarity


class IDSIntegrator:
    """Use lightweight embeddings to evaluate suspicious events."""

    def __init__(self) -> None:
        # A handful of seed embeddings representing known attack categories
        self.knowledge_base = {
            "sql_injection": [0.9, 0.1, 0.2],
            "command_injection": [0.8, 0.2, 0.3],
            "buffer_overflow": [0.1, 0.9, 0.4],
        }

    def _score_event(self, vector: Iterable[float]) -> float:
        scores = [cosine_similarity(vector, reference) for reference in self.knowledge_base.values()]
        return max(scores)

    def analyze_events(self, events: Iterable[dict]) -> List[DefenseFinding]:
        findings: List[DefenseFinding] = []
        for event in events:
            vector = event.get("vector", [0.1, 0.1, 0.1])
            similarity = self._score_event(vector)
            confidence = float(event.get("confidence", similarity))
            risk = 1 - exp(-3 * confidence * similarity)
            findings.append(
                DefenseFinding(
                    source="ids",
                    message=event.get("message", "Suspicious activity"),
                    confidence=min(1.0, max(risk, 0.0)),
                    metadata={"similarity": f"{similarity:.2f}"},
                )
            )
        return findings


if __name__ == "__main__":  # pragma: no cover - sanity test
    ids = IDSIntegrator()
    findings = ids.analyze_events([{"message": "Stack smash", "vector": [0.2, 0.8, 0.4]}])
    assert findings and findings[0].confidence > 0
    print("IDS integrator self-test passed.")
