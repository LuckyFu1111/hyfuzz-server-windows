"""Embedding manager coordinating vector storage and retrieval."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class EmbeddingRecord:
    """Simple embedding record."""

    key: str
    vector: List[float]


@dataclass
class EmbeddingManager:
    """Lightweight embedding store used for tests."""

    embeddings: Dict[str, EmbeddingRecord] = field(default_factory=dict)

    def add(self, key: str, vector: List[float]) -> None:
        self.embeddings[key] = EmbeddingRecord(key=key, vector=vector)

    def get(self, key: str) -> List[float]:
        record = self.embeddings.get(key)
        return record.vector if record else []


def _self_test() -> bool:
    manager = EmbeddingManager()
    manager.add("demo", [0.1, 0.2])
    return manager.get("demo") == [0.1, 0.2]


if __name__ == "__main__":
    print("Embedding manager self test:", _self_test())
