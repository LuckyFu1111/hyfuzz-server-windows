"""Mutation strategies used by the fuzzing engine."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterable, Iterator

from ..protocols.base_protocol import ProtocolPayload


class MutationStrategy(ABC):
    """Base class for mutation strategies."""

    @abstractmethod
    def generate(self, payload: ProtocolPayload) -> Iterable[str]:
        """Yield mutation tokens for the payload."""


class PrefixMutationStrategy(MutationStrategy):
    """Generate prefix variations for payload bodies."""

    def __init__(self, prefix: str) -> None:
        self.prefix = prefix

    def generate(self, payload: ProtocolPayload) -> Iterable[str]:
        return (f"-{self.prefix}{i}" for i in range(3))


def basic_mutations(seed: str) -> Iterator[str]:
    """Generate a deterministic set of basic mutations."""

    for suffix in ("-null", "-overflow", "-unicode"):
        yield f"-{seed}{suffix}"


if __name__ == "__main__":  # pragma: no cover - sanity check
    strategy = PrefixMutationStrategy(prefix="test")
    payload = ProtocolPayload(body=b"demo")
    assert len(list(strategy.generate(payload))) == 3
    assert len(list(basic_mutations("demo"))) == 3
    print("Fuzzing strategies self-test passed.")
