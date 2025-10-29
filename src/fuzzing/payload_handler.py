"""Payload handler for fuzzing inputs."""

from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

@dataclass
class PayloadHandler:
    mutations: List[str]
    def prepare(self, seed: str) -> List[str]:
        return [seed + mutation for mutation in self.mutations]

def _self_test() -> bool:
    """Basic smoke test for module."""
    try:
        _ = PayloadHandler.__name__
        return True
    except Exception as exc:
        print(f"Self test failed: {exc}")
        return False

if __name__ == "__main__":
    print("Module self test:", _self_test())
