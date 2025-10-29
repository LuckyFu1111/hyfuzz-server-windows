"""Prompt strategy helpers."""

from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

@dataclass
class PromptStrategy:
    name: str
    prefix: str
    def apply(self, seed: str) -> str:
        return f"{self.prefix} {seed}"

def _self_test() -> bool:
    """Basic smoke test for module."""
    try:
        _ = PromptStrategy.__name__
        return True
    except Exception as exc:
        print(f"Self test failed: {exc}")
        return False

if __name__ == "__main__":
    print("Module self test:", _self_test())
