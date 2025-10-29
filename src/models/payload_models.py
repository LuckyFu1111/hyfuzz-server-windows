"""Payload data models."""

from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

@dataclass
class Payload:
    content: str
    protocol: str

@dataclass
class PayloadBatch:
    items: List[Payload]

def _self_test() -> bool:
    """Basic smoke test for module."""
    try:
        _ = Payload.__name__
        _ = PayloadBatch.__name__
        return True
    except Exception as exc:
        print(f"Self test failed: {exc}")
        return False

if __name__ == "__main__":
    print("Module self test:", _self_test())
