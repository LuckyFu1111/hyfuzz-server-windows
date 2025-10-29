"""Sandbox manager for executing payloads safely."""

from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

@dataclass
class SandboxManager:
    active: bool = False
    def start(self) -> None:
        self.active = True
    def stop(self) -> None:
        self.active = False

def _self_test() -> bool:
    """Basic smoke test for module."""
    try:
        _ = SandboxManager.__name__
        return True
    except Exception as exc:
        print(f"Self test failed: {exc}")
        return False

if __name__ == "__main__":
    print("Module self test:", _self_test())
