"""Signal capture helpers for fuzzing targets."""

from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

@dataclass
class SignalCapture:
    signals: List[str]
    def capture(self, signal: str) -> None:
        self.signals.append(signal)

def _self_test() -> bool:
    """Basic smoke test for module."""
    try:
        _ = SignalCapture.__name__
        return True
    except Exception as exc:
        print(f"Self test failed: {exc}")
        return False

if __name__ == "__main__":
    print("Module self test:", _self_test())
