"""Protocol-aware fuzzing engine."""

from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

@dataclass
class ProtocolFuzzer:
    protocol: str
    def supported(self) -> bool:
        return self.protocol in {"coap", "modbus", "mqtt", "http"}

def _self_test() -> bool:
    """Basic smoke test for module."""
    try:
        _ = ProtocolFuzzer.__name__
        return True
    except Exception as exc:
        print(f"Self test failed: {exc}")
        return False

if __name__ == "__main__":
    print("Module self test:", _self_test())
