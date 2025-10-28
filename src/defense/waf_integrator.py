"""Simple heuristic WAF integrator."""

from __future__ import annotations

import re
from typing import Dict, Iterable, List, Mapping

from .defense_models import DefenseEvent


class WAFIntegrator:
    """Applies lightweight heuristics inspired by WAF rule sets."""

    DEFAULT_PATTERNS = {
        "sql_injection": re.compile(r"(?:select|union|drop)\s", re.I),
        "command_injection": re.compile(r"(?:;|&&|\|\|)"),
        "path_traversal": re.compile(r"\.\./"),
    }

    def __init__(self, patterns: Mapping[str, re.Pattern[str]] | None = None) -> None:
        self.patterns = dict(patterns or self.DEFAULT_PATTERNS)

    def inspect(self, payload: Mapping[str, object]) -> DefenseEvent:
        text = " ".join(str(value) for value in payload.values())
        detections = [name for name, pattern in self.patterns.items() if pattern.search(text)]
        risk = min(1.0, 0.2 * len(detections))
        return DefenseEvent(payload=dict(payload), detections=detections, risk_score=risk)

    def bulk_inspect(self, payloads: Iterable[Mapping[str, object]]) -> List[DefenseEvent]:
        return [self.inspect(payload) for payload in payloads]


if __name__ == "__main__":
    waf = WAFIntegrator()
    event = waf.inspect({"payload": "SELECT * FROM users"})
    assert "sql_injection" in event.detections
    print("waf_integrator self-test passed.")
