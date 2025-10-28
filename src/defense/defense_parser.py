"""Parse heterogeneous defense telemetry into a normalized format."""

from __future__ import annotations

from typing import Dict, Iterable, List

from .defense_models import DefenseFinding


def normalize_events(events: Iterable[Dict[str, object]], source: str) -> List[DefenseFinding]:
    findings: List[DefenseFinding] = []
    for event in events:
        findings.append(
            DefenseFinding(
                source=source,
                message=str(event.get("message", "")),
                confidence=float(event.get("confidence", 0.5)),
                metadata={k: str(v) for k, v in event.items() if k not in {"message", "confidence"}},
            )
        )
    return findings


if __name__ == "__main__":  # pragma: no cover - sanity test
    normalized = normalize_events([{"message": "alert", "confidence": 0.7, "rule": "x"}], "ids")
    assert normalized[0].metadata["rule"] == "x"
    print("Defense parser self-test passed.")
