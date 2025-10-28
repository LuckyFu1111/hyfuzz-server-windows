"""Detect attempts to evade detection based on historical patterns."""

from __future__ import annotations

from typing import Mapping


class EvasionDetector:
    def __init__(self) -> None:
        self._history: set[str] = set()

    def detect(self, parsed_event: Mapping[str, object]) -> Mapping[str, float]:
        fingerprint = repr(sorted(parsed_event["payload"].items()))
        seen_before = fingerprint in self._history
        if not seen_before:
            self._history.add(fingerprint)
        return {"suspicious_overlap": 0.8 if seen_before else 0.2}


if __name__ == "__main__":
    detector = EvasionDetector()
    first = detector.detect({"payload": {"payload": "test"}})
    second = detector.detect({"payload": {"payload": "test"}})
    assert second["suspicious_overlap"] > first["suspicious_overlap"]
    print("evasion_detector self-test passed.")
