"""Simple heuristics for detecting defense evasion attempts."""

from __future__ import annotations

from typing import Dict, Iterable, List

from .defense_models import DefenseSignal

SUSPICIOUS_HEADERS = {"x-forwarded-for", "x-real-ip"}


class EvasionDetector:
    """Detects potential evasion attempts based on signals."""

    def __init__(self, suspicious_keywords: Iterable[str] | None = None) -> None:
        self.suspicious_keywords = set(suspicious_keywords or {"bypass", "encoded", "obfuscated"})

    def score(self, signal: DefenseSignal) -> float:
        """Return a score representing likelihood of evasion."""

        score = 0.0
        payload = signal.event.payload
        headers: Dict[str, str] = payload.get("headers", {})
        if any(header.lower() in SUSPICIOUS_HEADERS for header in headers):
            score += 0.3
        anomalies: List[str] = payload.get("anomalies", [])
        for anomaly in anomalies:
            if any(keyword in anomaly.lower() for keyword in self.suspicious_keywords):
                score += 0.25
        score += max(signal.confidence - 0.5, 0) * 0.5
        return min(score, 1.0)

    def is_evasion(self, signal: DefenseSignal, threshold: float = 0.6) -> bool:
        return self.score(signal) >= threshold


if __name__ == "__main__":
    from .defense_models import DefenseEvent

    event = DefenseEvent(
        source="waf",
        payload={
            "headers": {"X-Forwarded-For": "127.0.0.1"},
            "anomalies": ["Payload contained obfuscated SQL"],
        },
    )
    signal = DefenseSignal(event=event, confidence=0.9)
    detector = EvasionDetector()
    print("Evasion score:", detector.score(signal))
    print("Is evasion:", detector.is_evasion(signal))
