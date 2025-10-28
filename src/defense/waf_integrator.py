"""Lightweight Web Application Firewall (WAF) log integrator."""

from __future__ import annotations

from typing import Iterable, List

from .defense_models import DefenseFinding


class WAFIntegrator:
    """Process WAF log events into defense findings."""

    def parse_logs(self, logs: Iterable[dict]) -> List[DefenseFinding]:
        findings: List[DefenseFinding] = []
        for log in logs:
            message = log.get("message", "")
            confidence = float(log.get("confidence", 0.5))
            findings.append(
                DefenseFinding(
                    source="waf",
                    message=message or "Anomalous request detected",
                    confidence=max(0.0, min(confidence, 1.0)),
                    metadata={"rule": log.get("rule", "unknown")},
                )
            )
        return findings


if __name__ == "__main__":  # pragma: no cover - sanity test
    integrator = WAFIntegrator()
    findings = integrator.parse_logs([{"message": "SQLi pattern", "confidence": 0.9, "rule": "942100"}])
    assert findings[0].metadata["rule"] == "942100"
    print("WAF integrator self-test passed.")
