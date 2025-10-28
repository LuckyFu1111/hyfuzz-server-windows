"""Unit tests for the enhanced defense integration pipeline."""

from __future__ import annotations

from typing import Dict

from src.defense import (
    DefenseEvent,
    DefenseIntegrator,
    DefenseSignal,
    IDSIntegrator,
    ThreatContextBuilder,
    WAFIntegrator,
)


def _make_context_builder() -> ThreatContextBuilder:
    sample_cves: Dict[str, Dict[str, object]] = {
        "CVE-2020-93810": {
            "cve_id": "CVE-2020-93810",
            "title": "Remote Code Execution in demo service",
            "severity": "critical",
            "references": ["https://example.com/CVE-2020-93810"],
        }
    }
    return ThreatContextBuilder(cve_index={key.upper(): value for key, value in sample_cves.items()})


def test_integrator_enriches_context_and_notifies() -> None:
    builder = _make_context_builder()
    integrator = DefenseIntegrator(context_builder=builder)
    integrator.register_integrator("waf", WAFIntegrator(blocklist=["CVE-2020-93810"]))
    integrator.register_integrator("ids", IDSIntegrator())

    notifications = []
    integrator.subscribe(lambda result: notifications.append(result.verdict))

    event = DefenseEvent(
        source="edge",
        payload={
            "status": "blocked",
            "reason": "CVE-2020-93810",
            "alert": {
                "severity": "High",
                "description": "Exploit attempt detected",
                "signature_id": "CVE-2020-93810",
                "sensor": "ids-main",
                "cve_id": "CVE-2020-93810",
            },
        },
    )
    signal = DefenseSignal(event=event, severity="info", confidence=0.55)

    result = integrator.process_signal(signal)

    assert result is not None
    assert result.verdict == "block"
    assert result.risk_score >= 0.85
    assert notifications == ["block"]
    assert result.context["cves"][0]["cve_id"] == "CVE-2020-93810"
    assert "knowledge_risk" in result.context["analytics"]
    assert "average_risk_window" in result.context["analytics"]


def test_process_batch_tracks_recent_results() -> None:
    builder = ThreatContextBuilder(cve_index={})
    integrator = DefenseIntegrator(context_builder=builder)
    integrator.register_integrator("waf", WAFIntegrator(blocklist=["sql_injection"]))

    events = [
        DefenseEvent(source="waf", payload={"status": "blocked", "reason": "sql_injection"}),
        DefenseEvent(source="waf", payload={"status": "allowed", "reason": "benign"}),
    ]
    signals = [DefenseSignal(event=event, severity="info", confidence=0.7) for event in events]

    results = integrator.process_batch(signals)

    assert len(results) == 1  # only the blocked request should produce an action
    assert integrator.recent_results(1)[0].verdict == "investigate"
    assert integrator.recent_results(5)[-1].context["analytics"]["average_confidence_window"] >= 0.7


if __name__ == "__main__":
    test_integrator_enriches_context_and_notifies()
    test_process_batch_tracks_recent_results()
    print("Defense pipeline tests executed successfully.")
