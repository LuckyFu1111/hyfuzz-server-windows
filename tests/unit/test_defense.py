"""Tests for defense integration pipeline."""

from src.defense import DefenseIntegrator
from src.defense.defense_models import DefenseDecision


def test_defense_integrator_combines_sources():
    integrator = DefenseIntegrator()
    decision = integrator.evaluate(
        [
            {"source": "waf", "message": "SQLi", "confidence": 0.9},
            {"source": "ids", "message": "Overflow", "vector": [0.2, 0.8, 0.3]},
        ]
    )
    assert isinstance(decision, DefenseDecision)
    assert decision.findings
    assert "increase" in decision.reasoning or "decrease" in decision.reasoning


def test_defense_summary_groups_findings():
    integrator = DefenseIntegrator()
    decision = integrator.evaluate([{"source": "waf", "message": "rule"}])
    summary = integrator.summarize(decision)
    assert summary["groups"]["waf"] == 1
