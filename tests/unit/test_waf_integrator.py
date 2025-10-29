import pytest

from src.defense.defense_models import DefenseEvent, DefenseSignal
from src.defense.waf_integrator import WAFIntegrator


def test_waf_blocks_malicious_reason() -> None:
    event = DefenseEvent(source="waf", payload={"status": "blocked", "reason": "sql_injection"})
    signal = DefenseSignal(event=event, severity="low", confidence=0.4)
    integrator = WAFIntegrator(blocklist=["sql_injection"])

    result = integrator.handle_signal(signal)

    assert result is not None
    assert result.verdict == "block"
    assert result.actions[0].metadata["reason"] == "sql_injection"


def test_waf_allows_benign_reason() -> None:
    event = DefenseEvent(source="waf", payload={"status": "allowed", "reason": "static_asset"})
    signal = DefenseSignal(event=event, severity="low", confidence=0.9)
    integrator = WAFIntegrator()

    assert integrator.handle_signal(signal) is None


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__])
