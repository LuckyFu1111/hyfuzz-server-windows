import pytest

from src.defense.defense_integrator import DefenseIntegrator
from src.defense.defense_models import DefenseEvent, DefenseSignal
from src.defense.ids_integrator import IDSIntegrator
from src.defense.waf_integrator import WAFIntegrator


def test_defense_integrator_with_waf_and_ids() -> None:
    integrator = DefenseIntegrator()
    integrator.register_integrator("waf", WAFIntegrator(blocklist=["sql_injection"]))
    integrator.register_integrator("ids", IDSIntegrator())

    event = DefenseEvent(source="waf", payload={"status": "blocked", "reason": "sql_injection"})
    signal = DefenseSignal(event=event, severity="medium", confidence=0.7)

    result = integrator.process_signal(signal)
    assert result is not None
    assert any(action.name.startswith("waf") for action in result.actions)


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__])
