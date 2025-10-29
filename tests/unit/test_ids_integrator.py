import pytest

from src.defense.defense_models import DefenseEvent, DefenseSignal
from src.defense.ids_integrator import IDSIntegrator


def test_ids_escalates_on_high_alert() -> None:
    event = DefenseEvent(
        source="ids",
        payload={
            "alert": {
                "severity": "HIGH",
                "description": "Suspicious traffic",
                "signature_id": "SIG-001",
                "sensor": "sensor-1",
                "cve_id": "CVE-2024-0001",
            }
        },
    )
    signal = DefenseSignal(event=event, severity="info", confidence=0.5)
    integrator = IDSIntegrator()

    result = integrator.handle_signal(signal)

    assert result is not None
    assert result.verdict in {"investigate", "monitor"}
    assert any(tag == "CVE-2024-0001" for tag in result.signal.event.tags)


def test_ids_ignores_missing_alert() -> None:
    event = DefenseEvent(source="ids", payload={})
    signal = DefenseSignal(event=event, severity="info", confidence=0.2)

    assert IDSIntegrator().handle_signal(signal) is None


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__])
