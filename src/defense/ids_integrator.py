"""Intrusion Detection System integration module."""

from __future__ import annotations

from typing import Optional

from .defense_integrator import BaseDefenseModule
from .defense_models import DefenseResult, DefenseSignal, DefenseAction

SEVERITY_MAP = {
    "informational": "info",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}


class IDSIntegrator(BaseDefenseModule):
    """Transforms IDS alerts into defense actions."""

    def handle_signal(self, signal: DefenseSignal) -> Optional[DefenseResult]:
        alert = signal.event.payload.get("alert")
        if not alert:
            return None

        ids_severity = alert.get("severity", "informational").lower()
        mapped_severity = SEVERITY_MAP.get(ids_severity, "low")
        signal.escalate(mapped_severity, f"IDS alert of severity {ids_severity}")

        action = DefenseAction(
            name="ids_alert",
            description=alert.get("description", "IDS detected suspicious activity"),
            metadata={
                "signature": alert.get("signature_id"),
                "sensor": alert.get("sensor"),
                "cve_id": alert.get("cve_id"),
            },
        )

        if cve_id := alert.get("cve_id"):
            signal.event.tag(cve_id)

            metadata={"signature": alert.get("signature_id"), "sensor": alert.get("sensor")},
        )

        verdict = "investigate" if mapped_severity in {"medium", "high", "critical"} else "monitor"
        rationale = f"IDS signature {alert.get('signature_id', 'unknown')} triggered"
        return DefenseResult(signal=signal, actions=[action], verdict=verdict, rationale=rationale)


if __name__ == "__main__":
    from .defense_models import DefenseEvent

    event = DefenseEvent(
        source="ids",
        payload={
            "alert": {
                "severity": "High",
                "description": "Potential buffer overflow",
                "signature_id": "BOF-001",
                "sensor": "snort-1",
            }
        },
    )
    signal = DefenseSignal(event=event, severity="info")
    result = IDSIntegrator().handle_signal(signal)
    print(result.to_dict() if result else "No result")
