"""Web Application Firewall integration module."""

from __future__ import annotations

from typing import List, Optional

from .defense_integrator import BaseDefenseModule
from .defense_models import DefenseResult, DefenseSignal, DefenseAction

WAF_BLOCK_TAGS = {"blocked", "rate_limited", "mitigated"}


class WAFIntegrator(BaseDefenseModule):
    """Consumes WAF logs and converts them to actionable signals."""

    def __init__(self, blocklist: Optional[List[str]] = None) -> None:
        self.blocklist = blocklist or []

    def handle_signal(self, signal: DefenseSignal) -> Optional[DefenseResult]:
        waf_status = signal.event.payload.get("status", "allowed")
        reason = signal.event.payload.get("reason", "unknown")

        if waf_status.lower() == "allowed" and reason not in self.blocklist:
            return None

        if reason in self.blocklist:
            signal.escalate("high", f"Blocked by custom rule for {reason}")
            if reason.upper().startswith("CVE-"):
                signal.event.tag(reason)

        action = DefenseAction(
            name="waf_block" if waf_status.lower() in WAF_BLOCK_TAGS else "waf_monitor",
            description=f"WAF marked request as {waf_status}",
            metadata={"reason": reason},
        )

        verdict = "block" if waf_status.lower() in WAF_BLOCK_TAGS else "monitor"
        rationale = f"WAF decision: {waf_status} (reason={reason})"
        return DefenseResult(signal=signal, actions=[action], verdict=verdict, rationale=rationale)


if __name__ == "__main__":
    from .defense_models import DefenseEvent

    event = DefenseEvent(source="waf", payload={"status": "blocked", "reason": "sql_injection"})
    signal = DefenseSignal(event=event, severity="medium")
    integrator = WAFIntegrator(blocklist=["sql_injection"])
    result = integrator.handle_signal(signal)
    print(result.to_dict() if result else "No result")
