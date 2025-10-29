"""Defense subsystem public interface."""

from .defense_analyzer import DefenseAnalyzer
from .defense_integrator import DefenseIntegrator
from .defense_models import DefenseEvent, DefenseResult, DefenseSignal
from .ids_integrator import IDSIntegrator
from .log_aggregator import DefenseLogAggregator
from .orchestrator import DefenseOrchestrator
from .threat_context import ThreatContextBuilder
from .waf_integrator import WAFIntegrator

__all__ = [
    "DefenseAnalyzer",
    "DefenseEvent",
    "DefenseIntegrator",
    "DefenseLogAggregator",
    "DefenseOrchestrator",
    "DefenseResult",
    "DefenseSignal",
    "IDSIntegrator",
    "ThreatContextBuilder",
    "WAFIntegrator",
]


if __name__ == "__main__":  # pragma: no cover - illustrative example
    integrator = DefenseIntegrator()
    integrator.register_integrator("waf", WAFIntegrator())
    integrator.register_integrator("ids", IDSIntegrator())
    sample_event = DefenseEvent(source="waf", payload={"status": "blocked"})
    integrator.process_signal(DefenseSignal(event=sample_event))
    print("Registered integrators:", integrator.list_integrators())
