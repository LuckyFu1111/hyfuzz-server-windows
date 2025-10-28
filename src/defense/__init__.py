"""Defense integration package for HyFuzz server."""

from .defense_models import DefenseEvent, DefenseResult, DefenseSignal
from .defense_integrator import DefenseIntegrator
from .waf_integrator import WAFIntegrator
from .ids_integrator import IDSIntegrator
from .log_aggregator import DefenseLogAggregator
from .defense_analyzer import DefenseAnalyzer
from .threat_context import ThreatContextBuilder

__all__ = [
    "DefenseEvent",
    "DefenseResult",
    "DefenseSignal",
    "DefenseIntegrator",
    "WAFIntegrator",
    "IDSIntegrator",
    "DefenseLogAggregator",
    "DefenseAnalyzer",
    "ThreatContextBuilder",
]


if __name__ == "__main__":
    integrator = DefenseIntegrator()
    integrator.register_integrator("waf", WAFIntegrator())
    integrator.register_integrator("ids", IDSIntegrator())
    sample_event = DefenseEvent(source="waf", payload={"status": "blocked"})
    integrator.process_signal(DefenseSignal(event=sample_event))
    print("Registered integrators:", integrator.list_integrators())
