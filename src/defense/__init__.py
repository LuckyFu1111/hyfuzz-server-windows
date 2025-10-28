"""Defense orchestration package for HyFuzz."""

from .defense_integrator import DefenseIntegrator
from .ids_integrator import IDSIntegrator
from .waf_integrator import WAFIntegrator
from .defense_models import DefenseEvent, DefenseInsight, DefenseRecommendation

__all__ = [
    "DefenseIntegrator",
    "IDSIntegrator",
    "WAFIntegrator",
    "DefenseEvent",
    "DefenseInsight",
    "DefenseRecommendation",
]


if __name__ == "__main__":
    waf = WAFIntegrator()
    ids = IDSIntegrator()
    integrator = DefenseIntegrator(waf=waf, ids=ids)
    events = integrator.assess_payload({"payload": "select * from users"})
    assert events
    print("Defense package smoke test passed.")
