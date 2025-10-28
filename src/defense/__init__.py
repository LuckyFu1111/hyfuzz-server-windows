"""Defense aware analytics for HyFuzz Windows Server."""

from .defense_integrator import DefenseIntegrator
from .waf_integrator import WAFIntegrator
from .ids_integrator import IDSIntegrator
from .defense_models import DefenseFinding, DefenseDecision

__all__ = [
    "DefenseIntegrator",
    "WAFIntegrator",
    "IDSIntegrator",
    "DefenseFinding",
    "DefenseDecision",
]


if __name__ == "__main__":  # pragma: no cover - smoke test
    waf = WAFIntegrator()
    ids = IDSIntegrator()
    integrator = DefenseIntegrator(waf, ids)
    report = integrator.evaluate([{"message": "Possible SQLi", "confidence": 0.8}])
    assert report.overall_score >= 0
    print("Defense package self-test passed.")
