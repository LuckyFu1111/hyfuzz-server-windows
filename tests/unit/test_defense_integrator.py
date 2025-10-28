import pytest

from src.defense import DefenseIntegrator


def test_defense_recommendations_generated():
    integrator = DefenseIntegrator()
    recommendations = integrator.assess_payload({"payload": "SELECT * FROM users"})
    assert recommendations
    actions = {rec.action for rec in recommendations}
    assert "increase_mutation" in actions or "diversify" in actions


if __name__ == "__main__":
    pytest.main([__file__])
