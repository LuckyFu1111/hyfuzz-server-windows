"""Tests for the DefenseOrchestrator helper."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from src.defense import DefenseEvent, DefenseOrchestrator


@pytest.fixture()
def orchestrator_config(tmp_path: Path) -> Path:
    payload = {
        "integrators": {
            "waf": {"type": "waf", "options": {"blocklist": ["forbidden"]}},
            "ids": {"type": "ids"},
        },
        "defaults": {"severity": "low", "confidence": 0.7},
    }
    path = tmp_path / "defense.yaml"
    path.write_text(yaml.safe_dump(payload), encoding="utf-8")
    return path


def test_from_file_registers_integrators(orchestrator_config: Path) -> None:
    orchestrator = DefenseOrchestrator.from_file(orchestrator_config)
    assert sorted(orchestrator.list_integrators()) == ["ids", "waf"]

    event = DefenseEvent(source="waf", payload={"status": "blocked", "reason": "forbidden"})
    result = orchestrator.process_event(event)

    assert result is not None
    assert result.verdict in {"block", "investigate"}
    assert pytest.approx(result.signal.confidence, rel=1e-3) == 0.7


def test_process_events_returns_only_results(orchestrator_config: Path) -> None:
    orchestrator = DefenseOrchestrator.from_file(orchestrator_config)

    events = [
        DefenseEvent(source="waf", payload={"status": "blocked", "reason": "forbidden"}),
        DefenseEvent(source="waf", payload={"status": "allowed", "reason": "forbidden"}),
    ]
    results = orchestrator.process_events(events)

    assert len(results) == 2
    verdicts = {item.verdict for item in results}
    assert "investigate" in verdicts
    assert verdicts <= {"monitor", "investigate", "block"}


if __name__ == "__main__":
    pytest.main([__file__])
