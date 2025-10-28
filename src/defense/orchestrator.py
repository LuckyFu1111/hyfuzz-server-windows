"""High-level defense orchestration helpers for the HyFuzz server."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Mapping, MutableMapping, Optional, Sequence

import yaml

from .defense_integrator import BaseDefenseModule, DefenseIntegrator
from .defense_models import DefenseEvent, DefenseResult, DefenseSignal
from .ids_integrator import IDSIntegrator
from .threat_context import ThreatContextBuilder
from .waf_integrator import WAFIntegrator

LOGGER = logging.getLogger(__name__)

# Mapping between short names and concrete defense module factories.
INTEGRATOR_FACTORIES: Dict[str, Callable[..., BaseDefenseModule]] = {
    "waf": WAFIntegrator,
    "ids": IDSIntegrator,
}


class DefenseOrchestrator:
    """Convenience wrapper around :class:`DefenseIntegrator`.

    The orchestrator reads configuration files, registers the requested defense
    modules, and exposes ergonomic helpers that turn raw events into processed
    :class:`DefenseResult` objects. This is intended to be used by the Windows
    service responsible for ingesting WAF/IDS telemetry before forwarding the
    aggregated verdicts to the rest of the fuzzing pipeline.
    """

    def __init__(
        self,
        *,
        integrator: Optional[DefenseIntegrator] = None,
        context_builder: Optional[ThreatContextBuilder] = None,
        defaults: Optional[Mapping[str, Any]] = None,
    ) -> None:
        self.context_builder = context_builder or ThreatContextBuilder()
        self.integrator = integrator or DefenseIntegrator(context_builder=self.context_builder)
        self.defaults: Dict[str, Any] = {
            "severity": "info",
            "confidence": 0.5,
        }
        if defaults:
            self.defaults.update({key: value for key, value in defaults.items() if value is not None})

    # ------------------------------------------------------------------
    # Configuration helpers
    # ------------------------------------------------------------------
    @classmethod
    def from_file(
        cls,
        config_path: Path | str,
        *,
        context_builder: Optional[ThreatContextBuilder] = None,
    ) -> "DefenseOrchestrator":
        """Instantiate an orchestrator from a YAML configuration file."""

        path = Path(config_path)
        if not path.exists():
            raise FileNotFoundError(f"Defense configuration file not found: {path}")
        with path.open("r", encoding="utf-8") as handle:
            raw_config = yaml.safe_load(handle) or {}
        return cls.from_mapping(raw_config, context_builder=context_builder)

    @classmethod
    def from_mapping(
        cls,
        config: Mapping[str, Any],
        *,
        context_builder: Optional[ThreatContextBuilder] = None,
    ) -> "DefenseOrchestrator":
        """Instantiate an orchestrator from an in-memory mapping."""

        defaults = config.get("defaults", {}) if isinstance(config, Mapping) else {}
        orchestrator = cls(context_builder=context_builder, defaults=defaults)
        orchestrator.configure_integrators(config.get("integrators", {}))
        return orchestrator

    def configure_integrators(self, integrators_config: Mapping[str, Any]) -> None:
        """Register defense modules as described by the configuration."""

        for name, entry in integrators_config.items():
            if not isinstance(entry, Mapping):
                LOGGER.warning("Skipping malformed integrator config for %s", name)
                continue
            module_type = str(entry.get("type", name)).lower()
            factory = INTEGRATOR_FACTORIES.get(module_type)
            if not factory:
                available = ", ".join(sorted(INTEGRATOR_FACTORIES)) or "<none>"
                raise ValueError(
                    f"Unsupported defense integrator '{module_type}'. Available: {available}"
                )
            options = entry.get("options", {}) if isinstance(entry.get("options"), Mapping) else {}
            module = factory(**options)
            self.integrator.register_integrator(name, module)
            LOGGER.debug("Registered defense integrator '%s' of type '%s'", name, module_type)

    # ------------------------------------------------------------------
    # Processing helpers
    # ------------------------------------------------------------------
    def process_event(
        self,
        event: DefenseEvent,
        *,
        severity: Optional[str] = None,
        confidence: Optional[float] = None,
    ) -> Optional[DefenseResult]:
        """Convert a raw event into a :class:`DefenseResult`."""

        signal = DefenseSignal(
            event=event,
            severity=severity or self.defaults.get("severity", "info"),
            confidence=float(
                confidence if confidence is not None else self.defaults.get("confidence", 0.5)
            ),
        )
        return self.integrator.process_signal(signal)

    def process_events(
        self,
        events: Iterable[DefenseEvent],
        *,
        severity: Optional[str] = None,
        confidence: Optional[float] = None,
    ) -> Sequence[DefenseResult]:
        """Process multiple events in order and return all generated results."""

        results: list[DefenseResult] = []
        for event in events:
            result = self.process_event(event, severity=severity, confidence=confidence)
            if result:
                results.append(result)
        return results

    # ------------------------------------------------------------------
    # Delegated helpers
    # ------------------------------------------------------------------
    def subscribe(self, callback: Callable[[DefenseResult], None]) -> None:
        """Register a callback on the underlying integrator."""

        self.integrator.subscribe(callback)

    def list_integrators(self) -> Sequence[str]:
        """Return the names of registered defense modules."""

        return self.integrator.list_integrators()

    # ------------------------------------------------------------------
    # Serialization helpers
    # ------------------------------------------------------------------
    @staticmethod
    def load_default_config() -> Mapping[str, Any]:
        """Load the bundled defense configuration if it exists."""

        default_path = Path("config/defense_config.yaml")
        if not default_path.exists():
            return {}
        with default_path.open("r", encoding="utf-8") as handle:
            return yaml.safe_load(handle) or {}


if __name__ == "__main__":
    sample_config: MutableMapping[str, Any] = {
        "integrators": {
            "waf": {"type": "waf", "options": {"blocklist": ["CVE-2020-93810"]}},
            "ids": {"type": "ids"},
        },
        "defaults": {"severity": "low", "confidence": 0.65},
    }
    orchestrator = DefenseOrchestrator.from_mapping(sample_config)
    orchestrator.subscribe(lambda result: LOGGER.info("Verdict: %s", result.verdict))
    demo_event = DefenseEvent(source="waf", payload={"status": "blocked", "reason": "CVE-2020-93810"})
    processed = orchestrator.process_event(demo_event)
    print(processed.to_dict() if processed else "No result produced")
