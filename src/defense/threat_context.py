"""Threat intelligence helpers for enriching defense results."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from .defense_models import DefenseSignal


class ThreatContextBuilder:
    """Load lightweight threat intelligence for contextual enrichment."""

    DEFAULT_DATA_PATH = Path("data/sample_cve.json")
    _SEVERITY_SCORES = {
        "critical": 1.0,
        "high": 0.85,
        "medium": 0.6,
        "low": 0.35,
        "none": 0.1,
    }

    def __init__(self, *, data_path: Optional[Path] = None, cve_index: Optional[Dict[str, Dict[str, object]]] = None) -> None:
        self.data_path = data_path or self.DEFAULT_DATA_PATH
        self._cve_index = cve_index or self._load_index(self.data_path)

    def _load_index(self, path: Path) -> Dict[str, Dict[str, object]]:
        if not path.exists():
            return {}
        with path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
        nodes = payload.get("nodes", {})
        return {key.upper(): value for key, value in nodes.items()}

    def build_context(self, signal: DefenseSignal) -> Dict[str, object]:
        """Derive context for a signal by resolving CVE identifiers."""

        cve_ids = self._extract_cve_ids(signal)
        cve_context: List[Dict[str, object]] = []
        knowledge_risk = 0.0

        for cve_id in cve_ids:
            entry = self._cve_index.get(cve_id.upper())
            if not entry:
                cve_context.append({"cve_id": cve_id, "known": False})
                continue
            severity = str(entry.get("severity", "medium")).lower()
            score = self._SEVERITY_SCORES.get(severity, 0.6)
            knowledge_risk = max(knowledge_risk, score)
            cve_context.append(
                {
                    "cve_id": entry.get("cve_id", cve_id),
                    "title": entry.get("title"),
                    "severity": severity,
                    "score": score,
                    "references": entry.get("references", []),
                }
            )

        if not cve_context:
            return {}

        analytics = {"knowledge_risk": knowledge_risk} if knowledge_risk else {}
        return {"cves": cve_context, "analytics": analytics, "tags": list(signal.event.tags)}

    def merge_contexts(self, contexts: Iterable[Dict[str, object]]) -> Dict[str, object]:
        """Merge multiple context payloads into a single dictionary."""

        merged: Dict[str, object] = {"cves": [], "tags": []}
        analytics_risk = 0.0

        for context in contexts:
            if not context:
                continue
            for key in ("cves", "tags"):
                if key in context:
                    merged.setdefault(key, [])
                    for item in context[key]:
                        if item not in merged[key]:
                            merged[key].append(item)
            analytics = context.get("analytics")
            if isinstance(analytics, dict):
                analytics_risk = max(analytics_risk, float(analytics.get("knowledge_risk", 0.0)))

        if analytics_risk:
            merged.setdefault("analytics", {})["knowledge_risk"] = analytics_risk

        # Remove empty containers for cleaner output
        if not merged["cves"]:
            merged.pop("cves")
        if not merged["tags"]:
            merged.pop("tags")

        return merged

    def _extract_cve_ids(self, signal: DefenseSignal) -> List[str]:
        payload = signal.event.payload
        cve_ids: List[str] = []

        def _maybe_add(value: Optional[str]) -> None:
            if not value:
                return
            candidate = str(value).strip()
            if candidate and candidate.upper().startswith("CVE-") and candidate not in cve_ids:
                cve_ids.append(candidate)

        _maybe_add(payload.get("cve_id"))
        alert = payload.get("alert", {})
        if isinstance(alert, dict):
            _maybe_add(alert.get("cve_id"))
            signature = alert.get("signature_id")
            if isinstance(signature, str) and signature.upper().startswith("CVE-"):
                _maybe_add(signature)
        for tag in signal.event.tags:
            _maybe_add(tag)
        return cve_ids


if __name__ == "__main__":
    from .defense_models import DefenseEvent

    builder = ThreatContextBuilder()
    demo_event = DefenseEvent(source="ids", payload={"cve_id": "CVE-2020-93810"})
    demo_event.tag("CVE-2021-22280")
    context = builder.build_context(DefenseSignal(event=demo_event))
    print(context)
