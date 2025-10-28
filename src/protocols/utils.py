"""Miscellaneous helpers for protocol adapters."""

from __future__ import annotations

from typing import Dict


def normalize_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Normalize headers for deterministic comparison."""

    return {key.lower(): value.strip() for key, value in headers.items()}


if __name__ == "__main__":  # pragma: no cover - sanity test
    headers = {"Content-Type": " application/json ", "Accept": "*/*"}
    normalized = normalize_headers(headers)
    assert normalized["content-type"] == "application/json"
    print("Protocol utils self-test passed.")
