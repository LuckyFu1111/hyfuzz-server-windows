"""Validation helpers for protocol payloads."""

from __future__ import annotations

from typing import Dict


class ProtocolValidator:
    """Validates payload dictionaries."""

    def ensure_fields(self, payload: Dict[str, object], *fields: str) -> bool:
        missing = [field for field in fields if field not in payload]
        if missing:
            raise ValueError(f"Missing required fields: {', '.join(missing)}")
        return True


if __name__ == "__main__":
    validator = ProtocolValidator()
    print(validator.ensure_fields({"path": "/", "method": "GET"}, "path", "method"))
    try:
        validator.ensure_fields({}, "path")
    except ValueError as exc:
        print("Validation failed:", exc)
