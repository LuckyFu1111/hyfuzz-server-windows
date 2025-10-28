"""Validates database schema definitions."""

from __future__ import annotations

from typing import Dict


class SchemaValidator:
    def validate(self, schema: Dict[str, str]) -> bool:
        if not schema:
            raise ValueError("Schema is empty")
        return True


if __name__ == "__main__":
    validator = SchemaValidator()
    print(validator.validate({"table": "CREATE TABLE demo"}))
