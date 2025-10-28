"""Utility module for parsing protocol messages."""

from __future__ import annotations

import json
from typing import Any, Dict


class ProtocolParser:
    """Parses raw strings into Python dictionaries."""

    def parse(self, raw: str) -> Dict[str, Any]:
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {"raw": raw}


if __name__ == "__main__":
    parser = ProtocolParser()
    print(parser.parse('{"hello": "world"}'))
    print(parser.parse('not json'))
