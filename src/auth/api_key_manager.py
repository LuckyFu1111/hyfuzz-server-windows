"""API key management."""

from __future__ import annotations

from secrets import token_urlsafe
from typing import Dict


class APIKeyManager:
    def __init__(self) -> None:
        self.keys: Dict[str, str] = {}

    def generate(self, name: str) -> str:
        key = token_urlsafe(24)
        self.keys[name] = key
        return key

    def validate(self, key: str) -> bool:
        return key in self.keys.values()


if __name__ == "__main__":
    manager = APIKeyManager()
    key = manager.generate("demo")
    print("Valid:", manager.validate(key))
