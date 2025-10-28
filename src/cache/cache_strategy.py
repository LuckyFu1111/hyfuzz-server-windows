"""Cache strategy helper."""

from __future__ import annotations

from typing import Protocol


class CacheStrategy(Protocol):
    def select_cache(self, key: str) -> int:
        ...


class RoundRobinStrategy:
    def __init__(self) -> None:
        self.index = 0

    def select_cache(self, key: str) -> int:
        self.index += 1
        return self.index


if __name__ == "__main__":
    strategy = RoundRobinStrategy()
    print(strategy.select_cache("a"))
    print(strategy.select_cache("b"))
