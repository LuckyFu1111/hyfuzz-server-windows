"""Simple alert management for monitoring events."""

from __future__ import annotations

from typing import Callable, List


class AlertManager:
    """Register callbacks triggered when thresholds are exceeded."""

    def __init__(self) -> None:
        self._subscribers: List[Callable[[str], None]] = []

    def subscribe(self, callback: Callable[[str], None]) -> None:
        self._subscribers.append(callback)

    def notify(self, message: str) -> None:
        for callback in self._subscribers:
            callback(message)


if __name__ == "__main__":  # pragma: no cover - sanity test
    manager = AlertManager()
    received: List[str] = []
    manager.subscribe(received.append)
    manager.notify("Alert!")
    assert received == ["Alert!"]
    print("Alert manager self-test passed.")
