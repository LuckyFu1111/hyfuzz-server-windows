"""Base plugin interface."""

from __future__ import annotations

from typing import Protocol


class Plugin(Protocol):
    name: str

    def initialize(self) -> None:
        ...


if __name__ == "__main__":
    class DemoPlugin:
        name = "demo"

        def initialize(self) -> None:
            print("initialized")

    plugin: Plugin = DemoPlugin()
    plugin.initialize()
