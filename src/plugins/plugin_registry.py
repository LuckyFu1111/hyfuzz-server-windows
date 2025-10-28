"""Registry of available plugins."""

from __future__ import annotations

from typing import Dict, List

from .plugin_interface import Plugin


class PluginRegistry:
    def __init__(self) -> None:
        self._plugins: Dict[str, Plugin] = {}

    def register(self, plugin: Plugin) -> None:
        self._plugins[plugin.name] = plugin

    def list_plugins(self) -> List[str]:
        return sorted(self._plugins)


if __name__ == "__main__":
    class DemoPlugin:
        name = "demo"

        def initialize(self) -> None:
            pass

    registry = PluginRegistry()
    registry.register(DemoPlugin())
    print(registry.list_plugins())
