"""High level plugin manager."""

from __future__ import annotations

from typing import List

from .plugin_loader import PluginLoader
from .plugin_registry import PluginRegistry


class PluginManager:
    def __init__(self) -> None:
        self.registry = PluginRegistry()
        self.loader = PluginLoader()

    def load_and_register(self, dotted_path: str) -> None:
        plugin = self.loader.load(dotted_path)
        self.registry.register(plugin)

    def list_plugins(self) -> List[str]:
        return self.registry.list_plugins()


if __name__ == "__main__":
    manager = PluginManager()
    print(manager.list_plugins())
