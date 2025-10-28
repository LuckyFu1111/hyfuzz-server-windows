"""Loads plugins from modules."""

from __future__ import annotations

from importlib import import_module
from typing import List, Type

from .plugin_interface import Plugin


class PluginLoader:
    def load(self, dotted_path: str) -> Plugin:
        module_path, class_name = dotted_path.rsplit(".", 1)
        module = import_module(module_path)
        plugin_cls: Type[Plugin] = getattr(module, class_name)
        plugin = plugin_cls()
        plugin.initialize()
        return plugin


if __name__ == "__main__":
    loader = PluginLoader()
    # Example requires a real module; for demonstration we'll skip actual load.
    print("Plugin loader ready")
