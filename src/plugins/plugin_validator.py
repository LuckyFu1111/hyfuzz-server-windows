"""Plugin validation utilities."""

from __future__ import annotations

from .plugin_interface import Plugin


class PluginValidator:
    def validate(self, plugin: Plugin) -> bool:
        if not hasattr(plugin, "name"):
            raise ValueError("Plugin missing name")
        if not callable(getattr(plugin, "initialize", None)):
            raise ValueError("Plugin missing initialize()")
        return True


if __name__ == "__main__":
    class DemoPlugin:
        name = "demo"

        def initialize(self) -> None:
            pass

    print(PluginValidator().validate(DemoPlugin()))
