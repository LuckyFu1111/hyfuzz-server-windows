"""Plugin system for HyFuzz."""

from .plugin_manager import PluginManager

__all__ = ["PluginManager"]


if __name__ == "__main__":
    manager = PluginManager()
    print(manager.list_plugins())
