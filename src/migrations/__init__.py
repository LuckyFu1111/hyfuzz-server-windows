"""Database migration utilities."""

from .migration_manager import MigrationManager

__all__ = ["MigrationManager"]


if __name__ == "__main__":
    manager = MigrationManager()
    manager.register("v1", "Initial schema")
    print(manager.pending())
