"""Backup utilities."""

from .backup_manager import BackupManager

__all__ = ["BackupManager"]


if __name__ == "__main__":
    manager = BackupManager()
    manager.create_backup("demo")
