"""Manages backups."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from .snapshot_handler import SnapshotHandler


class BackupManager:
    def __init__(self, directory: Path | None = None) -> None:
        self.directory = directory or Path("./backups")
        self.directory.mkdir(parents=True, exist_ok=True)
        self.handler = SnapshotHandler()

    def create_backup(self, name: str) -> Path:
        timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
        path = self.directory / f"{name}-{timestamp}.bak"
        self.handler.create_snapshot(path)
        return path


if __name__ == "__main__":
    manager = BackupManager(Path("/tmp/hyfuzz-backups"))
    print(manager.create_backup("demo"))
