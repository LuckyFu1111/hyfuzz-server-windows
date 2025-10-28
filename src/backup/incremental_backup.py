"""Incremental backup tracker."""

from __future__ import annotations

from datetime import datetime
from typing import Dict


class IncrementalBackupTracker:
    def __init__(self) -> None:
        self.last_backup: Dict[str, datetime] = {}

    def mark(self, name: str) -> None:
        self.last_backup[name] = datetime.utcnow()

    def last_run(self, name: str) -> datetime | None:
        return self.last_backup.get(name)


if __name__ == "__main__":
    tracker = IncrementalBackupTracker()
    tracker.mark("demo")
    print(tracker.last_run("demo"))
