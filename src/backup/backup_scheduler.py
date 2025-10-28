"""Schedules backups."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Dict


class BackupScheduler:
    def __init__(self) -> None:
        self.schedule: Dict[str, datetime] = {}

    def schedule_daily(self, name: str, hour: int = 0) -> None:
        run_at = datetime.utcnow().replace(hour=hour, minute=0, second=0, microsecond=0)
        if run_at < datetime.utcnow():
            run_at += timedelta(days=1)
        self.schedule[name] = run_at


if __name__ == "__main__":
    scheduler = BackupScheduler()
    scheduler.schedule_daily("demo")
    print(scheduler.schedule)
