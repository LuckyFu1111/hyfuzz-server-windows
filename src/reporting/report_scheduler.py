"""Simple report scheduling utility."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import List

from .report_generator import ReportGenerator


class ReportScheduler:
    def __init__(self, generator: ReportGenerator | None = None) -> None:
        self.generator = generator or ReportGenerator()
        self.scheduled_times: List[datetime] = []

    def schedule_daily(self, hour: int = 0) -> None:
        next_run = datetime.utcnow().replace(hour=hour, minute=0, second=0, microsecond=0)
        if next_run < datetime.utcnow():
            next_run += timedelta(days=1)
        self.scheduled_times.append(next_run)


if __name__ == "__main__":
    scheduler = ReportScheduler()
    scheduler.schedule_daily()
    print(scheduler.scheduled_times)
