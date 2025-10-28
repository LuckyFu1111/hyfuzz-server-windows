"""CSV exporter."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Iterable, Sequence


class CSVExporter:
    def export(self, rows: Iterable[Sequence[str]], output_path: Path) -> Path:
        with output_path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerows(rows)
        return output_path


if __name__ == "__main__":
    exporter = CSVExporter()
    path = Path("/tmp/demo.csv")
    exporter.export([["col1", "col2"], ["a", "b"]], path)
    print(path.read_text())
