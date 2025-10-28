"""JSON exporter."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class JSONExporter:
    def export(self, data: Any, output_path: Path) -> Path:
        output_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return output_path


if __name__ == "__main__":
    exporter = JSONExporter()
    path = Path("/tmp/demo.json")
    exporter.export({"demo": True}, path)
    print(path.read_text())
