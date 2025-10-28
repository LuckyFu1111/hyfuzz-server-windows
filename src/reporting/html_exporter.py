"""HTML exporter."""

from __future__ import annotations

from pathlib import Path


class HTMLExporter:
    def export(self, html: str, output_path: Path) -> Path:
        output_path.write_text(html, encoding="utf-8")
        return output_path


if __name__ == "__main__":
    exporter = HTMLExporter()
    path = Path("/tmp/demo.html")
    exporter.export("<h1>Demo</h1>", path)
    print(path.read_text())
