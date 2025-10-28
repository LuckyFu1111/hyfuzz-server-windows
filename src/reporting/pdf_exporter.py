"""PDF exporter stub."""

from __future__ import annotations

from pathlib import Path


class PDFExporter:
    """Writes HTML content into a .pdf placeholder file."""

    def export(self, html: str, output_path: Path) -> Path:
        output_path.write_text(f"PDF PLACEHOLDER\n{html}", encoding="utf-8")
        return output_path


if __name__ == "__main__":
    exporter = PDFExporter()
    path = Path("/tmp/demo.pdf")
    exporter.export("<h1>Demo</h1>", path)
    print(path.read_text())
