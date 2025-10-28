"""Very small HTML template renderer."""

from __future__ import annotations

from pathlib import Path
from typing import Dict

TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"


class TemplateEngine:
    """Loads HTML templates and performs simple substitution."""

    def render(self, template_name: str, context: Dict[str, object]) -> str:
        template_path = TEMPLATE_DIR / template_name
        content = template_path.read_text(encoding="utf-8")
        for key, value in context.items():
            content = content.replace(f"{{{{ {key} }}}}", str(value))
        return content


if __name__ == "__main__":
    engine = TemplateEngine()
    (TEMPLATE_DIR / "sample.html").write_text("Hello {{ name }}", encoding="utf-8")
    print(engine.render("sample.html", {"name": "HyFuzz"}))
