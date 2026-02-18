"""Report generation for SSI investigations.

Renders investigation results into structured markdown reports using
Jinja2 templates.  The output is suitable for human review, LEA
submission appendices, or further rendering to HTML/PDF.
"""

from __future__ import annotations

import logging
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ssi.models.investigation import InvestigationResult

logger = logging.getLogger(__name__)

# Template directory relative to the project root
_TEMPLATE_DIR = Path(__file__).resolve().parents[2] / "templates"


def render_markdown_report(
    result: InvestigationResult,
    output_path: Path | None = None,
    template_name: str = "report.md.j2",
) -> str:
    """Render an investigation result into a markdown report.

    Args:
        result: The investigation result to render.
        output_path: If provided, write the report to this file.
        template_name: Jinja2 template file name.

    Returns:
        The rendered markdown string.
    """
    template_dir = _resolve_template_dir()
    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=select_autoescape(default=False),
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )

    try:
        template = env.get_template(template_name)
    except Exception as e:
        logger.error("Failed to load template %s from %s: %s", template_name, template_dir, e)
        raise

    rendered = template.render(result=result)

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered)
        logger.info("Markdown report written to %s", output_path)

    return rendered


def _resolve_template_dir() -> Path:
    """Resolve the templates directory, checking project root first."""
    from ssi.settings import get_settings

    settings = get_settings()

    # Check project-root/templates first
    project_templates = settings.project_root / "templates"
    if project_templates.is_dir():
        return project_templates

    # Fallback to the package-relative path
    if _TEMPLATE_DIR.is_dir():
        return _TEMPLATE_DIR

    raise FileNotFoundError(
        f"Templates directory not found. Checked: {project_templates}, {_TEMPLATE_DIR}"
    )
