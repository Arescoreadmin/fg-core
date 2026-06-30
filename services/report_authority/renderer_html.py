"""services/report_authority/renderer_html.py

Deterministic HTML renderer. Offline capable — no external CDN assets.
Produces accessible, printable, responsive HTML.
"""

from __future__ import annotations

from typing import Any

_CSS = """
/* Embedded stylesheet — offline capable */
body { font-family: Arial, sans-serif; margin: 2em; color: #1a1a1a; }
h1 { color: #1a3a5c; border-bottom: 2px solid #1a3a5c; padding-bottom: .5em; }
h2 { color: #1a3a5c; margin-top: 2em; }
h3 { color: #2a4a6c; }
table { border-collapse: collapse; width: 100%; margin: 1em 0; }
th { background: #1a3a5c; color: white; padding: .5em 1em; text-align: left; }
td { padding: .4em 1em; border-bottom: 1px solid #ddd; }
tr:nth-child(even) { background: #f5f5f5; }
.badge { display: inline-block; padding: .2em .6em; border-radius: 3px; font-size: .85em; font-weight: bold; }
.badge-critical { background: #c0392b; color: white; }
.badge-high { background: #e67e22; color: white; }
.badge-medium { background: #f39c12; color: #1a1a1a; }
.badge-low { background: #27ae60; color: white; }
.badge-info { background: #2980b9; color: white; }
.section { margin: 2em 0; page-break-inside: avoid; }
.manifest-box { background: #f0f4f8; border: 1px solid #1a3a5c; padding: 1em; font-family: monospace; font-size: .85em; }
@media print { body { margin: 0; } .no-print { display: none; } }
"""


def render_html(
    report_data: dict[str, Any],
    title: str = "FrostGate Assessment Report",
) -> bytes:
    """Render report as standalone, offline-capable HTML."""
    # Build sections deterministically — sort all dict keys for determinism.
    html_parts = [
        "<!DOCTYPE html>",
        "<html lang='en'>",
        "<head>",
        "<meta charset='UTF-8'>",
        "<meta name='viewport' content='width=device-width, initial-scale=1'>",
        f"<title>{_escape(title)}</title>",
        f"<style>{_CSS}</style>",
        "</head>",
        "<body>",
        f"<h1>{_escape(title)}</h1>",
    ]

    for section_key in sorted(report_data.keys()):
        section = report_data[section_key]
        html_parts.append(f"<div class='section' id='{_escape(section_key)}'>")
        html_parts.append(f"<h2>{_escape(section_key.replace('_', ' ').title())}</h2>")
        if isinstance(section, dict):
            html_parts.append(_render_dict_as_table(section))
        elif isinstance(section, list):
            html_parts.append(_render_list(section))
        else:
            html_parts.append(f"<p>{_escape(str(section))}</p>")
        html_parts.append("</div>")

    html_parts.extend(["</body>", "</html>"])
    return "\n".join(html_parts).encode("utf-8")


def _escape(value: str) -> str:
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _render_dict_as_table(data: dict[str, Any]) -> str:
    rows = ["<table><thead><tr><th>Field</th><th>Value</th></tr></thead><tbody>"]
    for k in sorted(data.keys()):
        v = data[k]
        rows.append(f"<tr><td>{_escape(k)}</td><td>{_escape(str(v))}</td></tr>")
    rows.append("</tbody></table>")
    return "\n".join(rows)


def _render_list(items: list[Any]) -> str:
    parts = ["<ul>"]
    for item in items:
        if isinstance(item, dict):
            parts.append(f"<li>{_render_dict_as_table(item)}</li>")
        else:
            parts.append(f"<li>{_escape(str(item))}</li>")
    parts.append("</ul>")
    return "\n".join(parts)
