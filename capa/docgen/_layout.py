"""Page chrome for the documentation HTML output.

The ``_CSS`` block matches the visual identity of the Capa project
site (dark background, purple accent) and is inlined into every
generated page so the output is fully self-contained, no external
resources required.

- ``_html_prologue``: opening tags through ``<body>``.
- ``_render_header``: the top-of-page summary block.
- ``_render_footer``: the closing block with version metadata.
"""

from __future__ import annotations

import html as _html
from typing import Any


_CSS = """
* { box-sizing: border-box; }
html { background: #0d1117; color: #c9d1d9; font-family: -apple-system,
       BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
       font-size: 16px; line-height: 1.55; }
body { margin: 0; padding: 0; }
main { max-width: 920px; margin: 0 auto; padding: 0 1.5rem 4rem; }
header { border-bottom: 1px solid #30363d; padding: 2rem 1.5rem;
         max-width: 920px; margin: 0 auto; }
h1 { font-size: 1.6rem; color: #f0f6fc; margin: 0 0 0.4rem; }
h2 { font-size: 1.35rem; color: #f0f6fc; margin: 2rem 0 1rem;
     padding-top: 1rem; border-top: 1px solid #30363d; }
h3 { font-size: 1.05rem; color: #f0f6fc; margin: 1.5rem 0 0.5rem; }
a { color: #a78bfa; text-decoration: none; }
a:hover { text-decoration: underline; }
code { font-family: ui-monospace, "SF Mono", Menlo, Monaco, Consolas,
       monospace; font-size: 0.88em; }
pre.sig { background: #1a1f29; border: 1px solid #30363d; border-radius:
          6px; padding: 0.75rem 1rem; overflow-x: auto;
          font-size: 0.85rem; }
pre.sig .kw   { color: #ff7b72; font-weight: 600; }
pre.sig .name { color: #a78bfa; font-weight: 600; }
pre.sig .cap  { color: #79c0ff; font-weight: 600; }
pre.sig .ret  { color: #7ee787; }
pre.sig .param { color: #c9d1d9; }
.entry { padding: 0.5rem 0 1rem; }
.entry h3 .name { color: #a78bfa; }
.entry h3 .kw { color: #ff7b72; font-weight: 600; }
.entry > p, .entry .attributes, .entry .calls { margin: 0.5rem 0; }
.entry pre { background: #1a1f29; border: 1px solid #30363d;
             border-radius: 6px; padding: 0.6rem 0.9rem; overflow-x: auto;
             font-size: 0.82rem; margin: 0.6rem 0; }
.entry pre code { background: transparent; padding: 0; }
.entry ul li { font-size: 0.92rem; padding: 0.1rem 0; }
.badge { display: inline-block; padding: 0.1rem 0.55rem; border-radius:
         999px; font-family: ui-monospace, monospace; font-size: 0.78rem;
         margin-right: 0.3rem; background: rgba(121, 192, 255, 0.15);
         color: #79c0ff; }
.badge.unsafe { background: rgba(255, 123, 114, 0.18); color: #ff7b72; }
.badges { color: #8b949e; font-size: 0.85rem; }
.attribute { font-family: ui-monospace, monospace; font-size: 0.85rem;
             color: #8b949e; padding: 0.1rem 0; }
.attr-name { color: #a78bfa; font-weight: 600; }
.attribute code { background: #161b22; padding: 0.05em 0.3em;
                  border-radius: 3px; color: #c9d1d9; }
.src-pos { color: #8b949e; font-size: 0.8rem; }
.src-pos code { background: transparent; padding: 0; color: inherit; }
dl { margin: 0.5rem 0; }
dt { color: #8b949e; font-size: 0.85rem; text-transform: uppercase;
     letter-spacing: 0.04em; margin-top: 0.6rem; }
dd { margin: 0.25rem 0 0; }
ul { margin: 0.25rem 0; padding-left: 1.4rem; }
.toc { background: #161b22; border: 1px solid #30363d;
       border-radius: 8px; padding: 1rem 1.25rem; margin: 1.5rem 0; }
.toc ul { list-style: none; padding: 0; margin: 0; }
.toc li { margin: 0.3rem 0; font-size: 0.92rem; }
.toc strong { color: #f0f6fc; }
details.calls { border: 1px solid #30363d; border-radius: 6px;
                padding: 0.5rem 0.9rem; }
details.calls summary { cursor: pointer; color: #8b949e;
                        font-size: 0.88rem; }
details.calls li { font-size: 0.85rem; padding: 0.15rem 0; }
.call-kind { color: #8b949e; font-size: 0.75rem; text-transform: uppercase;
             margin-right: 0.4rem; }
footer { border-top: 1px solid #30363d; padding: 2rem 1.5rem;
         color: #8b949e; font-size: 0.85rem; text-align: center; }
"""


def _html_prologue(title: str) -> str:
    return (
        "<!DOCTYPE html>\n"
        f'<html lang="en"><head>\n'
        f'<meta charset="UTF-8">\n'
        f'<meta name="viewport" content="width=device-width, '
        f'initial-scale=1.0">\n'
        f'<title>{_html.escape(title)}</title>\n'
        f'<style>{_CSS}</style>\n'
        "</head><body>\n"
    )


def _render_header(title: str, manifest: dict[str, Any]) -> str:
    summary = manifest["summary"]
    return (
        "<header>\n"
        f'<h1>{_html.escape(title)}</h1>\n'
        f'<p>{summary["total_functions"]} functions, '
        f'{summary["functions_with_capabilities"]} with capabilities, '
        f'{summary["functions_with_attributes"]} annotated, '
        f'{summary["functions_crossing_unsafe"]} crossing the '
        f'<code>Unsafe</code> boundary.</p>\n'
        "</header>\n"
    )


def _render_footer(manifest: dict[str, Any]) -> str:
    return (
        "<footer>\n"
        f"Generated by Capa v{_html.escape(manifest['capa_version'])} "
        f"(<code>--doc</code>). Schema version: "
        f"<code>{manifest['schema_version']}</code>.\n"
        "</footer>\n"
    )
