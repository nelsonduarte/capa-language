"""capa.docgen, human-readable documentation generator.

Reads an analysed Capa module and emits a self-contained HTML page
documenting every function, type, and user-defined capability,
using the doc comments (``///``, ``/** */``) attached to each
declaration.

The output is the human-readable counterpart to ``--manifest``,
which targets machines. Together they cover both axes of CRA
documentation: an SBOM-style structured artefact for tooling, and
a readable artefact for engineers and auditors.

A small subset of markdown is supported in doc-comment bodies:
paragraphs separated by blank lines, fenced code blocks, bulleted
lists, and inline ``code`` spans written with single backticks.
HTML special characters are always escaped.

Use::

    from capa.docgen import build_html
    html = build_html(module, filename="program.capa")

or, from the CLI::

    python -m capa --doc program.capa > program.html

The package is organised into focused submodules:

- :mod:`._collect` - extract types and traits from the AST.
- :mod:`._markdown` - the markdown-lite renderer for doc bodies.
- :mod:`._entries` - per-declaration HTML renderers (and the TOC).
- :mod:`._layout` - page chrome and the inline CSS.
"""

from __future__ import annotations

from typing import Optional

from .. import capa_ast as A
from ..manifest import build_manifest

from ._collect import _collect_traits, _collect_types
from ._entries import (
    _render_capability,
    _render_function,
    _render_toc,
    _render_trait,
    _render_type,
)
from ._layout import _html_prologue, _render_footer, _render_header


__all__ = ["build_html"]


def build_html(
    module: A.Module,
    *,
    filename: str = "<input>",
    capa_version: Optional[str] = None,
    title: Optional[str] = None,
) -> str:
    """Return a complete HTML document documenting ``module``.

    The page is self-contained (inline CSS, no external resources)
    and matches the visual identity of the project site (dark
    background, purple accent).
    """
    if capa_version is None:
        from .. import __version__ as capa_version
    if title is None:
        title = filename

    manifest = build_manifest(
        module, filename=filename, capa_version=capa_version,
    )

    funcs = manifest["functions"]
    user_caps = manifest["user_defined_capabilities"]
    types = _collect_types(module)
    traits = _collect_traits(module)

    parts: list[str] = []
    parts.append(_html_prologue(title))
    parts.append(_render_header(title, manifest))
    parts.append("<main>\n")
    parts.append(_render_toc(funcs, types, user_caps, traits))
    if user_caps:
        parts.append('<section id="capabilities">\n<h2>Capabilities</h2>\n')
        for uc in user_caps:
            parts.append(_render_capability(uc))
        parts.append("</section>\n")
    if traits:
        parts.append('<section id="traits">\n<h2>Traits</h2>\n')
        for t in traits:
            parts.append(_render_trait(t))
        parts.append("</section>\n")
    if types:
        parts.append('<section id="types">\n<h2>Types</h2>\n')
        for t in types:
            parts.append(_render_type(t))
        parts.append("</section>\n")
    if funcs:
        parts.append('<section id="functions">\n<h2>Functions</h2>\n')
        for fn in funcs:
            parts.append(_render_function(fn))
        parts.append("</section>\n")
    parts.append("</main>\n")
    parts.append(_render_footer(manifest))
    parts.append("</body></html>\n")
    return "".join(parts)
