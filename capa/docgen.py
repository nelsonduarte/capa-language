"""capa/docgen.py, human-readable documentation generator.

Reads an analysed Capa module and emits a self-contained HTML page
documenting every function, type, and user-defined capability,
using the doc comments (``///``, ``/** */``) attached to each
declaration.

The output is the human-readable counterpart to ``--manifest``,
which targets machines. Together they cover both axes of CRA
documentation: an SBOM-style structured artefact for tooling, and
a readable artefact for engineers and auditors.

A small subset of markdown is supported in doc-comment bodies:
paragraphs separated by blank lines, and inline ``code`` spans
written with single backticks. HTML special characters are
always escaped.

Use::

    from capa.docgen import build_html
    html = build_html(module, filename="program.capa")

or, from the CLI::

    python -m capa --doc program.capa > program.html
"""

from __future__ import annotations

import html as _html
import re
from typing import Any, Optional

from . import capa_ast as A
from .manifest import build_manifest, _ty_text  # type: ignore[attr-defined]


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
        from . import __version__ as capa_version
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


# =====================================================================
# Type extraction (the manifest does not surface types yet)
# =====================================================================


def _collect_traits(module: A.Module) -> list[dict[str, Any]]:
    """Collect plain (non-capability) traits with their method
    signatures, doc, and implementor types. Capability declarations
    (``capability X``) are out of scope here; they appear in the
    manifest's ``user_defined_capabilities`` list and are rendered
    separately.
    """
    out: list[dict[str, Any]] = []
    impl_map: dict[str, list[str]] = {}
    for item in module.items:
        if isinstance(item, A.ImplBlock) and item.trait_name is not None:
            impl_map.setdefault(item.trait_name, []).append(item.type_name)
    for item in module.items:
        if isinstance(item, A.TraitDecl) and not item.is_capability:
            out.append({
                "name": item.name,
                "type_params": item.type_params,
                "doc": item.doc,
                "methods": [
                    {
                        "name": m.name,
                        "params": [
                            {
                                "name": p.name,
                                "type": _ty_text(p.type_expr)
                                if p.type_expr else "Self",
                            }
                            for p in m.params
                        ],
                        "return_type": _ty_text(m.return_type)
                        if m.return_type else "()",
                    }
                    for m in item.methods
                ],
                "implementors": sorted(impl_map.get(item.name, [])),
            })
    return out


def _collect_types(module: A.Module) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for item in module.items:
        if isinstance(item, A.TypeStruct):
            out.append({
                "kind": "struct",
                "name": item.name,
                "type_params": item.type_params,
                "doc": item.doc,
                "fields": [
                    {"name": f.name, "type": _ty_text(f.type_expr)}
                    for f in item.fields
                ],
            })
        elif isinstance(item, A.TypeSum):
            out.append({
                "kind": "sum",
                "name": item.name,
                "type_params": item.type_params,
                "doc": item.doc,
                "variants": [
                    {
                        "name": v.name,
                        "payload": _ty_text(v.payload) if v.payload else None,
                    }
                    for v in item.variants
                ],
            })
    return out


# =====================================================================
# Markdown-lite (escape + paragraphs + inline code + fenced code blocks
# + bulleted lists)
# =====================================================================


_CODE_SPAN_RE = re.compile(r"`([^`\n]+)`")
_FENCE_RE = re.compile(r"\s*```\s*([a-zA-Z0-9_]*)\s*$")


def _render_inline(text: str) -> str:
    """Escape HTML in ``text`` and re-introduce inline ``code`` spans
    written with backticks. Called on every chunk of paragraph or
    list-item text before splicing into output."""
    escaped = _html.escape(text)
    return _CODE_SPAN_RE.sub(lambda m: f"<code>{m.group(1)}</code>", escaped)


def _render_doc(doc: Optional[str]) -> str:
    """Render a doc-comment body as HTML.

    Supports a small markdown subset, processed line by line:
    - blank lines separate paragraphs;
    - a line beginning with ``- `` starts (or continues) a bulleted
      list;
    - a line containing only ```` ``` ```` (optionally followed by a
      language tag) opens or closes a fenced code block; the body is
      emitted verbatim (no inline-code re-substitution, no escaping
      of backticks);
    - inline ``code`` spans inside paragraphs and list items use
      single backticks;
    - HTML special characters are always escaped.
    """
    if not doc:
        return ""
    lines = doc.strip().split("\n")
    out: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]

        # Fenced code block.
        fence = _FENCE_RE.match(line)
        if fence:
            lang = fence.group(1)
            i += 1
            code_lines: list[str] = []
            while i < len(lines):
                if _FENCE_RE.match(lines[i]):
                    i += 1
                    break
                code_lines.append(lines[i])
                i += 1
            code_text = "\n".join(code_lines)
            cls = f' class="lang-{_html.escape(lang)}"' if lang else ""
            out.append(
                f"<pre><code{cls}>{_html.escape(code_text)}</code></pre>"
            )
            continue

        # Bulleted list: contiguous lines starting with "- ".
        if line.lstrip().startswith("- "):
            items: list[str] = []
            while i < len(lines) and lines[i].lstrip().startswith("- "):
                items.append(_render_inline(lines[i].lstrip()[2:]))
                i += 1
            out.append(
                "<ul>" + "".join(f"<li>{it}</li>" for it in items) + "</ul>"
            )
            continue

        # Blank line: paragraph separator.
        if not line.strip():
            i += 1
            continue

        # Paragraph: collect consecutive non-special lines.
        para_lines: list[str] = []
        while i < len(lines):
            cur = lines[i]
            if not cur.strip():
                break
            if _FENCE_RE.match(cur):
                break
            if cur.lstrip().startswith("- "):
                break
            para_lines.append(cur.strip())
            i += 1
        text = " ".join(para_lines)
        out.append(f"<p>{_render_inline(text)}</p>")
    return "\n".join(out)


# =====================================================================
# Section renderers
# =====================================================================


def _slug(name: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_-]+", "-", name).strip("-").lower() or "x"


def _render_toc(funcs, types, user_caps, traits) -> str:
    items: list[str] = []
    if user_caps:
        cap_links = ", ".join(
            f'<a href="#cap-{_slug(c["name"])}">{_html.escape(c["name"])}</a>'
            for c in user_caps
        )
        items.append(f"<li><strong>Capabilities:</strong> {cap_links}</li>")
    if traits:
        tr_links = ", ".join(
            f'<a href="#tr-{_slug(t["name"])}">{_html.escape(t["name"])}</a>'
            for t in traits
        )
        items.append(f"<li><strong>Traits:</strong> {tr_links}</li>")
    if types:
        ty_links = ", ".join(
            f'<a href="#ty-{_slug(t["name"])}">{_html.escape(t["name"])}</a>'
            for t in types
        )
        items.append(f"<li><strong>Types:</strong> {ty_links}</li>")
    if funcs:
        fn_links = ", ".join(
            f'<a href="#fn-{_slug(_qualname(f))}">{_html.escape(_qualname(f))}</a>'
            for f in funcs
        )
        items.append(f"<li><strong>Functions:</strong> {fn_links}</li>")
    if not items:
        return ""
    return '<nav class="toc">\n<ul>\n' + "\n".join(items) + "\n</ul>\n</nav>\n"


def _qualname(fn: dict[str, Any]) -> str:
    if fn["container"]:
        return f'{fn["container"]}::{fn["name"]}'
    return fn["name"]


def _render_trait(t: dict[str, Any]) -> str:
    name = _html.escape(t["name"])
    slug = _slug(t["name"])
    type_params = ""
    if t["type_params"]:
        type_params = (
            "&lt;" + ", ".join(_html.escape(p) for p in t["type_params"])
            + "&gt;"
        )
    if t["methods"]:
        def _m(m):
            params = ", ".join(
                f'<span class="param">{_html.escape(p["name"])}</span>: '
                f'{_html.escape(p["type"])}'
                for p in m["params"]
            )
            ret = _html.escape(m["return_type"])
            return (
                f'<li><code>{_html.escape(m["name"])}({params}) '
                f"-&gt; <span class=\"ret\">{ret}</span></code></li>"
            )
        methods_html = "<ul>" + "".join(_m(m) for m in t["methods"]) + "</ul>"
    else:
        methods_html = "<p><em>no methods</em></p>"
    impls = ", ".join(
        f'<code>{_html.escape(i)}</code>' for i in t["implementors"]
    ) or "<em>none</em>"
    return (
        f'<article id="tr-{slug}" class="entry trait">\n'
        f'<h3>trait <span class="name">{name}</span>{type_params}</h3>\n'
        f"{_render_doc(t.get('doc'))}\n"
        f"<dl>\n"
        f"<dt>Methods</dt><dd>{methods_html}</dd>\n"
        f"<dt>Implementors</dt><dd>{impls}</dd>\n"
        f"</dl>\n"
        f"</article>\n"
    )


def _render_capability(c: dict[str, Any]) -> str:
    name = _html.escape(c["name"])
    slug = _slug(c["name"])
    impls = ", ".join(_html.escape(i) for i in c["implementors"]) or "<em>none</em>"
    methods = ", ".join(
        f"<code>{_html.escape(m)}</code>" for m in c["methods"]
    ) or "<em>none</em>"
    return (
        f'<article id="cap-{slug}" class="entry cap">\n'
        f'<h3>capability <span class="name">{name}</span></h3>\n'
        f"{_render_doc(c.get('doc'))}\n"
        f"<dl>\n"
        f"<dt>Methods</dt><dd>{methods}</dd>\n"
        f"<dt>Implementors</dt><dd>{impls}</dd>\n"
        f"</dl>\n"
        f"</article>\n"
    )


def _render_type(t: dict[str, Any]) -> str:
    name = _html.escape(t["name"])
    slug = _slug(t["name"])
    type_params = ""
    if t["type_params"]:
        type_params = (
            "&lt;" + ", ".join(_html.escape(p) for p in t["type_params"]) + "&gt;"
        )
    if t["kind"] == "struct":
        if t["fields"]:
            members = "<ul>" + "".join(
                f'<li><code>{_html.escape(f["name"])}: '
                f'{_html.escape(f["type"])}</code></li>'
                for f in t["fields"]
            ) + "</ul>"
        else:
            members = "<p><em>no fields</em></p>"
        members_label = "Fields"
    else:
        if t["variants"]:
            def _v(v):
                if v["payload"]:
                    return (
                        f'<li><code>{_html.escape(v["name"])}'
                        f'({_html.escape(v["payload"])})</code></li>'
                    )
                return f'<li><code>{_html.escape(v["name"])}</code></li>'
            members = "<ul>" + "".join(_v(v) for v in t["variants"]) + "</ul>"
        else:
            members = "<p><em>no variants</em></p>"
        members_label = "Variants"
    return (
        f'<article id="ty-{slug}" class="entry type">\n'
        f'<h3>type <span class="name">{name}</span>{type_params}</h3>\n'
        f"{_render_doc(t.get('doc'))}\n"
        f"<dl>\n"
        f"<dt>{members_label}</dt><dd>{members}</dd>\n"
        f"</dl>\n"
        f"</article>\n"
    )


def _render_function(fn: dict[str, Any]) -> str:
    name = _qualname(fn)
    slug = _slug(name)
    sig = _render_signature(fn)
    caps_html = _render_cap_badges(fn)
    attrs_html = _render_attr_badges(fn)
    body_doc = _render_doc(fn.get("doc"))
    calls_html = _render_calls(fn)
    pos = _html.escape(fn["pos"])
    return (
        f'<article id="fn-{slug}" class="entry fn">\n'
        f'<h3><span class="kw">fun</span> <span class="name">{_html.escape(name)}</span></h3>\n'
        f'<pre class="sig"><code>{sig}</code></pre>\n'
        f"{caps_html}{attrs_html}{body_doc}{calls_html}"
        f'<p class="src-pos">Defined at <code>{pos}</code></p>\n'
        f"</article>\n"
    )


def _render_signature(fn: dict[str, Any]) -> str:
    params = []
    for p in fn["params"]:
        consume = '<span class="kw">consume</span> ' if p["consuming"] else ""
        is_cap = ' class="cap"' if p["is_capability"] else ""
        params.append(
            f'{consume}<span class="param">{_html.escape(p["name"])}</span>: '
            f'<span{is_cap}>{_html.escape(p["type"])}</span>'
        )
    params_str = ", ".join(params)
    return_part = (
        f' -&gt; <span class="ret">{_html.escape(fn["return_type"])}</span>'
    )
    return (
        f'<span class="kw">fun</span> '
        f'<span class="name">{_html.escape(_qualname(fn))}</span>'
        f"({params_str}){return_part}"
    )


def _render_cap_badges(fn: dict[str, Any]) -> str:
    if not fn["declared_capabilities"] and not fn["has_unsafe"]:
        return ""
    badges = []
    for c in fn["declared_capabilities"]:
        cls = "badge cap" + (" unsafe" if c == "Unsafe" else "")
        badges.append(f'<span class="{cls}">{_html.escape(c)}</span>')
    return '<p class="badges">' + " ".join(badges) + "</p>\n"


def _render_attr_badges(fn: dict[str, Any]) -> str:
    if not fn["attributes"]:
        return ""
    rows = []
    for a in fn["attributes"]:
        cls = f"attribute attribute-{_slug(a['name'])}"
        body = ", ".join(
            f'<code>{_html.escape(k)}</code>: '
            f'<code>{_html.escape(v)}</code>'
            for k, v in a["args"].items()
        )
        rows.append(
            f'<div class="{cls}">'
            f'<span class="attr-name">@{_html.escape(a["name"])}</span>'
            f"{(' (' + body + ')') if body else ''}"
            f"</div>"
        )
    return '<div class="attributes">' + "".join(rows) + "</div>\n"


def _render_calls(fn: dict[str, Any]) -> str:
    if not fn["calls"]:
        return ""
    items = []
    for c in fn["calls"]:
        kind = _html.escape(c["kind"])
        callee = _html.escape(c["callee"])
        pos = _html.escape(c["pos"])
        args_str = ", ".join(_html.escape(a) for a in c["args"])
        items.append(
            f'<li><span class="call-kind">{kind}</span> '
            f'<code>{callee}({args_str})</code> '
            f'<span class="src-pos">at {pos}</span></li>'
        )
    return (
        '<details class="calls"><summary>'
        f'Calls ({len(fn["calls"])})</summary>\n'
        f"<ul>{''.join(items)}</ul></details>\n"
    )


# =====================================================================
# Page chrome
# =====================================================================


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
