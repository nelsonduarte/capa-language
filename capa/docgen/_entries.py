"""Per-entry HTML renderers for traits, capabilities, types, and functions.

These produce one ``<article>`` per declaration plus the matching
table-of-contents block. They consume the dicts produced by
:mod:`._collect` and the manifest's function records.

- ``_slug`` / ``_qualname``: id and label helpers shared by the
  renderers.
- ``_render_toc``: the navigation block at the top of the page.
- ``_render_trait`` / ``_render_capability`` / ``_render_type``:
  one per declaration kind.
- ``_render_function`` and its supporting helpers
  (``_render_signature``, ``_render_cap_badges``,
  ``_render_attr_badges``, ``_render_calls``).
"""

from __future__ import annotations

import html as _html
import re
from typing import Any

from ._markdown import _render_doc


def _slug(name: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_-]+", "-", name).strip("-").lower() or "x"


def _qualname(fn: dict[str, Any]) -> str:
    if fn["container"]:
        return f'{fn["container"]}::{fn["name"]}'
    return fn["name"]


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
