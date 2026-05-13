"""Markdown-lite rendering for doc-comment bodies.

A deliberately small subset:

- paragraphs separated by blank lines
- bulleted lists started by ``- ``
- fenced code blocks via ``` ``` ``` with an optional language tag
- inline ``code`` spans via single backticks
- HTML special characters are always escaped

Anything beyond that is rendered as plain text. The renderer is
intentionally line-oriented and stateless across calls, so each
doc comment is rendered independently.
"""

from __future__ import annotations

import html as _html
import re
from typing import Optional


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
