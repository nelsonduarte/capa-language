"""Runtime traceback rewriting for ``capa --run``.

``capa --run`` execs transpiled Python in-process under the synthetic
filename ``<transpiled>``. A raw Python traceback names that synthetic
file and Python line numbers, which mean nothing to a Capa author. The
transpiler emits a statement-level ``python_line -> Pos`` source map;
``_rewrite_traceback`` consumes it to produce a concise Capa-level
summary that names the originating ``file:line:col`` for each transpiled
frame and, when the source text is available, shows the offending Capa
source line with a caret pointing at the column. The snippet matches the
style of ``errors.py`` so runtime and compile diagnostics look the same.

Statement granularity: the map keys are the Python line each Capa
statement begins on. A failing frame's line is matched to the nearest
map key ``<= frame.lineno`` (the statement the line belongs to). Because
the map records the statement's ``Pos`` (not the throwing sub-expression),
the caret points at the start of the statement, not the precise failing
sub-expression within it. That is the accepted scope.
"""

from __future__ import annotations

import traceback

_TRANSPILED = "<transpiled>"


def _nearest_pos(line_map: dict, py_line: int):
    """Return the ``Pos`` of the statement that owns ``py_line``: the
    entry with the greatest key ``<= py_line``. ``None`` if no key
    qualifies (the line predates any recorded statement)."""
    best_key = None
    for key in line_map:
        if key <= py_line and (best_key is None or key > best_key):
            best_key = key
    if best_key is None:
        return None
    return line_map[best_key]


def _render_snippet(pos, source: str) -> list[str]:
    """Render the gutter+source-line and caret-line for ``pos`` against
    ``source``, in the exact style of ``errors.LexerError.format``.

    Returns an empty list when ``pos.line`` is out of range for the
    supplied source (so the caller emits just the header)."""
    lines = source.split("\n")
    if not (1 <= pos.line <= len(lines)):
        return []
    line_text = lines[pos.line - 1]
    gutter = f"{pos.line:>4} | "
    caret_pad = " " * (len(gutter) + max(0, pos.col - 1))
    return [f"{gutter}{line_text}", f"{caret_pad}^"]


def _rewrite_traceback(
    exc_info,
    line_map: dict,
    *,
    sources: dict | None = None,
    default_source: str = "",
) -> str:
    """Build a Capa-level traceback summary from ``exc_info`` (the
    ``(type, value, tb)`` tuple) and a ``python_line -> Pos`` map.

    Each ``<transpiled>`` frame whose line maps to a Capa ``Pos`` is
    rendered as a header ``file:line:col`` followed, when the source is
    resolvable, by a snippet: the source line and a caret. The source
    for a frame is ``sources[pos.filename]`` when ``sources`` is given
    and the filename is present, else ``default_source`` (used when a
    ``Pos`` has an empty filename or one absent from ``sources``). When
    no source resolves, only the header line is emitted.

    Returns the empty string when no frame maps, so the caller falls
    back to the plain Python traceback."""
    exc_type, exc_value, tb = exc_info
    frames = traceback.extract_tb(tb)

    rendered: list[str] = []
    for frame in frames:
        if frame.filename != _TRANSPILED:
            continue
        pos = _nearest_pos(line_map, frame.lineno)
        if pos is None:
            continue
        where = pos.filename or _TRANSPILED
        rendered.append(f"  {where}:{pos.line}:{pos.col}")
        # Resolve the source text for this frame's file. A non-empty
        # filename present in ``sources`` wins; otherwise the root
        # file's source is used (the common single-file case, where
        # the Pos filename is empty or matches the root).
        source = ""
        if sources is not None and pos.filename and pos.filename in sources:
            source = sources[pos.filename]
        else:
            source = default_source
        if source:
            rendered.extend(_render_snippet(pos, source))

    if not rendered:
        return ""

    name = getattr(exc_type, "__name__", str(exc_type))
    msg = str(exc_value)
    tail = f"{name}: {msg}" if msg else name

    out = ["Capa traceback (most recent call last):"]
    out.extend(rendered)
    out.append(tail)
    return "\n".join(out)
