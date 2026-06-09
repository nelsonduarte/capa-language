"""``textDocument/codeLens`` implementation.

An inline annotation above every top-level function declaration
showing the function's *capability surface*: the set of
capabilities it is permitted to exercise. This is the on-brand
Capa lens - it makes the SBOM's central fact (what a function can
touch) visible right where the code is written.

The capability set is NOT re-derived heuristically here. It is
read straight from the manifest builder (``capa.manifest``'s
per-function ``declared_capabilities``), the same authoritative
source the SBOM / regulatory tooling consumes, so a lens can never
disagree with the manifest for the same function. A function with
no capabilities reads as ``caps: none (pure)``; otherwise the lens
lists the capability type names, e.g. ``caps: Fs, Net``.

The lens is title-only (informational). LSP allows a code lens
with no command, which is the simplest accurate form; attaching a
command would imply a client-side action this server does not
need.

Returns an empty list on lex / parse / analyse failure: a
mid-edit buffer shows no lenses rather than crashing the request.
"""

from __future__ import annotations

from dataclasses import dataclass

from .. import capa_ast as A
from ..manifest import build_manifest
from .context import LspContext, _resolve_or_none


@dataclass
class CodeLens:
    """Capa-native code lens. ``line`` is the 1-based line of the
    function declaration the lens annotates; ``col`` is its 1-based
    starting column; ``title`` is the rendered annotation text."""
    line: int
    col: int
    title: str


def compute_code_lenses(source: str, filename: str) -> list[CodeLens]:
    """Return one capability-surface lens per top-level function
    declaration. Returns an empty list on lex / parse / analyse
    failure."""
    ctx = LspContext.parse(source, filename)
    if ctx is None:
        return []

    try:
        manifest = build_manifest(ctx.module, filename=filename)
    except Exception:
        # The lens is a best-effort overlay; a manifest-builder
        # hiccup on a mid-edit buffer must not crash the request.
        return []

    # Map loader-time function name -> declared capability list.
    # ``build_manifest`` keys ``name`` on the loader-time identifier
    # (the same field carried on ``FunDecl.name``), so top-level
    # records line up by name with the module's ``FunDecl`` items.
    caps_by_name: dict[str, list[str]] = {}
    for rec in manifest["functions"]:
        if rec.get("container") is None:
            caps_by_name[rec["name"]] = rec["declared_capabilities"]

    # After the loader inlines imports, ``ctx.module.items`` also
    # carries the imported modules' top-level functions, mangled and
    # tagged with the *imported* file's position. Emitting a lens for
    # those would paint phantom lenses onto unrelated lines of the
    # open document. Gate on the declaration's own ``pos.filename``
    # so only functions genuinely declared in the open file get a
    # lens, at their own position. The resolution matches the path
    # ``LspContext.parse`` was given (the same comparison the context
    # uses to filter idents / decl sites to this file).
    this_file = _resolve_or_none(filename)

    out: list[CodeLens] = []
    for item in ctx.module.items:
        if not isinstance(item, A.FunDecl):
            continue
        if item.name not in caps_by_name:
            continue
        if this_file is not None:
            item_file = _resolve_or_none(item.pos.filename)
            # An empty / unresolvable item filename falls through to
            # the root file (synthetic or parser-side gaps default to
            # the open document, matching the context's filter).
            if item_file is not None and item_file != this_file:
                continue
        out.append(
            CodeLens(
                line=item.pos.line,
                col=item.pos.col,
                title=_render_title(caps_by_name[item.name]),
            )
        )
    return out


def _render_title(caps: list[str]) -> str:
    """``caps: none (pure)`` for an empty set, else ``caps: A, B``
    with the capability type names in declared order, deduplicated
    while preserving first-seen order."""
    seen: list[str] = []
    for c in caps:
        if c not in seen:
            seen.append(c)
    if not seen:
        return "caps: none (pure)"
    return "caps: " + ", ".join(seen)
