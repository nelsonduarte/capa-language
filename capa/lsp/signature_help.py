"""``textDocument/signatureHelp`` implementation.

When the cursor sits inside the argument list of a call
``foo(a, b, <cursor>)`` (or a method call
``recv.m(<cursor>)``), surface the callee's signature: its
name, its typed parameters, and its return type, plus the index
of the parameter the cursor is currently on.

Two pieces of work:

* **Where am I?** A purely textual scan back from the cursor
  finds the innermost unclosed ``(`` that opens a call and counts
  the top-level commas between that paren and the cursor. Commas
  nested inside parens / brackets / braces do not advance the
  active parameter. Angle brackets ``<`` / ``>`` are intentionally
  *not* treated as nesting: they are far more often comparison
  operators (``f(a < b, c)``) than generic delimiters here, so
  treating them as nesting would miscount commas. The scan is
  text-based so it works on mid-edit buffers whose trailing ``(``
  does not parse.

Known future nicety: signature help currently vanishes while the
cursor sits inside a ``[list]`` / ``{map}`` literal passed as an
argument, because such a bracket pair is read as "not a call
argument list". Restoring help in that case is left as a follow-up.

* **What is the callee?** The open-paren position is matched
  against the ``Call`` / ``MethodCall`` nodes in the parsed AST;
  the callee resolves through the same Symbol tables hover and
  completion use (``result.bindings`` for a free function,
  ``result.types`` + ``global_symbols[...].methods`` for a
  method on a struct / sum / capability). Unresolved callee ->
  no signature (we do not guess).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .. import capa_ast as A
from ..analyzer import Symbol, SymbolKind
from ..typesys import TyFun, TyName, ty_str
from .context import LspContext, walk


@dataclass
class SignatureInfo:
    """Capa-native signature-help payload.

    ``label`` is the full signature string
    (``fun foo(a: Int, b: String) -> Bool``); ``parameters`` is
    the list of per-parameter label substrings (``a: Int``);
    ``active_parameter`` is the 0-based index of the parameter the
    cursor is on (clamped to the last parameter when the cursor
    runs past the final comma)."""
    label: str
    parameters: list[str] = field(default_factory=list)
    active_parameter: int = 0


def compute_signature_help(
    source: str, filename: str, line: int, col: int,
) -> Optional[SignatureInfo]:
    """Return the signature for the call enclosing the (1-based)
    cursor position, or ``None`` when the cursor is not inside a
    resolvable call's argument list (or the buffer does not
    parse)."""
    scan = _scan_enclosing_call(source, line, col)
    if scan is None:
        return None
    open_line, open_col, active = scan

    ctx = LspContext.parse(source, filename)
    if ctx is None:
        return None

    call = _find_enclosing_call(ctx, open_line, open_col)
    if call is None:
        return None

    sym = _resolve_callee(call, ctx)
    if sym is None or not isinstance(sym.ty, TyFun):
        return None

    return _signature_from_symbol(sym, active)


# ---------------------------------------------------------------
# Textual scan: find the enclosing call + active parameter.
# ---------------------------------------------------------------


def _scan_enclosing_call(
    source: str, line: int, col: int,
) -> Optional[tuple[int, int, int]]:
    """Scan backwards from the cursor for the innermost unclosed
    ``(``. Returns ``(open_line, open_col, active_parameter)`` in
    1-based positions, or ``None`` when the cursor is not inside
    an open paren group whose ``(`` is preceded by a call target
    (identifier or ``.method``).

    ``active_parameter`` is the number of top-level commas between
    the open paren and the cursor (commas nested in deeper
    brackets / parens / braces are skipped). Angle brackets are
    intentionally not treated as nesting, so a comparison like
    ``f(a < b, c)`` still counts its comma at top level.
    """
    lines = source.split("\n")
    if line < 1 or line > len(lines):
        return None

    # Build a flat list of (char, line, col) from the buffer start
    # up to the cursor; scanning a flat sequence keeps the
    # bracket-matching logic readable across line boundaries.
    flat: list[tuple[str, int, int]] = []
    for li in range(line):
        text = lines[li]
        end = (col - 1) if li == line - 1 else len(text)
        end = min(end, len(text))
        for ci in range(end):
            flat.append((text[ci], li + 1, ci + 1))

    depth = 0          # nesting below the candidate call paren
    commas = 0         # top-level commas seen since the open paren
    i = len(flat) - 1
    while i >= 0:
        ch, li, ci = flat[i]
        if ch in ")]}":
            depth += 1
        elif ch in "[{":
            if depth == 0:
                # Cursor is inside a list / map / block literal, not
                # a call argument list.
                return None
            depth -= 1
        elif ch == "(":
            if depth == 0:
                # Innermost unclosed paren. Is it a call paren?
                if _preceded_by_call_target(flat, i):
                    return li, ci, commas
                return None
            depth -= 1
        elif ch == "," and depth == 0:
            commas += 1
        i -= 1
    return None


def _preceded_by_call_target(
    flat: list[tuple[str, int, int]], paren_idx: int,
) -> bool:
    """True when the ``(`` at ``flat[paren_idx]`` follows a call
    target: an identifier character or a closing ``)`` / ``]`` /
    ``>`` (chained / generic calls). A ``(`` after whitespace, an
    operator, or another ``(`` is a grouping paren, not a call."""
    j = paren_idx - 1
    # Skip horizontal whitespace between the target and the paren.
    while j >= 0 and flat[j][0] in " \t":
        j -= 1
    if j < 0:
        return False
    prev = flat[j][0]
    return prev.isalnum() or prev == "_" or prev in ")]>"


# ---------------------------------------------------------------
# AST match: open-paren position -> Call / MethodCall node.
# ---------------------------------------------------------------


def _find_enclosing_call(
    ctx: LspContext, paren_line: int, paren_col_max: int,
):
    """Find the Call / MethodCall that encloses the open paren the
    textual scan landed on.

    The parser does not record the open-paren position on the call
    node, so we cannot match the paren column exactly. Instead we
    take ``(paren_line, paren_col_max)`` as the latest position the
    call may start at, and pick the call whose start is closest to
    (at or before) it, preferring the inner-most / latest-starting
    match. ``paren_col_max`` is used only as an upper bound on the
    same line, not as a precise paren-column key."""
    best = None
    best_key: Optional[tuple[int, int]] = None
    for n in walk(ctx.module):
        if not isinstance(n, (A.Call, A.MethodCall)):
            continue
        pos = n.pos
        if pos.line > paren_line:
            continue
        if pos.line == paren_line and pos.col > paren_col_max:
            continue
        # Prefer the call whose start is latest (deepest / closest
        # to the paren): that is the immediately-enclosing call.
        key = (pos.line, pos.col)
        if best_key is None or key > best_key:
            best = n
            best_key = key
    return best


# ---------------------------------------------------------------
# Callee resolution + signature rendering.
# ---------------------------------------------------------------


def _resolve_callee(call, ctx: LspContext) -> Optional[Symbol]:
    """Resolve the callee of ``call`` to its Symbol.

    Free function: the callee Ident resolves through
    ``result.bindings``. Method: the receiver's inferred type
    (``result.types``) names a struct / sum / capability whose
    ``methods`` table carries the method Symbol. Returns ``None``
    when nothing resolves."""
    if isinstance(call, A.Call):
        callee = call.callee
        if isinstance(callee, A.Ident):
            sym = ctx.result.bindings.get(id(callee))
            if sym is not None and sym.kind == SymbolKind.FUNCTION:
                return sym
            # Fall back to a top-level lookup (the binding map can
            # miss a call target the analyzer never bound, e.g. a
            # forward reference in a half-typed buffer).
            top = ctx.result.global_symbols.get(callee.name)
            if top is not None and top.kind == SymbolKind.FUNCTION:
                return top
        return None

    if isinstance(call, A.MethodCall):
        recv_ty = ctx.result.types.get(id(call.receiver))
        if isinstance(recv_ty, TyName):
            owner = ctx.result.global_symbols.get(recv_ty.name)
            if owner is not None:
                m = owner.methods.get(call.method)
                if m is not None:
                    return m
        return None

    return None


def _signature_from_symbol(
    sym: Symbol, active: int,
) -> SignatureInfo:
    """Render a FUNCTION Symbol's declared signature, consistent
    with hover's rendering, and clamp ``active`` to the parameter
    count."""
    assert isinstance(sym.ty, TyFun)
    param_names = sym.param_names or [
        f"arg{i + 1}" for i in range(len(sym.ty.params))
    ]
    param_labels = [
        f"{pn}: {ty_str(pt)}"
        for pn, pt in zip(param_names, sym.ty.params)
    ]
    label = (
        f"fun {sym.name}(" + ", ".join(param_labels) + ")"
        f" -> {ty_str(sym.ty.ret)}"
    )
    if param_labels:
        active = max(0, min(active, len(param_labels) - 1))
    else:
        active = 0
    return SignatureInfo(
        label=label, parameters=param_labels, active_parameter=active,
    )
