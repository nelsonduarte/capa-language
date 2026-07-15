"""Type-name / type-string free helpers used across the lowerer.

Four functions pulled out of ``_lower.py`` so the per-AST-family
mixins (``_lower_expr``, ``_lower_stmt``, ``_lower_pattern``) can
share them without a circular import back to ``_lower.py``:

- ``_type_name`` -- best-effort string name for a TypeExpr / Ty.
- ``_split_tuple_elem_types`` -- ``"(A, B)"`` -> ``["A", "B"]``.
- ``_split_top_level_comma`` -- depth-aware single split.
- ``_ty_to_str`` -- typesys Ty -> string, mirroring ``_type_name``.

All four are pure; no shared state, no emitter dependencies.

Also hosts ``UnsupportedInIR`` for the same reason: every
``_lower_*`` mixin raises it, so it must live below them in the
import graph. ``_lower.py`` re-exports it so the public
``capa.ir.UnsupportedInIR`` surface keeps working.
"""

from __future__ import annotations

import re as _re


class UnsupportedInIR(Exception):
    """Raised when the lowerer hits an AST node it does not yet
    handle. The caller (typically ``capa.ir.compile`` or a test) is
    expected to catch this and fall back to the legacy transpiler.
    The message identifies the unsupported shape so coverage can be
    extended incrementally."""

    def __init__(self, shape: str):
        super().__init__(f"CIR lowering does not yet support: {shape}")
        self.shape = shape


def _type_name(te: object) -> str:
    """Best-effort name for a TypeExpr or Ty. Phase 1 only needs the
    string form for the Python emitter; structured Ty access can come
    later via the type map. ``FunType`` is rendered as
    ``Fun(P1, P2) -> R`` so backends that pattern-match the type
    string (the Wasm closure-signature lookup, for instance) can
    recognise it."""
    if te is None:
        return "Unknown"
    if isinstance(te, str):
        return te
    # FunType: render as ``Fun(P1, P2) -> R`` to match the canonical
    # Capa source syntax and the Wasm emitter's sig-key parser.
    if te.__class__.__name__ == "FunType":
        params = ", ".join(_type_name(p) for p in te.param_types)
        ret = _type_name(te.return_type)
        return f"Fun({params}) -> {ret}"
    # TupleType: render as ``(T1, T2, ...)`` to match the Capa
    # source syntax. Empty tuple renders as ``()`` (i.e., Unit
    # alias). Without this branch the fall-through to ``repr(te)``
    # would put the raw AST node text into a ``ty`` string, which
    # tripped the Wasm emitter with "Capa type '<AST repr>' has no
    # Wasm encoding" -- visible only on bare tuple parameters
    # (``cand: (String, Int)``); wrapped forms like
    # ``List<(String, Int)>`` short-circuited via the
    # ``head in ("List", ...)`` check in ``_wasm_type``.
    if te.__class__.__name__ == "TupleType":
        inner = ", ".join(_type_name(e) for e in te.elements)
        return f"({inner})"
    if hasattr(te, "name"):
        # Parametric types (List<T>, Map<K, V>, Option<T>, user-
        # defined generics) carry their args in ``te.args``; render
        # them in the canonical ``Name<A, B>`` form so downstream
        # consumers (for-iter element extraction, method dispatch
        # on receiver type, Wasm size_of) can parse them back.
        args = getattr(te, "args", None) or []
        if args:
            inner = ", ".join(_type_name(a) for a in args)
            return f"{te.name}<{inner}>"
        return te.name
    return _ty_to_str(te)


def _split_top_level(s: str) -> list[str]:
    """Split ``s`` on commas that sit at bracket-depth zero, treating
    ``(`` / ``<`` as openers and ``)`` / ``>`` as closers. The ``>``
    in a function-type arrow ``->`` is NOT a closing bracket, so a
    tuple / generic argument that is itself a ``Fun(...) -> R`` value
    splits correctly: ``"Fun(Int) -> Int, Fun(Int) -> Int"`` yields
    two elements, not one. This is the shared primitive behind every
    top-level type-string comma split (tuple elements, Fun params,
    Map<K, V> / Result<T, E> / generic args)."""
    out: list[str] = []
    buf = ""
    depth = 0
    prev = ""
    for ch in s:
        if ch in "(<":
            depth += 1
        elif ch == ")" or (ch == ">" and prev != "-"):
            depth -= 1
        if ch == "," and depth == 0:
            out.append(buf.strip())
            buf = ""
            prev = ch
            continue
        buf += ch
        prev = ch
    if buf.strip():
        out.append(buf.strip())
    return out


def _split_tuple_elem_types(ty: str) -> list[str]:
    """``(String, Int)`` -> ``['String', 'Int']``. Returns an empty
    list when ``ty`` isn't shaped like a parenthesised tuple, so
    callers can fall back to per-element ``Unknown``. Arrow-aware via
    ``_split_top_level`` so a tuple of ``Fun(...) -> R`` elements
    splits at the right commas."""
    if not ty.startswith("(") or not ty.endswith(")"):
        return []
    inner = ty[1:-1].strip()
    if not inner:
        return []
    return _split_top_level(inner)


def _unwrap_try_payload_ty(ty: str) -> str:
    """Strip the ``Ok`` / ``Some`` arm from a ``Result<T, E>`` /
    ``Option<T>`` type string and return the unwrapped payload ``T``.
    Returns ``""`` when ``ty`` is not Result / Option shaped so the
    caller keeps its own fallback.

    This lets ``_lower_try`` recover the precise ``?`` result type
    from the operand's ``Result`` / ``Option`` type when the analyzer
    left the ``Try`` node untyped. Without it the payload defaults to
    ``Unknown``, which the Wasm tuple emitter then sizes as an i64
    slot even for a pointer-shaped element (Map / List / Set), so a
    destructured ``let (m, s) = f()?`` binder loses its pointer type
    and the module fails the Wasm validator."""
    head, sep, rest = ty.partition("<")
    if not sep or not rest.endswith(">"):
        return ""
    inner = rest[:-1].strip()
    if head == "Result":
        payload, _err = _split_top_level_comma(inner)
        return payload.strip()
    if head == "Option":
        return inner
    return ""


def _split_top_level_comma(s: str) -> tuple[str, str]:
    """Split ``"T, Map<K, V>"`` into ``("T", "Map<K, V>")`` by
    counting angle brackets AND parentheses so commas inside
    nested ``<...>`` or tuple ``(...)`` shapes don't split. For
    example ``"(JsonValue, Int), String"`` splits into
    ``("(JsonValue, Int)", "String")``. Returns the whole string
    and an empty string if there is no comma at depth zero, which
    matches Result with a single generic arg (unusual but
    possible). The ``>`` in a ``->`` arrow is not treated as a
    bracket close, so a ``Fun(...) -> R`` component keeps its
    commas grouped."""
    depth = 0
    prev = ""
    for i, ch in enumerate(s):
        if ch in "<(":
            depth += 1
        elif ch == ")" or (ch == ">" and prev != "-"):
            depth -= 1
        elif ch == "," and depth == 0:
            return s[:i].strip(), s[i + 1:].strip()
        prev = ch
    return s.strip(), ""


def _ty_to_str(t: object) -> str:
    """Convert a typesys Ty to a string. Falls back to ``repr`` for
    unknown shapes; the Python emitter does not consume this string.

    Capa's analyzer renders function types as ``fun(...) -> R``
    (lowercase). The IR's downstream consumers (Wasm emitter
    closure machinery, in particular) match against the
    ``Fun(...)`` form used by the AST-side rendering, so we
    normalise the spelling here to keep the two paths in lockstep.
    The normalisation applies at ANY nesting depth, not just the
    top level: ``List<fun(JsonValue) -> ...>`` must yield the
    element type ``Fun(...)`` or the closure checks
    (``startswith("Fun")``) miss it and the element slot is sized
    4 bytes instead of the packed-i64 8 (Wasm validator rejection).
    ``fun`` is a keyword, so no user type name can produce the
    ``fun(`` token; the word-boundary anchor keeps a hypothetical
    ``Xfun`` name safe regardless.
    """
    try:
        from ..typesys import ty_str
        s = ty_str(t)
    except Exception:
        return repr(t)
    s = _re.sub(r"\bfun\(", "Fun(", s)
    # Unit renders as ``()`` from the type printer (Unit is the empty
    # tuple), but the IR and both backends key their Unit handling off
    # the canonical spelling ``Unit``. Normalise here so a Unit-typed
    # local / call result carries the same string every downstream
    # consumer's ``== "Unit"`` guard expects; otherwise a Unit value
    # (e.g. the result of a user method call that returns nothing)
    # slips past those guards and the Wasm backend emits a spurious
    # ``local.set`` / local declaration for a callee that pushed
    # nothing.
    if s == "()":
        return "Unit"
    return s

