"""String-level type machinery for the monomorphisation pass:
parsing, unification, substitution, and name mangling over the
Capa type strings the IR carries.

These are the pure leaf helpers shared by both the generic-function
and generic-type specialisers; they hold no module state.
"""

from __future__ import annotations

import re
from dataclasses import fields, is_dataclass, replace

from .. import _nodes as N


# ============================================================
# String-level type machinery
# ============================================================

_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _substitute_ty(ty_str: str, subst: dict[str, str]) -> str:
    """Replace each type-parameter name in ``ty_str`` with its
    concrete substitution, respecting identifier boundaries so
    ``T`` in ``List<T>`` rewrites but ``T`` inside ``Time`` does
    not. ``subst`` empty => returns the input unchanged."""
    if not subst or not ty_str:
        return ty_str

    def repl(m: re.Match) -> str:
        return subst.get(m.group(0), m.group(0))

    return _IDENT_RE.sub(repl, ty_str)


def _split_top_level_args(args_str: str) -> list[str]:
    """Split ``T, Map<K, V>, List<U>`` into
    ``["T", "Map<K, V>", "List<U>"]``. Respects angle-bracket
    nesting so nested commas don't break the split. Empty input
    returns ``[]``."""
    out: list[str] = []
    if not args_str.strip():
        return out
    depth = 0
    start = 0
    for i, ch in enumerate(args_str):
        if ch == "<" or ch == "(":
            depth += 1
        elif ch == ">" or ch == ")":
            depth -= 1
        elif ch == "," and depth == 0:
            out.append(args_str[start:i].strip())
            start = i + 1
    tail = args_str[start:].strip()
    if tail:
        out.append(tail)
    return out


def _parse_ty(ty_str: str) -> tuple[str, list[str]]:
    """Decompose a Capa type string into ``(head, args)`` where
    ``head`` is the leading identifier and ``args`` is the list of
    top-level arg strings.

    Shapes handled:
    - ``T`` / ``Int`` / ``String``        -> ``(ty_str, [])``
    - ``List<T>``, ``Map<K, V>``, ...      -> ``(head, [args...])``
    - ``(T, U)`` (tuple)                   -> ``("(tuple)", [...])``
    - ``Fun(T, U) -> R`` (closure type)    -> ``("(fun)", [T, U, R])``

    The ``(fun)`` head lets the monomorphiser unify
    ``Fun(T) -> String`` against ``Fun(LogEntry) -> String``
    structurally and infer ``T=LogEntry``. Without this case the
    closure-typed param of a generic HOF (e.g.
    ``count_by<T>(items: List<T>, key: Fun(T) -> String)``)
    would be treated as an opaque atom and unification would
    fail, leaving the call un-monomorphised."""
    ty_str = ty_str.strip()
    if ty_str.startswith("Fun(") and "->" in ty_str:
        # Locate the matching ``)`` of the ``Fun(...)`` to
        # tolerate nested parens (``Fun((A, B), C) -> R``).
        depth = 0
        close_idx = -1
        for i, ch in enumerate(ty_str[3:], start=3):
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    close_idx = i
                    break
        if close_idx > 0:
            params_str = ty_str[4:close_idx]
            tail = ty_str[close_idx + 1:].lstrip()
            if tail.startswith("->"):
                ret_str = tail[2:].strip()
                parts = _split_top_level_args(params_str)
                parts.append(ret_str)
                return ("(fun)", parts)
    if ty_str.startswith("(") and ty_str.endswith(")"):
        inner = ty_str[1:-1]
        return ("(tuple)", _split_top_level_args(inner))
    if "<" in ty_str and ty_str.endswith(">"):
        bracket = ty_str.index("<")
        head = ty_str[:bracket]
        args = _split_top_level_args(ty_str[bracket + 1 : -1])
        return (head, args)
    return (ty_str, [])


def _unify_ty(
    generic: str, concrete: str, type_params: set[str],
    mapping: dict[str, str],
) -> bool:
    """Unify a generic type string (which may contain type
    parameters) against a concrete type string, recording
    inferences in ``mapping``. Returns True on success, False on
    structural mismatch. ``type_params`` is the set of names that
    count as type variables (others are treated as fixed names)."""
    if generic in type_params:
        existing = mapping.get(generic)
        if existing is not None and existing != concrete:
            return False
        mapping[generic] = concrete
        return True
    g_head, g_args = _parse_ty(generic)
    c_head, c_args = _parse_ty(concrete)
    if g_head != c_head:
        return False
    if len(g_args) != len(c_args):
        return False
    for ga, ca in zip(g_args, c_args):
        if not _unify_ty(ga, ca, type_params, mapping):
            return False
    return True


def _mangle(name: str, subst: dict[str, str], type_params: list[str]) -> str:
    """Mangled name for a specialised function. Stable shape so
    repeated calls with the same substitution dedupe. Uses the
    declaration order of ``type_params`` so ``fun f<T, U>(...)``
    instantiated with ``{T: Int, U: String}`` yields
    ``f__Int__String`` (not ``f__String__Int``)."""
    parts = [name]
    for tp in type_params:
        c = subst.get(tp, tp)
        # Sanitise: ``List<Int>`` => ``List_Int``, ``(T, U)`` =>
        # ``Tup_T_U``. Stays readable in WAT dumps + stack traces.
        sanitised = (
            c.replace("<", "_")
             .replace(">", "")
             .replace(", ", "_")
             .replace(",", "_")
             .replace(" ", "")
             .replace("(", "Tup_")
             .replace(")", "")
        )
        parts.append(sanitised)
    return "__".join(parts)


def _substitute_value(v: N.Value, subst: dict[str, str]) -> N.Value:
    if not subst:
        return v
    new_ty = _substitute_ty(v.ty, subst)
    if new_ty == v.ty:
        return v
    return N.Value(kind=v.kind, name=v.name, literal=v.literal, ty=new_ty)


def _substitute_node(node, subst: dict[str, str]):
    """Recursively rewrite a dataclass node: substitute every
    ``Value.ty`` and ``ty`` string field, recurse into ``Instr``
    children, recurse into nested lists. Returns a new node
    (does not mutate the input)."""
    if subst is None or not subst:
        return node
    if node is None:
        return node
    if isinstance(node, N.Value):
        return _substitute_value(node, subst)
    if isinstance(node, str):
        # Bare string nodes only appear as type annotations on
        # certain Instr / Param fields, which are handled by the
        # dataclass walk below; this branch is here to keep the
        # walker safe on string operands in lists.
        return node
    if isinstance(node, list):
        return [_substitute_node(x, subst) for x in node]
    if isinstance(node, tuple):
        return tuple(_substitute_node(x, subst) for x in node)
    if is_dataclass(node):
        changes = {}
        for f in fields(node):
            old = getattr(node, f.name)
            new = _substitute_node(old, subst)
            # Bare ``ty: str`` / ``return_type: str`` fields:
            # substitute textually if they look like type names.
            if (
                isinstance(old, str)
                and f.name in _TYPE_STRING_FIELDS
            ):
                new = _substitute_ty(old, subst)
            if new is not old:
                changes[f.name] = new
        if changes:
            return replace(node, **changes)
        return node
    return node


# Dataclass field names that carry Capa type strings (as opposed
# to identifier names or other string roles). Used by
# ``_substitute_node`` to know which ``str`` fields to rewrite.
_TYPE_STRING_FIELDS = {
    "ty",
    "return_type",
    "receiver_ty",
    "result_type",
    "iter_ty",
    "scrutinee_ty",
    "element_ty",
}


def _substitute_locals(
    locals_map: dict[str, str], subst: dict[str, str],
) -> dict[str, str]:
    if not subst:
        return dict(locals_map)
    return {
        name: _substitute_ty(ty, subst) for name, ty in locals_map.items()
    }


def _mangle_type(name: str, args: list[str]) -> str:
    """Mangled name for a specialised generic type. ``Pair`` + ``[Char]``
    -> ``Pair__Char``; ``Box`` + ``[List<Int>]`` -> ``Box__List_Int``.
    Stable so the same instantiation dedupes to one clone."""
    parts = [name]
    for a in args:
        parts.append(
            a.replace("<", "_")
             .replace(">", "")
             .replace(", ", "_")
             .replace(",", "_")
             .replace(" ", "")
             .replace("(", "Tup_")
             .replace(")", "")
        )
    return "__".join(parts)


def _is_abstract_ty(ty_str: str, abstract: set[str]) -> bool:
    """True if ``ty_str`` is not fully concrete: it is (or recursively
    contains) a type-parameter name or an unresolved type-variable
    marker (``?...``). Such a type cannot be monomorphised on its own
    and must not seed a clone."""
    if not ty_str:
        return True
    if ty_str.startswith("?"):
        return True
    head, args = _parse_ty(ty_str)
    if head in abstract and not args:
        return True
    return any(_is_abstract_ty(a, abstract) for a in args)


def _has_question_mark(ty_str: str) -> bool:
    """True if ``ty_str`` contains an unresolved type-variable marker
    (``?`` anywhere). The lowerer writes ``?`` for a type arg it could
    not infer (e.g. the ``R`` of ``Either<Int, ?>`` from a one-arm
    ``Left(7)`` constructor)."""
    return "?" in ty_str


def _strip_head(ty_str: str) -> str:
    """Bare head of a type string: ``Either__Int_String`` ->
    ``Either__Int_String``, ``List<Int>`` -> ``List``."""
    return ty_str.split("<", 1)[0].split("[", 1)[0]
