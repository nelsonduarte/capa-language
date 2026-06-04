"""Monomorphisation pass: specialise generic user functions per
concrete instantiation seen at call sites.

The lowerer leaves generic functions ungeneralised: a
``fun first<T>(items: List<T>) -> Option<T>`` arrives in the IR
with ``type_params=["T"]`` and a body whose ``Value.ty`` /
``locals[name]`` strings still mention ``T`` / ``List<T>`` /
``Option<T>``. The Python backend tolerates this (duck typing),
but the Wasm backend's layout machinery fails on ``T`` because
the type has no Wasm encoding.

This pass walks the IR module and, for each call to a generic
function whose substitution can be inferred from argument types,
synthesises a specialised clone of the function (name mangled,
``T`` replaced by the concrete type throughout the body) and
rewrites the call to target the clone. After the pass, the
module contains no generic functions and no calls to type
variables: the Wasm backend can emit normally.

Scope (v1):

* Free functions only. Generic methods (``impl<T> Trait for ...``),
  generic struct types, and generic capability methods are out
  of scope; the pass leaves them alone, which means programs
  using those features still hit the actionable
  "no Wasm encoding" error.
* String-based unification. The IR stores types as strings; the
  inference walks ``"List<T>"`` against ``"List<Int>"`` to derive
  ``T=Int``. Works for nested arities the backend already
  supports (``Option<T>``, ``Result<T, E>``, ``List<T>``,
  ``Map<K, V>``, ``(T, U)``).
* No partial application; every type parameter must be resolved
  from the concrete argument types.

When a call cannot be monomorphised (callee not found, ambiguous
substitution, etc.), the pass leaves the call alone and the
downstream backend will surface its existing error.
"""

from __future__ import annotations

import re
from dataclasses import fields, is_dataclass, replace
from typing import Optional

from . import _nodes as N


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


# ============================================================
# Function cloning + body substitution
# ============================================================


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


def _specialise_function(
    fn: N.Function, subst: dict[str, str], mangled_name: str,
) -> N.Function:
    """Clone ``fn`` with all ``type_params`` substituted to their
    concrete types. Returns a new Function with empty
    ``type_params`` (it is now monomorphic), the mangled name,
    substituted params / return type / locals / body. Pure: does
    not touch the input."""
    new_params = [
        N.Param(
            name=p.name,
            ty=_substitute_ty(p.ty, subst),
            is_capability=p.is_capability,
        )
        for p in fn.params
    ]
    new_return_type = _substitute_ty(fn.return_type, subst)
    new_locals = _substitute_locals(fn.locals, subst)
    new_body = [_substitute_node(instr, subst) for instr in fn.body]
    return N.Function(
        name=mangled_name,
        params=new_params,
        return_type=new_return_type,
        declared_caps=list(fn.declared_caps),
        body=new_body,
        locals=new_locals,
        type_params=[],
    )


# ============================================================
# Call-site inference + rewrite
# ============================================================


def _infer_subst_for_call(
    call: N.Call, callee: N.Function,
) -> Optional[dict[str, str]]:
    """Walk the call's args against the generic function's params
    to infer a substitution for every ``type_params`` entry.
    Returns None when any type parameter cannot be resolved or
    when a structural mismatch shows up."""
    if not callee.type_params:
        return {}
    if len(call.args) != len(callee.params):
        return None
    type_param_set = set(callee.type_params)
    mapping: dict[str, str] = {}
    for arg, p in zip(call.args, callee.params):
        if not arg.ty or arg.ty in ("?", "Unknown", ""):
            # We cannot trust an unresolved arg type to drive
            # inference; abort so the call falls through to the
            # downstream backend's existing error.
            return None
        if arg.ty.startswith("?"):
            return None
        if not _unify_ty(p.ty, arg.ty, type_param_set, mapping):
            return None
    # Every declared type param must be resolved.
    for tp in callee.type_params:
        if tp not in mapping:
            return None
    return mapping


def _walk_calls(instrs: list[N.Instr], visitor) -> None:
    """Walk every ``Call`` in the instruction list (recursing into
    nested bodies) calling ``visitor(call_owner_list, index)``."""
    for i, instr in enumerate(instrs):
        if isinstance(instr, N.Call):
            visitor(instrs, i)
        elif isinstance(instr, N.If):
            _walk_calls(instr.then_body, visitor)
            _walk_calls(instr.else_body, visitor)
        elif isinstance(instr, N.While):
            _walk_calls(instr.cond_setup, visitor)
            _walk_calls(instr.body, visitor)
        elif isinstance(instr, N.For):
            _walk_calls(instr.body, visitor)
        elif isinstance(instr, N.Match):
            for arm in instr.arms:
                _walk_calls(arm.body, visitor)


# ============================================================
# Generic type (struct / sum) monomorphisation
# ============================================================
#
# Generic *functions* are specialised above; generic *types* are
# specialised here. A ``type Pair<T> { a: T, b: Int }`` referenced
# concretely as ``Pair<Char>`` must become a distinct monomorphic
# struct ``Pair__Char { a: Char, b: Int }`` before the Wasm layout
# machinery sees it -- otherwise the field ``a`` is sized / decoded
# as the type variable ``T`` (which has no Wasm encoding), and a
# struct returned across a function boundary mis-decodes its
# generic field. The pass:
#
#   1. finds every concrete instantiation ``G<args>`` of a generic
#      type reachable from any type string in the module (plus the
#      struct-literal / variant-construction sites, whose bare
#      ``type_name`` carries no args and must be inferred from the
#      operand types);
#   2. synthesises one mangled clone decl per instantiation with the
#      type parameters substituted through field / payload types;
#   3. rewrites every reference -- type strings, ``Value.ty``,
#      ``MakeStruct.type_name``, function locals / params / return
#      types, and clone decls' own field types -- to the mangled
#      name.
#
# After this pass the module contains no generic type decls and no
# type string mentioning a generic head with arguments, so the Wasm
# backend emits each instantiation's layout from concrete field
# types. The non-generic path is untouched (no generic decls => the
# pass is a no-op).


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


def _collect_generic_type_refs(
    ty_str: str, generic_names: set[str], abstract: set[str],
    out: dict[str, tuple[str, list[str]]],
) -> None:
    """Record every fully-concrete instantiation of a generic type
    that appears anywhere inside ``ty_str`` (including nested
    positions like ``List<Pair<Int>>`` or ``Map<String, Box<Bool>>``).
    Each entry maps the canonical instantiation string -> (head,
    args). Instantiations whose args still mention a type variable or
    an unresolved ``?`` marker are skipped: they belong to an
    enclosing generic that has not been resolved, or to a call site
    whose inference is incomplete, and emitting a clone for them
    would produce a bogus (un-encodable) layout."""
    if not ty_str:
        return
    head, args = _parse_ty(ty_str)
    for a in args:
        _collect_generic_type_refs(a, generic_names, abstract, out)
    if head in generic_names and args and not any(
        _is_abstract_ty(a, abstract) for a in args
    ):
        canonical = f"{head}<{', '.join(args)}>"
        out[canonical] = (head, args)


def _rewrite_ty(ty_str: str, rewrites: dict[str, str]) -> str:
    """Rewrite every concrete generic instantiation inside ``ty_str``
    to its mangled monomorphic name, recursing into nested args so
    ``List<Pair<Char>>`` becomes ``List<Pair__Char>``. Leaves
    non-generic and already-monomorphic heads untouched."""
    if not ty_str:
        return ty_str
    # The rewrites map is keyed by the *original* canonical form
    # (``Box<Pair<Int, String>>``); try that before recursing so a
    # whole-string hit resolves the outer generic in one step.
    if ty_str in rewrites:
        return rewrites[ty_str]
    head, args = _parse_ty(ty_str)
    if not args:
        return ty_str
    new_args = [_rewrite_ty(a, rewrites) for a in args]
    if head == "(tuple)":
        return "(" + ", ".join(new_args) + ")"
    if head == "(fun)":
        *params, ret = new_args
        return f"Fun({', '.join(params)}) -> {ret}"
    # Re-check after inner rewrites in case the map was keyed by the
    # inner-mangled form, then fall back to the rebuilt string.
    rebuilt = f"{head}<{', '.join(new_args)}>"
    return rewrites.get(rebuilt, rebuilt)


# Field name on a dataclass node that carries a (bare or generic)
# *type name* used as a constructor target rather than a value type.
_TYPE_NAME_FIELDS = {"type_name"}


def _rewrite_node_types(node, rewrites: dict[str, str]):
    """Recursively rewrite every type-string field of a node so a
    concrete generic instantiation points at its mangled clone.
    Mirrors ``_substitute_node`` but applies the instantiation
    rewrite (``Pair<Char>`` -> ``Pair__Char``) instead of a
    type-parameter substitution."""
    if node is None:
        return node
    if isinstance(node, N.Value):
        new_ty = _rewrite_ty(node.ty, rewrites)
        if new_ty == node.ty:
            return node
        return N.Value(
            kind=node.kind, name=node.name, literal=node.literal, ty=new_ty,
        )
    if isinstance(node, str):
        return node
    if isinstance(node, list):
        return [_rewrite_node_types(x, rewrites) for x in node]
    if isinstance(node, tuple):
        return tuple(_rewrite_node_types(x, rewrites) for x in node)
    if is_dataclass(node):
        changes = {}
        for f in fields(node):
            old = getattr(node, f.name)
            if isinstance(old, str) and f.name in _TYPE_STRING_FIELDS:
                new = _rewrite_ty(old, rewrites)
            elif isinstance(old, str) and f.name in _TYPE_NAME_FIELDS:
                # Bare constructor targets (``MakeStruct.type_name``)
                # carry no args, so a plain-string lookup resolves the
                # per-site instantiation the caller has injected into
                # ``rewrites`` under the bare name.
                new = rewrites.get(old, old)
            else:
                new = _rewrite_node_types(old, rewrites)
            if new is not old:
                changes[f.name] = new
        if changes:
            return replace(node, **changes)
        return node
    return node


def _infer_make_struct_subst(
    instr: N.MakeStruct, decl: N.StructDecl,
) -> Optional[dict[str, str]]:
    """Infer the type-parameter substitution for a generic struct
    literal from its field values' concrete types. ``Pair { a: 'x',
    b: 5 }`` against ``Pair<T> { a: T, b: Int }`` yields ``{T: Char}``.
    Returns None when any type parameter stays unresolved or a field
    value's type is itself unresolved."""
    type_param_set = set(decl.type_params)
    field_decl_ty = {f.name: f.ty for f in decl.fields}
    mapping: dict[str, str] = {}
    for fname, fval in instr.fields:
        decl_ty = field_decl_ty.get(fname)
        if decl_ty is None:
            return None
        if not fval.ty or fval.ty.startswith("?") or fval.ty in (
            "Unknown", "",
        ):
            # Cannot trust an unresolved field type to drive inference
            # when the field position is generic; if the field is a
            # plain concrete field (e.g. ``b: Int``) an unresolved
            # value type is harmless, so only bail when the decl side
            # is a type variable we still need to resolve.
            if decl_ty in type_param_set and decl_ty not in mapping:
                return None
            continue
        if not _unify_ty(decl_ty, fval.ty, type_param_set, mapping):
            return None
    for tp in decl.type_params:
        if tp not in mapping:
            return None
    return mapping


def _specialise_struct_decl(
    decl: N.StructDecl, subst: dict[str, str], mangled: str,
) -> N.StructDecl:
    return N.StructDecl(
        name=mangled,
        fields=[
            N.StructField(name=f.name, ty=_substitute_ty(f.ty, subst))
            for f in decl.fields
        ],
        type_params=[],
    )


def _specialise_sum_decl(
    decl: N.SumDecl, subst: dict[str, str], mangled: str,
) -> N.SumDecl:
    return N.SumDecl(
        name=mangled,
        variants=[
            N.SumVariant(
                name=v.name,
                payload_tys=[_substitute_ty(p, subst) for p in v.payload_tys],
            )
            for v in decl.variants
        ],
        type_params=[],
    )


def _has_question_mark(ty_str: str) -> bool:
    """True if ``ty_str`` contains an unresolved type-variable marker
    (``?`` anywhere). The lowerer writes ``?`` for a type arg it could
    not infer (e.g. the ``R`` of ``Either<Int, ?>`` from a one-arm
    ``Left(7)`` constructor)."""
    return "?" in ty_str


def _resolve_partial_against(partial: str, concrete: str) -> Optional[str]:
    """If ``partial`` (which contains ``?`` markers) and ``concrete``
    share a head and arity, fill ``partial``'s ``?`` positions from
    ``concrete``. ``Either<Int, ?>`` + ``Either<Int, String>`` ->
    ``Either<Int, String>``. Returns None when they do not align."""
    p_head, p_args = _parse_ty(partial)
    c_head, c_args = _parse_ty(concrete)
    if p_head != c_head or len(p_args) != len(c_args):
        return None
    resolved_args = []
    for pa, ca in zip(p_args, c_args):
        if "?" in pa:
            sub = _resolve_partial_against(pa, ca)
            if sub is None:
                if pa.startswith("?"):
                    resolved_args.append(ca)
                    continue
                return None
            resolved_args.append(sub)
        else:
            resolved_args.append(pa)
    if p_head == "(tuple)":
        return "(" + ", ".join(resolved_args) + ")"
    return f"{p_head}<{', '.join(resolved_args)}>"


def _resolve_partial_types(fn, generic_names, abstract_names) -> None:
    """Replace partial generic instantiations (those carrying a ``?``)
    in ``fn``'s locals + Value types with the concrete sibling type
    the function already mentions. Collects every fully-concrete
    ``G<args>`` from the function (return type, params, locals, Value
    types) as candidates, then rewrites each partial that aligns with
    one. Mutates ``fn`` in place."""
    concretes: set[str] = set()

    def add_concrete(ty_str: str) -> None:
        if not ty_str or _has_question_mark(ty_str):
            return
        head, args = _parse_ty(ty_str)
        if head in generic_names and args and not any(
            _is_abstract_ty(a, abstract_names) for a in args
        ):
            concretes.add(ty_str)

    add_concrete(fn.return_type)
    for p in fn.params:
        add_concrete(p.ty)
    for lty in fn.locals.values():
        add_concrete(lty)

    def collect_value_concretes(node) -> None:
        if isinstance(node, N.Value):
            add_concrete(node.ty)
        elif isinstance(node, (list, tuple)):
            for x in node:
                collect_value_concretes(x)
        elif is_dataclass(node):
            for f in fields(node):
                collect_value_concretes(getattr(node, f.name))

    for instr in fn.body:
        collect_value_concretes(instr)

    if not concretes:
        return

    def resolve(ty_str: str) -> str:
        if not ty_str or not _has_question_mark(ty_str):
            return ty_str
        for cand in concretes:
            filled = _resolve_partial_against(ty_str, cand)
            if filled is not None and not _has_question_mark(filled):
                return filled
        return ty_str

    fn.locals = {name: resolve(lty) for name, lty in fn.locals.items()}

    def rewrite_values(node):
        if isinstance(node, N.Value):
            new_ty = resolve(node.ty)
            if new_ty == node.ty:
                return node
            return N.Value(
                kind=node.kind, name=node.name,
                literal=node.literal, ty=new_ty,
            )
        if isinstance(node, list):
            return [rewrite_values(x) for x in node]
        if isinstance(node, tuple):
            return tuple(rewrite_values(x) for x in node)
        if is_dataclass(node):
            changes = {}
            for f in fields(node):
                old = getattr(node, f.name)
                new = rewrite_values(old)
                if new is not old:
                    changes[f.name] = new
            if changes:
                return replace(node, **changes)
            return node
        return node

    fn.body = [rewrite_values(instr) for instr in fn.body]


def monomorphise_generic_types(module: N.Module) -> N.Module:
    """Specialise every generic struct / sum type per concrete
    instantiation referenced in the module (see the module-level
    comment above). Mutates ``module`` in place and returns it. A
    no-op when the module declares no generic types."""
    generic_structs: dict[str, N.StructDecl] = {}
    generic_sums: dict[str, N.SumDecl] = {}
    for ty in module.types:
        if isinstance(ty, N.StructDecl) and ty.type_params:
            generic_structs[ty.name] = ty
        elif isinstance(ty, N.SumDecl) and ty.type_params:
            generic_sums[ty.name] = ty
    generic_names = set(generic_structs) | set(generic_sums)
    if not generic_names:
        return module

    # Names that mark a type as not-yet-concrete: every generic decl's
    # type parameters. A ``?...`` marker is handled positionally by
    # ``_is_abstract_ty``. Used to skip instantiations whose args are
    # still abstract (a clone of ``Box<Pair>`` or ``Either<Int, ?>``
    # would have an un-encodable field).
    abstract_names: set[str] = set()
    for decl in (*generic_structs.values(), *generic_sums.values()):
        abstract_names.update(decl.type_params)

    # 0. Resolve partial instantiations (``Either<Int, ?>`` from a
    #    ``Left(7)`` variant constructor that pins only one type arg)
    #    against the concrete type strings the same function already
    #    carries (its return type, params, fully-resolved locals).
    #    Without this the partial type seeds no clone and the emitter
    #    later hits "has no Wasm encoding" on the un-erased ``?``.
    for fn in module.functions:
        _resolve_partial_types(fn, generic_names, abstract_names)

    # 1. Collect concrete instantiations from every type string the
    #    module carries: function signatures + locals, Value types,
    #    decl field / payload types.
    instantiations: dict[str, tuple[str, list[str]]] = {}

    def collect_in(ty_str: str) -> None:
        _collect_generic_type_refs(
            ty_str, generic_names, abstract_names, instantiations,
        )

    def walk_node_tys(node) -> None:
        if node is None:
            return
        if isinstance(node, N.Value):
            collect_in(node.ty)
            return
        if isinstance(node, (list, tuple)):
            for x in node:
                walk_node_tys(x)
            return
        if is_dataclass(node):
            for f in fields(node):
                old = getattr(node, f.name)
                if isinstance(old, str) and f.name in _TYPE_STRING_FIELDS:
                    collect_in(old)
                else:
                    walk_node_tys(old)
            return

    for fn in module.functions:
        for p in fn.params:
            collect_in(p.ty)
        collect_in(fn.return_type)
        for lty in fn.locals.values():
            collect_in(lty)
        for instr in fn.body:
            walk_node_tys(instr)
    for ty in module.types:
        if isinstance(ty, N.StructDecl):
            for f in ty.fields:
                collect_in(f.ty)
        elif isinstance(ty, N.SumDecl):
            for v in ty.variants:
                for p in v.payload_tys:
                    collect_in(p)

    # Per-site inference for generic struct literals whose bare
    # ``type_name`` (and dst local) carry no type arguments. The
    # inferred instantiation both seeds the clone table and lets us
    # rewrite the bare ``type_name`` + dst local for that one site.
    # Keyed by (fn_name, MakeStruct.dst) -> mangled name.
    make_struct_sites: dict[tuple[str, str], str] = {}

    def register_instantiation(head: str, args: list[str]) -> Optional[str]:
        if any(_is_abstract_ty(a, abstract_names) for a in args):
            return None
        canonical = f"{head}<{', '.join(args)}>"
        instantiations[canonical] = (head, args)
        # Recurse into the args so a nested generic instantiation
        # (``Box<Pair<Int, String>>``) also seeds the inner clone.
        for a in args:
            collect_in(a)
        return _mangle_type(head, args)

    for fn in module.functions:
        for instr in fn.body:
            _scan_make_struct_sites(
                fn, instr, generic_structs,
                register_instantiation, make_struct_sites,
            )

    if not instantiations:
        return module

    # 2. Build clones + the canonical-string -> mangled rewrite map.
    rewrites: dict[str, str] = {}
    new_decls: dict[str, object] = {}
    for canonical, (head, args) in instantiations.items():
        mangled = _mangle_type(head, args)
        rewrites[canonical] = mangled
        if mangled in new_decls:
            continue
        if head in generic_structs:
            decl = generic_structs[head]
            subst = dict(zip(decl.type_params, args))
            new_decls[mangled] = _specialise_struct_decl(decl, subst, mangled)
        elif head in generic_sums:
            decl = generic_sums[head]
            subst = dict(zip(decl.type_params, args))
            new_decls[mangled] = _specialise_sum_decl(decl, subst, mangled)

    # 3. Rewrite the module. Generic decls are dropped; their clones
    #    replace them (themselves run through the rewrite so a generic
    #    field referencing another generic instantiation is threaded).
    new_types: list = []
    for ty in module.types:
        if isinstance(ty, (N.StructDecl, N.SumDecl)) and ty.type_params:
            continue
        new_types.append(_rewrite_node_types(ty, rewrites))
    for decl in new_decls.values():
        new_types.append(_rewrite_node_types(decl, rewrites))
    module.types = new_types

    for fn in module.functions:
        fn.params = [
            N.Param(
                name=p.name,
                ty=_rewrite_ty(p.ty, rewrites),
                is_capability=p.is_capability,
            )
            for p in fn.params
        ]
        fn.return_type = _rewrite_ty(fn.return_type, rewrites)
        fn.locals = {
            name: _rewrite_ty(lty, rewrites) for name, lty in fn.locals.items()
        }
        new_body = []
        for instr in fn.body:
            rewritten = _rewrite_node_types(instr, rewrites)
            new_body.append(rewritten)
        fn.body = new_body
        _patch_bare_generic_struct_refs(fn, make_struct_sites)

    # Variant payloads of a monomorphised sum carry concrete types
    # now (``Either__Int_String`` -> ``Left(Int)``), but a ``match``
    # arm's binder local was typed from the original generic decl
    # (``n: L``). Refine each PatVariant binder's local type from the
    # concrete sum decl so the Wasm match-payload extractor decodes
    # it as its real type rather than choking on the type variable.
    concrete_sum_payloads: dict[str, dict[str, list[str]]] = {}
    for decl in new_decls.values():
        if isinstance(decl, N.SumDecl):
            concrete_sum_payloads[decl.name] = {
                v.name: list(v.payload_tys) for v in decl.variants
            }
    if concrete_sum_payloads:
        for fn in module.functions:
            for instr in fn.body:
                _refine_match_binders(fn, instr, concrete_sum_payloads)

    return module


def _refine_match_binders(fn, instr, concrete_sum_payloads: dict) -> None:
    """Set the local type of every PatVariant binder in a ``match``
    against a monomorphised sum to the concrete payload type from the
    specialised decl. Recurses through nested control flow and nested
    sub-patterns."""
    if isinstance(instr, N.Match):
        scrut_head = _strip_head(instr.scrutinee.ty)
        payloads = concrete_sum_payloads.get(scrut_head)
        if payloads is not None:
            for arm in instr.arms:
                _refine_pattern_binders(arm.pattern, payloads, fn)
                for sub in arm.body:
                    _refine_match_binders(fn, sub, concrete_sum_payloads)
        else:
            for arm in instr.arms:
                for sub in arm.body:
                    _refine_match_binders(fn, sub, concrete_sum_payloads)
        return
    if isinstance(instr, N.If):
        for sub in (*instr.then_body, *instr.else_body):
            _refine_match_binders(fn, sub, concrete_sum_payloads)
    elif isinstance(instr, N.While):
        for sub in (*instr.cond_setup, *instr.body):
            _refine_match_binders(fn, sub, concrete_sum_payloads)
    elif isinstance(instr, N.For):
        for sub in instr.body:
            _refine_match_binders(fn, sub, concrete_sum_payloads)


def _refine_pattern_binders(pattern, payloads: dict, fn) -> None:
    """Walk a PatVariant's payload sub-patterns, setting each bound
    identifier's local type to the concrete payload type from the
    specialised sum decl."""
    if isinstance(pattern, N.PatVariant):
        tys = payloads.get(pattern.name)
        if tys is not None:
            for sub, ty in zip(pattern.payloads, tys):
                if isinstance(sub, N.PatIdent):
                    fn.locals[sub.name] = ty


def _strip_head(ty_str: str) -> str:
    """Bare head of a type string: ``Either__Int_String`` ->
    ``Either__Int_String``, ``List<Int>`` -> ``List``."""
    return ty_str.split("<", 1)[0].split("[", 1)[0]


def _patch_bare_generic_struct_refs(fn, make_struct_sites: dict) -> None:
    """Patch the bare-headed references a generic struct literal leaves
    behind. ``MakeStruct.type_name`` and its dst local carry the bare
    head (``Pair``, no args), which the instantiation-string rewrite
    cannot reach. Resolve them from the per-site inference, then
    propagate the concrete instantiation through alias assignments
    (``let p = _ir_t0``) to a fixed point so every later
    ``FieldAccess`` / ``Return`` against the value sees the mangled
    type, and the emitter sizes / decodes it as a struct pointer
    rather than hitting the bare-name fallback."""
    # local name -> (bare_head, mangled) for locals that hold a
    # concrete generic-struct instance.
    concrete: dict[str, tuple[str, str]] = {}
    for instr in fn.body:
        if isinstance(instr, N.MakeStruct):
            site = make_struct_sites.get((fn.name, instr.dst))
            if site is not None:
                bare_head, mangled = site
                instr.type_name = mangled
                fn.locals[instr.dst] = mangled
                concrete[instr.dst] = (bare_head, mangled)
    if not concrete:
        return
    # Fixed-point alias propagation: an assignment whose src is a
    # concrete local and whose dst is still typed with the same bare
    # head inherits the concrete instantiation.
    changed = True
    while changed:
        changed = False
        for instr in fn.body:
            if isinstance(instr, (N.AssignConst, N.Reassign)):
                src = instr.src
                if (src.kind in ("local", "param")
                        and src.name in concrete
                        and instr.dst not in concrete):
                    bare_head, mangled = concrete[src.name]
                    dst_ty = fn.locals.get(instr.dst, "")
                    if dst_ty in (bare_head, mangled):
                        concrete[instr.dst] = (bare_head, mangled)
                        fn.locals[instr.dst] = mangled
                        changed = True
    fn.body = [
        _rewrite_bare_local_refs(instr, concrete) for instr in fn.body
    ]


def _rewrite_bare_local_refs(node, bare_local_types: dict):
    """Rewrite the ``ty`` of any Value that refers (by name) to a
    local whose concrete generic instantiation was inferred from a
    struct literal, but whose annotated type is still the bare
    generic head. ``return _ir_t0`` where ``_ir_t0: Pair`` (bare) and
    the literal resolved to ``Pair__Char`` gets ``ty="Pair__Char"``."""
    if node is None:
        return node
    if isinstance(node, N.Value):
        if node.name in bare_local_types:
            bare_head, mangled = bare_local_types[node.name]
            if node.ty == bare_head:
                return N.Value(
                    kind=node.kind, name=node.name,
                    literal=node.literal, ty=mangled,
                )
        return node
    if isinstance(node, list):
        return [_rewrite_bare_local_refs(x, bare_local_types) for x in node]
    if isinstance(node, tuple):
        return tuple(
            _rewrite_bare_local_refs(x, bare_local_types) for x in node
        )
    if is_dataclass(node):
        changes = {}
        for f in fields(node):
            old = getattr(node, f.name)
            new = _rewrite_bare_local_refs(old, bare_local_types)
            if new is not old:
                changes[f.name] = new
        if changes:
            return replace(node, **changes)
        return node
    return node


def _scan_make_struct_sites(
    fn, instr, generic_structs, register_instantiation, sites,
) -> None:
    """Recurse through an instruction tree recording, for every
    generic struct literal, the mangled instantiation inferred from
    its field values. Registers the instantiation so a clone is built
    even when no annotated type string elsewhere mentions it."""
    if isinstance(instr, N.MakeStruct) and instr.type_name in generic_structs:
        decl = generic_structs[instr.type_name]
        subst = _infer_make_struct_subst(instr, decl)
        if subst is not None:
            args = [subst[tp] for tp in decl.type_params]
            mangled = register_instantiation(instr.type_name, args)
            if mangled is not None:
                sites[(fn.name, instr.dst)] = (instr.type_name, mangled)
        return
    if isinstance(instr, N.If):
        for sub in instr.then_body:
            _scan_make_struct_sites(
                fn, sub, generic_structs, register_instantiation, sites)
        for sub in instr.else_body:
            _scan_make_struct_sites(
                fn, sub, generic_structs, register_instantiation, sites)
    elif isinstance(instr, N.While):
        for sub in instr.cond_setup:
            _scan_make_struct_sites(
                fn, sub, generic_structs, register_instantiation, sites)
        for sub in instr.body:
            _scan_make_struct_sites(
                fn, sub, generic_structs, register_instantiation, sites)
    elif isinstance(instr, N.For):
        for sub in instr.body:
            _scan_make_struct_sites(
                fn, sub, generic_structs, register_instantiation, sites)
    elif isinstance(instr, N.Match):
        for arm in instr.arms:
            for sub in arm.body:
                _scan_make_struct_sites(
                    fn, sub, generic_structs, register_instantiation, sites)


# ============================================================
# Top-level pass
# ============================================================


def monomorphise(module: N.Module) -> N.Module:
    """Specialise every generic free function in ``module`` per
    concrete instantiation reached from any non-generic function,
    iterated to a fixed point so generic-calls-generic chains also
    monomorphise.

    The module is mutated in place: original generic functions
    are removed, specialised clones are appended, and every call
    to a generic function is rewritten to its mangled name. The
    same module reference is returned for convenience."""
    generics: dict[str, N.Function] = {
        fn.name: fn for fn in module.functions if fn.type_params
    }
    if not generics:
        # No generic functions, but the module may still declare
        # generic struct / sum types instantiated concretely (e.g.
        # ``Pair<Char>``); those need their own monomorphisation.
        return monomorphise_generic_types(module)

    # Specialised clones, keyed by (callee_name, mangled_name) so
    # the same instantiation reuses one clone.
    specialised: dict[str, N.Function] = {}

    def specialise_call(call: N.Call) -> None:
        """Try to rewrite ``call`` in place; queue any newly-
        produced specialisations for subsequent passes."""
        if call.callee_name not in generics:
            return
        callee = generics[call.callee_name]
        subst = _infer_subst_for_call(call, callee)
        if subst is None:
            return
        mangled = _mangle(call.callee_name, subst, callee.type_params)
        if mangled not in specialised:
            specialised[mangled] = _specialise_function(
                callee, subst, mangled,
            )
        call.callee_name = mangled
        # Mutate the dst type so downstream typing flows through.
        # Use the callee's substituted return type.
        # (Call.dst is a string, not a Value, so the dst's type
        # lives in the parent function's locals dict; the caller
        # is responsible for updating that.)

    def visitor(owner_list, index):
        instr = owner_list[index]
        if isinstance(instr, N.Call):
            specialise_call(instr)

    # Fixed-point: each iteration walks all non-generic functions
    # and any clones produced so far. Stops when an iteration
    # produces zero new clones.
    seen_clone_names: set[str] = set()
    while True:
        before = len(specialised)
        for fn in module.functions:
            if fn.type_params:
                continue  # skip the originals; they go away below
            _walk_calls(fn.body, visitor)
        # Walk new clones, which may themselves call other generics.
        for name, fn in list(specialised.items()):
            if name in seen_clone_names:
                continue
            seen_clone_names.add(name)
            _walk_calls(fn.body, visitor)
            # The clone's own locals dict needs the dst types of
            # rewritten calls patched. _walk_calls already updated
            # call.callee_name; the local's ty was substituted
            # when the clone was created. New nested clones get
            # picked up in subsequent iterations.
        if len(specialised) == before:
            break

    # Replace the generics in the module with the specialised
    # clones. Preserve declaration order for stability of
    # downstream emit (the seed libraries' WIT generation cares
    # about a stable function order).
    new_funcs: list[N.Function] = []
    for fn in module.functions:
        if fn.type_params:
            continue
        new_funcs.append(fn)
    new_funcs.extend(specialised.values())
    module.functions = new_funcs
    # Specialise generic struct / sum types last: it consumes the
    # now-concrete type strings produced by the function clones (a
    # ``first<Char>`` clone returns ``Option<Char>``, which carries
    # no generic struct, but ``wrap<Int>`` returns ``Box<Int>`` whose
    # ``Box`` decl must be monomorphised here).
    return monomorphise_generic_types(module)
