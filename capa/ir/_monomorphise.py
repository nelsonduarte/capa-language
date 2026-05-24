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
        return module

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
    return module
