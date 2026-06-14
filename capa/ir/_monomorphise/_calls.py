"""Call-site inference + rewrite and the top-level generic-function
pass: walk the module, infer a substitution per call to a generic
free function, synthesise a mangled clone, and rewrite the call.
"""

from __future__ import annotations

from dataclasses import fields, is_dataclass, replace
from typing import Optional

from .. import _nodes as N
from ._functions import _specialise_function
from ._typestr import (
    _has_question_mark,
    _mangle,
    _parse_ty,
    _strip_head,
    _substitute_ty,
    _unify_ty,
)
from ._types import _infer_make_struct_subst, monomorphise_generic_types


# ============================================================
# Call-site inference + rewrite
# ============================================================


def _is_concrete_ty(ty: str) -> bool:
    """True when a type string is usable to drive return-type
    inference: present, not a placeholder, and free of unresolved
    type-variable markers (``?...``)."""
    if not ty or ty in ("?", "Unknown", ""):
        return False
    if ty.startswith("?") or _has_question_mark(ty):
        return False
    return True


def _infer_subst_for_call(
    call: N.Call,
    callee: N.Function,
    expected_return: Optional[str] = None,
) -> Optional[dict[str, str]]:
    """Walk the call's args against the generic function's params
    to infer a substitution for every ``type_params`` entry.

    Type parameters that no value argument carries (a zero-arg
    factory like ``empty_tally<T>() -> Tally<T>``, or a param list
    that simply never mentions ``T``) are filled from
    ``expected_return``: the concrete type the call's result is
    used at (the annotated binding, the enclosing ``return`` type,
    or a consuming call's parameter type). This is the
    cross-backend parity fix -- the Python backend never
    monomorphises, so it accepts these calls; the Wasm backend
    must derive the same instantiation the analyzer already
    resolved.

    Returns None when any type parameter still cannot be resolved
    or when a structural mismatch shows up."""
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
    # Type parameters the arguments did not pin down are recovered
    # from the expected result type (the call-site context the
    # analyzer already resolved), by unifying the callee's declared
    # return type against it.
    if (
        any(tp not in mapping for tp in callee.type_params)
        and expected_return
        and _is_concrete_ty(expected_return)
    ):
        # Unify into a copy first: a structural mismatch against the
        # expected type must not corrupt the argument-derived
        # bindings (those are trustworthy on their own).
        ret_mapping = dict(mapping)
        if _unify_ty(
            callee.return_type, expected_return,
            type_param_set, ret_mapping,
        ):
            mapping = ret_mapping
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
# Generic-struct-literal local typing (pre-pass)
# ============================================================
#
# A generic struct literal bound to a local (``let bi = Box { value:
# 42 }``) leaves that local typed with the *bare* generic head
# (``Box``) -- the lowerer carries no type argument because the
# arguments are only implied by the field values. A subsequent call
# whose generic parameter is that struct type (``unwrap_box(bi)`` with
# ``b: Box<T>``) then cannot infer ``T``: unifying ``Box<T>`` against
# the bare ``Box`` fails on arity. Sum constructors already carry the
# full instantiation (``Just(7)`` -> ``Opt<Int>``), so only struct
# literals need this.
#
# This pre-pass runs BEFORE call-site inference. It walks each
# function in body order, infers each generic struct literal's
# canonical instantiation (``Box<Int>``) from its field values via the
# same ``_infer_make_struct_subst`` the type pass uses, threads the
# result through aliases, and rewrites the bare head on the bound
# local's type (in ``fn.locals`` and on every Value that references
# it) to the canonical ``G<args>`` form. The later type pass then
# mangles ``Box<Int>`` -> ``Box__Int`` uniformly with all other
# concrete instantiations.


def _annotate_generic_struct_literal_types(
    module: N.Module,
) -> None:
    generic_structs: dict[str, N.StructDecl] = {
        ty.name: ty
        for ty in module.types
        if isinstance(ty, N.StructDecl) and ty.type_params
    }
    if not generic_structs:
        return
    for fn in module.functions:
        concrete: dict[str, str] = {}
        _scan_literal_types(fn.body, generic_structs, fn, concrete)
        if not concrete:
            continue
        for name, canonical in concrete.items():
            if _strip_head(fn.locals.get(name, "")) == _strip_head(canonical):
                fn.locals[name] = canonical
        fn.body = [_retype_local_refs(instr, concrete) for instr in fn.body]


def _scan_literal_types(
    body: list[N.Instr], generic_structs: dict[str, N.StructDecl],
    fn: N.Function, concrete: dict[str, str],
) -> None:
    """Walk one instruction list in body order, recording for each
    generic struct literal the canonical instantiation it resolves to
    and propagating it through alias assignments. Recurses into nested
    control-flow bodies (the same scope; a literal in a branch still
    types its bound local for later calls)."""
    for instr in body:
        if (
            isinstance(instr, N.MakeStruct)
            and instr.type_name in generic_structs
        ):
            decl = generic_structs[instr.type_name]
            subst = _infer_make_struct_subst(instr, decl, concrete)
            if subst is not None and all(tp in subst for tp in decl.type_params):
                args = [subst[tp] for tp in decl.type_params]
                concrete[instr.dst] = (
                    f"{instr.type_name}<{', '.join(args)}>"
                )
        elif isinstance(instr, (N.AssignConst, N.Reassign)):
            src = instr.src
            if src.kind in ("local", "param") and src.name in concrete:
                concrete[instr.dst] = concrete[src.name]
        else:
            for sub in _child_bodies(instr):
                _scan_literal_types(sub, generic_structs, fn, concrete)


def _child_bodies(instr):
    if isinstance(instr, N.If):
        yield instr.then_body
        yield instr.else_body
    elif isinstance(instr, N.While):
        yield instr.cond_setup
        yield instr.body
    elif isinstance(instr, N.For):
        yield instr.body
    elif isinstance(instr, N.Match):
        for arm in instr.arms:
            yield arm.body


def _retype_local_refs(node, concrete: dict[str, str]):
    """Rewrite the ``ty`` of any Value referencing a local that a
    generic struct literal resolved to a canonical instantiation, when
    that Value still carries the bare generic head. Mirrors the
    type-pass's ``_rewrite_bare_local_refs`` but rewrites to the
    canonical (un-mangled) form."""
    if node is None:
        return node
    if isinstance(node, N.Value):
        if node.name in concrete:
            canonical = concrete[node.name]
            if node.ty == _strip_head(canonical) and node.ty != canonical:
                return N.Value(
                    kind=node.kind, name=node.name,
                    literal=node.literal, ty=canonical,
                )
        return node
    if isinstance(node, list):
        return [_retype_local_refs(x, concrete) for x in node]
    if isinstance(node, tuple):
        return tuple(_retype_local_refs(x, concrete) for x in node)
    if is_dataclass(node):
        changes = {}
        for f in fields(node):
            old = getattr(node, f.name)
            new = _retype_local_refs(old, concrete)
            if new is not old:
                changes[f.name] = new
        if changes:
            return replace(node, **changes)
        return node
    return node


def _retype_placeholder_refs(node, retyped: dict[str, str]):
    """Rewrite the ``ty`` of any Value referencing a local that the
    monomorphiser retyped from a ``?`` placeholder to a concrete
    instantiation. Unlike ``_retype_local_refs`` (which keys off the
    bare generic head), this matches the placeholder form a generic
    factory's dst temp carries (``Tally<?>`` -> ``Tally<String>``)."""
    if node is None:
        return node
    if isinstance(node, N.Value):
        if node.name in retyped and node.ty != retyped[node.name]:
            return N.Value(
                kind=node.kind, name=node.name,
                literal=node.literal, ty=retyped[node.name],
            )
        return node
    if isinstance(node, list):
        return [_retype_placeholder_refs(x, retyped) for x in node]
    if isinstance(node, tuple):
        return tuple(_retype_placeholder_refs(x, retyped) for x in node)
    if is_dataclass(node):
        changes = {}
        for f in fields(node):
            old = getattr(node, f.name)
            new = _retype_placeholder_refs(old, retyped)
            if new is not old:
                changes[f.name] = new
        if changes:
            return replace(node, **changes)
        return node
    return node


# ============================================================
# Expected-return-type resolution
# ============================================================
#
# A generic factory whose type parameter no value argument carries
# (``empty_tally<T>() -> Tally<T>``) leaves the monomorphiser nothing
# to infer ``T`` from at the call site -- unless it consults the
# context the call's result flows into. The analyzer already resolved
# that context (``--check`` passes, Python runs correctly), and the
# lowerer preserved it on the surrounding IR:
#
#   * an annotated binding (``var t: Tally<String> = factory()``)
#     types the bound local ``t`` concretely; the call's own dst temp
#     stays ``Tally<?>`` but an ``AssignConst`` aliases it to ``t``.
#   * a direct return (``return factory()``) flows the temp into a
#     ``Return`` whose type is the enclosing function's return type.
#   * a function argument (``count(factory())``) passes the temp into
#     a consuming call whose parameter type is concrete.
#
# ``_expected_return_types`` walks one function body and builds a map
# from each ``Call.dst`` temp to the concrete type its result is used
# at, following all three edges. The inference above unifies the
# callee's declared return type against that concrete type to recover
# the missing type parameters.


def _struct_field_types(
    type_name: str, struct_ty: str, struct_decls: dict[str, N.StructDecl],
) -> dict[str, str]:
    """Field-name -> field-type map for a struct literal whose
    instantiation ``struct_ty`` (``Wrap<Int>``) is concretely known.
    Returns the field types with the struct's type parameters
    substituted (``inner: Box<T>`` -> ``inner: Box<Int>``). Returns
    an empty map when the struct is not generic, not declared, or its
    instantiation is unknown/abstract -- callers treat that as "no
    context"."""
    decl = struct_decls.get(type_name)
    if decl is None or not decl.type_params:
        # Non-generic struct: field types are already concrete and the
        # plain decl serves directly.
        if decl is None:
            return {}
        return {f.name: f.ty for f in decl.fields}
    if not _is_concrete_ty(struct_ty):
        return {}
    head, args = _parse_ty(struct_ty)
    if head != type_name or len(args) != len(decl.type_params):
        return {}
    subst = dict(zip(decl.type_params, args))
    return {f.name: _substitute_ty(f.ty, subst) for f in decl.fields}


def _expected_return_types(
    fn: N.Function,
    module_funcs: dict[str, N.Function],
    struct_decls: dict[str, N.StructDecl],
) -> dict[str, str]:
    """Map each local that a ``Call`` result is bound to onto the
    concrete type its value is consumed at within ``fn``. Covers the
    annotated-binding, direct-return, concrete-callee-argument, and
    known-instantiation struct-field cases. Locals whose use site is
    not concretely typed are omitted; the inference treats a missing
    entry as "no context"."""
    # Forward alias edges: ``dst = src`` (AssignConst / Reassign) means
    # the value in ``src`` reaches ``dst``. We resolve a temp to the
    # first concretely-typed local it aliases into, plus the direct
    # uses below.
    expected: dict[str, str] = {}
    aliases: dict[str, str] = {}
    make_structs: list[N.MakeStruct] = []
    params_by_name = {p.name: p.ty for p in fn.params}

    def record(name: Optional[str], ty: Optional[str]) -> None:
        if name and ty and _is_concrete_ty(ty) and name not in expected:
            expected[name] = ty

    def scan(instrs: list[N.Instr]) -> None:
        for instr in instrs:
            if isinstance(instr, (N.AssignConst, N.Reassign)):
                src = instr.src
                if src.kind in ("local", "param") and src.name:
                    aliases.setdefault(src.name, instr.dst)
            elif isinstance(instr, N.Return):
                v = instr.value
                if v is not None and v.kind in ("local", "param") and v.name:
                    record(v.name, fn.return_type)
            elif isinstance(instr, N.Call):
                # A temp passed as an argument to a NON-generic callee
                # is pinned by that callee's parameter type. (A generic
                # consuming callee's param may itself mention a type
                # variable, so it is not a reliable concrete context.)
                callee = module_funcs.get(instr.callee_name)
                if callee is not None and not callee.type_params:
                    for arg, p in zip(instr.args, callee.params):
                        if arg.kind in ("local", "param") and arg.name:
                            record(arg.name, p.ty)
            elif isinstance(instr, N.MakeStruct):
                make_structs.append(instr)
            for sub in _child_bodies(instr):
                scan(sub)

    scan(fn.body)

    # Resolve alias chains: a temp aliased to a concretely-typed local
    # inherits that type. ``var t: Tally<String> = factory()`` records
    # ``_ir_t0 -> t`` here and ``t``'s concrete type via fn.locals.
    def resolve_local_ty(name: str) -> Optional[str]:
        """Concrete type of a local: its expected-use type if known,
        else its declared type, following alias chains forward."""
        if name in expected:
            return expected[name]
        seen: set[str] = set()
        cur: Optional[str] = name
        while cur and cur not in seen:
            seen.add(cur)
            if cur in expected:
                return expected[cur]
            ty = fn.locals.get(cur) or params_by_name.get(cur)
            if ty and _is_concrete_ty(ty):
                return ty
            cur = aliases.get(cur)
        return None

    # A temp used as a struct-literal field value is pinned by that
    # field's type, with the struct's type arguments resolved from the
    # struct literal's own (possibly use-derived) instantiation. Run
    # after alias resolution so a struct whose only concrete anchor is
    # how the struct itself is later used (``return Wrap { ... }`` ->
    # ``Wrap<Int>``) still types its field values -- this is what makes
    # nested generic-factory-into-generic-struct chains resolve.
    for ms in make_structs:
        struct_ty = resolve_local_ty(ms.dst) or fn.locals.get(ms.dst, "")
        field_ctx = _struct_field_types(
            ms.type_name, struct_ty, struct_decls,
        )
        for fname, fval in ms.fields:
            if fval.kind in ("local", "param") and fval.name:
                record(fval.name, field_ctx.get(fname))

    for temp, target in aliases.items():
        if temp in expected:
            continue
        # Walk forward through chained aliases to a concrete local.
        seen: set[str] = set()
        cur = target
        while cur and cur not in seen:
            seen.add(cur)
            ty = fn.locals.get(cur) or params_by_name.get(cur)
            if ty and _is_concrete_ty(ty):
                expected[temp] = ty
                break
            cur = aliases.get(cur)
    return expected


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
    # Pre-pass: give every local bound to a generic struct literal its
    # canonical instantiation type (``Box`` -> ``Box<Int>``) so a call
    # whose generic parameter is that struct type can infer the
    # substitution. Must precede call-site inference below.
    _annotate_generic_struct_literal_types(module)

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

    # Concrete return-type context for the function currently being
    # walked, keyed by ``Call.dst``. Re-derived per function so a
    # zero-value-arg generic factory (``empty_tally<T>()``) can recover
    # ``T`` from the binding / return / argument the analyzer resolved.
    current_expected: dict[str, str] = {}
    # The locals dict of the function currently being walked, so a
    # rewritten call's dst temp can be retyped from the placeholder
    # (``Tally<?>``) to the concrete instantiated return type.
    current_locals: dict[str, str] = {}

    def specialise_call(call: N.Call) -> None:
        """Try to rewrite ``call`` in place; queue any newly-
        produced specialisations for subsequent passes."""
        if call.callee_name not in generics:
            return
        callee = generics[call.callee_name]
        expected = current_expected.get(call.dst) if call.dst else None
        subst = _infer_subst_for_call(call, callee, expected)
        if subst is None:
            return
        mangled = _mangle(call.callee_name, subst, callee.type_params)
        if mangled not in specialised:
            specialised[mangled] = _specialise_function(
                callee, subst, mangled,
            )
        call.callee_name = mangled
        # Retype the call's dst temp to the concrete instantiated
        # return type. The lowerer leaves it as a placeholder
        # (``Tally<?>``) when no value argument fixed the type
        # parameter; without this the Wasm backend hits the temp's
        # un-encodable ``?`` even though the clone now exists.
        if call.dst and call.dst in current_locals:
            concrete_ret = specialised[mangled].return_type
            if _is_concrete_ty(concrete_ret):
                current_locals[call.dst] = concrete_ret
        # Mutate the dst type so downstream typing flows through.
        # Use the callee's substituted return type.
        # (Call.dst is a string, not a Value, so the dst's type
        # lives in the parent function's locals dict; the caller
        # is responsible for updating that.)

    def visitor(owner_list, index):
        instr = owner_list[index]
        if isinstance(instr, N.Call):
            specialise_call(instr)

    struct_decls = {
        ty.name: ty
        for ty in module.types
        if isinstance(ty, N.StructDecl)
    }

    def walk_function(fn: N.Function, module_funcs: dict[str, N.Function]) -> None:
        # Re-derive the return-type context for this function, then
        # walk its calls. ``current_expected`` / ``current_locals`` are
        # the closure channels ``specialise_call`` reads and patches.
        current_expected.clear()
        current_expected.update(
            _expected_return_types(fn, module_funcs, struct_decls)
        )
        current_locals.clear()
        current_locals.update(fn.locals)
        _walk_calls(fn.body, visitor)
        # Propagate any dst-temp retypes ``specialise_call`` recorded
        # back onto the function and its Value operands, so a temp the
        # backend reads (a call argument, a return value) no longer
        # carries the un-encodable ``?`` placeholder.
        retyped = {
            name: ty
            for name, ty in current_locals.items()
            if fn.locals.get(name) != ty
        }
        if retyped:
            fn.locals.update(retyped)
            fn.body = [
                _retype_placeholder_refs(instr, retyped) for instr in fn.body
            ]

    # Fixed-point: each iteration walks all non-generic functions
    # and any clones produced so far. Stops when an iteration
    # produces zero new clones.
    seen_clone_names: set[str] = set()
    while True:
        before = len(specialised)
        # Table of every callable in play (module functions plus
        # clones produced so far) so consuming-call argument contexts
        # can read a callee's concrete parameter types.
        module_funcs = {fn.name: fn for fn in module.functions}
        module_funcs.update(specialised)
        for fn in module.functions:
            if fn.type_params:
                continue  # skip the originals; they go away below
            walk_function(fn, module_funcs)
        # Walk new clones, which may themselves call other generics.
        for name, fn in list(specialised.items()):
            if name in seen_clone_names:
                continue
            seen_clone_names.add(name)
            walk_function(fn, module_funcs)
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
