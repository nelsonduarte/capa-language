"""Call-site inference + rewrite and the top-level generic-function
pass: walk the module, infer a substitution per call to a generic
free function, synthesise a mangled clone, and rewrite the call.
"""

from __future__ import annotations

from typing import Optional

from .. import _nodes as N
from ._functions import _specialise_function
from ._typestr import _mangle, _unify_ty
from ._types import monomorphise_generic_types


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
