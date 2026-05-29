"""Per-impl capability reachability for the manifest builder.

Computes, for each user-defined capability ``T`` and each cap-
bearing struct ``S`` in a program, the set of built-in caps that
values of that type can transitively cause to be exercised. The
``provably_excluded_capabilities`` field uses this to compute a
sound exclusion list under closed-world reasoning over all impls
in the program.

The set is sound (an over-approximation) for any closed program:
adding a new impl can only add caps to the reachable set; the
fixpoint terminates because the set is monotone.

Audit slice 21 followup (2026-05-29) documented the motivation:
under the prior signature-only rule, a function
``use_logger(lg: FileLogger)`` where ``FileLogger { out: Stdio }``
could claim to provably-exclude Stdio while actually exercising
Stdio through the impl's method. This module fills the gap.
"""

from __future__ import annotations

from typing import Optional

from .. import capa_ast as A
from ..typesys import CAPABILITY_NAMES


def _caps_via_type(
    t: Optional[A.TypeExpr],
    reachable: dict[str, set[str]],
) -> tuple[set[str], bool]:
    """Walk a type expression. Return ``(caps, has_fun)`` where
    ``caps`` is the set of built-in cap names this type can reach
    (via direct mention or via known per-type reachable sets) and
    ``has_fun`` is True if any ``FunType`` is encountered. A
    ``FunType`` in an impl method signature lets the impl exercise
    any cap the caller captures into the closure — unprovable, so
    the caller must downgrade fully."""
    if t is None:
        return set(), False
    if isinstance(t, A.TypeName):
        caps: set[str] = set()
        has_fun = False
        if t.name in CAPABILITY_NAMES:
            caps.add(t.name)
        elif t.name in reachable:
            caps |= reachable[t.name]
        for a in t.args or ():
            cs, hf = _caps_via_type(a, reachable)
            caps |= cs
            has_fun |= hf
        return caps, has_fun
    if isinstance(t, A.TupleType):
        caps = set()
        has_fun = False
        for e in t.elements:
            cs, hf = _caps_via_type(e, reachable)
            caps |= cs
            has_fun |= hf
        return caps, has_fun
    if isinstance(t, A.FunType):
        return set(), True
    return set(), False


def _type_mentions_any(
    t: Optional[A.TypeExpr], names: set[str]
) -> bool:
    """True if any TypeName head in ``t`` is in ``names``."""
    if t is None:
        return False
    if isinstance(t, A.TypeName):
        if t.name in names:
            return True
        return any(_type_mentions_any(a, names) for a in (t.args or ()))
    if isinstance(t, A.TupleType):
        return any(_type_mentions_any(e, names) for e in t.elements)
    if isinstance(t, A.FunType):
        return any(_type_mentions_any(p, names) for p in t.param_types) or (
            _type_mentions_any(t.return_type, names)
        )
    return False


def compute_reachability(
    module: A.Module,
    *,
    user_cap_names: set[str],
) -> tuple[dict[str, set[str]], set[str]]:
    """Return ``(reachable, unprovable)``:

    - ``reachable[name]`` is the set of built-in capability names
      that values of type ``name`` can transitively cause to be
      exercised. Defined for every user-defined capability and
      every cap-bearing struct in the module.

    - ``unprovable`` is the set of type names whose reachable set
      is *not* a sound upper bound — typically because an impl
      method takes or returns a ``Fun(...)`` type, which lets the
      impl exercise any cap the caller captures into the closure.
      A function with a sig touching an unprovable type must
      downgrade ``provably_excluded_capabilities`` to empty rather
      than rely on the (incomplete) reachable set.

    Names are kept in the analyzer-internal (mangled) namespace so
    that they line up with ``ImplBlock.trait_name`` /
    ``ImplBlock.type_name`` / ``TypeName.name`` as the loader
    produced them. The manifest builder demangles for the
    regulator-facing surfaces."""
    cap_bearing_structs: set[str] = set()
    for item in module.items:
        if (
            isinstance(item, A.ImplBlock)
            and item.trait_name is not None
            and item.trait_name in user_cap_names
        ):
            cap_bearing_structs.add(item.type_name)

    structs_by_name: dict[str, A.TypeStruct] = {
        item.name: item
        for item in module.items
        if isinstance(item, A.TypeStruct)
    }
    impls_by_trait: dict[str, list[A.ImplBlock]] = {}
    for item in module.items:
        if isinstance(item, A.ImplBlock) and item.trait_name is not None:
            impls_by_trait.setdefault(item.trait_name, []).append(item)

    reachable: dict[str, set[str]] = {}
    for name in user_cap_names | cap_bearing_structs:
        reachable[name] = set()
    unprovable: set[str] = set()

    changed = True
    while changed:
        changed = False

        # Cap-bearing structs: union built-in caps reachable via
        # each field type.
        for sname in cap_bearing_structs:
            td = structs_by_name.get(sname)
            if td is None:
                continue
            was_unprovable = sname in unprovable
            new_caps = set(reachable[sname])
            for fld in td.fields:
                cs, hf = _caps_via_type(fld.type_expr, reachable)
                new_caps |= cs
                if hf:
                    unprovable.add(sname)
                if _type_mentions_any(fld.type_expr, unprovable):
                    unprovable.add(sname)
            if (
                new_caps != reachable[sname]
                or (sname in unprovable and not was_unprovable)
            ):
                reachable[sname] = new_caps
                changed = True

        # User-defined capabilities: union over all impls.
        for ucn in user_cap_names:
            was_unprovable = ucn in unprovable
            new_caps = set(reachable[ucn])
            for impl in impls_by_trait.get(ucn, ()):
                # Caps reachable through the impl's struct
                # (its fields can hold built-in caps or other
                # cap-bearing types).
                if impl.type_name in reachable:
                    new_caps |= reachable[impl.type_name]
                if impl.type_name in unprovable:
                    unprovable.add(ucn)
                # Caps mentioned in the impl method signatures
                # (non-self params + return type). A method that
                # takes ``stdio: Stdio`` directly exercises Stdio,
                # so any value of the user-cap can reach Stdio.
                for m in impl.methods:
                    for p in m.params:
                        if p.name == "self":
                            continue
                        cs, hf = _caps_via_type(p.type_expr, reachable)
                        new_caps |= cs
                        if hf:
                            unprovable.add(ucn)
                        if _type_mentions_any(p.type_expr, unprovable):
                            unprovable.add(ucn)
                    cs, hf = _caps_via_type(m.return_type, reachable)
                    new_caps |= cs
                    if hf:
                        unprovable.add(ucn)
                    if _type_mentions_any(m.return_type, unprovable):
                        unprovable.add(ucn)
            if (
                new_caps != reachable[ucn]
                or (ucn in unprovable and not was_unprovable)
            ):
                reachable[ucn] = new_caps
                changed = True

    return reachable, unprovable


def caps_reachable_via_sig(
    fn: A.FunDecl,
    *,
    container: Optional[str],
    reachable: dict[str, set[str]],
    unprovable: set[str],
) -> tuple[set[str], bool]:
    """Return ``(extra_caps, sig_unprovable)`` for one function.

    ``extra_caps`` is the union of built-in caps reachable through
    each param, return type, and the impl-method ``self``
    container — beyond what's directly named in the signature.

    ``sig_unprovable`` is True if any sig element touches an
    unprovable type (transitive Fun) or has its own ``FunType``.
    Caller treats this the same as ``has_fun_in_sig`` /
    ``has_unsafe`` — downgrade ``provably_excluded`` to empty."""
    extra: set[str] = set()
    sig_unprovable = False

    for p in fn.params:
        if p.name == "self":
            continue
        cs, hf = _caps_via_type(p.type_expr, reachable)
        extra |= cs
        if hf:
            sig_unprovable = True
        if _type_mentions_any(p.type_expr, unprovable):
            sig_unprovable = True

    cs, hf = _caps_via_type(fn.return_type, reachable)
    extra |= cs
    if hf:
        sig_unprovable = True
    if _type_mentions_any(fn.return_type, unprovable):
        sig_unprovable = True

    if container is not None:
        if container in reachable:
            extra |= reachable[container]
        if container in unprovable:
            sig_unprovable = True

    return extra, sig_unprovable
