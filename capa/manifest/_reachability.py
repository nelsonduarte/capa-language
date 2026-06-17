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
    any cap the caller captures into the closure - unprovable, so
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


def _contains_fun_via_structs(
    t: Optional[A.TypeExpr],
    structs_by_name: dict[str, A.TypeStruct],
    known_fun_bearing: set[str],
    sum_payloads_by_name: Optional[dict[str, list]] = None,
    _seen: Optional[set[str]] = None,
) -> bool:
    """True if ``t`` is, or transitively (through named struct fields or
    sum-variant payloads), contains a ``Fun(...)`` type. Unlike
    ``_strings._contains_fun_type``, this EXPANDS a named struct's field
    definitions AND a named sum type's variant payloads, so a plain data
    struct whose field holds a closure -- or a sum type one of whose
    variants carries a closure (``Run(Fun() -> Unit)``) -- is detected,
    in either nesting order (sum inside struct, struct inside sum).
    ``known_fun_bearing`` short-circuits names already proven Fun-bearing
    by the fixpoint; ``_seen`` guards against recursive definitions."""
    sums = sum_payloads_by_name or {}
    if t is None:
        return False
    if isinstance(t, A.FunType):
        return True
    if isinstance(t, A.TupleType):
        return any(
            _contains_fun_via_structs(
                e, structs_by_name, known_fun_bearing, sums,
            )
            for e in t.elements
        )
    if isinstance(t, A.TypeName):
        if any(
            _contains_fun_via_structs(
                a, structs_by_name, known_fun_bearing, sums,
            )
            for a in (t.args or ())
        ):
            return True
        if t.name in known_fun_bearing:
            return True
        seen = _seen if _seen is not None else set()
        if t.name in seen:
            return False
        td = structs_by_name.get(t.name)
        if td is not None:
            inner = seen | {t.name}
            for fld in td.fields:
                if _contains_fun_via_structs(
                    fld.type_expr, structs_by_name, known_fun_bearing,
                    sums, inner,
                ):
                    return True
            return False
        payloads = sums.get(t.name)
        if payloads is not None:
            inner = seen | {t.name}
            for p in payloads:
                if _contains_fun_via_structs(
                    p, structs_by_name, known_fun_bearing, sums, inner,
                ):
                    return True
    return False


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
      exercised. Defined for every user-defined capability, every
      cap-bearing struct, and every plain data struct in the module
      (a plain struct that nests a cap-bearing struct in a field
      inherits the nested struct's reachable caps at any depth).

    - ``unprovable`` is the set of type names whose reachable set
      is *not* a sound upper bound - typically because an impl
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
    # struct name -> set of user-defined caps it implements. Audit
    # 2026-06-17 C6: a holder of a cap-bearing struct ``S`` can
    # exercise the user-cap ``C`` that ``S`` implements (by calling a
    # method of ``C`` on it), so ``C`` itself must be reachable via
    # ``S`` -- not only the built-in caps that ``S``'s fields reach.
    user_caps_of_struct: dict[str, set[str]] = {}
    for item in module.items:
        if (
            isinstance(item, A.ImplBlock)
            and item.trait_name is not None
            and item.trait_name in user_cap_names
        ):
            cap_bearing_structs.add(item.type_name)
            user_caps_of_struct.setdefault(item.type_name, set()).add(
                item.trait_name
            )

    structs_by_name: dict[str, A.TypeStruct] = {
        item.name: item
        for item in module.items
        if isinstance(item, A.TypeStruct)
    }

    # Sum types indexed by name to their flattened variant payloads, so a
    # ``type Action = Run(Fun() -> Unit) | Noop`` whose variant carries a
    # closure is walked for Fun-bearing-ness exactly like a struct field.
    # Without this a function ``runner(a: Action)`` falsely
    # provably-excludes every cap while ``Run(f) -> f()`` lets the impl
    # exercise whatever the caller captured into the closure.
    sum_payloads_by_name: dict[str, list] = {
        item.name: [p for v in item.variants for p in v.payloads]
        for item in module.items
        if isinstance(item, A.TypeSum)
    }

    # A struct whose fields TRANSITIVELY hold a ``Fun(...)`` value is
    # unprovable EVEN IF it is a plain data struct (not cap-bearing): a
    # closure stored in a field can exercise whatever capability the
    # builder captured into it, so a function touching that struct in its
    # signature cannot honestly claim to provably-exclude any cap. Without
    # this, ``type Holder { action: Fun() -> Unit }`` (no impls) is
    # invisible to the downgrade and ``runner(h: Holder)`` falsely
    # provably-excludes every cap. Computed to a fixpoint so a struct that
    # nests another Fun-bearing struct (``Outer { inner: Inner }``) is
    # caught too.
    # A sum type counts the SAME WAY (one of its variant payloads is, or
    # transitively contains, a ``Fun``): a function whose signature
    # touches it cannot honestly provably-exclude any cap. Folded into
    # the same fixpoint as structs (key ``fun_bearing_structs`` holds both
    # struct and sum names) so a sum nesting a Fun-bearing struct and a
    # struct nesting a Fun-bearing sum are both caught.
    fun_bearing_structs: set[str] = set()
    fb_changed = True
    while fb_changed:
        fb_changed = False
        for sname, td in structs_by_name.items():
            if sname in fun_bearing_structs:
                continue
            for fld in td.fields:
                if _contains_fun_via_structs(
                    fld.type_expr, structs_by_name, fun_bearing_structs,
                    sum_payloads_by_name,
                ):
                    fun_bearing_structs.add(sname)
                    fb_changed = True
                    break
        for sname, payloads in sum_payloads_by_name.items():
            if sname in fun_bearing_structs:
                continue
            for p in payloads:
                if _contains_fun_via_structs(
                    p, structs_by_name, fun_bearing_structs,
                    sum_payloads_by_name,
                ):
                    fun_bearing_structs.add(sname)
                    fb_changed = True
                    break
    impls_by_trait: dict[str, list[A.ImplBlock]] = {}
    for item in module.items:
        if isinstance(item, A.ImplBlock) and item.trait_name is not None:
            impls_by_trait.setdefault(item.trait_name, []).append(item)

    reachable: dict[str, set[str]] = {}
    # Seed a reachable entry for every user-cap, every cap-bearing
    # struct, AND every plain data struct. Audit 2026-06-17: a plain
    # data struct ``Outer { mailer: SmtpMailer }`` that merely NESTS a
    # cap-bearing struct must propagate the nested caps too, otherwise a
    # function ``process(o: Outer)`` calling ``o.mailer.send(...)``
    # falsely provably-excludes SendEmail and Net. Without a reachable
    # entry, ``_caps_via_type`` resolves the plain struct to empty and
    # the nested caps never surface. Seeding every struct (mirroring how
    # ``fun_bearing_structs`` walks all structs transitively) lets the
    # fixpoint union the nested caps up through the field chain at any
    # depth.
    for name in user_cap_names | cap_bearing_structs:
        reachable[name] = set()
    for name in structs_by_name:
        reachable.setdefault(name, set())
    # Seed every sum type too. Audit 2026-06-17: a cap reachable ONLY
    # through a sum-variant payload (``type Wrap = Carry(SmtpMailer) |
    # Nope`` with ``process(w: Wrap)`` doing ``match w { Carry(m) ->
    # m.send(...) }``) escapes the reachability the same way a plain
    # struct nesting a cap-bearing struct did before commit 3cdb421:
    # without a ``reachable`` entry ``_caps_via_type`` resolves the sum
    # name to empty and the variant caps never surface, so the function
    # falsely provably-excludes Net + SendEmail despite exercising both.
    # Seeding each sum (mirroring ``sum_payloads_by_name``) lets the
    # fixpoint union the per-variant caps up through any nesting depth.
    for name in sum_payloads_by_name:
        reachable.setdefault(name, set())
    # Seed ``unprovable`` with every Fun-bearing struct (cap-bearing or
    # plain data), so ``_type_mentions_any(t, unprovable)`` downgrades any
    # signature that touches one. A plain data struct gets no ``reachable``
    # entry (it carries no statically-named caps), but its presence in
    # ``unprovable`` is what forces the caller's exclusion list to empty.
    unprovable: set[str] = set(fun_bearing_structs)

    changed = True
    while changed:
        changed = False

        # Every struct (cap-bearing or plain data): union built-in
        # caps reachable via each field type, plus -- for cap-bearing
        # structs -- the user-cap(s) the struct itself implements. A
        # plain data struct that nests a cap-bearing struct in a field
        # thereby inherits both the nested struct's built-in caps and
        # the user-cap it implements, at any nesting depth (audit
        # 2026-06-17).
        for sname, td in structs_by_name.items():
            was_unprovable = sname in unprovable
            new_caps = set(reachable[sname])
            # The user-cap(s) this struct implements are exercisable
            # by any holder of the struct (audit 2026-06-17 C6).
            new_caps |= user_caps_of_struct.get(sname, set())
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

        # Every sum type: union the built-in (and user-) caps reachable
        # via each variant payload. A sum one of whose variants carries a
        # cap-bearing struct (``Carry(SmtpMailer)``) thereby inherits both
        # the struct's built-in caps and the user-cap it implements, at
        # any nesting depth -- and a sum carrying a struct that itself
        # nests a cap-bearing struct (a chain) too, because the struct's
        # ``reachable`` entry is already the transitive closure by the
        # time ``_caps_via_type`` resolves it (audit 2026-06-17).
        for sname, payloads in sum_payloads_by_name.items():
            was_unprovable = sname in unprovable
            new_caps = set(reachable[sname])
            for p in payloads:
                cs, hf = _caps_via_type(p, reachable)
                new_caps |= cs
                if hf:
                    unprovable.add(sname)
                if _type_mentions_any(p, unprovable):
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
    container - beyond what's directly named in the signature.

    ``sig_unprovable`` is True if any sig element touches an
    unprovable type (transitive Fun) or has its own ``FunType``.
    Caller treats this the same as ``has_fun_in_sig`` /
    ``has_unsafe`` - downgrade ``provably_excluded`` to empty."""
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
