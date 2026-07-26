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
from ..analyzer._frozen import _BUILTIN_TYPE_NAMES
from ..typesys import CAPABILITY_NAMES

# ``_BUILTIN_TYPE_NAMES`` (imported from ``capa.analyzer._frozen``) is the
# analyzer's authoritative set of built-in type names: capabilities,
# primitives, the built-in parametric/container types, and the built-in
# nominal types (``JsonValue``, ``Task``, ``Self``, ``Unit``). It is
# reused here as the SINGLE SOURCE OF TRUTH for the known-built-in-type
# check in ``_type_arg_unresolvable``; re-listing it once drifted (it
# omitted ``Unit``/``Task``/``Self`` and over-failed impls parameterised
# on them). Extended per-compilation with every user-declared type name
# (see ``compute_reachability``); a ``TypeName`` head that is in neither
# is a free/unbound generic type parameter.


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
    # Single visited-set shared by the WHOLE traversal: forwarding the
    # current ``_seen`` through every recursive branch (tuple elements
    # and type arguments included, not only struct fields and sum
    # payloads) is what guarantees termination on a recursive sum whose
    # self-reference passes through a ``List<Self>``/tuple. Resetting it
    # to empty on those branches (the prior bug) caused infinite
    # recursion (RecursionError) without ever revisiting the guard.
    seen = _seen if _seen is not None else set()
    if t is None:
        return False
    if isinstance(t, A.FunType):
        return True
    if isinstance(t, A.TupleType):
        return any(
            _contains_fun_via_structs(
                e, structs_by_name, known_fun_bearing, sums, seen,
            )
            for e in t.elements
        )
    if isinstance(t, A.TypeName):
        if any(
            _contains_fun_via_structs(
                a, structs_by_name, known_fun_bearing, sums, seen,
            )
            for a in (t.args or ())
        ):
            return True
        if t.name in known_fun_bearing:
            return True
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


def _type_arg_unresolvable(
    t: Optional[A.TypeExpr], known_type_names: frozenset[str]
) -> bool:
    """True if ``t`` contains a ``TypeName`` head that names no known
    type - a free/unbound generic type parameter.

    A concrete argument (a built-in like ``Int``/``List`` or a
    user-declared type) resolves to a definite reachable set (possibly
    empty), so it is charged precisely. A free type parameter (``T`` in
    ``impl SomeTrait for Wrapper<T>``) could be instantiated downstream
    with a capability-bearing type this compilation cannot see, so an
    impl carrying it must fail CLOSED (authority-unprovable) rather than
    charge the zero caps its unresolved name resolves to. A ``Fun`` arrow
    is not flagged here: its unprovable downgrade is already handled by
    ``_caps_via_type``'s ``has_fun`` short-circuit at the call site."""
    if isinstance(t, A.TypeName):
        if t.name not in known_type_names:
            return True
        return any(
            _type_arg_unresolvable(a, known_type_names)
            for a in (t.args or ())
        )
    if isinstance(t, A.TupleType):
        return any(
            _type_arg_unresolvable(e, known_type_names) for e in t.elements
        )
    return False


def _impl_reachable_caps(
    impl: A.ImplBlock,
    reachable: dict[str, set[str]],
    unprovable: set[str],
    known_type_names: frozenset[str],
) -> tuple[set[str], bool]:
    """Caps an implementor of a trait can transitively exercise, plus
    whether it makes the trait unprovable.

    Returns ``(caps, unprov)`` where ``caps`` is the union of built-in
    (and user-) caps reachable through the impl's receiver type, the
    receiver's TYPE ARGUMENTS, and the impl method signatures. ``unprov``
    is True when the reachable set is NOT a sound upper bound and the
    trait must downgrade fully: the impl carries a ``Fun`` (in a type arg
    or a method sig), mentions an already-unprovable type, or carries an
    UNRESOLVABLE type argument (a free generic parameter).

    The receiver's type ARGUMENTS are walked because an
    ``impl SomeTrait for Wrapper<Smtp>`` exercises whatever ``Smtp``
    reaches (``Net``), which ``reachable[Wrapper]`` alone drops: the impl
    stores the concrete arguments in ``type_args``, not as ``args`` on a
    ``TypeName``, so the ordinary field/signature walk never sees them.
    A concrete argument is resolved by ``_caps_via_type`` exactly as it
    already is for a generic argument inside a struct field (a cap-free
    argument charges nothing; a cap-bearing one is charged). A FREE
    generic argument (``Wrapper<T>``) resolves to no known type and could
    be instantiated downstream with a cap-bearing type, so it fails
    closed instead of charging zero (``_type_arg_unresolvable``).

    The union is SOUND for resolvable receiver / type-argument / method-
    signature caps; an unresolvable generic type argument fails closed.
    """
    caps: set[str] = set()
    unprov = False
    # Caps reachable through the impl's receiver struct (its fields can
    # hold built-in caps or other cap-bearing types).
    if impl.type_name in reachable:
        caps |= reachable[impl.type_name]
    if impl.type_name in unprovable:
        unprov = True
    # Caps carried by the receiver's TYPE ARGUMENTS (``Wrapper<Smtp>``).
    # A free/unbound argument (``Wrapper<T>``) is charge-UNPROVABLE, not
    # charge-zero: it could be a cap-bearing type downstream.
    for ta in impl.type_args or ():
        if _type_arg_unresolvable(ta, known_type_names):
            unprov = True
        cs, hf = _caps_via_type(ta, reachable)
        caps |= cs
        if hf:
            unprov = True
        if _type_mentions_any(ta, unprovable):
            unprov = True
    # Caps mentioned in the impl method signatures (non-self params +
    # return type). A method that takes ``stdio: Stdio`` directly
    # exercises Stdio, so any value dispatched through the trait can too.
    for m in impl.methods:
        for p in m.params:
            if p.name == "self":
                continue
            cs, hf = _caps_via_type(p.type_expr, reachable)
            caps |= cs
            if hf:
                unprov = True
            if _type_mentions_any(p.type_expr, unprovable):
                unprov = True
        cs, hf = _caps_via_type(m.return_type, reachable)
        caps |= cs
        if hf:
            unprov = True
        if _type_mentions_any(m.return_type, unprovable):
            unprov = True
    return caps, unprov


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

    # Plain (non-capability) traits: an abstract interface a signature
    # position can be typed as. A value of that type dispatches
    # DYNAMICALLY to some implementor's method, so the position can
    # exercise whatever that implementor reaches -- exactly the way a
    # user-capability position does. Pre-fix such a position was charged
    # ZERO caps, letting a function ``use_greeter(g: Greeter)`` claim to
    # provably-exclude a cap an implementor exercises through the trait.
    #
    # A PRIVATE trait is sealed by construction (no external package can
    # implement it), so it is charged the union of the reachable caps of
    # its implementors visible in this compilation, folded into the same
    # fixpoint as user capabilities. A ``pub`` trait is externally
    # implementable: a downstream package could implement it with a
    # cap-bearing type this package cannot see, so it is authority-
    # UNPROVABLE (seeded into ``unprovable`` below) and any signature that
    # touches it downgrades fully, exactly like a ``Fun`` in the signature.
    non_cap_trait_names: set[str] = set()
    pub_trait_names: set[str] = set()
    for item in module.items:
        if isinstance(item, A.TraitDecl) and not item.is_capability:
            non_cap_trait_names.add(item.name)
            if item.is_pub:
                pub_trait_names.add(item.name)

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
    # Seed a reachable entry for every plain (non-capability) trait, so
    # ``_caps_via_type`` resolves a trait-typed signature position to the
    # union of its implementors' caps (computed in the fixpoint below)
    # rather than to empty.
    for name in non_cap_trait_names:
        reachable.setdefault(name, set())
    # Seed ``unprovable`` with every Fun-bearing struct (cap-bearing or
    # plain data), so ``_type_mentions_any(t, unprovable)`` downgrades any
    # signature that touches one. A plain data struct gets no ``reachable``
    # entry (it carries no statically-named caps), but its presence in
    # ``unprovable`` is what forces the caller's exclusion list to empty.
    # Seed every ``pub`` (externally implementable) plain trait too: a
    # downstream package could implement it with a cap-bearing type this
    # compilation cannot see, so a signature touching it must fail closed
    # exactly like a ``Fun`` in the signature.
    unprovable: set[str] = set(fun_bearing_structs) | pub_trait_names

    # The names that denote a concrete, KNOWN type: the built-in set plus
    # every user-declared type in this compilation (all reachable keys -
    # structs, sums, plain traits and user capabilities - plus typestates
    # and extern-component boundaries, which are not seeded into
    # ``reachable``). A ``TypeName`` head appearing in an impl's type
    # arguments that is in none of these is a free/unbound generic
    # parameter, which must fail closed rather than charge zero.
    known_type_names: frozenset[str] = (
        _BUILTIN_TYPE_NAMES
        | frozenset(reachable.keys())
        | frozenset(
            item.name
            for item in module.items
            if isinstance(item, (A.TypestateDecl, A.ExternComponent))
        )
    )

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

        # User-defined capabilities AND plain (non-capability) traits:
        # union over all impls of the trait. Both are dispatch surfaces --
        # a value typed as either exercises whatever an implementor
        # reaches -- so they share one loop and one implementor-union
        # helper (``_impl_reachable_caps``, which also accounts for the
        # impl's TYPE ARGUMENTS and replicates the unprovable propagation).
        # A ``pub`` trait was already seeded into ``unprovable`` above; the
        # union still runs so its ``reachable`` set stays a precise upper
        # bound for the ceiling surface even though the exclusion claim is
        # already voided.
        for tname in user_cap_names | non_cap_trait_names:
            was_unprovable = tname in unprovable
            new_caps = set(reachable[tname])
            for impl in impls_by_trait.get(tname, ()):
                cs, unprov = _impl_reachable_caps(
                    impl, reachable, unprovable, known_type_names,
                )
                new_caps |= cs
                if unprov:
                    unprovable.add(tname)
            if (
                new_caps != reachable[tname]
                or (tname in unprovable and not was_unprovable)
            ):
                reachable[tname] = new_caps
                changed = True

    return reachable, unprovable


def caps_reachable_via_sig(
    fn: A.FunDecl,
    *,
    container: Optional[str],
    reachable: dict[str, set[str]],
    unprovable: set[str],
    skip_fun_params: frozenset[str] = frozenset(),
) -> tuple[set[str], bool]:
    """Return ``(extra_caps, sig_unprovable)`` for one function.

    ``extra_caps`` is the union of built-in caps reachable through
    each param, return type, and the impl-method ``self``
    container - beyond what's directly named in the signature.

    ``sig_unprovable`` is True if any sig element touches an
    unprovable type (transitive Fun) or has its own ``FunType``.
    Caller treats this the same as ``has_fun_in_sig`` /
    ``has_unsafe`` - downgrade ``provably_excluded`` to empty.

    ``skip_fun_params`` names parameters whose ``Fun`` arrow must NOT
    contribute to ``sig_unprovable``: a ``borrow`` parameter the body
    only ever invokes (verified invoke-only). This is used ONLY for the
    ceiling-scoped signal; the strict call (empty set) is unchanged, so
    ``provably_excluded_capabilities`` keeps its full guarantee."""
    extra: set[str] = set()
    sig_unprovable = False

    for p in fn.params:
        if p.name == "self":
            continue
        cs, hf = _caps_via_type(p.type_expr, reachable)
        extra |= cs
        if p.name in skip_fun_params:
            # A verified invoke-only ``borrow`` inlet: its Fun arrow does
            # not make the enclosing signature unprovable. The Fun-arrow /
            # unprovable-mention downgrade is withheld for this parameter,
            # BUT the caps carried by the arrow's own parameter and return
            # types are charged here: a ``borrow mk: Fun() -> Net`` that the
            # body invokes (``mk().get(...)``) manufactures and exercises a
            # ``Net`` locally, so that authority belongs to THIS function,
            # not to a caller. ``_caps_via_type`` on the bare Fun type above
            # returns none (its short-circuit protects the strict
            # ``has_fun`` downgrade), so the arrow's inner types are walked
            # explicitly. A cap-free arrow (``Fun(Request) -> Response``)
            # charges nothing and keeps the ceiling clean.
            if isinstance(p.type_expr, A.FunType):
                for at in p.type_expr.param_types:
                    acs, _ = _caps_via_type(at, reachable)
                    extra |= acs
                acs, _ = _caps_via_type(p.type_expr.return_type, reachable)
                extra |= acs
            continue
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
