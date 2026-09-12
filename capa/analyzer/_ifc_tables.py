"""Pure IFC tables and helpers shared by ``_ifc`` and ``_ifc_summary``.

These are the genuinely pure symbols the label-propagation pass
(``_ifc``) and the cross-function summary pass (``_ifc_summary``) both
consult: the sink / source / mutator / constant-time lookup tables, the
two access-path / pattern helpers, and the summary-side sentinel and
argument-binding helpers. They reference no module-level mutable state
and import nothing back from ``_ifc`` / ``_ifc_summary``, so hoisting
them here breaks the load-time import cycle between those two modules
(``_ifc_summary`` imported the tables from ``_ifc`` at module level;
``_ifc`` imported ``INTERNAL_SECRET`` / ``_bind`` / ``methods_by_name``
back through function-local imports purely to dodge the cycle). Both
now import everything they need from here at module level.
"""

from __future__ import annotations

from .. import capa_ast as A
from ._callables import method_key


# Built-in capability methods that exfiltrate data out of the program
# -- the public sinks. A ``@secret`` value reaching any of these
# argument positions is an information-flow violation unless it was
# declassified. Keyed by ``(CapName, method)`` -> the set of 0-based
# argument indices that are sinks. Roadmap S2.4.
#
# Receiver-only / pure-query methods (allows, exists, read, get from
# Env, now_secs, ...) are NOT sinks: they bring data IN or inspect,
# they don't send it out. ``restrict_to*`` take a config string, not
# user data. The path argument of fs.write is included (a secret
# written to an attacker-chosen path is still disclosure), as is the
# URL of net.get/post (a secret in a URL leaks via the request line /
# server logs).
_PUBLIC_SINKS: dict[tuple[str, str], set[int]] = {
    ("Stdio", "print"):    {0},
    ("Stdio", "println"):  {0},
    ("Stdio", "eprintln"): {0},
    ("Net", "get"):        {0},
    ("Net", "post"):       {0, 1},
    ("Fs", "write"):       {0, 1},
    ("Db", "exec"):        {0, 1},
    ("Db", "query"):       {0, 1},
    # Serve.send writes bytes to whoever is on the other end of an
    # inbound connection -- exfiltration exactly like Net.post. Only
    # argument 1 (the payload) is a sink; argument 0 is the connection
    # id the runtime handed out, not program data, so gating it would
    # be noise.
    #
    # It is spelled ``send`` and not ``write`` because the summary pass
    # in ``_ifc_summary`` attributes a sink to a capability BY METHOD
    # NAME (it has no receiver type at that point), which is sound only
    # while each sink method name belongs to exactly one capability.
    # ``Fs.write`` already owns "write", so a ``Serve.write`` made every
    # ``fs.write`` report Serve as a reached capability too -- caught by
    # tests/test_unaudited_secret_sink_fact.py when this landed.
    ("Serve", "send"):     {1},
}

# Built-in capability methods that PRODUCE secret data -- the sources.
# Their result is labelled ``@secret`` regardless of argument labels,
# so a program that reads a secret and routes it to a public sink is
# caught without the programmer annotating anything. Roadmap S2
# (source caps). Keyed ``(CapName, method)``.
#
# Conservative on purpose -- only ``Env.get`` for now. Environment
# variables are where API keys / tokens / credentials live (the
# headline prompt-injection-exfiltration case), so treating them as
# secret-by-default is the safe and accurate call. ``Fs.read`` is
# deliberately NOT a source: a config / data file is usually public,
# and over-labelling it would warn on every legitimate file echo. A
# program that does hold a secret in a file can annotate the binding
# ``@secret`` explicitly. Future levels could make this configurable.
#
# ``Serve.read`` is deliberately NOT a source either, and this is the
# one entry whose ABSENCE is a decision worth spelling out. Serve
# (2026-07) is the language's first INBOUND data source, so it is the
# first time the question "is data arriving from outside secret?" has
# an answer to give. It is ``@public``.
#
# The reason is that this lattice models CONFIDENTIALITY -- who is
# allowed to LEARN a value -- and not integrity or taint. An inbound
# request is untrusted, but "untrusted" is an integrity property, and
# labelling it ``@secret`` would encode it in the wrong lattice: the
# immediate consequence is that echoing a request back to the client
# that sent it (the single most ordinary thing a server does) becomes
# a reported violation. The useful signal would drown in that noise.
#
# ``Serve.read`` being ``@public`` therefore asserts only "these bytes
# are not a secret whose disclosure this analysis must prevent". It
# asserts NOTHING about whether they can be trusted. Integrity /
# taint tracking would be a second lattice, not a relabelling of this
# one.
_SECRET_SOURCES: frozenset = frozenset({
    ("Env", "get"),
})

# THE mutator classification: every method of a mutable built-in
# container (List / Set / Map) that MUTATES the container's observable
# state (length, membership, iteration). MEMBERSHIP answers "does this
# method mutate observable state?"; the VALUE is the possibly EMPTY set
# of 0-based argument positions that carry data into the container.
# The two questions are deliberately separated because the domain has
# three cases -- mutator with taint arguments, mutator without,
# non-mutator -- and a table that only answered the argument question
# lost every no-argument mutator: ``List.pop`` mutates the receiver
# with no argument at all, so its entry is the empty set, and every
# consumer must test MEMBERSHIP (``positions is not None``), never
# truthiness (``if not positions``), or an empty-index member silently
# degrades to a non-mutator.
#
# Two consumers derive from this one classification so they cannot
# drift: the DATA direction joins the labels at the listed indices (a
# @secret argument taints the receiver, so a later read -- ``get`` /
# ``contains`` / ``keys`` / iteration -- does not launder it back to
# public; the removal entries are the same rule reached from the other
# side: nothing secret is STORED by ``remove(k)``, but which element
# leaves is decided by the argument). The CONTROL direction joins the
# strict pc for EVERY member, empty-index ones included: under
# ``@strict_ifc`` a mutation executed inside a secret-conditioned
# branch makes the container's observable state secret from then on
# (see ``_check_ifc_container_mutation``).
#
# The set is enumerated BY CONSTRUCTION, not by reading signatures: an
# oracle called every List / Set / Map method under a secret-conditioned
# branch and diffed the observable state across the two secret values
# (.claude/IFC_PC_DESIGN_2.md section 2.3; a signature rule provably
# fails here -- ``Map.remove`` returns ``Option<V>`` exactly like
# ``List.pop`` and mutates, while ``List.reverse`` returns a ``List``
# and does not). ``Set.remove`` (increment 2) and ``List.pop`` (this
# fix) were each once missing from a hand-read version of this table
# with a live three-backend leak behind the omission; the completeness
# guard below (``container_classification_defects``) is what makes a
# third omission a RED build instead of a silent fail-open.
_CONTAINER_MUTATORS: dict[tuple[str, str], frozenset[int]] = {
    ("List", "push"):   frozenset({0}),
    ("List", "pop"):    frozenset(),
    ("Set",  "add"):    frozenset({0}),
    ("Set",  "remove"): frozenset({0}),
    ("Map",  "set"):    frozenset({0, 1}),
    ("Map",  "remove"): frozenset({0}),
}

# The DECLARED complement: every List / Set / Map method that does NOT
# mutate the receiver's observable state (pure queries and fresh-value
# transforms). Declared, never inferred, so the completeness guard can
# fail CLOSED: a container method in NEITHER set is a defect, which is
# the direction that would otherwise lose a rejection silently.
_CONTAINER_NON_MUTATORS: frozenset[tuple[str, str]] = frozenset({
    ("List", "length"),
    ("List", "contains"),
    ("List", "map"),
    ("List", "filter"),
    ("List", "fold"),
    ("List", "is_empty"),
    ("List", "first"),
    ("List", "last"),
    ("List", "get"),
    ("List", "find"),
    ("List", "find_index"),
    ("List", "sorted_by"),
    ("List", "reverse"),
    ("List", "enumerate"),
    ("List", "zip"),
    ("List", "flat_map"),
    ("List", "sorted"),
    ("List", "min"),
    ("List", "max"),
    ("Set",  "length"),
    ("Set",  "contains"),
    ("Set",  "to_list"),
    ("Set",  "is_empty"),
    ("Set",  "union"),
    ("Set",  "intersection"),
    ("Set",  "difference"),
    ("Set",  "is_subset"),
    ("Map",  "length"),
    ("Map",  "get"),
    ("Map",  "contains_key"),
    ("Map",  "keys"),
    ("Map",  "values"),
    ("Map",  "pairs"),
    ("Map",  "is_empty"),
    ("Map",  "filter"),
})

# Value-type owners whose every method returns a fresh value, measured
# by the same by-construction oracle (String 19, Range 12 methods, plus
# the Option / Result / JsonValue value owners): they carry no mutable
# state a secret pc could mark, so they are out of the mutator
# classification by construction, not by omission. Declared so the
# guard can refuse an entry filed under one of them, and so a NEW
# non-capability owner (a future Deque / Queue) lands in the mutable
# universe by default and must be classified before the build is green.
# FAIL-OPEN direction: an owner wrongly added here AND to the registry
# escapes the guard, so this set's exact value is pinned by an equality
# test (tests/analyzer/test_ifc_pc_container.py) that states the
# run-the-oracle-first obligation for any growth.
_IMMUTABLE_VALUE_OWNERS: frozenset[str] = frozenset({
    "String", "Range", "Option", "Result", "JsonValue",
})


def container_classification_defects(methods=None) -> list[str]:
    """The fail-closed completeness guard over the mutator
    classification: every method of every MUTABLE value owner must be
    declared in exactly one of ``_CONTAINER_MUTATORS`` /
    ``_CONTAINER_NON_MUTATORS``, and no entry may name an owner outside
    that universe. Returns a list of human-readable defects; an empty
    list is the green state (tests/analyzer/test_ifc_pc_container.py
    asserts it).

    The universe is DERIVED, never hand-declared: every owner in
    ``capa.builtins.METHODS`` that is not a capability (the registry's
    own ``CAPABILITY_NAMES``) and not a declared immutable value owner
    is a mutable owner whose methods need classifying. So a new METHOD
    on List / Set / Map and a new mutable OWNER both fail closed here,
    instead of being silently treated as non-mutators -- the direction
    that loses a rejection. Capability methods are excluded by the
    registry's capability set, not by this table: a capability's
    observable state (filesystem marks, generator state, peer-visible
    effects) is the separately disclosed effect-classification family,
    not container state. Dead keys (an entry naming a method the
    registry does not declare) are guarded by
    tests/test_ifc_tables_declared.py and are not re-checked here.

    ``methods`` defaults to the live registry; tests pass simulated
    registries to prove both RED directions bite."""
    # Function-local imports: this module is imported by both IFC
    # passes at load time and must stay free of import-cycle risk.
    from ..builtins import METHODS
    from ..typesys import CAPABILITY_NAMES

    if methods is None:
        methods = METHODS
    defects: list[str] = []
    mutable_owners = {
        owner for owner in methods
        if owner not in CAPABILITY_NAMES
        and owner not in _IMMUTABLE_VALUE_OWNERS
    }
    for owner in sorted(mutable_owners):
        for name in sorted({m for (m, _sig, _extra) in methods[owner]}):
            in_mut = (owner, name) in _CONTAINER_MUTATORS
            in_non = (owner, name) in _CONTAINER_NON_MUTATORS
            if in_mut and in_non:
                defects.append(
                    f"{owner}.{name} is declared BOTH a mutator and a "
                    f"non-mutator; remove it from one set"
                )
            elif not in_mut and not in_non:
                defects.append(
                    f"{owner}.{name} is unclassified: declare it in "
                    f"_CONTAINER_MUTATORS (with its taint-argument "
                    f"positions, possibly the empty set) or in "
                    f"_CONTAINER_NON_MUTATORS"
                )
    classified_owners = (
        {o for (o, _m) in _CONTAINER_MUTATORS}
        | {o for (o, _m) in _CONTAINER_NON_MUTATORS}
    )
    for owner in sorted(classified_owners - mutable_owners):
        defects.append(
            f"{owner} carries container-classification entries but is "
            f"not a mutable value owner in the registry (capability and "
            f"immutable-owner methods do not belong in these tables)"
        )
    for owner in sorted(_IMMUTABLE_VALUE_OWNERS - set(methods)):
        defects.append(
            f"{owner} is declared an immutable value owner but registers "
            f"no methods; remove the stale declaration"
        )
    return defects

# Lookup methods whose index / key argument selects which memory is
# touched. In a ``@constant_time`` function (roadmap S4) a @secret in
# one of these positions is a data-dependent access (the cache-timing
# side channel behind table lookups, e.g. an AES S-box). Keyed
# ``(TypeName, method)`` -> the 0-based argument positions that act as
# the index / key. This is the method-call analogue of ``xs[secret]``.
_CT_INDEX_METHODS: dict[tuple[str, str], set[int]] = {
    ("List",   "get"):          {0},
    ("Map",    "get"):          {0},
    ("Map",    "contains_key"): {0},
    # Same linear key scan as Map.get, so the key decides which memory
    # is walked and how far. Measured: the remove lowering calls
    # $str_eq exactly as many times as the get lowering does.
    ("Map",    "remove"):       {0},
    ("Set",    "contains"):     {0},
    ("String", "char_at"):      {0},
}

# Operators whose latency depends on operand values on the targets we
# emit (the variable-latency divider, CWE-208). A @secret operand of any
# of these leaks through timing. Add the next variable-time operator
# here, and ``_check_ct_arith`` picks it up with no further change.
_VARIABLE_TIME_OPS: frozenset[str] = frozenset({"/", "%"})

# Comparison operators that short-circuit byte-by-byte over a String /
# List operand on the targets we emit (CWE-208). ``==`` / ``!=`` on a
# String or List run ``$str_eq`` / element-wise compare with a
# length fast-path and an early exit at the first differing element, so
# the timing reveals the position of the first difference -- the classic
# MAC / token / password compare oracle. The ordering operators
# (``<`` ``<=`` ``>`` ``>=``) on a String are a lexicographic byte scan
# with the same early exit. A @secret operand of any of these in a
# ``@constant_time`` function is rejected (see ``_check_ct_compare``).
# Int / Float scalar comparison is single-cycle and stays allowed.
_SHORT_CIRCUIT_COMPARE_OPS: frozenset[str] = frozenset({
    "==", "!=", "<", "<=", ">", ">=",
})

# String / List methods that short-circuit byte-by-byte against a
# @secret operand, the method-call analogue of the comparison operators
# above. ``starts_with`` / ``ends_with`` / ``contains`` early-exit at the
# first mismatch; ``index_of`` and ``split_once`` scan for a match. Keyed
# ``(TypeName, method)`` -> the 0-based argument positions whose @secret
# label (or a @secret receiver) makes the call a timing oracle.
#
# MEMBERSHIP CRITERION, so this stops being an ad-hoc list: a String
# method belongs here when its Wasm lowering CALLS ``$str_eq``, the
# shared byte-comparison helper that exits at the first differing byte
# and so reveals where two strings first differ (the compare oracle,
# CWE-208). That is exactly what the shipped diagnostic describes, and
# it is mechanically checkable by counting ``call $str_eq`` in the
# emitted WAT of a one-call program.
#
# The criterion is NOT yet satisfied by every method that meets it:
# ``String.split`` and ``String.replace`` also call ``$str_eq`` and are
# NOT listed. That is a known fail-open, tracked by the separate
# constant-time effort along with the other unlisted methods; it is not
# counter-precedent for this table and must not be read as one. Nothing
# here claims a listed method IS constant-time, only that omitting it
# would remove a diagnostic the table already gives for the same
# mechanism.
_CT_SHORT_CIRCUIT_METHODS: dict[tuple[str, str], set[int]] = {
    ("String", "starts_with"): {0},
    ("String", "ends_with"):   {0},
    ("String", "contains"):    {0},
    ("String", "index_of"):    {0},
    # Same scan as index_of, same helper, same oracle: it answers WHERE
    # the separator first occurs. Measured: one ``call $str_eq``, the
    # same count as index_of and contains.
    ("String", "split_once"):  {0},
    ("List",   "contains"):    {0},
}


def _prefix_compatible(a: tuple, b: tuple) -> bool:
    """True when access paths ``a`` and ``b`` lie on the same root-to-leaf
    line: one is a prefix of the other. Used by the Stage 2 read-side check
    to decide whether a TAINTED access path is actually SUNK. ``a`` sunk at
    ``b``: the container taint at ``a`` reaches a sink iff the sunk path
    ``b`` is at or under ``a`` (``b`` reads into the tainted container) or
    ``a`` is at or under ``b`` (the tainted sub-path is inside what the
    callee sinks). The sentinel ``()`` (whole struct / param) is a prefix
    of everything, so it is compatible with any path -- the conservative
    catch-all."""
    n = min(len(a), len(b))
    return a[:n] == b[:n]


def _pattern_bound_names(pat: A.Pattern):
    """Yield every name a pattern binds, walking nested payloads,
    tuple elements, and struct fields. Wildcard / literal patterns
    bind nothing; or-patterns bind nothing in v0 (the parser forbids
    bindings inside alternatives)."""
    if isinstance(pat, A.IdentPat):
        yield pat.name
    elif isinstance(pat, A.VariantPat):
        for sub in pat.payloads:
            yield from _pattern_bound_names(sub)
    elif isinstance(pat, A.TuplePat):
        for sub in pat.elements:
            yield from _pattern_bound_names(sub)
    elif isinstance(pat, A.StructPat):
        for _field, sub in pat.fields:
            if sub is not None:
                yield from _pattern_bound_names(sub)
            else:
                yield _field


# Sentinel source for a field written from an internal secret source
# (``env.get(...)``) rather than from another parameter. Distinct from
# any real 0-based parameter index.
INTERNAL_SECRET = -1


def build_impl_reverse_index(symbols) -> dict:
    """``trait / capability name -> {concrete type names implementing it}``,
    the reverse of each ``Symbol.implements`` set (populated at
    ``impl Trait for T``). The ONE authoritative reversed view of the
    trait->implementor relation, shared by the intra-procedural pass
    (``_ifc._impl_reverse_index``) and the cross-function summary pass so
    neither hand-rolls a second trait walk. ``symbols`` is the iterable of
    populated global-scope ``Symbol`` objects."""
    index: dict = {}
    for sym in symbols:
        for r in getattr(sym, "implements", ()) or ():
            index.setdefault(r, set()).add(sym.name)
    return index


def trait_destructure_field_label(impl_index, labels_of, trait_name, field):
    """The IFC label a name bound by destructuring a TRAIT-typed scrutinee
    must carry for ``field``: the join, over every concrete implementor of
    ``trait_name``, of that implementor's same-named DECLARED field label
    (``labels_of(impl)`` yields ``{field name: declared label}`` for a
    concrete type). The runtime value is one of the trait's implementors,
    so this join is a sound upper bound on the true runtime field label --
    no runtime tag is needed. ``PUBLIC`` when the trait has no implementor
    declaring the field secret.

    The single source both destructure seams call, so the intra-procedural
    pass and the cross-function summary cannot drift on the JOIN itself (the
    ``test_ifc_destructure_pattern_typecheck`` cross-check runs every
    compositional spelling through both seams to guard it). The passes still
    differ in WHICH scrutinee expression forms each resolves to a trait type
    before calling this: the intra pass types the scrutinee from the
    type-checker (every form); the summary pass re-derives it COMPOSITIONALLY in
    ``_ifc_summary._scrutinee_static_type``, typing a receiver by recursion and
    reading each next hop's declared type from an existing signature / field
    table, so it certifies every hop the NAME-ONLY type representation that pass
    carries can express (a single-level element / named field / hoisted-binding /
    named function-or-method-return chain off any resolvable root). Two residuals
    stay disclosed, each by ROOT CAUSE: a hop whose type is ERASED by the
    name-only representation (a NESTED-container element like ``List<List<Trait>>``
    indexed past the first level, whose inner argument the element-type tables
    collapse to the bare name ``"List"``; closing it needs a structured-type
    representation, design item B), and a hop that is not statically NAMEABLE at
    all -- the pre-pass's inference ceiling (a call to a GENERIC callee returning
    a type PARAMETER, ``idish<T>(x: T) -> T``, a dynamic / unknown receiver, or an
    untracked / foreign callee). Both classes cross a function boundary silently
    on Python / ``--ir`` only and are still caught intra-procedurally, so the
    launder is NOT closed "by construction" for every scrutinee.

    SOUNDNESS rests on WHOLE-PROGRAM visibility of every implementor at the
    analysis that certifies the sink -- true today (the registry ships
    source and the consumer re-analyzes everything). It would become
    unsound under any future separate-compilation / trusted-precompiled-
    library path where an implementor is invisible at certification time."""
    from .. import _labels as L
    label = L.PUBLIC
    for impl_name in impl_index.get(trait_name, ()):
        label = L.join(label, labels_of(impl_name).get(field))
    return label


def methods_by_name(summaries: dict) -> dict[str, list]:
    """Group method summary keys by method name:
    ``method_name -> [("method", type_name, method_name), ...]``.

    Derived from the summary table's keys so the same by-name
    over-approximation the builder uses at a receiver-type-unknown
    method call (``_taint_of_method_call``) is available to the
    call-site checker (``_check_ifc_method_call_summary``) without
    duplicating the grouping logic. A trait-typed (dynamic-dispatch)
    receiver, or a missing exact key, falls back to the UNION over
    every concrete impl type that defines a method of that name -- a
    sound over-approximation (never misses a leak)."""
    out: dict[str, list] = {}
    for key in summaries:
        if isinstance(key, tuple) and len(key) == 3 and key[0] == "method":
            out.setdefault(key[2], []).append(key)
    return out


def result_effect_keys(recv_name, method, effects, is_trait, by_name, fallback):
    """The return-effect keys whose effect narrows a method call's RESULT
    label for a receiver whose static type is ``recv_name``, in the
    TRAIT-FIRST ordering:

    * a TRAIT-typed (dynamic-dispatch) receiver takes ``by_name`` -- the
      union over every concrete impl method of this name -- checked FIRST,
      BEFORE the exact key, so the trait's OWN bodiless empty exact-key
      entry (``("method", trait, method)``, registered only to declare the
      abstract return type) can never shadow the union and fail the
      narrowing open;
    * a concrete receiver uses its EXACT impl-method key when one exists;
    * otherwise the caller's ``fallback`` governs.

    The ONE ordering site the trait-first rule lives in. Both intra
    resolvers (``_ifc._method_call_returns_secret`` /
    ``_method_call_return_label``) and the cross-function summary
    (``_ifc_summary._result_candidate_keys``) delegate here, so no consumer
    can drift back into letting the empty trait key shadow the implementor
    union -- exactly the divergence this closes (the summary already had
    the trait-first order right; the two intra sites open-coded it wrong).

    Pure. Each caller supplies the parts that genuinely differ between them:
    ``by_name`` (the intra pass groups it from the live return-effect table,
    which harmlessly includes the empty trait key; the summary supplies its
    precomputed trait-EXCLUDED grouping) and ``fallback`` (the by-name union
    for the return-secret check, ``()`` -> the conservative whole-value join
    for the result-label check and the summary), along with the already
    resolved ``is_trait``."""
    if is_trait:
        return tuple(by_name)
    exact_key = method_key(recv_name, method)
    if exact_key in effects:
        return (exact_key,)
    return tuple(fallback)


def _bind(args: list, arg_names: list, param_names: list[str]) -> dict:
    """Return ``{param_index: arg_index}`` resolving positional and
    named arguments against ``param_names``. Mirrors the analyzer's
    ``_resolve_named_args`` shape but is permissive about errors (a
    malformed call is diagnosed by the main walk; here we only need a
    best-effort binding for taint flow)."""
    name_to_param = {p: i for i, p in enumerate(param_names)}
    out: dict = {}
    names = arg_names if arg_names else [None] * len(args)
    for arg_idx, n in enumerate(names):
        if n is None:
            if arg_idx < len(param_names):
                out[arg_idx] = arg_idx
        else:
            pidx = name_to_param.get(n)
            if pidx is not None:
                out[pidx] = arg_idx
    return out
