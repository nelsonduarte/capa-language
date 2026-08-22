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

# Mutating methods that can inject tainted data INTO a mutable
# container. When called with a @secret argument in one of the listed
# positions, the receiver container becomes @secret: a later read
# (``get`` / ``contains`` / ``keys`` / iteration) would otherwise
# launder the secret back to public. Keyed ``(TypeName, method)`` ->
# the 0-based argument positions that carry data into the container.
# This is the mutable-container analogue of the aggregate-literal
# rule; together they stop a secret from being hidden in a collection.
_CONTAINER_MUTATORS: dict[tuple[str, str], set[int]] = {
    ("List", "push"): {0},
    ("Set",  "add"):  {0},
    ("Map",  "set"):  {0, 1},
}

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
# first mismatch; ``index_of`` scans for a match. Keyed
# ``(TypeName, method)`` -> the 0-based argument positions whose @secret
# label (or a @secret receiver) makes the call a timing oracle.
_CT_SHORT_CIRCUIT_METHODS: dict[tuple[str, str], set[int]] = {
    ("String", "starts_with"): {0},
    ("String", "ends_with"):   {0},
    ("String", "contains"):    {0},
    ("String", "index_of"):    {0},
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
