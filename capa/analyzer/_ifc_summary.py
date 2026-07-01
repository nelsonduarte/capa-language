"""Cross-function information-flow summaries (roadmap S2.6).

The intra-procedural IFC pass in :mod:`._ifc` propagates labels and
catches a ``@secret`` value reaching a public sink *within one
function body*. Crossing a function boundary relied on an explicit
``@secret`` parameter: a secret passed to an un-annotated parameter
that then reaches a sink *inside the callee* was silently missed.

This module closes that gap with a modular, additive, sound slice:
for every user-defined function and impl/trait method it computes a
**sink-reaching parameter set** -- the 0-based indices of value
parameters whose value, by the existing intra-procedural flow rules,
reaches a public-sink argument position inside the body, either
directly (the parameter, or a value derived from it, reaches a
``_PUBLIC_SINKS`` position) or transitively (the parameter is passed
into a position that is itself a sink-reaching parameter of the called
user function). A flow that passes through ``declassify(...)`` before
the sink does NOT count -- declassify breaks the chain, mirroring the
PUBLIC relabel in ``_compute_label``.

Summaries are computed to a least fixpoint over the call graph
(monotone: start empty, grow until stable), so mutual and self
recursion terminate.

The analyzer's main walk then consults these summaries at each user
call / method-call site (see ``_check_ifc_call_summary`` in
:mod:`._ifc`): an argument that is ``@secret`` and binds to a
sink-reaching parameter of the callee is flagged at the call site --
a warning by default, a hard error under ``@strict_ifc``, matching
the intra-procedural tier.

This is whole-value granularity (no per-field precision) and a sound
over-approximation: a method call whose receiver type is not known
statically is matched against every user method of that name, so the
analysis never under-reports a leak. It only ADDS detection; no
existing label or check is relaxed.

FIELD-WRITE EFFECTS (closes the cross-function self/param field-write
false negative). Alongside the sink-reaching set, every callable also
gets a **field-write effect**: a map ``target_param_idx -> set of
sources`` recording that the callee writes a field of the object bound
to ``target_param_idx`` (``self`` is index 0) from a value tainted by
either another parameter (the source's index) or an internal secret
source within the body (the sentinel ``INTERNAL_SECRET``), directly or
transitively (the field is written from a value passed to a further
call that itself has the effect). It is computed to the SAME fixpoint.

The call site (see ``_check_ifc_field_write_effect`` in :mod:`._ifc`)
propagates it CONSERVATIVELY: when the callee writes a field of param
``j`` from param ``i`` and the caller's argument for ``i`` is @secret,
the caller's binding bound to ``j`` is tainted at WHOLE-VALUE secret
(so a later read of any field of it is caught); an internal-secret
source taints the caller's binding-``j`` unconditionally. This is an
explicit data-flow taint, default-warn / strict-error like the
sink-reaching check, and whole-value (never per-field) on the caller
side -- the sound approximation.
"""

from __future__ import annotations

from .. import capa_ast as A
from ._ifc import (
    _PUBLIC_SINKS, _CONTAINER_MUTATORS, _SECRET_SOURCES,
    _pattern_bound_names,
)


# Sentinel source for a field written from an internal secret source
# (``env.get(...)``) rather than from another parameter. Distinct from
# any real 0-based parameter index.
INTERNAL_SECRET = -1

# Capability type names whose source methods (``_SECRET_SOURCES``)
# produce secret data. Used to recognise an internal secret source at
# summary time (no resolved types here) by matching a method call whose
# receiver is a parameter of that capability type. Keeps the source
# recognition precise (so e.g. ``List.get`` / ``Map.get`` are not
# mistaken for the ``Env.get`` source).
_SECRET_SOURCE_CAPS: frozenset = frozenset(cap for cap, _m in _SECRET_SOURCES)
_SECRET_SOURCE_METHODS: frozenset = frozenset(m for _c, m in _SECRET_SOURCES)


# A callable's parameters, in the canonical order the analyzer uses:
# for a method, index 0 is ``self`` and the explicit parameters follow
# (matching ``has_self`` + ``param_names``); for a free function, the
# explicit parameters in declaration order.
#
# Keys into the summary table:
#   ("fun", name)                  -- a free function
#   ("method", type_name, method)  -- an impl / trait method


def compute_ifc_summaries(
    module: A.Module, global_scope,
) -> tuple[dict, dict, dict]:
    """Return ``(sink_summaries, field_effects, return_effects)``:

    * ``sink_summaries``: ``{callable_key: frozenset(sink_reaching
      param indices)}`` -- a value parameter whose value reaches a
      public sink inside the body.
    * ``field_effects``: ``{callable_key: {target_param_idx:
      frozenset(source_param_idx | INTERNAL_SECRET)}}`` -- the callee
      writes a field of the object at ``target_param_idx`` from the
      named source(s).
    * ``return_effects``: ``{callable_key: frozenset(source_param_idx |
      INTERNAL_SECRET)}`` -- the callee returns a value derived from the
      named source(s); the call result is @secret when one fires (a real
      param whose argument is @secret, or the unconditional internal
      secret, which includes a declared-@secret field read).

    ``global_scope`` is the analyzer's populated global scope, used to
    tell user functions / variants / capabilities apart at call sites.
    All three results are the least fixpoint of the monotone summary
    operator, so recursion (self or mutual) terminates.
    """
    builder = _SummaryBuilder(module, global_scope)
    return builder.run()


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


class _SummaryBuilder:
    def __init__(self, module: A.Module, global_scope) -> None:
        self.module = module
        self.global_scope = global_scope
        # callable_key -> set of sink-reaching param indices.
        self.summaries: dict = {}
        # callable_key -> {target param idx -> set of source param idx /
        # INTERNAL_SECRET}: the field-write effect (see module docstring).
        self.field_effects: dict = {}
        # callable_key -> set of source param idx / INTERNAL_SECRET that
        # flow into a RETURNED value -- the return-secret effect. The
        # call result is @secret when one of these sources fires (a real
        # param whose argument is @secret, or the unconditional internal
        # secret, which includes a declared-@secret field read). This is
        # what carries a callee's secret-derived return across the
        # boundary to the caller's call-result label, mirroring the
        # intra-procedural rule and closing the field-return laundering.
        self.return_effects: dict = {}
        # callable_key -> (param_names_in_order, A.FunDecl, is_method).
        # ``param_names_in_order`` includes ``self`` at index 0 for a
        # method, so a positional / named argument binds to the right
        # index uniformly with the call-site logic.
        self.callables: dict = {}
        # callable_key -> set of parameter names that are typed as a
        # secret-source capability (e.g. ``Env``). Used to recognise an
        # internal secret source (``env.get(...)``) at summary time.
        self.secret_source_params: dict = {}
        # callable_key -> {param name: struct type name}. The declared
        # struct type of each struct-typed parameter (``self`` resolves
        # to the impl's owner type), so a field read off it can be
        # resolved to the field's declared label precisely.
        self.param_struct_types: dict = {}
        # callable_key -> {param name: declared type name} for EVERY typed
        # parameter (``self`` -> the impl owner type), regardless of
        # whether the type has labelled fields. Used to tell, at a method
        # call, whether the receiver is a USER-defined type (so the
        # return-effect narrowing is applied) or a built-in container /
        # primitive (so the conservative whole-value join governs and a
        # same-named user method cannot under-taint the result).
        self.param_type_names: dict = {}
        # method name -> list of method callable_keys (for the
        # receiver-type-unknown over-approximation at method calls).
        self.methods_by_name: dict[str, list] = {}
        # struct type name -> {field name: declared label}. Records
        # which struct fields are DECLARED ``@secret`` (roadmap S2), so a
        # field read off a parameter of that struct type is recognised as
        # an internal secret source at summary time -- the cross-function
        # analogue of the intra-procedural declared-field-label rule.
        self.struct_field_labels: dict[str, dict[str, str]] = {}
        # Names of module-level consts DECLARED ``@secret`` (roadmap S2).
        # A reference to one is an internal secret source in the summary
        # walk, the cross-function analogue of the intra-procedural
        # ``sym.label`` on the const's global symbol. Pre-computed once so
        # each identifier costs a set membership test, not a lookup.
        self.secret_consts: set[str] = set()
        self._collect_secret_fields()
        self._collect_secret_consts()
        self._collect_callables()

    def _collect_secret_fields(self) -> None:
        """Populate ``struct_field_labels`` from every struct (and
        typestate) declaration's field labels, so the body walk can
        recognise a declared-@secret field read off a parameter of that
        struct type (``_field_read_is_secret``)."""
        from .. import _labels as L
        for item in self.module.items:
            fields = getattr(item, "fields", None)
            name = getattr(item, "name", None)
            if not fields or name is None:
                continue
            for fld in fields:
                te = getattr(fld, "type_expr", None)
                label = getattr(te, "label", None) if te is not None else None
                if label in L.VALID_LABELS:
                    self.struct_field_labels.setdefault(name, {})[fld.name] = \
                        label

    def _collect_secret_consts(self) -> None:
        """Populate ``secret_consts`` from every module-level ``const``
        whose declared type carries the ``@secret`` label, so the body
        walk recognises a reference to it as an internal secret source
        (``_taint_of`` of an ``A.Ident``). The cross-function analogue of
        the intra-procedural label stamped on the const's global symbol;
        without it a secret const that crosses a free-function return or
        field-write to a public sink is missed (fail-open)."""
        from .. import _labels as L
        for item in self.module.items:
            if isinstance(item, A.ConstDecl):
                te = getattr(item, "type_expr", None)
                label = getattr(te, "label", None) if te is not None else None
                if label == L.SECRET:
                    self.secret_consts.add(item.name)

    # ---- collection -------------------------------------------------

    def _collect_callables(self) -> None:
        for item in self.module.items:
            if isinstance(item, A.FunDecl):
                key = ("fun", item.name)
                names = [p.name for p in item.params]
                self.callables[key] = (names, item, False)
                self.summaries[key] = set()
                self.field_effects[key] = {}
                self.return_effects[key] = set()
                self.secret_source_params[key] = self._secret_source_params(
                    item.params,
                )
                self.param_struct_types[key] = self._param_struct_types(
                    item.params,
                )
                self.param_type_names[key] = self._param_type_names(
                    item.params,
                )
            elif isinstance(item, A.ImplBlock):
                for method in item.methods:
                    key = ("method", item.type_name, method.name)
                    # Methods are keyed by (type, name); a name unique
                    # across states is guaranteed by the analyzer.
                    if key in self.callables:
                        continue
                    names = [p.name for p in method.params]
                    self.callables[key] = (names, method, True)
                    self.summaries[key] = set()
                    self.field_effects[key] = {}
                    self.return_effects[key] = set()
                    self.secret_source_params[key] = (
                        self._secret_source_params(method.params)
                    )
                    self.param_struct_types[key] = self._param_struct_types(
                        method.params, owner=item.type_name,
                    )
                    self.param_type_names[key] = self._param_type_names(
                        method.params, owner=item.type_name,
                    )
                    self.methods_by_name.setdefault(
                        method.name, []
                    ).append(key)

    def _param_struct_types(self, params, owner: str = None) -> dict:
        """``{param name: struct type name}`` for parameters whose
        declared type names a struct that has at least one declared-label
        field. ``self`` (no ``type_expr``) resolves to the impl ``owner``
        type. Restricting to structs we actually track keeps the map
        small and the field-read recognition precise."""
        out: dict = {}
        for p in params:
            te = getattr(p, "type_expr", None)
            if p.name == "self" and te is None and owner is not None:
                tyname = owner
            else:
                tyname = getattr(te, "name", None) if te is not None else None
            if tyname is not None and tyname in self.struct_field_labels:
                out[p.name] = tyname
        return out

    def _param_type_names(self, params, owner: str = None) -> dict:
        """``{param name: declared type name}`` for every parameter with
        a named type (``self`` -> the impl ``owner``). Unlike
        ``_param_struct_types`` this is NOT restricted to labelled-field
        structs: it is the general signal used to tell a user-typed
        receiver from a built-in one at a method call."""
        out: dict = {}
        for p in params:
            te = getattr(p, "type_expr", None)
            if p.name == "self" and te is None and owner is not None:
                tyname = owner
            else:
                tyname = getattr(te, "name", None) if te is not None else None
            if tyname is not None:
                out[p.name] = tyname
        return out

    @staticmethod
    def _secret_source_params(params) -> set:
        """The names of parameters whose declared type is a
        secret-source capability (``Env``), so a ``param.get(...)`` on
        them is an internal secret source."""
        out: set = set()
        for p in params:
            te = getattr(p, "type_expr", None)
            if te is not None and getattr(te, "name", None) in \
                    _SECRET_SOURCE_CAPS:
                out.add(p.name)
        return out

    # ---- fixpoint ---------------------------------------------------

    def run(self) -> tuple[dict, dict]:
        changed = True
        # The summary operator is monotone over a finite lattice (each
        # sink summary is a subset of parameter indices; each field
        # effect maps a finite set of target indices to a finite set of
        # source indices), so the ascending chain stabilises and the
        # loop is bounded.
        while changed:
            changed = False
            for key in self.callables:
                names, decl, _is_method = self.callables[key]
                reaching, effects, returns = self._analyze_body(
                    names, decl, key,
                )
                if not reaching <= self.summaries[key]:
                    self.summaries[key] |= reaching
                    changed = True
                if self._merge_effects(self.field_effects[key], effects):
                    changed = True
                if not returns <= self.return_effects[key]:
                    self.return_effects[key] |= returns
                    changed = True
        sinks = {k: frozenset(v) for k, v in self.summaries.items()}
        feffects = {
            k: {t: frozenset(s) for t, s in v.items()}
            for k, v in self.field_effects.items()
        }
        reffects = {k: frozenset(v) for k, v in self.return_effects.items()}
        return sinks, feffects, reffects

    @staticmethod
    def _merge_effects(acc: dict, new: dict) -> bool:
        """Monotonically merge field-write effect map ``new`` into
        ``acc`` (target idx -> set of sources). Return True if ``acc``
        grew (drives the fixpoint)."""
        grew = False
        for target, sources in new.items():
            cur = acc.get(target)
            if cur is None:
                acc[target] = set(sources)
                grew = grew or bool(sources)
            elif not sources <= cur:
                cur |= sources
                grew = True
        return grew

    # ---- per-body taint analysis ------------------------------------

    def _analyze_body(
        self, param_names: list[str], decl: A.FunDecl, key,
    ) -> tuple[set, dict, set]:
        """Compute (a) which parameter indices of ``decl`` reach a sink,
        (b) the field-write effects, and (c) the return-secret sources,
        using the summaries computed so far for transitive calls.

        Taint is tracked as ``name -> set(param indices)``: the set of
        source parameters (or ``INTERNAL_SECRET``) whose value flows
        into that name. A sink position taints those source params
        (adds them to ``reaching``); a field store on a param-rooted
        object records a field-write effect. ``declassify(...)`` yields
        the empty source set, breaking the chain. The set of names that
        ALIAS a parameter's object (for the field-store target) is the
        same taint set, since a struct binding carries its source
        params' indices by reference.
        """
        env: dict[str, set] = {}
        for idx, pname in enumerate(param_names):
            # ``self`` and every explicit parameter is a potential
            # carrier; a capability-typed parameter never holds secret
            # data, but it also never appears as a sink ARGUMENT, so
            # seeding it is harmless and keeps the index alignment.
            env[pname] = {idx}
        reaching: set = set()
        effects: dict = {}
        returns: set = set()
        # Per-callable analysis state consulted inside the walk (which
        # threads only ``env`` / ``reaching`` through its signatures):
        # the names of secret-source-capability params, the accumulating
        # field-write effect map, and the return-secret source set.
        self._cur_secret_source_params = self.secret_source_params.get(
            key, set(),
        )
        self._cur_param_struct_types = self.param_struct_types.get(key, {})
        self._cur_param_type_names = self.param_type_names.get(key, {})
        self._cur_effects = effects
        self._cur_returns = returns
        self._walk_block(decl.body, env, reaching)
        # A function body's trailing bare expression is an implicit
        # return (unit / expression-bodied functions), so its taint is a
        # return source too -- mirroring the analyzer's block-as-value
        # rule and the match-arm tail handling below.
        returns |= self._block_tail_taint(decl.body, env, reaching)
        return reaching, effects, returns

    def _walk_block(self, block: A.Block, env: dict, reaching: set) -> None:
        for stmt in block.stmts:
            self._walk_stmt(stmt, env, reaching)

    def _walk_stmt(self, stmt: A.Stmt, env: dict, reaching: set) -> None:
        if isinstance(stmt, A.LetStmt):
            src = self._taint_of(stmt.value, env, reaching)
            self._bind_pattern_taint(stmt.pattern, src, env)
        elif isinstance(stmt, A.VarStmt):
            env[stmt.name] = self._taint_of(stmt.value, env, reaching)
        elif isinstance(stmt, A.AssignStmt):
            src = self._taint_of(stmt.value, env, reaching)
            self._taint_of(stmt.target, env, reaching)
            if isinstance(stmt.target, A.Ident):
                # Monotone over loops / branches: join, never clear.
                env[stmt.target.name] = (
                    env.get(stmt.target.name, set()) | src
                )
            elif isinstance(stmt.target, A.FieldAccess):
                # A field store ``obj.f = value`` (or ``obj.a.b = ...``):
                # if the written object is rooted at a parameter (or a
                # binding that aliases one), record a field-write effect
                # from each source flowing into ``value`` onto each
                # target param the object aliases. Whole-value on both
                # sides (the conservative, sound granularity). ANY store
                # op is recorded: an augmented store (``box.f += v``) reads
                # the old field and joins ``value`` into it, so it can only
                # RAISE the field's label, never lower it -- recording the
                # effect for every op is sound and closes the augmented-
                # store cross-function leak.
                self._record_field_write(stmt.target, src, env)
        elif isinstance(stmt, A.IfStmt):
            self._taint_of(stmt.cond, env, reaching)
            self._walk_block(stmt.then_block, env, reaching)
            for cond, blk in stmt.elif_arms:
                self._taint_of(cond, env, reaching)
                self._walk_block(blk, env, reaching)
            if stmt.else_block is not None:
                self._walk_block(stmt.else_block, env, reaching)
        elif isinstance(stmt, A.WhileStmt):
            self._taint_of(stmt.cond, env, reaching)
            self._walk_block(stmt.body, env, reaching)
        elif isinstance(stmt, A.ForStmt):
            iter_src = self._taint_of(stmt.iter, env, reaching)
            self._bind_pattern_taint(stmt.pattern, iter_src, env)
            self._walk_block(stmt.body, env, reaching)
        elif isinstance(stmt, A.ReturnStmt):
            if stmt.value is not None:
                # The returned value's source set is a return-secret
                # effect: it carries the callee's secret-derived result
                # to the caller's call-result label cross-function.
                self._cur_returns |= self._taint_of(stmt.value, env, reaching)
        elif isinstance(stmt, A.ExprStmt):
            self._taint_of(stmt.expr, env, reaching)
        # break / continue carry no value.

    def _bind_pattern_taint(self, pat: A.Pattern, src: set, env: dict) -> None:
        """Propagate a scrutinee / value's source-param set to every
        name the pattern binds (whole-value granularity, matching
        ``_label_pattern_binds``).

        A name bound to a struct field DECLARED ``@secret`` additionally
        carries the ``INTERNAL_SECRET`` sentinel, independent of the
        scrutinee's own taint -- the cross-function analogue of
        ``_field_read_is_secret`` for a pattern bind. So a callee that
        destructures a declared-@secret field of a struct parameter and
        sinks / returns the bound name is caught across the boundary,
        exactly like one that reads ``param.iban`` directly. Resolved by
        the pattern's STRUCT TYPE NAME (never by bound-name spelling), so
        a same-named public field of an unrelated struct is not tainted."""
        if isinstance(pat, A.IdentPat):
            env[pat.name] = env.get(pat.name, set()) | src
            return
        for name in _pattern_bound_names(pat):
            env[name] = env.get(name, set()) | src
        self._bind_pattern_field_secrets(pat, env)

    def _bind_pattern_field_secrets(self, pat: A.Pattern, env: dict) -> None:
        """Taint every name bound to a DECLARED-``@secret`` struct field
        with ``INTERNAL_SECRET``, walking nested patterns. Mirrors the
        intra-procedural ``_label_pattern_field_secrets``; see
        ``_bind_pattern_taint`` for why resolution is by the pattern's
        struct type name."""
        from .. import _labels as L
        if isinstance(pat, A.StructPat):
            labels = self.struct_field_labels.get(pat.type_name, {})
            for fname, fpat in pat.fields:
                if labels.get(fname) == L.SECRET:
                    if fpat is None:
                        env[fname] = env.get(fname, set()) | {INTERNAL_SECRET}
                    else:
                        for name in _pattern_bound_names(fpat):
                            env[name] = (
                                env.get(name, set()) | {INTERNAL_SECRET}
                            )
                if fpat is not None:
                    self._bind_pattern_field_secrets(fpat, env)
            return
        if isinstance(pat, A.VariantPat):
            for sub in pat.payloads:
                self._bind_pattern_field_secrets(sub, env)
        elif isinstance(pat, A.TuplePat):
            for sub in pat.elements:
                self._bind_pattern_field_secrets(sub, env)

    def _record_field_write(
        self, target: A.FieldAccess, value_src: set, env: dict,
    ) -> None:
        """Record a field-write effect for ``target.f = value``. The
        written object's identity is the env taint set of the chain's
        ROOT name (a struct binding carries the param indices of every
        param it aliases by reference). For each such target param
        ``j``, every source flowing into the value becomes a field-write
        effect ``j <- source``. A source that is itself a parameter
        index (or ``INTERNAL_SECRET``) is recorded; transitive sources
        already collapsed into ``value_src`` by ``_taint_of``."""
        root = self._chain_root_name(target)
        if root is None:
            return
        target_params = env.get(root, set())
        if not target_params or not value_src:
            return
        for j in target_params:
            if j == INTERNAL_SECRET:
                continue
            self._cur_effects.setdefault(j, set()).update(value_src)

    def _field_read_is_secret(self, e: A.FieldAccess) -> bool:
        """True if reading field ``e`` yields a value declared
        ``@secret``, resolved PRECISELY: the receiver must be a parameter
        whose struct type we know (``param_struct_types``), and that
        struct must declare this exact field ``@secret``. Deliberately
        precise (no by-name over-approximation): a same-named field that
        is @secret in some UNRELATED struct must NOT taint a public field
        read here, so the cross-function summary never raises a false
        positive on a public field. The intra-procedural pass (resolved
        types) is the precise primary check; this only adds the
        cross-function carry for the common parameter-struct shape that
        the required facets use (a callee that reads a declared-@secret
        field of a struct PARAMETER and sinks / returns it).

        PARITY (field-read / field-pattern): the SAME declared-@secret
        field reached by DESTRUCTURING (``let Emp { iban } = e`` / a
        ``match`` arm) is covered too -- see
        ``_bind_pattern_field_secrets``, the pattern-bind analogue of
        this read rule -- so a field cannot launder its label through a
        pattern bind any more than through a direct ``e.iban`` read."""
        from .. import _labels as L
        recv = e.receiver
        if isinstance(recv, A.Ident):
            tyname = self._cur_param_struct_types.get(recv.name)
            if tyname is not None:
                labels = self.struct_field_labels.get(tyname, {})
                return labels.get(e.field_name) == L.SECRET
        return False

    @staticmethod
    def _chain_root_name(e: A.Expr):
        """The root identifier name of a field-access chain
        (``b`` -> ``"b"``, ``b.inner.x`` -> ``"b"``), or ``None`` if the
        chain is not rooted at a plain identifier."""
        while isinstance(e, A.FieldAccess):
            e = e.receiver
        return e.name if isinstance(e, A.Ident) else None

    # ---- taint of an expression ------------------------------------

    def _taint_of(self, e: A.Expr, env: dict, reaching: set) -> set:
        """Return the set of source-param indices that flow into the
        value of ``e``. Side effect: when ``e`` (or a sub-expression)
        places a param-derived value into a sink argument position,
        those source params are added to ``reaching``.
        """
        if isinstance(e, A.Ident):
            # A reference to a module-level ``@secret`` const is an
            # internal secret source, symmetric to a declared-@secret
            # field read: it carries the INTERNAL_SECRET sentinel so a
            # free function returning it / writing it to a field taints
            # its return / field-write effect and the leak is caught at
            # the call site. Only when the name is NOT shadowed by a local
            # (parameters and let/var binds populate ``env``, so a name in
            # ``env`` refers to the local, never the const).
            if e.name in self.secret_consts and e.name not in env:
                return {INTERNAL_SECRET}
            return set(env.get(e.name, set()))
        if isinstance(e, (
            A.IntLit, A.FloatLit, A.StringLit, A.CharLit,
            A.BoolLit, A.UnitLit,
        )):
            return set()
        if isinstance(e, A.InterpolatedString):
            out: set = set()
            for p in e.parts:
                if not isinstance(p, str):
                    out |= self._taint_of(p, env, reaching)
            return out
        if isinstance(e, A.BinOp):
            return (
                self._taint_of(e.left, env, reaching)
                | self._taint_of(e.right, env, reaching)
            )
        if isinstance(e, A.UnaryOp):
            return self._taint_of(e.operand, env, reaching)
        if isinstance(e, A.Try):
            return self._taint_of(e.expr, env, reaching)
        if isinstance(e, A.Index):
            return (
                self._taint_of(e.receiver, env, reaching)
                | self._taint_of(e.index, env, reaching)
            )
        if isinstance(e, A.FieldAccess):
            recv_src = self._taint_of(e.receiver, env, reaching)
            # A field whose declared type is ``@secret`` (``type Emp {
            # iban: @secret String }``) is an internal secret source when
            # READ: the value carries the INTERNAL_SECRET sentinel so it
            # reaches a sink / return cross-function, mirroring the
            # intra-procedural declared-field-label rule. Precise when the
            # receiver is a parameter whose struct type we resolved; a
            # by-name over-approximation (any struct declares this field
            # @secret) otherwise -- sound, never under-reports.
            if self._field_read_is_secret(e):
                return recv_src | {INTERNAL_SECRET}
            return recv_src
        if isinstance(e, A.RangeExpr):
            return (
                self._taint_of(e.start, env, reaching)
                | self._taint_of(e.end, env, reaching)
            )
        if isinstance(e, A.StructLit):
            out = set()
            for _name, v in e.fields:
                out |= self._taint_of(v, env, reaching)
            return out
        if isinstance(e, (A.ListLit, A.TupleLit)):
            out = set()
            for el in e.elements:
                out |= self._taint_of(el, env, reaching)
            return out
        if isinstance(e, A.IfExpr):
            self._taint_of(e.cond, env, reaching)
            return (
                self._taint_of(e.then_expr, env, reaching)
                | self._taint_of(e.else_expr, env, reaching)
            )
        if isinstance(e, A.MatchExpr):
            scrut = self._taint_of(e.scrutinee, env, reaching)
            out = set()
            for arm in e.arms:
                # Each arm sees a sub-env where the pattern binds carry
                # the scrutinee's taint (whole-value).
                arm_env = dict(env)
                self._bind_pattern_taint(arm.pattern, scrut, arm_env)
                if arm.guard is not None:
                    self._taint_of(arm.guard, arm_env, reaching)
                if isinstance(arm.body, A.Block):
                    self._walk_block(arm.body, arm_env, reaching)
                    out |= self._block_tail_taint(arm.body, arm_env, reaching)
                else:
                    out |= self._taint_of(arm.body, arm_env, reaching)
            return out
        if isinstance(e, A.Become):
            return self._taint_of(e.value, env, reaching)
        if isinstance(e, A.Call):
            return self._taint_of_call(e, env, reaching)
        if isinstance(e, A.MethodCall):
            return self._taint_of_method_call(e, env, reaching)
        # Lambda: bodies are checked intra-procedurally elsewhere; a
        # lambda value carries no parameter taint of the enclosing fn
        # for this slice.
        return set()

    def _block_tail_taint(
        self, block: A.Block, env: dict, reaching: set,
    ) -> set:
        """The taint of a block used as an expression: its trailing
        bare expression's taint, mirroring the analyzer's
        block-as-expression rule for match arms."""
        if block.stmts and isinstance(block.stmts[-1], A.ExprStmt):
            return self._taint_of(block.stmts[-1].expr, env, reaching)
        return set()

    # ---- calls ------------------------------------------------------

    def _taint_of_call(self, e: A.Call, env: dict, reaching: set) -> set:
        # declassify breaks the chain: its arguments are still walked
        # (so a sink *inside* an argument is still seen), but the value
        # it yields carries no source taint.
        if self._is_declassify(e):
            for a in e.args:
                self._taint_of(a, env, reaching)
            return set()

        arg_srcs = [self._taint_of(a, env, reaching) for a in e.args]

        # The builtin ``panic(message)`` is a public sink (the message
        # goes to stderr, like Stdio.eprintln): a parameter flowing
        # into its argument is sink-reaching, so a caller passing a
        # @secret to a function that panics with it is flagged at the
        # boundary. A user function named ``panic`` shadows the
        # builtin and takes the regular summary path below instead.
        if (
            isinstance(e.callee, A.Ident)
            and e.callee.name == "panic"
            and ("fun", "panic") not in self.callables
            and arg_srcs
        ):
            reaching |= arg_srcs[0]

        if not isinstance(e.callee, A.Ident):
            # Non-Ident callee (lambda result, etc.): conservatively
            # join the argument taints into the result; no summary.
            self._taint_of(e.callee, env, reaching)
            out = set()
            for s in arg_srcs:
                out |= s
            return out

        key = ("fun", e.callee.name)
        # Invoking a Fun-typed PARAMETER: ``f()`` where ``f`` is parameter
        # ``idx``. The result carries ``f``'s taint, so if it reaches a
        # sink the parameter ``idx`` becomes sink-reaching -- the
        # INVOKE-SINK-REACHING parameter (a Fun parameter the callee
        # invokes and whose result it sinks). The call site disambiguates
        # by the parameter's declared TYPE: a Fun-typed sink-reaching
        # parameter consults a closure argument's RESULT label (so a
        # declassifying closure is not flagged), a data-typed one its
        # whole-value label. Only fires for a callee name that is NOT a
        # known free function (those take the summary path) and that
        # carries parameter taint in ``env`` (an ordinary public local
        # does not).
        invoke_src: set = set()
        if key not in self.callables:
            invoke_src = set(env.get(e.callee.name, set()))
        if key in self.callables:
            names, _decl, _is_method = self.callables[key]
            perm = self._bind_args(e, names)
            sink_params = self.summaries.get(key, set())
            for pidx, arg_idx in perm.items():
                if pidx in sink_params and arg_idx < len(arg_srcs):
                    reaching |= arg_srcs[arg_idx]
            # Transitive field-write effect: ``g`` writes a field of its
            # param ``j`` from sources ``S``; if the argument bound to
            # ``j`` here is rooted at one of MY params, that object's
            # field is written, so I inherit the effect (with ``S``
            # translated from g's params to my taint).
            self._propagate_callee_effects(
                self.field_effects.get(key, {}), perm, e.args, arg_srcs, env,
            )
            # The call RESULT follows the callee's RETURN-EFFECT, mapped
            # back to this call's taint -- the same rule the method path
            # uses (``_return_taint_of_method_call``), and the key fix for
            # the free-function return-laundering false negative. A free
            # function name resolves to EXACTLY ONE callable, so its
            # ``return_effects`` is precise (no by-name over-approximation):
            # ``INTERNAL_SECRET`` -> the sentinel (the result is secret
            # unconditionally, e.g. the callee reads a declared-@secret
            # field of a struct param and returns it, which the plain
            # argument join dropped); a real param ``s`` -> the taint of
            # the argument bound to ``s``. This both CLOSES the laundering
            # (INTERNAL_SECRET now propagates) and is more precise than the
            # old unconditional argument join (a param whose value does not
            # flow into the return no longer taints the result), mirroring
            # the method-path narrowing. The invoked Fun-typed-parameter
            # taint still joins in (it is not a summarised callee).
            out = set(invoke_src)
            for s in self.return_effects.get(key, set()):
                if s == INTERNAL_SECRET:
                    out.add(INTERNAL_SECRET)
                    continue
                arg_idx = perm.get(s)
                if arg_idx is not None and arg_idx < len(arg_srcs):
                    out |= arg_srcs[arg_idx]
            return out
        # Non-summarised callee (a Fun-typed parameter invocation, or a
        # name that is not a known free function): conservatively join the
        # argument taints into the result plus the invoked value's taint.
        out = set(invoke_src)
        for s in arg_srcs:
            out |= s
        return out

    def _taint_of_method_call(
        self, e: A.MethodCall, env: dict, reaching: set,
    ) -> set:
        recv_src = self._taint_of(e.receiver, env, reaching)
        arg_srcs = [self._taint_of(a, env, reaching) for a in e.args]

        # Internal secret source (``env.get(...)``): a method named in
        # ``_SECRET_SOURCE_METHODS`` called on a parameter typed as a
        # secret-source capability yields a value carrying the
        # INTERNAL_SECRET sentinel, so a field stored from it records an
        # unconditional field-write effect. Matched precisely (the
        # receiver is a known Env-typed parameter) so List/Map ``get``
        # are not misread as a source.
        if (
            e.method in _SECRET_SOURCE_METHODS
            and isinstance(e.receiver, A.Ident)
            and e.receiver.name in self._cur_secret_source_params
        ):
            return {INTERNAL_SECRET}

        # Built-in public sink (Stdio.println, Net.post, ...): a
        # param-derived value in a sink argument position reaches a
        # sink. The receiver-type name is the capability name; we only
        # know it syntactically when the receiver is a plain Ident
        # whose name matches a capability, but built-in sinks are
        # keyed by capability TYPE name, not value name. The
        # intra-procedural pass (which has resolved types) already
        # catches the in-body case; here we over-approximate by
        # matching the METHOD name against any sink signature, so a
        # secret routed to a parameter that the callee sinks via a
        # built-in cap is still caught at the boundary.
        for (_cap, meth), positions in _PUBLIC_SINKS.items():
            if meth != e.method:
                continue
            for pos in positions:
                if pos < len(arg_srcs):
                    reaching |= arg_srcs[pos]

        # A mutating container method (push / add / set) routes the
        # argument taint into the receiver, so a later read of the
        # receiver does not launder it. Reflect that in ``env`` when
        # the receiver is a plain name.
        for (_ty, meth), positions in _CONTAINER_MUTATORS.items():
            if meth != e.method:
                continue
            injected = set()
            for pos in positions:
                if pos < len(arg_srcs):
                    injected |= arg_srcs[pos]
            if injected and isinstance(e.receiver, A.Ident):
                env[e.receiver.name] = (
                    env.get(e.receiver.name, set()) | injected
                )

        # User method call: receiver-type may be unknown at summary
        # time, so over-approximate across every user method of this
        # name. ``self`` is parameter index 0, the explicit args
        # follow (positional / named).
        candidate_keys = self.methods_by_name.get(e.method, [])
        for key in candidate_keys:
            names, _decl, _is_method = self.callables[key]
            sink_params = self.summaries.get(key, set())
            if not sink_params:
                continue
            # Index 0 is ``self`` -> the receiver.
            if 0 in sink_params:
                reaching |= recv_src
            # Explicit parameters are names[1:]; bind the call's
            # positional / named args to them.
            explicit = names[1:] if names and names[0] == "self" else names
            perm = self._bind_explicit_args(e, explicit)
            for local_pidx, arg_idx in perm.items():
                # local_pidx indexes ``explicit``; the summary uses the
                # full param order, so shift by 1 when ``self`` leads.
                full_pidx = (
                    local_pidx + 1
                    if names and names[0] == "self" else local_pidx
                )
                if full_pidx in sink_params and arg_idx < len(arg_srcs):
                    reaching |= arg_srcs[arg_idx]

        # Transitive field-write effect across the (possibly
        # over-approximated) candidate methods. The full-order argument
        # map binds ``self`` (param 0) to the receiver and the explicit
        # params to their call arguments.
        for key in candidate_keys:
            names, _decl, _is_method = self.callables[key]
            effects = self.field_effects.get(key, {})
            if not effects:
                continue
            full_perm, full_args = self._method_full_perm(e, names)
            full_srcs = [recv_src] + arg_srcs
            self._propagate_callee_effects(
                effects, full_perm, full_args, full_srcs, env,
            )

        # Result label follows the RETURN-EFFECT of the candidate
        # methods, not the whole-value taint of the receiver: the result
        # carries source ``s`` iff ``s`` is in some candidate's
        # ``return_effects``, mapped back to this call's taint. So a
        # method whose return derives only from its arguments / a response
        # does NOT inherit the receiver's secret fields (kills the
        # false positive), while a method that returns a secret-derived
        # value (a real param echoed back, ``self``, or an internal
        # secret) still taints the result (laundering stays closed).
        #
        # UNION BY-NAME over every candidate impl (the same
        # over-approximation ``_method_call_returns_secret`` uses): a
        # receiver whose concrete type is unknown / dynamically dispatched
        # contributes the union of every matching method's effect, so the
        # result is never under-tainted.
        return self._return_taint_of_method_call(
            e, candidate_keys, recv_src, arg_srcs,
        )

    def _return_taint_of_method_call(
        self, e: A.MethodCall, candidate_keys: list,
        recv_src: set, arg_srcs: list,
    ) -> set:
        """The taint the RESULT of ``recv.m(args)`` carries, derived from
        the candidate methods' return-effects (full param order: index 0
        is ``self``, explicit params follow). For each source ``s`` in a
        candidate's return-effect: ``INTERNAL_SECRET`` -> the sentinel
        (result tainted unconditionally); ``0`` -> the receiver taint;
        a real param ``s`` -> the taint of the argument bound to ``s``.
        Union over every candidate (by-name over-approximation).

        The narrowing is applied ONLY when the receiver's declared type
        is provably a USER method owner: a parameter whose type has an
        EXACT impl-method key for this call, or a parameter typed as a
        TRAIT (dynamic dispatch, where the by-name union is sound). When
        the receiver is a built-in container / primitive (``list.get`` /
        ``str.to_upper``), a non-parameter local, or its type cannot be
        resolved here, fall back to the conservative whole-value join of
        the receiver + argument taints -- the original, sound rule -- so a
        same-named user method cannot under-taint a built-in receiver's
        result and a read off a secret-derived receiver stays tainted."""
        full_srcs = [recv_src] + arg_srcs
        conservative: set = set(recv_src)
        for s in arg_srcs:
            conservative |= s
        keys = self._result_candidate_keys(e, candidate_keys)
        if not keys:
            return conservative
        out: set = set()
        for key in keys:
            sources = self.return_effects.get(key)
            if not sources:
                continue
            names, _decl, _is_method = self.callables[key]
            full_perm, _full_args = self._method_full_perm(e, names)
            for s in sources:
                if s == INTERNAL_SECRET:
                    out.add(INTERNAL_SECRET)
                    continue
                full_arg_idx = full_perm.get(s)
                if full_arg_idx is not None and full_arg_idx < len(full_srcs):
                    out |= full_srcs[full_arg_idx]
        return out

    def _result_candidate_keys(self, e: A.MethodCall, by_name: list) -> tuple:
        """The method keys whose return-effect may NARROW the result label
        of ``e``, or ``()`` to fall back to the conservative whole-value
        join. Narrowing requires the receiver's declared type to be a
        provable user method owner in the current body:

        * a parameter whose declared type has an EXACT impl-method key for
          this call (``("method", tyname, e.method)``) -> that key; or
        * a parameter typed as a TRAIT (dynamic dispatch) -> the by-name
          union over every impl method of this name.

        Any other receiver (a built-in container modelled as a struct such
        as ``List``, a non-parameter local, an unresolved chain) yields
        ``()`` so the conservative join governs -- so a same-named user
        method cannot under-taint a built-in receiver's result."""
        if not isinstance(e.receiver, A.Ident):
            return ()
        tyname = self._cur_param_type_names.get(e.receiver.name)
        if tyname is None:
            return ()
        exact_key = ("method", tyname, e.method)
        if exact_key in self.return_effects:
            return (exact_key,)
        if self._is_trait_type(tyname):
            return tuple(by_name)
        return ()

    def _is_trait_type(self, type_name: str) -> bool:
        """True if ``type_name`` resolves to a TRAIT (dynamic dispatch),
        the only concrete case where the by-name union over impl methods
        is justified for the result label; a built-in container modelled
        as a struct (``List``) is NOT a trait, so it falls back to the
        conservative join."""
        from . import SymbolKind
        sym = self.global_scope.lookup(type_name)
        return sym is not None and sym.kind == SymbolKind.TRAIT

    def _method_full_perm(self, e: A.MethodCall, names: list[str]):
        """Full-order ``{param_idx: full_arg_idx}`` map and the matching
        argument list for a method call, where index 0 is ``self`` (the
        receiver) and the explicit params follow. ``full_arg_idx`` 0 is
        the receiver; explicit args are shifted by 1 so they line up
        with the ``[recv] + args`` source list."""
        has_self = bool(names) and names[0] == "self"
        explicit = names[1:] if has_self else names
        explicit_perm = _bind(e.args, e.arg_names, explicit)
        full_perm: dict = {}
        if has_self:
            full_perm[0] = 0
        for local_pidx, arg_idx in explicit_perm.items():
            full_pidx = local_pidx + 1 if has_self else local_pidx
            full_perm[full_pidx] = arg_idx + 1
        full_args = [e.receiver] + list(e.args)
        return full_perm, full_args

    def _propagate_callee_effects(
        self, effects: dict, perm: dict, args: list,
        arg_srcs: list, env: dict,
    ) -> None:
        """Inherit a callee's field-write effects at a call site. For
        each callee target param ``j`` with sources ``S``: the argument
        bound to ``j`` is the written object; if it is rooted at one of
        MY bindings, record a field-write effect on every param that
        object aliases, with ``S`` translated from the callee's params
        to my taint (a real source param ``i`` -> the taint of my
        argument bound to ``i``; ``INTERNAL_SECRET`` stays itself).
        Conservative and whole-value throughout."""
        for target_pidx, sources in effects.items():
            arg_idx = perm.get(target_pidx)
            if arg_idx is None or arg_idx >= len(args):
                continue
            root = self._chain_root_name(args[arg_idx])
            if root is None:
                continue
            my_targets = env.get(root, set())
            if not my_targets:
                continue
            translated: set = set()
            for s in sources:
                if s == INTERNAL_SECRET:
                    translated.add(INTERNAL_SECRET)
                else:
                    src_arg = perm.get(s)
                    if src_arg is not None and src_arg < len(arg_srcs):
                        translated |= arg_srcs[src_arg]
            if not translated:
                continue
            for j in my_targets:
                if j == INTERNAL_SECRET:
                    continue
                self._cur_effects.setdefault(j, set()).update(translated)

    # ---- argument binding ------------------------------------------

    def _bind_args(self, e: A.Call, param_names: list[str]) -> dict:
        """Map ``{param_index: arg_index}`` for a free-function call,
        honouring positional and named arguments. Permissive: an
        ill-formed call (the analyzer reports it separately) just maps
        what it can."""
        return _bind(e.args, e.arg_names, param_names)

    def _bind_explicit_args(
        self, e: A.MethodCall, explicit_names: list[str],
    ) -> dict:
        """Map ``{explicit_param_index: arg_index}`` for a method
        call's explicit arguments (receiver handled separately)."""
        return _bind(e.args, e.arg_names, explicit_names)

    # ---- helpers ----------------------------------------------------

    def _is_declassify(self, e: A.Call) -> bool:
        if not isinstance(e.callee, A.Ident) or e.callee.name != "declassify":
            return False
        # A user function named ``declassify`` would shadow the
        # built-in; the analyzer forbids that collision, so a plain
        # name check is sufficient here, and matches the built-in.
        return ("fun", "declassify") not in self.callables


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
