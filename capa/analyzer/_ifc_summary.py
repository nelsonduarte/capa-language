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
"""

from __future__ import annotations

from .. import capa_ast as A
from ._ifc import _PUBLIC_SINKS, _CONTAINER_MUTATORS, _pattern_bound_names


# A callable's parameters, in the canonical order the analyzer uses:
# for a method, index 0 is ``self`` and the explicit parameters follow
# (matching ``has_self`` + ``param_names``); for a free function, the
# explicit parameters in declaration order.
#
# Keys into the summary table:
#   ("fun", name)                  -- a free function
#   ("method", type_name, method)  -- an impl / trait method


def compute_ifc_summaries(module: A.Module, global_scope) -> dict:
    """Return ``{callable_key: frozenset(sink_reaching_param_indices)}``.

    ``global_scope`` is the analyzer's populated global scope, used to
    tell user functions / variants / capabilities apart at call sites.
    The result is the least fixpoint of the monotone summary operator,
    so recursion (self or mutual) terminates.
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
        # callable_key -> (param_names_in_order, A.FunDecl, is_method).
        # ``param_names_in_order`` includes ``self`` at index 0 for a
        # method, so a positional / named argument binds to the right
        # index uniformly with the call-site logic.
        self.callables: dict = {}
        # method name -> list of method callable_keys (for the
        # receiver-type-unknown over-approximation at method calls).
        self.methods_by_name: dict[str, list] = {}
        self._collect_callables()

    # ---- collection -------------------------------------------------

    def _collect_callables(self) -> None:
        for item in self.module.items:
            if isinstance(item, A.FunDecl):
                key = ("fun", item.name)
                names = [p.name for p in item.params]
                self.callables[key] = (names, item, False)
                self.summaries[key] = set()
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
                    self.methods_by_name.setdefault(
                        method.name, []
                    ).append(key)

    # ---- fixpoint ---------------------------------------------------

    def run(self) -> dict:
        changed = True
        # The summary operator is monotone over a finite lattice
        # (each summary is a subset of its parameter indices), so the
        # ascending chain stabilises; the loop is bounded.
        while changed:
            changed = False
            for key in self.callables:
                names, decl, _is_method = self.callables[key]
                reaching = self._analyze_body(names, decl)
                if not reaching <= self.summaries[key]:
                    self.summaries[key] |= reaching
                    changed = True
        return {k: frozenset(v) for k, v in self.summaries.items()}

    # ---- per-body taint analysis ------------------------------------

    def _analyze_body(self, param_names: list[str], decl: A.FunDecl) -> set:
        """Compute which parameter indices of ``decl`` reach a sink,
        using the summaries computed so far for transitive calls.

        Taint is tracked as ``name -> set(param indices)``: the set of
        source parameters whose value flows into that name. A sink
        position taints those source params (adds them to the result).
        ``declassify(...)`` yields the empty source set, breaking the
        chain.
        """
        env: dict[str, set] = {}
        for idx, pname in enumerate(param_names):
            # ``self`` and every explicit parameter is a potential
            # carrier; a capability-typed parameter never holds secret
            # data, but it also never appears as a sink ARGUMENT, so
            # seeding it is harmless and keeps the index alignment.
            env[pname] = {idx}
        reaching: set = set()
        self._walk_block(decl.body, env, reaching)
        return reaching

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
                self._taint_of(stmt.value, env, reaching)
        elif isinstance(stmt, A.ExprStmt):
            self._taint_of(stmt.expr, env, reaching)
        # break / continue carry no value.

    def _bind_pattern_taint(self, pat: A.Pattern, src: set, env: dict) -> None:
        """Propagate a scrutinee / value's source-param set to every
        name the pattern binds (whole-value granularity, matching
        ``_label_pattern_binds``)."""
        if isinstance(pat, A.IdentPat):
            env[pat.name] = env.get(pat.name, set()) | src
            return
        for name in _pattern_bound_names(pat):
            env[name] = env.get(name, set()) | src

    # ---- taint of an expression ------------------------------------

    def _taint_of(self, e: A.Expr, env: dict, reaching: set) -> set:
        """Return the set of source-param indices that flow into the
        value of ``e``. Side effect: when ``e`` (or a sub-expression)
        places a param-derived value into a sink argument position,
        those source params are added to ``reaching``.
        """
        if isinstance(e, A.Ident):
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
            return self._taint_of(e.receiver, env, reaching)
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

        if not isinstance(e.callee, A.Ident):
            # Non-Ident callee (lambda result, etc.): conservatively
            # join the argument taints into the result; no summary.
            self._taint_of(e.callee, env, reaching)
            out = set()
            for s in arg_srcs:
                out |= s
            return out

        key = ("fun", e.callee.name)
        if key in self.callables:
            names, _decl, _is_method = self.callables[key]
            perm = self._bind_args(e, names)
            sink_params = self.summaries.get(key, set())
            for pidx, arg_idx in perm.items():
                if pidx in sink_params and arg_idx < len(arg_srcs):
                    reaching |= arg_srcs[arg_idx]
        # Either way the call RESULT joins argument taints (the
        # conservative result-label rule, mirrored here).
        out = set()
        for s in arg_srcs:
            out |= s
        return out

    def _taint_of_method_call(
        self, e: A.MethodCall, env: dict, reaching: set,
    ) -> set:
        recv_src = self._taint_of(e.receiver, env, reaching)
        arg_srcs = [self._taint_of(a, env, reaching) for a in e.args]

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

        # Result joins receiver + argument taints (conservative).
        out = set(recv_src)
        for s in arg_srcs:
            out |= s
        return out

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
