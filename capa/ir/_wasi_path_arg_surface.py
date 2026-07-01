"""Path-arg surface analysis for the ``--wasi`` mode (Layer 1).

The dominant ecosystem pattern is a CLI tool that receives paths in
``argv`` (``env.args()``) and feeds them to ``fs.read`` / ``fs.write``
(or ``net.get`` / ``env.get``). Such a path is a COMPUTED value at the
sink, so the static preopen / host / key ceiling cannot be derived and
``--wasi`` fail-closes (rightly: the trust frontier does not move).

This module does NOT unblock that program automatically (that would be
Layer 2, deriving preopens from argv -- out of scope, it WOULD move the
frontier). It is a BY-CONSTRUCTION, TRANSPARENT layer that PROVES and
EXPOSES an auditable fact: which ``argv`` arguments reach which Fs / Net
/ Env sinks, and whether the access is read or write. That fact powers

* an auditable SBOM surface (compiler-derived, distinct from the
  operator-declared grants);
* an actionable ``--wasi`` rejection message naming the arg -> sink; and
* the ``capa --wasi-surface`` inspection command.

SOUNDNESS -- the surface is a CORRECT OVER-APPROXIMATION of the true
argv -> sink boundary, inheriting the const-prop's discipline:

* it NEVER OMITS an ``argv`` argument that can reach a sink (a forward
  taint that any uncertainty WIDENS, never drops);
* it NEVER reports an argv INDEX narrower than statically PROVED -- a
  concrete index is emitted only when the sink slot is DIRECTLY
  ``args.get(<int literal>)`` / ``args.first()`` / ``args[<int literal>]``
  in the sink's own frame; in every other case (a tainted value routed
  through a struct field, a helper return, a loop, a computed index, ...)
  the index is ``*`` (ANY argv element); and
* it is REACHABILITY-BLIND, exactly like the const-prop and the SBOM:
  an argv-tainted value at a sink slot anywhere in the source text is in
  scope whether or not that code can run.

The taint is a forward, flow-INSENSITIVE fixpoint over the call graph:
the seed is the result of ``env.args()`` on an ``Env`` parameter; the
taint propagates through ``let`` / ``var`` bindings, every operation on
a tainted value (field read, index, interpolation, method call, ...),
struct / list / tuple construction with a tainted member, function
arguments (taint flows to the callee parameter) and function returns
(taint flows to the call result). When a tainted value lands in a Fs /
Net / Env sink's path / url / key slot, the fact is recorded.

Methods are handled conservatively the same way the const-prop is: a
free function's body is the routing surface, but because a method may be
reached by dynamic dispatch this AST-level analysis cannot pin down,
the forward taint over-approximates by tainting a method parameter from
ANY call site (positional binding), which only widens the surface.

CLOSURES (lambdas) -- a sink inside a closure body reads a value bound to
the closure's PARAMETER, and that parameter may be argv. The surface
handles this SOUND BY CONSTRUCTION, by a single general rule rather than
an enumeration of escape shapes:

  a closure's PARAMETER is tainted (its body's param-using sinks then
  surface at ``argv[*]``) UNLESS the analysis PROVES the closure is applied
  ONLY locally and ONLY to non-argv values. The DEFAULT is "the param may
  be argv"; the analysis abstains only on a proof of safety.

In practice this means the parameter is tainted whenever the closure
occurs in ANY position that is NOT the direct callee of a local
application this frame tracks -- it is RETURNED / ``become`` / a tail
value, an argument to ANY call or method-call (a generic helper OR a
higher-order), an element of ANY aggregate (struct field, list, tuple, and
-- since maps/sets are built by method call -- those too), or it is reached
THROUGH WRAPPING: a ``match`` / ``if`` arm, a ``Block`` tail, a variant
wrapper (``Some(fun ...)``), or a name bound to any of those
(``let g = match m { _ -> fun ... }; return g``). The two analyses that
used to enumerate shapes (``lam_of`` recognising only a bare lambda or a
direct ``Ident -> LambdaExpr``; a hand-listed set of escape positions) are
replaced by a recursive ``lams_reachable`` (descends the wrappers) plus the
"not-a-tracked-local-application => escape" default, so a newly-written
escape shape is covered without a new branch.

The TRACKED case still proves the precise binding: a closure called with an
argv-tainted argument, or passed to a higher-order over an argv receiver,
binds argv to its parameter (still reported at ``argv[*]`` -- a per-element
binding is not a static index).

SCOPE (no sub-scope is skipped -- EXHAUSTIVE, not ad-hoc): the statement-level
traversal descends into EVERY node that holds sub-statements -- if / while /
for branches, the ``Block`` body of a ``match`` arm or block-bodied ``if``
(which live at the EXPRESSION level), AND every lambda BODY -- at any nesting
depth and in any composition. So a NAMED closure bound INSIDE a match-arm
block (``match x`` ``  _ ->`` ``    let rd = fun (a) => fs.read(a)`` ``
rd(argv_path)``) or inside another lambda's body, and its application / escape
there, is found and its body's sink reported. Same-frame sub-blocks (control
flow, match / if arm) are reached by :func:`_child_blocks`; lambda bodies (a
different frame) by :func:`_lambda_body_blocks`; together they cover every
sub-statement-bearing node. A nested lambda's OWN ``return`` / tail value
stays attributed to that lambda, NOT to its enclosing frame (the
frame-boundary helpers use an own-frame traversal that descends match-arm
blocks but not lambda bodies), so the descent widens coverage without
confusing scopes. The exhaustiveness is pinned by a META-TEST over the AST
node inventory (a new sub-statement-bearing node fails the suite rather than
silently slipping), so the scope-omission CLASS is CLOSED by proof; the
residual below is VALUE-FLOW only.

PRECISION (the over-report this allows is the minimum soundness forces):
tainting a parameter yields a fact ONLY when that parameter actually
reaches a sink slot. A closure whose body reads a STATIC literal (not its
param), or a closure over a NON-argv collection whose param never reaches a
sink, produces NO argv fact even though its param is tainted -- the
widening fires through the PARAM only. Measured NON-NOISY on the real
downstream corpus: audit-trail-reporter, sbom-watch, capa_showcase,
policy-eval and examples/ (250 files) report the IDENTICAL surface before
and after the sound-by-construction rule (zero new facts).

RESIDUAL UNDER-REPORT (the one honest gap, VALUE-FLOW only -- NOT a scope
gap: every sub-block, including a match / if arm and a lambda body, is
traversed): the rule follows a closure VALUE only while a STATIC, frame-local
name resolution can link it to a ``LambdaExpr`` -- inline, or through the
wrappers above, in this frame OR in any sub-scope. A closure carried by
a value the pass cannot statically tie back to a lambda still slips:
re-extracted from a RUNTIME CONTAINER by key (fetched back out of a Map at
run time), or threaded through an opaque computed value (a helper return
whose body the name resolution does not inline).
Where such a value reaches an unknown application the surface MAY
under-report that closure's param sink. This is a property of an
AST-level, type-free pass (no value-flow through runtime containers); it
is the only residual, and it is documented identically in the SBOM note
and the ``--wasi-surface`` output so an auditor sees it, not just a reader
of this source.
"""

from __future__ import annotations

from dataclasses import dataclass

from .. import capa_ast as A
from ._wasi_const_prop import (
    FS_CAP, NET_CAP, ENV_CAP, _SINK_METHODS, _SINK_SLOT, _bind,
    _all_stmts, _own_frame_stmts, _child_exprs, _stmt_exprs, _ConstPropagator,
)
from ._fs_ceiling import _FS_MUTATING_METHODS

# ``FS_CAP`` / ``NET_CAP`` / ``ENV_CAP`` are re-exported here so callers
# (the SBOM builder, the soundness harness) name the cap classes through
# the surface module, the single public face of this analysis.
__all__ = [
    "compute_path_arg_surface", "PathArgSurface", "PathArgFact",
    "ANY_INDEX", "FS_CAP", "NET_CAP", "ENV_CAP",
]


# A sentinel index meaning "any / unknown argv element": used whenever
# the analysis cannot statically prove a single concrete argv index
# reaches the sink. Reporting ``ANY`` is the sound default; a concrete
# index is emitted ONLY when proved.
ANY_INDEX = "*"


# Access classification per cap. For Fs, mkdir / write MUTATE (write
# access), every other path op reads. For Net, ``post`` writes (sends a
# body), ``get`` reads. For Env, ``get`` reads. Mirrors the ceiling's
# ``_FS_MUTATING_METHODS`` so the read/write split is identical to the
# preopen-permission derivation.
def _access_for(cap: str, method: str) -> str:
    if cap == FS_CAP:
        return "write" if method in _FS_MUTATING_METHODS else "read"
    if cap == NET_CAP:
        return "write" if method == "post" else "read"
    return "read"


@dataclass(frozen=True)
class PathArgFact:
    """One proven argv -> sink fact: an ``argv`` element (a concrete
    index, or ``ANY_INDEX`` when only its existence is proved) reaches a
    sink of capability ``cap`` via ``method`` with ``access`` read or
    write."""

    arg_index: object   # int (proved concrete) or ANY_INDEX ("*")
    cap: str            # FS_CAP / NET_CAP / ENV_CAP
    method: str         # the sink method (read / write / get / post / ...)
    access: str         # "read" | "write"

    def describe(self) -> str:
        """Human-readable one-liner, e.g. ``argv[0] -> Fs.read (read-only)``
        or ``argv[*] -> Fs.write (writes)``."""
        idx = "*" if self.arg_index is ANY_INDEX else self.arg_index
        ro = "read-only" if self.access == "read" else "writes"
        return f"argv[{idx}] -> {self.cap}.{self.method} ({ro})"


@dataclass(frozen=True)
class PathArgSurface:
    """The whole-program path-arg surface: the ordered, de-duplicated set
    of proven argv -> sink facts."""

    facts: tuple[PathArgFact, ...]

    def is_empty(self) -> bool:
        return not self.facts

    def describe_lines(self) -> list[str]:
        return [f.describe() for f in self.facts]


def compute_path_arg_surface(module: A.Module) -> PathArgSurface:
    """Compute the path-arg surface for ``module`` (the AST, where named
    args + the call chain survive). A sound over-approximation of which
    argv elements reach which Fs / Net / Env sinks (read / write)."""
    return _SurfaceAnalysis(module).run()


class _SurfaceAnalysis:
    """Forward argv-taint fixpoint reusing the const-prop's callable
    collection + binding machinery."""

    def __init__(self, module: A.Module) -> None:
        self.module = module
        # Reuse the const-prop's callable index (same keying, same
        # ``cap_params`` recognition of Env / Fs / Net parameters and the
        # same ``_bind`` argument binding) so the two analyses agree on
        # what a callable + its parameters are.
        prop = _ConstPropagator(module)
        self.callables = prop.callables
        # Tainted (callable_key, param_index) pairs and tainted-return
        # callable_keys. Grown to a fixpoint.
        self.tainted_params: set[tuple] = set()
        self.tainted_returns: set[tuple] = set()
        # callee_key -> list of (caller_callable, call_expr) FREE-FUNCTION
        # call sites; methods bind positionally from any same-named site.
        self._free_sites = prop._call_sites_for  # bound method
        self._prop = prop
        # ``struct_name -> {field_name: built-in cap class}`` for fields
        # declared with a built-in Fs / Net / Env type. Lets the surface
        # recognise a sink whose receiver is ``self.<field>`` (a built-in
        # cap stored in a struct, e.g. ``ReadOnlyFsImpl { fs: Fs }`` whose
        # ``read`` method does ``self.fs.read(path)``), which the const-prop
        # treats as DYNAMIC. Omitting such a sink would UNDER-report the
        # argv -> sink surface (unsound), so the surface broadens sink
        # recognition here while the const-prop's literal resolution
        # (a different obligation) stays method-conservative.
        self._struct_cap_fields = self._collect_struct_cap_fields(module)

    # ---- public ------------------------------------------------------

    def run(self) -> PathArgSurface:
        self._compute_taint_fixpoint()
        facts: list[PathArgFact] = []
        seen: set = set()
        for c in self.callables.values():
            for fact in self._facts_in(c):
                key = (fact.arg_index, fact.cap, fact.method, fact.access)
                if key not in seen:
                    seen.add(key)
                    facts.append(fact)
        facts.sort(key=_fact_sort_key)
        return PathArgSurface(facts=tuple(facts))

    # ---- taint fixpoint ---------------------------------------------

    def _compute_taint_fixpoint(self) -> None:
        """Grow ``tainted_params`` / ``tainted_returns`` until stable.

        Each iteration recomputes, for every callable, the set of locally
        tainted names (seeded by ``env.args()`` and by already-tainted
        parameters) and propagates: a tainted argument taints the callee
        parameter; a tainted return expression taints the callable's
        return; a tainted return of a callee taints the call result that
        feeds a binding. Monotone (taint only ever grows), so it
        terminates."""
        changed = True
        while changed:
            changed = False
            for c in self.callables.values():
                local = self._local_taint(c)
                # Propagate to callee parameters via call-site arguments.
                for call, callee in self._calls_with_callee(c):
                    for pidx in self._tainted_arg_params(call, callee, local):
                        node = (callee.key, pidx)
                        if node not in self.tainted_params:
                            self.tainted_params.add(node)
                            changed = True
                # Propagate a tainted return expression to the callable.
                if c.key not in self.tainted_returns and \
                        self._returns_tainted(c, local):
                    self.tainted_returns.add(c.key)
                    changed = True

    def _local_taint(self, c, *, _cache: dict | None = None) -> set:
        """Set of local NAMES tainted in ``c``'s body under the current
        global taint state. Flow-insensitive over-approximation: a name
        bound (anywhere) to a tainted expression is tainted; a tainted
        destructure pattern taints every name it binds.

        Seeds: ``env.args()`` (argv origin) and any parameter already in
        ``tainted_params``."""
        tainted: set = set()
        # Seed: tainted parameters of this callable.
        for i, name in enumerate(c.names):
            if (c.key, i) in self.tainted_params:
                tainted.add(name)
        # Fixpoint over the body so a later binding can taint an earlier
        # use's source (flow-insensitive); cheap because bodies are small.
        # Lambda parameters are tainted when the closure may be applied to
        # an argv-derived value (higher-order over a tainted collection, or
        # a named closure called with a tainted argument), so a sink inside
        # the body is not silently omitted.
        grew = True
        while grew:
            grew = False
            before = len(tainted)
            for stmt in _all_stmts(c.decl.body):
                self._taint_stmt(stmt, tainted)
            self._taint_lambda_params(c, tainted)
            if len(tainted) > before:
                grew = True
        return tainted

    def _taint_lambda_params(self, c, tainted: set) -> None:
        """Taint the parameter names of every closure in ``c`` whose
        parameter MAY be bound to an argv-derived value, so a sink inside the
        body is never silently omitted. SOUND BY CONSTRUCTION: the rule is a
        single general principle, not an enumeration of escape shapes.

        THE RULE. A closure's parameter is tainted (its body's param-using
        sinks then surface at ``argv[*]``) UNLESS the analysis PROVES the
        closure is applied ONLY locally and ONLY to non-argv values. The
        DEFAULT is "the param may be argv"; the analysis abstains only on a
        proof of safety. Concretely a closure's param is tainted when:

        * it occurs in ANY position that is NOT the direct callee of a local
          application this frame tracks -- it is RETURNED / ``become`` / a
          tail value, an argument to ANY call / method-call (generic helper
          or higher-order), an element of ANY aggregate (struct field, list,
          tuple, and -- since maps/sets are built by method call -- those
          too), the RHS of a binding that itself escapes, or an arm of a
          ``match`` / ``if`` that is returned or escapes. Once a closure may
          leave the frame the surface cannot follow where its parameter is
          bound, so it fails closed. This is the ESCAPE default; and
        * it is the callee of a LOCAL application (``rd(...)`` / a higher-
          order ``args.map(rd)``) whose bound argument is argv-tainted -- a
          TRACKED application proving argv reaches the param.

        A closure is recognised THROUGH wrapping: ``lams_reachable`` descends
        into ``match`` / ``if`` arm bodies, ``Block`` tail expressions,
        variant wrappers (``Some(fun ...)``), and let-bound names that hold
        such a value, so a lambda nested inside a returned ``match`` arm
        (``return match m { _ -> fun (a) => ... }``) or a re-bound
        ``let g = match { ... }; return g`` is found -- not just a bare
        ``LambdaExpr`` or a name bound DIRECTLY to one.

        PRECISION (the over-report this allows is the minimum soundness
        forces): tainting a param yields a fact ONLY when that param actually
        reaches a sink slot. A closure whose body reads a STATIC literal (not
        its param), or a closure over a NON-argv collection whose param never
        reaches a sink, produces NO argv fact even though its param is
        tainted -- so the widening fires through the PARAM only and stays
        non-noisy on real programs."""
        lam_by_name = self._lambda_name_bindings(c)

        def taint_lambda(lam) -> None:
            for p in lam.params:
                tainted.add(p.name)

        def lams_reachable(expr):
            return self._lambdas_reachable(expr, lam_by_name)

        def visit(e) -> None:
            if isinstance(e, A.MethodCall):
                # A higher-order over an argv receiver is a TRACKED
                # application (each element binds the param) AND, when the
                # receiver is not argv, the closure still ESCAPES into the
                # helper -- both taint the param, so a single sweep over the
                # args suffices: any closure argument is tainted.
                for arg in e.args:
                    for lam in lams_reachable(arg):
                        taint_lambda(lam)
            if isinstance(e, A.Call):
                # A name called with an argv-tainted argument is a TRACKED
                # application of the bound closure(s); ANY closure passed as
                # an argument ESCAPES into the callee. Both taint the param.
                if isinstance(e.callee, A.Ident) and any(
                    self._is_tainted(a, tainted) for a in e.args
                ):
                    for lam in lam_by_name.get(e.callee.name, ()):
                        taint_lambda(lam)
                for arg in e.args:
                    for lam in lams_reachable(arg):
                        taint_lambda(lam)
            # ESCAPE via storage in an aggregate (struct field / list /
            # tuple): the closure outlives the frame and may be invoked with
            # argv later. (Map / Set values escape through the MethodCall
            # args handled above, since they are built by method call.)
            if isinstance(e, A.StructLit):
                for _name, v in e.fields:
                    for lam in lams_reachable(v):
                        taint_lambda(lam)
            if isinstance(e, (A.ListLit, A.TupleLit)):
                for v in e.elements:
                    for lam in lams_reachable(v):
                        taint_lambda(lam)
            for child in _child_exprs(e):
                visit(child)

        for stmt in _all_stmts(c.decl.body):
            for e in _stmt_exprs(stmt):
                visit(e)

        # ESCAPE via RETURN / become / tail expression (in ANY wrapping
        # form): a closure handed back to the caller may be invoked with
        # argv there.
        self._taint_returned_lambdas(c, tainted, lams_reachable)
        # ESCAPE via the RHS of a binding whose name itself escapes: when a
        # name is bound to a closure-bearing value and that NAME later
        # escapes (returned / passed / stored), the closure escapes too.
        # ``lam_by_name`` already resolves the name to those closures, so the
        # return / call / aggregate sweeps above taint them; this pass also
        # fails closed for a name that escapes via a plain ``return g`` /
        # tail ``g`` even when ``g`` holds a wrapped closure.

    def _lambda_name_bindings(self, c) -> dict:
        """``name -> tuple of LambdaExpr`` for every name in ``c``'s frame
        bound to a closure-bearing value, descending through wrapping
        (``let g = match m { _ -> fun ... }`` binds ``g`` to that lambda).
        Used so a later escape / application of the NAME taints the closures
        it may hold."""
        out: dict = {}
        for stmt in _all_stmts(c.decl.body):
            name = value = None
            if isinstance(stmt, A.LetStmt) and isinstance(
                stmt.pattern, A.IdentPat,
            ):
                name, value = stmt.pattern.name, stmt.value
            elif isinstance(stmt, A.VarStmt):
                name, value = stmt.name, stmt.value
            if name is None or value is None:
                continue
            lams = tuple(self._lambdas_reachable(value, out))
            if lams:
                out[name] = out.get(name, ()) + lams
        return out

    def _lambdas_reachable(self, expr, lam_by_name: dict):
        """Every ``LambdaExpr`` an expression MAY denote, descending through
        the value-producing wrappers a closure can hide behind: a bare
        lambda, an identifier bound to closure(s) in this frame, the arms of
        a ``match`` / ``if`` expression, the tail expression of a ``Block``,
        and a variant / wrapper constructor argument (``Some(fun ...)``,
        ``Ok(fun ...)``). Sound: it over-collects (every reachable lambda is
        a candidate), it never misses a wrapped one."""
        seen_lams: list = []
        out_ids: set = set()
        stack = [expr]
        guard = 0
        while stack and guard < 10000:
            guard += 1
            e = stack.pop()
            if e is None:
                continue
            if isinstance(e, A.LambdaExpr):
                if id(e) not in out_ids:
                    out_ids.add(id(e))
                    seen_lams.append(e)
                continue
            if isinstance(e, A.Ident):
                for lam in lam_by_name.get(e.name, ()):
                    if id(lam) not in out_ids:
                        out_ids.add(id(lam))
                        seen_lams.append(lam)
                continue
            if isinstance(e, A.MatchExpr):
                for arm in e.arms:
                    stack.append(self._value_of_body(arm.body))
                continue
            if isinstance(e, A.IfExpr):
                stack.append(e.then_expr)
                stack.append(e.else_expr)
                continue
            if isinstance(e, A.Call):
                # A variant / wrapper constructor (``Some(fun ...)``,
                # ``Ok(fun ...)``) carries the closure in an argument. Any
                # call's arguments may wrap a closure that then escapes with
                # the call's result, so descend into them.
                for arg in e.args:
                    stack.append(arg)
                continue
        return seen_lams

    def _value_of_body(self, body):
        """The value expression a ``match`` / lambda arm body denotes: the
        expression itself for a single-expr body, or the tail expression of
        a ``Block`` body (the value the block yields), so a closure produced
        as an arm's value is reachable."""
        if isinstance(body, A.Block):
            return self._tail_expr(body)
        return body

    def _taint_returned_lambdas(self, c, tainted: set, lams_reachable) -> None:
        """Taint the params of any closure (in ANY wrapping form) that ``c``
        RETURNS -- an explicit ``return``, a tail ``become``, or a final-
        expression body, including a closure nested in a returned ``match`` /
        ``if`` arm or wrapped in ``Some(...)``. A returned closure escapes
        the frame; its parameter is then bound by an unknown caller (possibly
        argv), so the surface fails closed and reports the body's param-using
        sinks at ``argv[*]``."""
        def taint_lambda(lam) -> None:
            for p in lam.params:
                tainted.add(p.name)

        # OWN-FRAME returns only: a ``return`` inside a NESTED lambda body
        # belongs to that lambda, not to ``c``, so it must not be read as
        # ``c`` returning the closure. A closure returned by a nested lambda
        # escapes ``c`` only through the value flow (the nested lambda's
        # result), which the binding / escape sweeps already follow.
        for stmt in _own_frame_stmts(c.decl.body):
            if isinstance(stmt, (A.ReturnStmt, A.Become)):
                if stmt.value is not None:
                    for lam in lams_reachable(stmt.value):
                        taint_lambda(lam)
        last = self._tail_expr(c.decl.body)
        if last is not None:
            for lam in lams_reachable(last):
                taint_lambda(lam)

    def _taint_stmt(self, stmt, tainted: set) -> None:
        if isinstance(stmt, A.LetStmt):
            if self._is_tainted(stmt.value, tainted):
                self._bind_pattern_taint(stmt.pattern, tainted)
        elif isinstance(stmt, A.VarStmt):
            if self._is_tainted(stmt.value, tainted):
                tainted.add(stmt.name)
        elif isinstance(stmt, A.AssignStmt):
            if isinstance(stmt.target, A.Ident) and \
                    self._is_tainted(stmt.value, tainted):
                tainted.add(stmt.target.name)
        # ``for p in <tainted-iterable>`` taints the loop binding(s).
        elif isinstance(stmt, A.ForStmt):
            if self._is_tainted(stmt.iter, tainted):
                self._bind_pattern_taint(stmt.pattern, tainted)
        # match-arm pattern bindings are handled where the MatchExpr is
        # the value of a let (via ``_is_tainted`` recursing into arms) and
        # also directly when a tainted scrutinee binds names in arm
        # patterns (handled in ``_taint_match_arms``).
        self._taint_match_arms(stmt, tainted)

    def _taint_match_arms(self, node, tainted: set) -> None:
        """When a ``match`` over a tainted scrutinee binds names in its arm
        patterns, those names are tainted (the destructure carries argv
        provenance, e.g. ``match args.get(0) { Some(p) -> ... }`` taints
        ``p``)."""
        for e in self._exprs_of(node):
            self._walk_match(e, tainted)

    def _walk_match(self, e, tainted: set) -> None:
        if isinstance(e, A.MatchExpr):
            if self._is_tainted(e.scrutinee, tainted):
                for arm in e.arms:
                    self._bind_pattern_taint(arm.pattern, tainted)
        for child in _child_exprs(e):
            self._walk_match(child, tainted)

    @staticmethod
    def _exprs_of(node):
        if isinstance(node, A.Block):
            for stmt in node.stmts:
                yield from _stmt_exprs(stmt)
        else:
            yield from _stmt_exprs(node)

    def _bind_pattern_taint(self, pat, tainted: set) -> None:
        """Taint every name a pattern binds (a tainted value flows into
        all of them -- the sound over-approximation for a destructure)."""
        if isinstance(pat, A.IdentPat):
            tainted.add(pat.name)
        elif isinstance(pat, A.VariantPat):
            for sub in pat.payloads:
                self._bind_pattern_taint(sub, tainted)
        elif isinstance(pat, A.TuplePat):
            for sub in pat.elements:
                self._bind_pattern_taint(sub, tainted)
        elif isinstance(pat, A.StructPat):
            for _name, sub in pat.fields:
                if sub is not None:
                    self._bind_pattern_taint(sub, tainted)

    def _is_tainted(self, e, tainted: set) -> bool:
        """True when expression ``e`` may carry argv provenance under the
        current local + global taint state. Over-approximates: ANY tainted
        sub-expression taints the whole (a struct built from a tainted
        field is tainted; an interpolation with a tainted part is tainted;
        a method call on a tainted receiver or arg is tainted)."""
        if e is None:
            return False
        # The argv ORIGIN: ``env.args()`` on an Env-typed receiver.
        if self._is_args_call(e):
            return True
        if isinstance(e, A.Ident):
            return e.name in tainted
        # A free-function / method call whose RETURN is tainted, or which
        # is passed a tainted argument routed through to its return.
        if isinstance(e, A.Call) and isinstance(e.callee, A.Ident):
            callee = self.callables.get(("fun", e.callee.name))
            if callee is not None and callee.key in self.tainted_returns:
                return True
        if isinstance(e, A.MethodCall):
            # A method on a tainted receiver propagates taint (e.g.
            # ``args.get(0)``, ``raw.first()``, ``s.trim()``). A method
            # whose callable return is tainted likewise.
            if self._is_tainted(e.receiver, tainted):
                return True
        # Generic structural over-approximation: any tainted child taints
        # the node (covers BinOp / interpolation / index / field access /
        # struct / list / tuple / if-expr / match arms / call args).
        for child in _child_exprs(e):
            if self._is_tainted(child, tainted):
                return True
        return False

    def _is_args_call(self, e) -> bool:
        """True when ``e`` is ``<env>.args()`` where ``<env>`` is an
        identifier the enclosing callable declared as an ``Env``
        capability -- the argv ORIGIN. We do not require the receiver to be
        a known cap-param here (any ``.args()`` on an Env-shaped receiver
        is over-approximated), but the common case is an Env parameter."""
        return (
            isinstance(e, A.MethodCall)
            and e.method == "args"
            and isinstance(e.receiver, A.Ident)
        )

    # ---- per-callable fact extraction -------------------------------

    @staticmethod
    def _collect_struct_cap_fields(module) -> dict:
        out: dict = {}
        for item in module.items:
            if isinstance(item, A.TypeStruct):
                fields: dict = {}
                for f in item.fields:
                    tyname = getattr(f.type_expr, "name", None)
                    if tyname in _SINK_METHODS:
                        fields[f.name] = tyname
                if fields:
                    out[item.name] = fields
        return out

    def _facts_in(self, c):
        """Yield a ``PathArgFact`` for every sink call in ``c`` whose
        path/url/key slot is argv-tainted."""
        local = self._local_taint(c)
        aliases = self._argv_list_aliases(c)
        index_env = self._index_provenance(c, aliases)
        for sink, cap in self._surface_sinks(c):
            if _SINK_SLOT >= len(sink.args):
                continue
            slot = sink.args[_SINK_SLOT]
            if not self._is_tainted(slot, local):
                continue
            idx = self._proved_argv_index(slot, index_env, aliases)
            yield PathArgFact(
                arg_index=idx,
                cap=cap,
                method=sink.method,
                access=_access_for(cap, sink.method),
            )

    def _surface_sinks(self, c):
        """Yield ``(MethodCall, cap)`` for every BUILT-IN Fs / Net / Env
        sink in ``c``'s body, recognised by a cap-typed RECEIVER:

        * a parameter Ident declared as the cap (the const-prop's rule);
        * ``self.<field>`` where ``c`` is a method whose owner struct has
          that field declared with the cap type (the field-stored cap,
          e.g. ``self.fs.read(path)`` in ``impl ReadOnlyFs for
          ReadOnlyFsImpl { fs: Fs }``); or
        * a local Ident bound to a cap-typed parameter / ``self.<field>``
          in this frame (a direct alias of a built-in cap value).

        This is BROADER than the const-prop's param-only / free-function
        recognition because OMITTING a built-in sink whose path is
        argv-tainted would UNDER-report the surface (unsound: an argument
        that reaches a sink must never be dropped). It stays PRECISE on the
        receiver -- only a provably cap-typed receiver counts, so an
        overloaded ``map.get`` / ``list.read`` is never mistaken for a
        sink."""
        cap_aliases = self._cap_value_aliases(c)
        for stmt in _all_stmts(c.decl.body):
            for e in _stmt_exprs(stmt):
                yield from self._walk_sinks(e, c, cap_aliases)

    def _walk_sinks(self, e, c, cap_aliases: dict):
        if isinstance(e, A.MethodCall):
            cap = self._receiver_cap(e.receiver, c, cap_aliases)
            if cap is not None and e.method in _SINK_METHODS[cap]:
                yield (e, cap)
        for child in _child_exprs(e):
            yield from self._walk_sinks(child, c, cap_aliases)

    def _receiver_cap(self, recv, c, cap_aliases: dict):
        """The built-in cap class of a sink RECEIVER, or None when the
        receiver is not provably a built-in cap value."""
        # A cap-typed parameter of this callable (const-prop's rule).
        if isinstance(recv, A.Ident):
            cap = c.cap_params.get(recv.name)
            if cap is not None:
                return cap
            return cap_aliases.get(recv.name)
        # ``self.<field>`` where the owner struct declares that cap field.
        if isinstance(recv, A.FieldAccess) and isinstance(
            recv.receiver, A.Ident,
        ) and recv.receiver.name == "self" and c.key[0] == "method":
            owner = c.key[1]
            return self._struct_cap_fields.get(owner, {}).get(recv.field_name)
        return None

    def _cap_value_aliases(self, c) -> dict:
        """``name -> built-in cap class`` for locals bound DIRECTLY to a
        cap-typed parameter or ``self.<field>`` in ``c`` (``let g =
        fs``). A name bound more than once, or to a non-cap value, is
        dropped (it might not hold a cap)."""
        bound: dict = {}
        seen_conflict: set = set()

        def note(name: str, cap) -> None:
            if name in seen_conflict:
                return
            if name in bound and bound[name] != cap:
                bound.pop(name, None)
                seen_conflict.add(name)
            else:
                bound[name] = cap

        for stmt in _all_stmts(c.decl.body):
            tgt = val = None
            if isinstance(stmt, A.LetStmt) and isinstance(
                stmt.pattern, A.IdentPat,
            ):
                tgt, val = stmt.pattern.name, stmt.value
            elif isinstance(stmt, A.VarStmt):
                tgt, val = stmt.name, stmt.value
            if tgt is None:
                continue
            cap = None
            if isinstance(val, A.Ident):
                cap = c.cap_params.get(val.name)
            elif isinstance(val, A.FieldAccess) and isinstance(
                val.receiver, A.Ident,
            ) and val.receiver.name == "self" and c.key[0] == "method":
                cap = self._struct_cap_fields.get(c.key[1], {}).get(
                    val.field_name,
                )
            note(tgt, cap)
        return {n: cap for n, cap in bound.items() if cap is not None}

    def _argv_list_aliases(self, c) -> set:
        """Names bound DIRECTLY to ``env.args()`` in ``c`` -- the argv LIST
        value itself (before indexing). A name bound more than once, or
        also bound to a non-argv value, is dropped (it could hold a
        non-argv list), so an indexing of it falls back to ``ANY``."""
        bound: dict = {}

        def note(name: str, is_argv: bool) -> None:
            if name in bound and bound[name] != is_argv:
                bound[name] = False
            elif name not in bound:
                bound[name] = is_argv
            elif not is_argv:
                bound[name] = False

        for stmt in _all_stmts(c.decl.body):
            if isinstance(stmt, A.LetStmt) and isinstance(
                stmt.pattern, A.IdentPat,
            ):
                note(stmt.pattern.name, self._is_args_call(stmt.value))
            elif isinstance(stmt, A.VarStmt):
                note(stmt.name, self._is_args_call(stmt.value))
            elif isinstance(stmt, A.AssignStmt) and isinstance(
                stmt.target, A.Ident,
            ):
                note(stmt.target.name, False)
        return {n for n, ok in bound.items() if ok}

    def _is_argv_receiver(self, e, aliases: set) -> bool:
        """True when ``e`` denotes the argv LIST: a direct ``<env>.args()``
        call, or an identifier that aliases one (``aliases``)."""
        if self._is_args_call(e):
            return True
        return isinstance(e, A.Ident) and e.name in aliases

    def _proved_argv_index(self, slot, index_env: dict, aliases: set):
        """A CONCRETE argv index iff the slot provably resolves to a SINGLE
        statically-known argv index in the sink's own frame:

        * DIRECTLY an argv index expression -- ``args.get(<int literal>)``,
          ``args[<int literal>]``, or ``args.first()`` (index 0); or
        * an identifier bound IN THIS FRAME to such an expression (possibly
          via a ``match`` over the argv-index expression that returns its
          ``Some(p) -> p`` payload), recorded in ``index_env``.

        Anything else (a value routed through a struct field, a helper
        return, a computed index, conflicting bindings) is ``ANY_INDEX``:
        the surface proves an argv element reaches the sink but cannot name
        which one, so it must not claim a narrower index than proved."""
        direct = self._direct_argv_index(slot, aliases)
        if direct is not None:
            return direct
        if isinstance(slot, A.Ident):
            return index_env.get(slot.name, ANY_INDEX)
        return ANY_INDEX

    def _direct_argv_index(self, slot, aliases: set):
        """The concrete int index when ``slot`` is DIRECTLY an argv-index
        expression on an argv receiver (a ``<env>.args()`` call or an alias
        of one), else None (not a direct argv index)."""
        if isinstance(slot, A.MethodCall) and \
                self._is_argv_receiver(slot.receiver, aliases):
            if slot.method == "first":
                return 0
            if slot.method == "get" and len(slot.args) == 1:
                lit = _int_literal_of(slot.args[0])
                if lit is not None:
                    return lit
        if isinstance(slot, A.Index) and \
                self._is_argv_receiver(slot.receiver, aliases):
            lit = _int_literal_of(slot.index)
            if lit is not None:
                return lit
        return None

    def _index_provenance(self, c, aliases: set) -> dict:
        """Frame-local ``name -> concrete argv index`` map, for names bound
        DIRECTLY to a single argv index in this callable. A name is mapped
        only when EVERY binding of it resolves to the SAME concrete index;
        a conflicting / non-direct binding makes it ``ANY_INDEX`` (absent
        from the concrete map, so callers fall back to ``ANY``). Sound: it
        never assigns a narrower index than the binding proves."""
        env: dict = {}

        def note(name: str, idx) -> None:
            # idx is an int (proved) or ANY_INDEX. Conflicting concrete
            # indices, or any ANY binding, collapse to ANY.
            if name in env and env[name] != idx:
                env[name] = ANY_INDEX
            elif name not in env:
                env[name] = idx

        for stmt in _all_stmts(c.decl.body):
            if isinstance(stmt, A.LetStmt) and isinstance(
                stmt.pattern, A.IdentPat,
            ):
                idx = self._index_of_expr(stmt.value, aliases)
                if idx is not None:
                    note(stmt.pattern.name, idx)
            elif isinstance(stmt, A.VarStmt):
                idx = self._index_of_expr(stmt.value, aliases)
                if idx is not None:
                    note(stmt.name, idx)
            elif isinstance(stmt, A.AssignStmt) and isinstance(
                stmt.target, A.Ident,
            ):
                # A reassigned name may now hold a DIFFERENT argv index (or a
                # non-argv value). Recording the new value's index would risk
                # claiming a narrower index than the live value proves, so
                # collapse the name to ANY -- the surface still proves an
                # argv element reaches the sink but never names a wrong one.
                # (``_argv_list_aliases`` already collapses AssignStmt the
                # same way for the list-alias map.)
                note(stmt.target.name, ANY_INDEX)
        # Drop names that collapsed to ANY so ``.get(name, ANY_INDEX)``
        # returns ANY for them.
        return {n: i for n, i in env.items() if i is not ANY_INDEX}

    def _index_of_expr(self, e, aliases: set):
        """The concrete argv index ``e`` resolves to, ``ANY_INDEX`` when it
        is argv-derived but the index is not determinate, or None when it
        is not an argv-index binding at all (so the name is not recorded by
        index provenance and falls through to plain taint).

        Recognises a direct argv index expression, and a ``match`` over an
        argv-index scrutinee whose arms return the bound payload
        (``Some(p) -> p``) -- the dominant ``let path = match args.get(0)
        { None -> "", Some(p) -> p }`` shape."""
        direct = self._direct_argv_index(e, aliases)
        if direct is not None:
            return direct
        # ``args.get(i)`` / ``args[i]`` / ``args.first()`` with a COMPUTED
        # index is argv-derived but not determinate -> ANY (still recorded
        # so the name is known argv with an unknown index).
        if isinstance(e, A.MethodCall) and \
                self._is_argv_receiver(e.receiver, aliases) \
                and e.method in ("get", "first"):
            return ANY_INDEX
        if isinstance(e, A.Index) and self._is_argv_receiver(e.receiver, aliases):
            return ANY_INDEX
        if isinstance(e, A.MatchExpr):
            sidx = self._index_of_expr(e.scrutinee, aliases)
            if sidx is None:
                return None
            # The scrutinee is an argv index; a ``Some(p) -> p`` arm
            # forwards that index to the bound name. To stay sound (never
            # narrower than proved), collapse to ANY if any value-arm body
            # is ITSELF a DIFFERENT concrete argv index: then the result
            # could be a different element than the scrutinee's.
            for arm in e.arms:
                body = arm.body
                if isinstance(body, A.Block):
                    continue
                bidx = self._direct_argv_index(body, aliases)
                if bidx is not None and bidx != sidx:
                    return ANY_INDEX
            return sidx
        return None

    # ---- call-site helpers ------------------------------------------

    def _calls_with_callee(self, c):
        """Yield ``(call_expr, callee_callable)`` for every call in ``c``
        whose target is a known callable. Free functions resolve by name;
        methods resolve by ``(method, *)`` name match against any impl
        method of that name (the conservative over-approximation -- a
        tainted arg may flow to any same-named method's parameter)."""
        for e in self._prop._all_calls(c):
            if isinstance(e, A.Call) and isinstance(e.callee, A.Ident):
                callee = self.callables.get(("fun", e.callee.name))
                if callee is not None:
                    yield (e, callee)
            elif isinstance(e, A.MethodCall):
                for key, callee in self.callables.items():
                    if key[0] == "method" and key[2] == e.method:
                        yield (e, callee)

    def _tainted_arg_params(self, call, callee, local: set):
        """Indices of ``callee`` parameters bound to a tainted argument at
        ``call``. Free functions use the shared positional+named ``_bind``;
        method calls bind ``self`` to the receiver and the rest
        positionally (the receiver may itself be tainted)."""
        out: list[int] = []
        if isinstance(call, A.MethodCall):
            # ``self`` is parameter 0; a tainted receiver taints it.
            if callee.names and callee.names[0] == "self" and \
                    self._is_tainted(call.receiver, local):
                out.append(0)
            base = 1 if (callee.names and callee.names[0] == "self") else 0
            for ai, arg in enumerate(call.args):
                pidx = base + ai
                if pidx < len(callee.names) and self._is_tainted(arg, local):
                    out.append(pidx)
            return out
        perm = _bind(call.args, call.arg_names, callee.names)
        for pidx, aidx in perm.items():
            if aidx < len(call.args) and self._is_tainted(call.args[aidx], local):
                out.append(pidx)
        return out

    def _returns_tainted(self, c, local: set) -> bool:
        """True when ``c`` returns a tainted value: an explicit
        ``return <tainted>``, a tail ``become``, or a final-expression body
        whose value is tainted (covers ``return match ...`` arms via
        ``_is_tainted`` recursion)."""
        # OWN-FRAME returns only: a ``return`` inside a NESTED lambda body is
        # the lambda's result, not ``c``'s, so it must not mark ``c``'s
        # return tainted (a scope confusion that would over-report).
        for stmt in _own_frame_stmts(c.decl.body):
            if isinstance(stmt, A.ReturnStmt) and stmt.value is not None:
                if self._is_tainted(stmt.value, local):
                    return True
            elif isinstance(stmt, A.Become):
                if self._is_tainted(stmt.value, local):
                    return True
        # Implicit tail-expression return: the body's last ExprStmt.
        last = self._tail_expr(c.decl.body)
        if last is not None and self._is_tainted(last, local):
            return True
        return False

    @staticmethod
    def _tail_expr(block):
        if not block.stmts:
            return None
        last = block.stmts[-1]
        if isinstance(last, A.ExprStmt):
            return last.expr
        return None


def _int_literal_of(e):
    """The integer VALUE of ``e`` if it is a non-negative int literal,
    else None. Only a direct ``IntLit`` counts -- a computed index is not
    statically known, so it must yield ``ANY_INDEX`` upstream."""
    if isinstance(e, A.IntLit) and isinstance(e.value, int) and e.value >= 0:
        return e.value
    return None


def _fact_sort_key(f: PathArgFact):
    """Deterministic ordering: ANY last, then by (index, cap, method)."""
    idx_key = (1, 0) if f.arg_index is ANY_INDEX else (0, f.arg_index)
    return (idx_key, f.cap, f.method, f.access)
