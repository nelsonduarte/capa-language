"""Inter-procedural constant propagation for the ``--wasi`` static
authority ceilings (Fs preopens / Net hosts / Env keys).

The three ceilings (``_fs_ceiling`` / ``_net_ceiling`` / ``_env_ceiling``)
are *literal-at-sink-slot* analyses: a path / url / key passed to an
``Fs`` / ``Net`` / ``Env`` sink counts only when the argument in the
sink's path/url/key slot is a string LITERAL at that exact call site
(``arg.kind == "lit_str"`` in the CIR). Idiomatic code that routes the
literal through a helper -- ``read_json(fs, path)`` doing ``fs.read(path)``
with ``path`` a PARAMETER, the literal ``"data.json"`` named several
frames away in ``main`` -- is therefore treated as dynamic and
fail-closed (Fs / Net reject at compile time, Env degrades to
``inherit_env``).

This module closes that gap by propagating the literal along the call
chain to the sink, so the ceiling materialises the correct preopens /
hosts / keys automatically while preserving the *machine-verifiable
by construction* property (no operator ``--preopen`` grant needed).

SOUNDNESS -- the analysis is a SECURITY FRONTIER and is FAIL-CLOSED,
NEVER FAIL-OPEN. It MAY refuse (be conservative) but it MUST NOT
materialise a preopen / host / key for a literal that does not actually
reach the sink, and MUST NOT report a sink as resolvable (closed) when a
genuinely COMPUTED value can reach it. Any uncertainty resolves to
DYNAMIC -> fail-closed. An over-grant (an extra preopen / host / key)
silently WIDENS authority, which is worse than a refusal.

REACHABILITY-BLIND BY DESIGN -- the analysis does NO dead-code pruning
and NO reachability filtering. A literal used as a path / url / key in a
statically DEAD block (``if false { fs.read("dead.json") }``) or in a
function that is NEVER called still contributes its preopen / host / key
to the ceiling. This is DELIBERATE and SOUND: it is a conservative
over-approximation (fail-closed -- the ceiling never materialises a
literal that is ABSENT from a sink slot in the program text, but it does
not try to prove a present-in-text literal unreachable). The property is
identical to the pre-existing direct-literal ceiling and to the
SBOM / manifest, both of which scan the whole program rather than only
its reachable subset; const-prop just extends the same whole-program
literal accounting across the call chain. An auditor should therefore NOT
expect dead-code pruning here: a literal that appears at a sink slot
anywhere in the source is in scope for the ceiling, whether or not that
code can run. (Over-approximating the ceiling can only WIDEN the declared
authority surface, never under-declare it, so it stays fail-closed.)

The analysis runs on the AST (``Module.items``), where named arguments
survive (the CIR loses argument names) and the same argument-binding
machinery the IFC cross-function summaries use
(:mod:`capa.analyzer._ifc_summary`) applies. The result is consumed by
the three ceilings, which run on the CIR.

BACKWARD LITERAL RESOLUTION (``reaching_literals``, a walk over the call
graph with an OBLIGATORY cycle guard): for each sink call site the
path/url/key SLOT argument is resolved backwards. A literal at the slot
(or a local / module ``const`` that const-folds to one in the sink's own
frame -- the LOCAL fold) contributes that literal directly; a PARAMETER
at the slot recurses to every call site that binds it; a genuinely
COMPUTED slot value (interpolation with substitution, concatenation, a
function result, a field read, a collection, ...) is DYNAMIC. A single
dynamic reaching path makes the whole resolution DYNAMIC (fail-closed).
The union over every reaching path is the resolved literal set. The walk
is NOT a monotone fixpoint, so a ``seen`` guard on ``(callable,
param_idx)`` is mandatory to terminate on self / mutual recursion.

METHODS are conservatively DYNAMIC: an impl method is reached by
dynamic-dispatch / receiver-type-unknown call sites this AST-level
analysis cannot pin down, so resolving a method PARAMETER could pick an
argument from an unrelated same-named method (an over-grant). The safe
default for any method-parameter resolution is DYNAMIC; the idiomatic
helper routing the layer targets is FREE functions.

Two public entry points:

* :func:`resolve_sink_literals` -- per sink capability class, the union
  of reaching literals and whether any reaching path is dynamic. Consumed
  by the three ceilings.

* :func:`substitute_resolved_sink_literals` -- rewrites the AST so a sink
  whose slot resolves to EXACTLY ONE literal is given that literal at the
  slot, so the existing literal-at-slot codegen + ceiling machinery
  handles helper-routed single-literal sinks unchanged. Run on the
  Wasm-lowering AST only, after the analyzer / SBOM have seen the original
  source.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .. import capa_ast as A


# Sink capability classes and, per class, the methods whose FIRST
# argument is the path / url / key that defines the ceiling. These
# mirror the per-ceiling method sets exactly (``_fs_ceiling`` /
# ``_net_ceiling`` / ``_env_ceiling``); the const-prop only changes
# WHICH literals reach those slots, never which slots are sinks.
FS_CAP = "Fs"
NET_CAP = "Net"
ENV_CAP = "Env"

_FS_PATH_METHODS = frozenset({
    "exists", "is_dir", "mkdir", "read", "write", "list_dir",
})
_NET_REQUEST_METHODS = frozenset({"get", "post"})
_ENV_GET_METHODS = frozenset({"get"})

# cap -> the methods whose arg[0] is the ceiling-defining slot.
_SINK_METHODS: dict[str, frozenset[str]] = {
    FS_CAP: _FS_PATH_METHODS,
    NET_CAP: _NET_REQUEST_METHODS,
    ENV_CAP: _ENV_GET_METHODS,
}

# The slot index of the path / url / key in each sink method's argument
# list. It is arg[0] for every sink op we model (``write`` is
# ``(path, content)``, ``post`` is ``(url, body)``; the ceiling-defining
# argument is the first in both).
_SINK_SLOT = 0


# A DYNAMIC reaching set: at least one reaching path is a genuinely
# computed value, so the sink cannot be statically resolved and the
# ceiling for it must fail closed. Distinct from an empty literal set
# (a sink with no reaching literal at all, e.g. a sink never called).
class _Dynamic:
    __slots__ = ()

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return "DYNAMIC"


DYNAMIC = _Dynamic()


@dataclass(frozen=True)
class SinkResolution:
    """The resolved reaching-literal information for one sink capability
    class across the whole program.

    ``literals`` is the union of every string literal that can reach a
    sink of this class along SOME call path (a sound under-set: never a
    superset of the true reaching literals). ``dynamic`` is True when at
    least one reaching path is a genuinely computed value, so the ceiling
    must fail closed for this class regardless of ``literals``.
    """

    literals: frozenset[str]
    dynamic: bool


@dataclass
class _Callable:
    """A user-defined callable in the AST, keyed like the IFC summaries:
    ``("fun", name)`` or ``("method", type_name, method)``. ``names`` is
    the canonical parameter order (``self`` at index 0 for a method),
    matching the IFC binding logic so positional / named arguments line
    up identically."""

    key: tuple
    names: list[str]
    decl: A.FunDecl
    # param name -> declared capability type name (Fs / Net / Env), for
    # the param-typed sink receiver recognition. Only capability params
    # are recorded; a non-capability param maps to nothing.
    cap_params: dict = field(default_factory=dict)


def resolve_sink_literals(module: A.Module) -> dict[str, SinkResolution]:
    """Resolve, per sink capability class (``Fs`` / ``Net`` / ``Env``),
    the set of string literals that reach any sink of that class and
    whether any reaching path is dynamic.

    For every sink call site, walks the path/url/key slot BACKWARDS over
    the call graph -- folding a local ``let`` / ``const`` to a literal
    first -- accumulating literals and noting any dynamic reaching path.
    Sound and fail-closed throughout: any shape it cannot prove literal
    contributes ``dynamic = True``.
    """
    return _ConstPropagator(module).run()


def substitute_resolved_sink_literals(
    module: A.Module, types: dict | None = None,
) -> int:
    """Rewrite the AST IN PLACE so every Fs / Net / Env sink whose
    path/url/key slot is a PARAMETER (or a non-folding local) that the
    const-prop resolves to EXACTLY ONE reaching literal is given that
    literal directly at the slot. Returns the number of slots rewritten.

    This is the bridge between the inter-procedural analysis (which runs
    on the AST, where the call chain and named args survive) and the Wasm
    codegen + ceilings (which resolve a literal AT the sink slot): after
    substitution a helper-routed single-literal sink looks exactly like a
    directly-literal sink, so the existing literal-at-slot machinery
    materialises the right preopen / host / key and emits the right call
    with NO new codegen and NO runtime path resolver.

    SOUNDNESS: a slot is rewritten ONLY when the analysis proves the slot
    value is that one literal along EVERY reaching path (the per-call
    resolution is a non-empty set of exactly one literal). A multi-literal
    union (the runtime value is one of several) is NOT substituted -- it
    stays a dynamic slot and the ceiling fails closed -- because picking
    any single literal would be unsound for the other paths. A DYNAMIC or
    empty resolution is never substituted. So this only ever turns a
    provably-constant slot into its constant; it never invents authority.

    ``types`` (the analyzer's ``id(node) -> type`` map) is updated in
    place for each new ``StringLit`` so the lowerer / emitter see the
    substituted slot as a ``String`` (the slot was already String-typed;
    the literal carries the same type). Passing it is required when the
    same ``types`` map drives lowering after substitution.

    Run on the Wasm-lowering AST only (in ``compile_wat``), AFTER the
    manifest / SBOM have been built from the original source, so the
    developer-facing capability surface is unchanged -- only the emitted
    code is tightened.
    """
    prop = _ConstPropagator(module)
    prop.run()
    rewrites = 0
    for _sid, (sink, res) in prop.per_sink.items():
        if res is DYNAMIC or len(res) != 1:
            continue
        if _SINK_SLOT >= len(sink.args):
            continue
        slot = sink.args[_SINK_SLOT]
        if _string_literal_of(slot) is not None:
            continue
        (lit,) = tuple(res)
        new_lit = A.StringLit(pos=slot.pos, value=lit)
        if types is not None:
            # The slot was String-typed; carry the type to the new node so
            # lowering type resolution (keyed by node identity) still sees
            # a String at the sink argument.
            old_ty = types.get(id(slot))
            if old_ty is not None:
                types[id(new_lit)] = old_ty
        sink.args[_SINK_SLOT] = new_lit
        rewrites += 1
    return rewrites


class _ConstPropagator:
    def __init__(self, module: A.Module) -> None:
        self.module = module
        # callable_key -> _Callable.
        self.callables: dict[tuple, _Callable] = {}
        # name -> const literal value, module-level (const fold base).
        self.const_literals: dict[str, str] = {}
        # id(sink MethodCall) -> (sink, frozenset literals | DYNAMIC): the
        # per-call resolution, for single-literal const substitution.
        self.per_sink: dict[int, tuple] = {}
        self._collect_consts()
        self._collect_callables()

    # ---- collection -------------------------------------------------

    def _collect_consts(self) -> None:
        """Record module-level ``const NAME = "lit"`` declarations that
        const-fold trivially to a string literal. A const whose body is
        not a trivial literal is recorded as DYNAMIC-foldable (absent
        from the map), so a sink that reads it stays dynamic."""
        for item in self.module.items:
            if isinstance(item, A.ConstDecl):
                lit = _string_literal_of(item.value)
                if lit is not None:
                    self.const_literals[item.name] = lit

    def _collect_callables(self) -> None:
        for item in self.module.items:
            if isinstance(item, A.FunDecl):
                key: tuple[str, ...] = ("fun", item.name)
                self.callables[key] = _Callable(
                    key=key,
                    names=[p.name for p in item.params],
                    decl=item,
                    cap_params=self._cap_params(item.params),
                )
            elif isinstance(item, A.ImplBlock):
                for method in item.methods:
                    key = ("method", item.type_name, method.name)
                    if key in self.callables:
                        continue
                    self.callables[key] = _Callable(
                        key=key,
                        names=[p.name for p in method.params],
                        decl=method,
                            cap_params=self._cap_params(
                            method.params, owner=item.type_name,
                        ),
                    )

    @staticmethod
    def _cap_params(params, owner: str | None = None) -> dict:
        """``{param name: cap class name}`` for parameters declared with a
        sink-capability type (``Fs`` / ``Net`` / ``Env``). ``self`` (no
        ``type_expr``) maps to ``owner`` only if ``owner`` is itself a
        sink capability -- which never happens for user impls, so a method
        ``self`` is never a sink receiver here; the receiver of an Fs / Net
        / Env op is always an explicit capability-typed parameter."""
        out: dict = {}
        for p in params:
            te = getattr(p, "type_expr", None)
            if p.name == "self" and te is None and owner is not None:
                tyname: str | None = owner
            else:
                tyname = getattr(te, "name", None) if te is not None else None
            if tyname in _SINK_METHODS:
                out[p.name] = tyname
        return out

    def run(self) -> dict[str, SinkResolution]:
        return self._resolve_all_sinks()

    # ---- PHASE B: backward literal resolution -----------------------

    def _resolve_all_sinks(self) -> dict[str, SinkResolution]:
        """For every sink call site of every cap, resolve the slot
        argument to its reaching literals (Phase B) and union per cap.
        A dynamic reaching path sets the cap's ``dynamic`` flag."""
        out: dict[str, SinkResolution] = {}
        for cap in _SINK_METHODS:
            literals: set[str] = set()
            dynamic = False
            for c in self.callables.values():
                lits, dyn = self._scan_body_sinks(c, cap)
                literals |= lits
                dynamic = dynamic or dyn
            out[cap] = SinkResolution(
                literals=frozenset(literals), dynamic=dynamic,
            )
        return out

    def _scan_body_sinks(self, c: _Callable, cap: str) -> tuple[set, bool]:
        """Find every ``cap`` sink call in ``c``'s body and resolve its
        slot argument. Returns (literals, any_dynamic). A LET/CONST that
        folds to a literal in this frame is used directly; a parameter is
        resolved backwards across call sites; anything else is dynamic.

        A local-fold environment (``name -> literal | DYNAMIC``) is built
        as the body is walked, so a ``let p = "x"`` before the sink is
        folded, while a ``let p = compute()`` marks ``p`` dynamic.

        Side effect: records each sink call's PER-CALL resolution in
        ``self.per_sink`` (keyed by the sink ``MethodCall`` node identity),
        so a single-literal sink can be const-substituted at lowering."""
        literals: set = set()
        dynamic = False
        local_lits = self._local_literal_env(c)
        for sink in self._sink_calls(c, cap):
            arg = sink.args[_SINK_SLOT] if len(sink.args) > _SINK_SLOT \
                else None
            res = self._resolve_arg(arg, c, local_lits)
            self.per_sink[id(sink)] = (sink, res)
            if res is DYNAMIC:
                dynamic = True
            else:
                literals |= res
        return literals, dynamic

    def _local_literal_env(self, c: _Callable) -> dict:
        """``name -> str literal`` for every ``let`` / ``var`` in the body
        whose initialiser const-folds to a single string literal in this
        frame (including a module const reference). A name bound more than
        once, or to a non-literal, is recorded as DYNAMIC so a later sink
        read of it stays dynamic. This is the (a) local fold; it is a
        flow-INSENSITIVE over-approximation made SAFE by marking any
        non-trivial binding dynamic (never inventing a literal)."""
        env: dict = {}

        def note(name: str, value) -> None:
            if name in env and env[name] != value:
                env[name] = DYNAMIC
            else:
                env[name] = value

        def walk(block: A.Block) -> None:
            for stmt in block.stmts:
                if isinstance(stmt, A.LetStmt) and isinstance(
                    stmt.pattern, A.IdentPat,
                ):
                    note(stmt.pattern.name, self._fold_local(stmt.value, env))
                elif isinstance(stmt, A.VarStmt):
                    note(stmt.name, self._fold_local(stmt.value, env))
                elif isinstance(stmt, A.AssignStmt) and isinstance(
                    stmt.target, A.Ident,
                ):
                    # A reassignment can only widen uncertainty.
                    env[stmt.target.name] = DYNAMIC
                # Recurse into nested blocks so a sink inside an ``if`` /
                # ``for`` still sees outer lets; bindings made inside a
                # branch are conservatively visible (flow-insensitive),
                # which can only ADD a literal that genuinely appears in
                # the frame, never invent one for a different name.
                for sub in _child_blocks(stmt):
                    walk(sub)

        walk(c.decl.body)
        return env

    def _fold_local(self, e, env: dict):
        """Fold ``e`` to a single string literal in the current frame, or
        ``DYNAMIC``. A string literal -> itself; an ident bound to a folded
        literal or a module const -> that literal; anything else ->
        DYNAMIC. Deliberately shallow (no arithmetic / concat folding):
        any uncertainty is DYNAMIC, never a guessed value."""
        lit = _string_literal_of(e)
        if lit is not None:
            return lit
        if isinstance(e, A.Ident):
            if e.name in env:
                return env[e.name]
            if e.name in self.const_literals:
                return self.const_literals[e.name]
            return DYNAMIC
        return DYNAMIC

    def _sink_calls(self, c: _Callable, cap: str) -> list:
        """Every ``MethodCall`` in ``c``'s body that is a ``cap`` sink:
        the method is a sink method and the receiver is a parameter
        declared as that capability (precise, no by-name guess)."""
        out: list = []

        def visit(e) -> None:
            if isinstance(e, A.MethodCall):
                if (
                    e.method in _SINK_METHODS[cap]
                    and isinstance(e.receiver, A.Ident)
                    and c.cap_params.get(e.receiver.name) == cap
                ):
                    out.append(e)
            for child in _child_exprs(e):
                visit(child)

        for stmt in _all_stmts(c.decl.body):
            for e in _stmt_exprs(stmt):
                visit(e)
        return out

    def _resolve_arg(self, arg, c: _Callable, local_lits: dict):
        """Resolve a sink's slot ARGUMENT in callable ``c`` to a set of
        reaching literals or ``DYNAMIC``.

        * a string literal -> ``{lit}``;
        * an ident that the local fold proved a literal / const -> that;
        * an ident that names one of ``c``'s PARAMETERS -> the backward
          walk ``_reaching_literals(c.key, param_idx)`` over every call
          site (Phase B);
        * anything else (computed, interpolation-with-subst, a non-param
          local that did not fold) -> ``DYNAMIC``.
        """
        if arg is None:
            return DYNAMIC
        lit = _string_literal_of(arg)
        if lit is not None:
            return {lit}
        if isinstance(arg, A.Ident):
            if arg.name in local_lits:
                folded = local_lits[arg.name]
                return DYNAMIC if folded is DYNAMIC else {folded}
            if arg.name in self.const_literals:
                return {self.const_literals[arg.name]}
            if arg.name in c.names:
                pidx = c.names.index(arg.name)
                return self._reaching_literals(c.key, pidx, set())
        return DYNAMIC

    def _reaching_literals(self, key: tuple, param_idx: int, seen: set):
        """The set of literals every call site passes for parameter
        ``param_idx`` of callable ``key``, or ``DYNAMIC`` if any path is a
        computed value. Walks the call graph BACKWARDS (caller call sites)
        with a mandatory ``seen`` cycle guard on ``(key, param_idx)`` --
        the backward walk is not a monotone fixpoint, so without the guard
        recursion / mutual recursion would loop forever. A node already on
        the current path contributes no NEW literal (its other reaching
        paths are accounted for by the outer frames), so revisiting it is
        skipped; this never drops a literal a non-cyclic path supplies.

        A parameter with NO call site (e.g. an entry point's parameter, or
        a public function never called internally) is UNRESOLVED -> a value
        supplied from outside the analysed program, which is DYNAMIC
        (fail-closed): the literal cannot be known."""
        node = (key, param_idx)
        if node in seen:
            return set()
        seen = seen | {node}
        # METHODS are conservatively DYNAMIC (fail-closed): an impl method
        # is reached by dynamic dispatch / trait / receiver-type-unknown
        # call sites whose exact target this AST-level analysis cannot
        # prove, so resolving a method parameter's literals could pick an
        # argument from an unrelated same-named method (an over-grant). The
        # SAFE default for any method-parameter resolution is DYNAMIC. The
        # idiomatic helper-routing the (full) layer targets is FREE
        # functions (``read_json`` / ``parse_sbom`` / ``write_log``); a
        # path that genuinely routes through a method stays fail-closed.
        if key[0] == "method":
            return DYNAMIC
        sites = self._call_sites_for(key)
        if not sites:
            # No internal caller binds this parameter: its value is
            # supplied from outside the analysed call graph (an entry
            # point, or an externally-invoked public function). Cannot be
            # resolved to a literal -> fail-closed.
            return DYNAMIC
        callee = self.callables[key]
        out: set = set()
        for caller_c, call in sites:
            arg = self._arg_for_param(call, callee, param_idx)
            res = self._resolve_arg_backward(arg, caller_c, seen)
            if res is DYNAMIC:
                return DYNAMIC
            out |= res
        return out

    def _resolve_arg_backward(self, arg, caller_c: _Callable, seen: set):
        """Resolve a call-site ARGUMENT in the CALLER's frame to literals
        or ``DYNAMIC``, recursing into the caller's parameters. Same rules
        as :meth:`_resolve_arg` but using the caller's local fold and
        threading the cycle-guard ``seen`` set through the backward
        recursion."""
        if arg is None:
            return DYNAMIC
        lit = _string_literal_of(arg)
        if lit is not None:
            return {lit}
        local_lits = self._local_literal_env(caller_c)
        if isinstance(arg, A.Ident):
            if arg.name in local_lits:
                folded = local_lits[arg.name]
                return DYNAMIC if folded is DYNAMIC else {folded}
            if arg.name in self.const_literals:
                return {self.const_literals[arg.name]}
            if arg.name in caller_c.names:
                pidx = caller_c.names.index(arg.name)
                return self._reaching_literals(caller_c.key, pidx, seen)
        return DYNAMIC

    def _call_sites_for(self, key: tuple) -> list:
        """Every internal FREE-FUNCTION call site that targets callable
        ``key``, a list of ``(caller_callable, call_expr)`` pairs matched
        by name. Method targets never reach here (they short-circuit to
        DYNAMIC in :meth:`_reaching_literals`)."""
        out: list = []
        for caller in self.callables.values():
            for e in self._all_calls(caller):
                if isinstance(e, A.Call) and isinstance(
                    e.callee, A.Ident,
                ) and ("fun", e.callee.name) == key:
                    out.append((caller, e))
        return out

    def _all_calls(self, c: _Callable) -> list:
        out: list = []

        def visit(e) -> None:
            if isinstance(e, (A.Call, A.MethodCall)):
                out.append(e)
            for child in _child_exprs(e):
                visit(child)

        for stmt in _all_stmts(c.decl.body):
            for e in _stmt_exprs(stmt):
                visit(e)
        return out

    def _arg_for_param(self, call: A.Call, callee: _Callable, param_idx: int):
        """The argument expression a FREE-FUNCTION call site binds to
        ``callee``'s parameter ``param_idx``, or ``None`` if the call does
        not bind it (a defaulted / missing argument -> the parameter is
        unresolved at this site, treated dynamic by the caller). Honours
        positional and named arguments via the shared ``_bind`` (so named
        args resolve on the AST, where they survive). Only free-function
        sites reach here (method targets short-circuit to DYNAMIC in
        :meth:`_reaching_literals`)."""
        perm = _bind(call.args, call.arg_names, callee.names)
        arg_idx = perm.get(param_idx)
        if arg_idx is None or arg_idx >= len(call.args):
            return None
        return call.args[arg_idx]


# ---- module-level helpers ------------------------------------------


def _string_literal_of(e):
    """The single string-literal VALUE of ``e`` if it is one, else None.
    A bare ``"x"`` (``StringLit``) and an interpolated string with NO
    substitution (a single ``str`` part, no ``${...}``) both fold; any
    interpolation with a substitution part does NOT (it is computed)."""
    if isinstance(e, A.StringLit):
        return e.value
    if isinstance(e, A.InterpolatedString):
        if len(e.parts) == 1 and isinstance(e.parts[0], str):
            return e.parts[0]
        if not e.parts:
            return ""
    return None


def _bind(args: list, arg_names: list, param_names: list) -> dict:
    """``{param_index: arg_index}`` honouring positional and named
    arguments, mirroring ``capa.analyzer._ifc_summary._bind`` so the
    binding is identical to the IFC summaries'."""
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


# ---- AST traversal helpers (no resolved types needed) --------------


def _all_stmts(block: A.Block):
    """Yield every statement in ``block`` and its nested blocks (depth
    first), so a sink / call anywhere in the body is visited."""
    for stmt in block.stmts:
        yield stmt
        for sub in _child_blocks(stmt):
            yield from _all_stmts(sub)


def _child_blocks(stmt):
    """The nested blocks of a statement (if / while / for / nested
    expression blocks reached via match arms are handled at expr level)."""
    out = []
    if isinstance(stmt, A.IfStmt):
        out.append(stmt.then_block)
        for _cond, blk in stmt.elif_arms:
            out.append(blk)
        if stmt.else_block is not None:
            out.append(stmt.else_block)
    elif isinstance(stmt, A.WhileStmt):
        out.append(stmt.body)
    elif isinstance(stmt, A.ForStmt):
        out.append(stmt.body)
    return out


def _stmt_exprs(stmt):
    """Yield the top-level expressions of a statement (recursion into
    nested blocks happens via ``_all_stmts``; this yields the exprs that
    may contain calls / sinks at this statement)."""
    if isinstance(stmt, (A.LetStmt, A.VarStmt)):
        if stmt.value is not None:
            yield stmt.value
    elif isinstance(stmt, A.AssignStmt):
        yield stmt.value
        yield stmt.target
    elif isinstance(stmt, A.ExprStmt):
        yield stmt.expr
    elif isinstance(stmt, A.ReturnStmt):
        if stmt.value is not None:
            yield stmt.value
    elif isinstance(stmt, A.IfStmt):
        yield stmt.cond
        for cond, _blk in stmt.elif_arms:
            yield cond
    elif isinstance(stmt, A.WhileStmt):
        yield stmt.cond
    elif isinstance(stmt, A.ForStmt):
        yield stmt.iter
    elif isinstance(stmt, A.Become):
        yield stmt.value


def _child_exprs(e):
    """Immediate sub-expressions of ``e`` (so a call / method-call / sink
    nested in an expression tree is reached). Conservative: yields every
    expression-typed child; non-expression children are skipped."""
    if isinstance(e, A.Call):
        yield e.callee
        yield from e.args
    elif isinstance(e, A.MethodCall):
        yield e.receiver
        yield from e.args
    elif isinstance(e, A.BinOp):
        yield e.left
        yield e.right
    elif isinstance(e, A.UnaryOp):
        yield e.operand
    elif isinstance(e, A.Try):
        yield e.expr
    elif isinstance(e, A.Index):
        yield e.receiver
        yield e.index
    elif isinstance(e, A.FieldAccess):
        yield e.receiver
    elif isinstance(e, A.RangeExpr):
        yield e.start
        yield e.end
    elif isinstance(e, A.InterpolatedString):
        for p in e.parts:
            if not isinstance(p, str):
                yield p
    elif isinstance(e, A.StructLit):
        for _name, v in e.fields:
            yield v
    elif isinstance(e, (A.ListLit, A.TupleLit)):
        yield from e.elements
    elif isinstance(e, A.IfExpr):
        yield e.cond
        yield e.then_expr
        yield e.else_expr
    elif isinstance(e, A.MatchExpr):
        yield e.scrutinee
        for arm in e.arms:
            if arm.guard is not None:
                yield arm.guard
            if isinstance(arm.body, A.Block):
                for stmt in _all_stmts(arm.body):
                    yield from _stmt_exprs(stmt)
            else:
                yield arm.body
    elif isinstance(e, A.Become):
        yield e.value
