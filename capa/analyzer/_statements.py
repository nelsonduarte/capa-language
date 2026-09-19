"""Statement-level checking mixin.

Implements ``_check_stmt_seq`` (the ONE statement walker) and
``_check_stmt`` plus the per-shape checkers:

- ``_check_let`` / ``_check_var``: binding introductions with
  inference and capability-flow exceptions for call-returned
  fresh capabilities.
- ``_check_assign``: assignment with mutability validation
  (immutable ``let``s, constants, and parameters cannot be
  reassigned).
- ``_check_if``: branch-aware ``_consumed`` snapshot + merge.
- ``_check_while``, ``_check_for``: both route through ``_check_loop``,
  the ONE loop rule, and ``_loop_label_fixpoint``, the ONE seam that
  re-walks a loop body speculatively until the labels the next
  iteration can read have stabilised, before the real pass.
- ``_check_return``: validate the return value against the
  current function's expected return type.
- ``_snapshot_for_dry_run`` / ``_restore_after_dry_run``: the
  flow-analysis bookkeeping a speculative pass relies on.

The implicit-flow discipline (strict tier) lives in the walker: after
each statement the pc for the next one is the enclosing pc joined with
the normal-termination label of the statements so far (Myers' path
labels), so a public sink after a secret-conditioned early exit is
checked under a secret pc. ``_paths`` computes that label, and the
exit-kind map the loop rule consumes, syntactically over the AST.

The mixin assumes ``self`` has the analyzer state set up and
pulls helpers from the other mixins (``_check_expr``,
``_bind_pattern``, ``_resolve_type``, ``_check_no_capability``,
``_err``, ``_push_scope``, ``_pop_scope``).
"""

from __future__ import annotations

from .. import capa_ast as A
from .. import _labels as L
from ..tokens import Pos
from ..typesys import (
    Ty, TyBool, TyName, TyString, TyUnit, TyUnknown,
    compatible, ty_str,
)
from ._exit_syntax import _NO_PATHS, _ExitSyntaxMixin


#: The AST statement kinds ``_check_stmt`` dispatches on, one per
#: ``isinstance`` branch in that method. Declared handled-set for the M1
#: exhaustiveness net, pinned against ``capa_ast.Stmt.__subclasses__()``
#: (``tests/test_node_exhaustiveness.py``): a new ``Stmt`` node this
#: dispatcher forgets fails that test rather than being silently skipped.
#: Keep it in lockstep with the branches below.
CHECKED_STMT_KINDS = frozenset({
    A.LetStmt, A.VarStmt, A.AssignStmt, A.IfStmt, A.WhileStmt, A.ForStmt,
    A.ReturnStmt, A.BreakStmt, A.ContinueStmt, A.ExprStmt,
})


class _StatementsMixin(_ExitSyntaxMixin):
    def _check_stmt_seq(self, stmts) -> dict:
        """THE ONE statement walker. Every body position (a function
        body, a loop body, an ``if`` branch, a match arm, a lambda body)
        routes its statements through here.

        Checks ``stmts`` in order. In the strict tier the pc under which
        statement i+1 is checked is the enclosing pc joined with the
        normal-termination label of statements 0..i (Myers: the correct
        pc for the second statement is the normal path label of the
        first), so a statement after a secret-conditioned early exit runs
        under a secret pc, however deep the exit sits. Returns the body's
        exit map (kind -> label) for the CALLER to consume at each kind's
        target: a loop reads ``break``; nothing else reads it, because an
        enclosing body recomputes its own paths through ``_paths``. The
        pc is restored on the way out: a body's raise is scoped to the
        body, and the pc after a construct is its enclosing walker's
        business."""
        base_pc = self._pc_label
        acc = _NO_PATHS
        try:
            for stmt in stmts:
                self._check_stmt(stmt)
                if getattr(self, "_strict_ifc", False):
                    acc = acc.then(self._paths(stmt, self._ALL_KINDS))
                    self._pc_label = L.join(base_pc, acc.norm)
            return acc.exits
        finally:
            self._pc_label = base_pc

    def _check_block(self, block: A.Block) -> dict:
        """Walk a block in its own binding scope; the exit map is handed
        to the caller (see ``_check_stmt_seq``)."""
        self._push_scope()
        try:
            return self._check_stmt_seq(block.stmts)
        finally:
            self._pop_scope()

    def _check_stmt(self, stmt: A.Stmt) -> None:
        if isinstance(stmt, A.LetStmt):
            self._check_let(stmt)
        elif isinstance(stmt, A.VarStmt):
            self._check_var(stmt)
        elif isinstance(stmt, A.AssignStmt):
            self._check_assign(stmt)
        elif isinstance(stmt, A.IfStmt):
            self._check_if(stmt)
        elif isinstance(stmt, A.WhileStmt):
            self._check_while(stmt)
        elif isinstance(stmt, A.ForStmt):
            self._check_for(stmt)
        elif isinstance(stmt, A.ReturnStmt):
            self._check_return(stmt)
        elif isinstance(stmt, A.BreakStmt):
            self._check_loop_jump(stmt, "break")
        elif isinstance(stmt, A.ContinueStmt):
            self._check_loop_jump(stmt, "continue")
        elif isinstance(stmt, A.ExprStmt):
            # A bare ``match`` statement discards its value, so an
            # open-domain scrutinee (Int / String / Float / Char) does
            # not need a catch-all: a miss is a legal no-op. Mark the
            # node as statement-position so the exhaustiveness check
            # stays lenient there, while a value-producing match still
            # requires full coverage. (Still routed through
            # ``_check_expr`` so the type / IFC-label registration the
            # IR and transpiler rely on happens as usual.)
            if isinstance(stmt.expr, A.MatchExpr):
                self._stmt_position_matches.add(id(stmt.expr))
            expr_ty = self._check_expr(stmt.expr)
            # A bare expression statement whose value is linear /
            # typestate drops it unconsumed (``open()`` /
            # ``become(c, S)`` as a statement). Flag it like a named
            # leak. ``become`` has already discharged its operand, so
            # only the freshly-produced (now dropped) value is reported.
            self._linear_check_anonymous_drop(stmt.expr, expr_ty, stmt.pos)
        else:
            self._err(
                f"unknown statement type {type(stmt).__name__}", stmt.pos,
            )

    def _check_loop_jump(self, stmt: A.Stmt, kw: str) -> None:
        """Validate a ``break`` / ``continue``. A jump is legal only
        when it is lexically inside a loop body of the SAME function:
        ``_loop_depth`` is bumped around ``while`` / ``for`` bodies and
        reset to 0 when entering a lambda body, so a jump inside a
        lambda (which cannot cross the lambda's function boundary)
        reports an error here rather than producing code that both
        backends reject at codegen."""
        if self._loop_depth <= 0:
            self._err(f"{kw} outside of a loop", stmt.pos)

    def _check_let(self, s: A.LetStmt) -> None:
        # Bidirectional typing for a list literal under a ``List<T>``
        # annotation: thread the declared element type into the list-lit
        # checker so each element is checked against ``T`` (trait /
        # capability membership) instead of against the first element.
        # This is confined to the list-literal shape -- tuple / struct
        # literals are unchanged -- and only kicks in when the
        # annotation is concretely ``List<T>``; every other RHS falls
        # through to the ordinary inference path.
        actual = None
        if isinstance(s.value, A.ListLit) and s.type_expr is not None:
            declared_ann = self._resolve_type(s.type_expr)
            if (
                isinstance(declared_ann, TyName)
                and declared_ann.name == "List"
                and len(declared_ann.args) == 1
            ):
                actual = self._check_list_lit(
                    s.value, expected_elem=declared_ann.args[0]
                )
                # Replicate the bookkeeping _check_expr would have done
                # (record the node's type, label it, and run the container-of-
                # linear use-gate) since we bypassed it to pass the expected
                # element type. The cap analogue is caught by the
                # _check_no_capability on the binding below; the linear one has
                # no such binding gate, so it is replicated here.
                self.types[id(s.value)] = actual
                self._label_expr(s.value)
                self._linear_container_use_gate(s.value, actual)
        if actual is None:
            actual = self._check_expr(s.value)
        if s.type_expr is not None:
            declared = self._resolve_type(s.type_expr)
            if not self._assignable(declared, actual, s.value):
                self._err(
                    f"let binding: expected {ty_str(declared)}, "
                    f"got {ty_str(actual)}",
                    s.value.pos,
                )
            # Higher-order IFC: a secret-returning closure bound to a
            # public-returning ``let`` slot can leak when later invoked.
            self._check_closure_ret_flow(
                declared, actual, s.value.pos, "bound to a 'let'",
            )
            actual = declared
        # Capabilities normally cannot be bound to a ``let`` to
        # prevent aliasing. Exception: a fresh capability
        # produced by a call (method call -> built-in
        # attenuation; regular call -> user-defined factory)
        # is a brand-new instance, not an alias. The flow-layer
        # non-aliasing rule still applies if the binding is
        # later passed around.
        if not isinstance(s.value, (A.MethodCall, A.Call)):
            self._check_no_capability(actual, s.pos, "a 'let' binding")
        self._reject_nested_struct_in_binding(s.pattern)
        self._bind_pattern(s.pattern, actual, mutable=False, init_expr=s.value)
        # Roadmap S2.3: the binding's label is the join of any declared
        # ``@secret``/``@public`` annotation and the label of the RHS
        # value -- so ``let x = secret_value`` makes x secret even
        # without an annotation, the core taint-propagation rule.
        # Roadmap S2 (per-field IFC, soundness): a struct value used as
        # a WHOLE on the RHS (aliasing ``let y = x``, or stored into an
        # aggregate / sub-struct) escapes -- structs are reference types,
        # so per-field tracking through it could go stale on a later
        # mutation. Mark escapes before labelling the new binding so the
        # alias does not inherit a map that may become unsound.
        self._mark_struct_escape(s.value)
        if isinstance(s.pattern, A.IdentPat):
            self._label_binding(
                s.pattern.name,
                s.type_expr.label if s.type_expr is not None else None,
                s.value,
            )
            # Roadmap S2 (two-hop closure-by-name): record a lambda-literal
            # RHS on this binding so a later ``invoke(f)`` can recover the
            # closure's precise result label. A ``let`` binds a fresh Symbol,
            # so this replaces any prior record for the name.
            self._record_binding_lambda(
                self.scope.lookup_local(s.pattern.name), s.value, fresh=True,
            )
            # Aliasing (``let b2 = b``): link the new binding into the
            # source's alias group so a later field store through either
            # taints both (structs are reference types).
            if isinstance(s.value, (A.Ident, A.FieldAccess)):
                self._ifc_alias_link(
                    self.scope.lookup_local(s.pattern.name), s.value,
                )
            # Embed-then-mutate (``let o = Outer { inner: b }``): link
            # the new binding into the alias group of every bare struct
            # binding embedded into the literal, so a later mutation of
            # the still-live source is visible through the embedding.
            self._ifc_link_embedded_structs(
                self.scope.lookup_local(s.pattern.name), s.value,
            )
        else:
            # A DESTRUCTURING ``let`` (``let Emp { id, iban } = e``)
            # carries the RHS label to its binds exactly as a ``match``
            # arm does, and -- independent of that whole-value label --
            # gives a name bound to a DECLARED-``@secret`` field the same
            # @secret label a direct ``e.iban`` read would. This closes
            # the destructuring laundering hole: extracting a declared-
            # secret field by pattern no longer launders it to public.
            self._label_pattern_binds(
                s.pattern, self._label_of(s.value), actual,
            )
        # Roadmap S1: a ``let h = open()`` of a linear-typed value
        # opens a must-consume obligation under the bound name. Only
        # a simple identifier pattern carries it (a destructure of a
        # linear value is not in S1's scope). If the RHS is itself a
        # bare identifier we treated as a move below in
        # ``_check_ident``; here the common ``let h = <call>`` case is
        # the obligation source.
        # ``let h2 = h`` aliasing a live linear value MOVES the obligation
        # onto the new name (poisoning the source) so the value stays
        # single-owner; a DESTRUCTURING ``let Box { c: inner } = b`` moves the
        # field out of its carrier per bound name; ``let _ = open()`` drops the
        # value into a slot that holds no obligation. All three are the ONE
        # owning-binding seam.
        self._linear_bind_pattern_own(s.pattern, s.value, actual, s.pos)

    def _check_var(self, s: A.VarStmt) -> None:
        from . import Symbol, SymbolKind

        actual = self._check_expr(s.value)
        if s.type_expr is not None:
            declared = self._resolve_type(s.type_expr)
            if not self._assignable(declared, actual, s.value):
                self._err(
                    f"var declaration: expected {ty_str(declared)}, "
                    f"got {ty_str(actual)}",
                    s.value.pos,
                )
            # Higher-order IFC: a secret-returning closure bound to a
            # public-returning ``var`` slot can leak when later invoked.
            self._check_closure_ret_flow(
                declared, actual, s.value.pos, "bound to a 'var'",
            )
            actual = declared
        if not isinstance(s.value, (A.MethodCall, A.Call)):
            self._check_no_capability(actual, s.pos, "a 'var' binding")
        if self.scope.lookup_local(s.name) is not None:
            self._err(f"duplicate declaration of {s.name!r}", s.pos)
        else:
            # A ``var`` inside a lambda body that shadows a name from an
            # ENCLOSING scope crosses the lambda boundary the same way a
            # shadowing ``let`` / pattern-bind does, and the two backends
            # compile it differently. ``var`` does not go through
            # ``_bind_pattern``, so the closure-shadow check is applied
            # here directly (blanket for an enclosing parameter / local,
            # capture-aware for a module const / function -- including a
            # self-referential ``var S = S`` whose RHS reads the const).
            enclosing = self._enclosing_scope_local(s.name, s.pos, s.value)
            if enclosing is not None:
                self._err(
                    self._closure_shadow_message(s.name, enclosing), s.pos,
                )
        _decl_label = s.type_expr.label if s.type_expr is not None else None
        _var_label = self._join_decl_and_value_label(_decl_label, s.value)
        # Roadmap S2 (per-field IFC, soundness): mark any whole-struct
        # value used on the RHS as escaped before defining the binding
        # (same rule as ``let``; structs are reference types).
        self._mark_struct_escape(s.value)
        sym = Symbol(
            name=s.name, kind=SymbolKind.LOCAL_VAR,
            pos=s.pos, ty=actual, label=_var_label,
        )
        # Carry the per-field map when the RHS is a tracked struct
        # literal / precise sub-struct read (not a bare alias / field
        # chain, and not when an explicit @secret raised the whole
        # value). Deep-copied so later field stores do not alias the
        # literal's recorded map.
        from ._ifc import _deepcopy_field_map
        _fmap = self._field_map_of(s.value)
        if (
            _fmap is not None
            and L.normalize(_decl_label) != L.SECRET
            and not isinstance(s.value, (A.Ident, A.FieldAccess))
        ):
            sym.field_labels = _deepcopy_field_map(_fmap)
        # Higher-order IFC precision (Phase B1): carry a combinator-result
        # element/structure split onto the ``var`` binding, unless an
        # explicit @secret annotation already raised the whole value.
        if L.normalize(_decl_label) != L.SECRET:
            self._copy_container_split(sym, s.value)
        self.scope.define(sym)
        # Roadmap S2 (two-hop closure-by-name): record a lambda-literal
        # RHS on the fresh ``var`` binding. A subsequent reassignment in
        # ``_check_assign`` poisons it (the denotation becomes ambiguous),
        # so only a never-reassigned ``var`` stays precise.
        self._record_binding_lambda(sym, s.value, fresh=True)
        # Roadmap S2 (reassigned-var sink recovery): note whether this Fun
        # ``var``'s INTRODUCTION value is a public-returning closure, so a
        # later reassigned-var sink check flags it only when every assigned
        # closure is secret-returning.
        self._note_fun_var_assignment(sym, s.value)
        # Aliasing (``var b2 = b``): link into the source's alias group
        # so a later field store through either taints both.
        if isinstance(s.value, (A.Ident, A.FieldAccess)):
            self._ifc_alias_link(sym, s.value)
        # Embed-then-mutate: link into the alias group of every bare
        # struct binding embedded into a struct literal RHS.
        self._ifc_link_embedded_structs(sym, s.value)
        # Roadmap S1: a ``var h = open()`` of a linear-typed value opens
        # the same must-consume obligation a ``let`` does -- ``var`` only
        # makes the slot re-assignable, it does not waive the obligation.
        # An aliasing ``var h2 = h`` MOVES the obligation off ``h`` (as in
        # ``let``) so the value remains single-owner.
        self._linear_transfer_if_alias(s.value, s.name)
        self._linear_bind(s.name, actual, s.pos)

    def _check_assign(self, s: A.AssignStmt) -> None:
        from . import SymbolKind

        # Roadmap S1: the left side of ``h = ...`` / ``s.conn = ...`` is a
        # WRITE target, not a use, so reading a poisoned (already-consumed)
        # linear place here must not raise use-after-consume --
        # ``close(h); h = open()`` and ``close(s.conn); s.conn = open()``
        # are both the legitimate re-arm. Lift the poison on the RESOLVED
        # place before evaluating the target; ``_linear_reassign`` below
        # restores the correct obligation state from the fresh RHS. One
        # branch, through the one resolver, because a bare name and a field
        # path are two spellings of one question -- asked separately, the
        # two copies drifted apart, and only the field one recorded the
        # re-arm the drop check below reads.
        _tpath = self._path_of(s.target)
        _field_target_rearm = False
        if _tpath is not None and _tpath in self._consumed:
            _field_target_rearm = isinstance(s.target, A.FieldAccess)
            self._consumed.discard(_tpath)
            self._linear_names.discard(_tpath)
        target_ty = self._check_expr(s.target)
        value_ty = self._check_expr(s.value)
        # Higher-order IFC: reassigning a secret-returning closure into a
        # public-returning slot (a ``var`` whose type is public-returning,
        # or a public-returning struct field) can leak the captured secret
        # when that slot is later invoked at a public sink. The target's
        # type is flow-insensitive (a ``var`` keeps its declared / first-
        # inferred return label), so a public-then-secret reassignment is
        # caught here while a secret-then-public one keeps the secret slot
        # type and is caught wherever it is invoked.
        self._check_closure_ret_flow(
            target_ty, value_ty, s.value.pos, "assigned into a slot",
        )
        if isinstance(s.target, A.Ident):
            sym = self.bindings.get(id(s.target))
            # Roadmap S2.3: a reassignment ``x = rhs`` is an EXPLICIT data
            # flow, so the RHS value's label JOINS onto the target's label
            # UNCONDITIONALLY (every tier). Without this, ``var x = "pub";
            # x = secret; sink(x)`` laundered the secret in the default
            # tier -- a silent PII leak (audit 2026-06-17). The join is
            # monotonic on the SAME Symbol (it never lowers), which is the
            # important difference from a ``let x = rhs`` introduction: a
            # fresh ``let`` binds a new Symbol whose label is exactly the
            # RHS's, whereas this reassignment can only RAISE the existing
            # binding's label. The known, pre-existing consequence is
            # flow-insensitivity: once ``x`` has been tainted secret,
            # reassigning a public value back to it (``x = "pub"``) does
            # NOT lower the label, so a later public use of ``x`` is still
            # treated as secret. That conservative over-approximation is
            # inherent to the single-Symbol flow-insensitive model and is
            # out of scope for this fix.
            #
            # Roadmap S2.implicit (strict only): the pc-label join (an
            # IMPLICIT flow -- a value written inside a secret-conditioned
            # branch / loop becomes secret) stays gated to ``@strict_ifc``
            # via ``_join_pc_if_strict``, so the default tier still does not
            # report implicit flows.
            if sym is not None:
                sym.label = self._join_pc_if_strict(
                    L.join(getattr(sym, "label", None), self._label_of(s.value))
                )
            # Roadmap S2 (two-hop closure-by-name): a reassignment makes
            # the name's denotation ambiguous (it may now denote a
            # DIFFERENT closure), so it POISONS the record regardless of
            # the RHS shape -- the boundary check then falls back to the
            # documented skip (never the capture label, never an
            # over-approximating join, hence never a false positive).
            if sym is not None:
                self._record_binding_lambda(sym, s.value, fresh=False)
            # Roadmap S2 (reassigned-var sink recovery): a reassignment to a
            # public-returning closure marks the ``var`` so the invoke-sink
            # boundary check no longer flags it (its current value may be
            # public). A reassignment to a secret closure leaves it flaggable.
            if sym is not None:
                self._note_fun_var_assignment(sym, s.value)
            if sym is not None and sym.kind == SymbolKind.LOCAL:
                self._err(
                    f"cannot assign to immutable binding {sym.name!r} "
                    f"(use 'var' instead of 'let' to make it mutable)",
                    s.pos,
                )
            elif sym is not None and sym.kind == SymbolKind.CONSTANT:
                self._err(
                    f"cannot assign to constant {sym.name!r}", s.pos,
                )
            elif sym is not None and sym.kind == SymbolKind.PARAM:
                self._err(
                    f"cannot assign to parameter {sym.name!r}", s.pos,
                )
            # Roadmap S1: re-assigning a name (``h = open()``) is the SAME
            # whole-value move / re-arm discipline a ``let`` / ``var``
            # introduction runs, so it routes through the ONE
            # ``_linear_transfer_if_alias`` seam rather than re-implementing a
            # partial slice of it here. That seam moves the whole obligation
            # off an aliased source (so ``t = s; close(s)`` rejects instead of
            # double-freeing), re-carries the source's moved-out sub-paths onto
            # the target, and propagates a borrowed marker (so ``t = h; close(t)``
            # on a borrowed ``h`` rejects instead of laundering the caller's
            # value). Three cases:
            #
            # - SELF-ASSIGN (the RHS RESOLVES to the target's own place): a
            #   no-op re-arm. There is no source to move off and the target's
            #   own moved-out sub-paths must be PRESERVED -- a spent husk
            #   assigned to itself stays a husk, so a later whole consume is
            #   still rejected. Routing it through the clear-then-transfer
            #   path below would wipe those sub-paths. Decided on the
            #   RESOLVED place, through ``_receiver_path_of`` (the one
            #   operand-place resolver, which sees through a selection, a
            #   pattern-binding view and a single-origin laundering call) --
            #   NOT on the RHS's syntax. Spelled as ``isinstance(s.value,
            #   Ident) and s.value.name == s.target.name``, only the literal
            #   ``a = a`` preserved the husk, and every wrapped spelling of
            #   the same self-assignment (``a = (if c then a else a)``,
            #   ``a = idc(a)``, ``a = match a { h -> h }``) took the clear
            #   path and re-armed a partially consumed value: a double-free
            #   with a clean ``--check`` on all three backends. One
            #   consequence is deliberate: the drop rule's conservative
            #   reject of a LIVE self-assign now lands on every spelling,
            #   not just the direct one -- one statement, one verdict,
            #   whatever the wrapping.
            # - ALIAS / FRESH / UNRESOLVABLE (everything else), in THIS
            #   ORDER: clear the target's OWN stale moved-out sub-tree FIRST
            #   (a spent-husk target re-armed to a fresh value must not keep
            #   rejecting a legitimate consume, nor mask the fresh value's
            #   leak), THEN ``_linear_transfer_if_alias`` (which re-carries
            #   the SOURCE's sub-paths and clears any stale borrow on the
            #   target), THEN the re-arm. The order is load-bearing: clearing
            #   AFTER the transfer, or clearing unconditionally, would wipe
            #   the sub-paths the transfer just re-carried and reopen the
            #   husk double-free. An RHS the resolver cannot reduce to one
            #   place (arms disagreeing, a multi-origin callee) lands here
            #   too, where the move seam already rejects it fail-closed.
            #
            # Out of scope here (a SEPARATE double-free class with its own seam):
            # a field-store linear laundering ``s.h = t`` is the FieldAccess-
            # target branch below, not this Ident-target re-arm.
            rhs_place = self._receiver_path_of(s.value)
            if rhs_place is not None and rhs_place == _tpath:
                self._linear_reassign(s.target.name, value_ty, s.pos)
            else:
                self._clear_moved_subpaths(s.target.name)
                self._linear_transfer_if_alias(s.value, s.target.name)
                self._linear_reassign(s.target.name, value_ty, s.pos)
        elif isinstance(s.target, (A.FieldAccess, A.Index)):
            # A bare index-element target (``xs[i] = v`` and the
            # augmented ``xs[i] += 1``) has no sound lowering on
            # either backend: the Python transpiler emits an
            # assignment to a function call (``_capa_list_get(...) =
            # v``), a runtime SyntaxError, and the Wasm backend
            # raises a CIR-lowering error. Reject it at the target
            # so both backends agree at compile time. Note that
            # ``xs[i].field = v`` is a FieldAccess target (its
            # receiver is the Index) and stays allowed: it lowers
            # via a field store whose receiver is the index.
            if isinstance(s.target, A.Index):
                self._err(
                    "assignment to a list element is not supported "
                    "(no backend can lower 'xs[i] = v'); rebuild the "
                    "list or assign through a struct field reached by "
                    "the index instead",
                    s.target.pos,
                )
            # Frozen-struct check: writing to a field of a struct
            # that flows (directly or transitively) into a
            # ``Set<...>`` or ``Map<...K, V>`` key would break the
            # data structure's hash invariant (the Wasm linear
            # scan misses entries; the Python ``CapaSet`` dict
            # corrupts its bucket). The set is computed once per
            # module in ``_compute_frozen_types``; here we just
            # consult it against the receiver type of the field
            # access. Indexed receivers (``xs[i].x = 5``) are
            # caught too, because the FieldAccess.receiver type
            # resolves to the struct after List/Map element
            # extraction.
            if isinstance(s.target, A.FieldAccess):
                recv_ty = self.types.get(id(s.target.receiver))
                if recv_ty is not None and self._is_frozen(recv_ty):
                    from ..typesys import TyName
                    tname = recv_ty.name if isinstance(recv_ty, TyName) else "?"
                    self._err(
                        f"field {s.target.field_name!r} of struct {tname!r} "
                        f"cannot be assigned: type {tname!r} is frozen "
                        f"(appears in Set or Map keys; mutating fields "
                        f"would break the structure)",
                        s.pos,
                    )
                # The builtin ``IoError`` is read-only: the Python
                # runtime backs it with a frozen dataclass (a field
                # write raises FrozenInstanceError at runtime), while
                # the Wasm backend would silently store through the
                # record pointer -- a silent backend divergence.
                # Reject the write here so both backends agree at
                # compile time. Reads (``e.message`` / ``e.cause``)
                # stay allowed. Guarded on BUILTIN_POS: a USER-declared
                # ``type IoError`` shadows the builtin with a real
                # source position and keeps ordinary mutable-struct
                # semantics on both backends.
                from ..typesys import TyName as _TyName
                if (isinstance(recv_ty, _TyName)
                        and recv_ty.name == "IoError"):
                    from ..builtins import BUILTIN_POS
                    io_sym = self.scope.lookup("IoError")
                    if io_sym is not None and io_sym.pos == BUILTIN_POS:
                        self._err(
                            f"field {s.target.field_name!r} of the "
                            f"built-in 'IoError' cannot be assigned: "
                            f"IoError values are read-only (construct a "
                            f"new IoError instead)",
                            s.pos,
                        )
            cap = self._contains_any_capability(target_ty)
            if cap is not None:
                self._err(
                    f"capability {cap.name!r} cannot be re-bound via field "
                    f"or index assignment; capabilities bind once at struct "
                    f"construction (or as a function parameter) and stay put",
                    s.pos,
                )
        if not self._assignable(target_ty, value_ty, s.value):
            self._err(
                f"assignment: cannot assign {ty_str(value_ty)} to "
                f"{ty_str(target_ty)}",
                s.value.pos,
            )
        # Roadmap S1 (field-store move, SOURCE side): storing an OWNED
        # linear/typestate value into a field that carries an obligation MOVES
        # it out of its source, exactly as packing it into a struct literal
        # does -- so route the RHS through the SAME borrowed-escape reject +
        # move seam the aggregate pack uses, in the SAME order. This covers a
        # bare-linear LEAF target (``s.conn = t``) AND a CARRIER-typed target
        # field (``o.inner = a``, a subtree of leaves): the gate is the widened
        # obligation predicate ``_owned_obligation(field_ty)``, and ``=`` only
        # (an augmented store on such a field is ill-typed). ``_move_linear_operand``
        # handles a whole-carrier / bare Ident (discharge) and a bare-linear
        # FIELD projection (field move), and returns False for a fresh call or a
        # borrowed bare ident (the escape reject fires with the pack wording).
        #
        # A carrier projection RHS (``o.inner = p.inner``) is now moved by the
        # seam itself: ``_move_linear_operand``'s FieldAccess branch routes
        # through the one field-projection mover, so the source carrier's subtree
        # is discharged and a self-store becomes a no-op re-arm without an inline
        # special-case here.
        if isinstance(s.target, A.FieldAccess) and s.op == "=":
            field_ty = self.types.get(id(s.target))
            if self._owned_obligation(field_ty):
                self._linear_check_borrowed_escape(s.value, s.value.pos)
                self._move_linear_operand(s.value)
        # WARNING-3: overwriting a LIVE linear/typestate field
        # (``s.conn = fresh()`` while the current ``s.conn`` was never
        # consumed) drops the old value with no consume -- a leak, symmetric
        # with the whole-name reassign guarded by ``_linear_reassign``. A
        # store after a legitimate prior consume/move of the field re-arms
        # it (the field place leaves ``_consumed``), so the fresh value is
        # tracked afresh.
        # Driven off the target field's linear-leaf SET (``_field_linear_leaves``):
        # a bare leaf is the one-element instance and a carrier-typed field is
        # its subtree of leaves, so one per-leaf loop handles both. For each leaf
        # a store after a legitimate prior consume/move RE-ARMS it (via the single
        # ``_linear_rearm_field`` primitive: clears the leaf + subtree through
        # ``_moved_subpath_sets()`` and re-opens the carrier root); overwriting a
        # still-LIVE leaf drops it, one diagnostic per leaked leaf by path.
        # ``_field_target_rearm`` (computed on the exact write path) only matches
        # the bare-leaf-exact term; for a carrier subtree leaf it is always False
        # and the condition reduces to ``leaf in _consumed``.
        if isinstance(s.target, A.FieldAccess):
            base = self._path_of(s.target)
            for leaf in self._field_linear_leaves(s.target):
                if (leaf == base and _field_target_rearm) or leaf in self._consumed:
                    self._linear_rearm_field(leaf, s.pos)
                elif not self._prefix_consumed(leaf):
                    self._err(
                        f"linear field {leaf!r} is overwritten without "
                        f"being consumed; a `linear type` / typestate value "
                        f"cannot be dropped -- consume the current value "
                        f"(e.g. a `consume self` method like `close`) before "
                        f"re-assigning",
                        s.pos,
                    )
        # Roadmap S2 (per-field IFC): a field store ``p.f = x`` raises
        # that field's per-field label monotonically (and the binding's
        # collapsed label), so a field made secret by a later assignment
        # is tracked precisely while never lowering an already-secret
        # field. Only ``=`` is handled here; an augmented ``+=`` already
        # reads the old (tracked) field on its RHS, so the join is sound.
        if isinstance(s.target, A.FieldAccess):
            self._ifc_field_store(s.target, s.value)

    #: The diagnostic de-duplication sets: a node id recorded here is not
    #: reported a second time. They ride the speculative-pass seam below
    #: because a diagnostic first emitted in a speculative pass is
    #: truncated with the pass; if its id stayed recorded, the real pass
    #: would skip it and the diagnostic would be lost.
    _DEDUP_SETS = (
        "_cap_container_reported",
        "_linear_container_reported",
        "_linear_conditional_reported",
    )

    def _snapshot_for_dry_run(self) -> dict:
        """Capture the state a SPECULATIVE pass must not leak into the
        real pass: the consumed set, the diagnostics, the bindings and
        types added, the diagnostic de-duplication marks, and the
        deferred empty-container reads (keyed by a per-pass fresh type
        variable, so a stale key would report once per pass). What is
        deliberately NOT captured is the fixpoint state: the binding
        labels and the container-mutation channel rise monotonically
        across passes, which is what a speculative pass is for."""
        return {
            "consumed": set(self._consumed),
            "errors_len": len(self.errors),
            "warnings_len": len(self.warnings),
            "bindings_keys": set(self.bindings.keys()),
            "types_keys": set(self.types.keys()),
            "dedup": {n: set(getattr(self, n)) for n in self._DEDUP_SETS},
            "deferred_elem_reads": set(self._deferred_elem_reads),
        }

    def _restore_after_dry_run(self, snap: dict) -> None:
        """Reverse :meth:`_snapshot_for_dry_run`. Added bindings /
        types / deferred reads are removed by key; new errors and
        warnings are truncated (the real pass is the single source of
        each diagnostic); ``_consumed`` and the de-duplication sets
        revert."""
        self._consumed = snap["consumed"]
        self.errors = self.errors[: snap["errors_len"]]
        self.warnings = self.warnings[: snap["warnings_len"]]
        for k in list(self.bindings.keys()):
            if k not in snap["bindings_keys"]:
                del self.bindings[k]
        for k in list(self.types.keys()):
            if k not in snap["types_keys"]:
                del self.types[k]
        for name, marks in snap["dedup"].items():
            setattr(self, name, marks)
        for k in list(self._deferred_elem_reads):
            if k not in snap["deferred_elem_reads"]:
                del self._deferred_elem_reads[k]

    #: A safety net only: the termination argument is the two-point label
    #: lattice (every channel rises monotonically, so the passes settle in
    #: links + O(1) trips). Reaching the cap is a DEFECT: it is counted on
    #: the result so a test can assert it never fires, and it fails CLOSED.
    _FIXPOINT_CAP = 64

    def _loop_label_fixpoint(self, run_body, pc_at_head) -> dict:
        """THE ONE seam for loop label stabilisation.

        ``run_body`` performs one speculative walk of the loop body under
        the current pc and returns its exit map. This repeats it, each
        pass under ``pc_at_head`` joined with the ``break`` label seen so
        far, until neither the label channels (``_label_channels``, the
        label store's own enumeration) nor the accumulated exit map
        change, and returns the stable exit map. Every pass is reverted
        through ``_restore_after_dry_run`` except the fixpoint state
        itself; the consumed set a pass discovers is accumulated across
        passes and re-applied, so the linear discipline sees every
        consume the body performs. When the cap is hit every exit kind
        is reported secret: an unstabilised program is never accepted."""
        exits: dict = {}
        consumed_seen: set = set()
        passes = 0
        while True:
            before = (self._label_channels(), self._exits_fingerprint(exits))
            snap = self._snapshot_for_dry_run()
            self._pc_label = L.join(pc_at_head, exits.get("break", L.PUBLIC))
            new_exits = run_body()
            passes += 1
            for kind, label in new_exits.items():
                exits[kind] = L.join(exits.get(kind), label)
            consumed_seen |= self._consumed - snap["consumed"]
            self._restore_after_dry_run(snap)
            self._consumed |= consumed_seen
            after = (self._label_channels(), self._exits_fingerprint(exits))
            self.fixpoint_max_passes = max(self.fixpoint_max_passes, passes)
            if after == before:
                return exits
            if passes >= self._FIXPOINT_CAP:
                self.fixpoint_overruns += 1
                return {kind: L.SECRET for kind in self._ALL_KINDS}

    def _check_loop(self, pc_at_head, speculative, real) -> None:
        """THE ONE loop rule, shared by ``while`` and ``for``.

        ``speculative`` walks the body once for the fixpoint and ``real``
        walks it for the real pass under the head pc it is given. Only a
        ``break`` changes how many times the body runs, so only the
        ``break`` label of the stabilised exit map raises the head pc,
        governing the whole body (a counter incremented in it becomes
        secret) and, through the body's labels, whatever the statements
        after the loop read. A ``continue`` skips the rest of one
        iteration, which the walker already governs within the body; a
        ``return`` leaves the frame, which the enclosing walker sees
        through ``_paths``.

        The linear state a branch suspended at a ``continue`` rejoins at
        the loop head, so the next iteration sees the consume; the state
        suspended at a ``break`` rejoins at the loop exit, so everything
        after the loop sees it. The frame is this loop's own: an inner
        loop never consumes what an outer body suspended, and the search
        idiom (consume once, then leave) stays accepted."""
        self._loop_depth += 1
        saved_pc = self._pc_label
        outer_frame = self._lin_exits
        self._lin_exits = {}
        before_consumed = set(self._consumed)
        try:
            exits = self._loop_label_fixpoint(speculative, pc_at_head)
            self._rejoin_linear_exits("continue", before_consumed)
            real(L.join(pc_at_head, exits.get("break", L.PUBLIC)))
            self._rejoin_linear_exits("break", before_consumed)
        finally:
            self._lin_exits = outer_frame
            self._loop_depth -= 1
            self._pc_label = saved_pc

    def _rejoin_linear_exits(self, kind: str, before_consumed: set) -> None:
        """Merge the consumed sets suspended at ``kind`` in the current
        loop's frame into the consumed set: what those branches consumed
        beyond the loop's entry state is consumed at the kind's target."""
        for suspended in self._lin_exits.get(kind, ()):
            self._consumed |= suspended - before_consumed

    def _suspend_linear_exit(self, block: A.Block) -> None:
        """THE ONE place a diverging branch's linear state is parked by
        exit kind for the enclosing loop's frame: a branch ending in
        ``break`` or ``continue`` does not reach the merge after its
        ``if`` / ``match``, but it does reach the loop's exit or head. A
        ``return`` branch reaches nothing else in this frame and is not
        suspended."""
        kind = self._jump_kind(block.stmts[-1]) if block.stmts else None
        if kind in ("break", "continue"):
            self._lin_exits.setdefault(kind, []).append(set(self._consumed))

    def _check_if(self, s: A.IfStmt) -> None:
        from ._expressions import _block_diverges
        cond_ty = self._check_expr(s.cond)
        if not compatible(TyBool, cond_ty):
            self._err(
                f"if condition must be Bool, got {ty_str(cond_ty)}",
                s.cond.pos,
            )
        # Roadmap S4: a @constant_time function cannot branch on a secret.
        self._ct_reject(self._label_of(s.cond), s.cond.pos, "an if-condition")
        # Flow analysis: snapshot ``_consumed`` before each branch
        # and take the conservative union after. Branches whose
        # body diverges (ends in ``return`` / ``break`` /
        # ``continue``) are excluded from the merge -- their
        # ``_consumed`` set cannot flow past the if because the
        # path itself does not reach the merge point. Matches the
        # divergence treatment match-arm type-unification already
        # uses (see _check_match_expr). A ``break`` / ``continue``
        # branch's set is not lost, though: it is suspended by exit
        # kind for the enclosing loop, which merges it at the loop
        # exit / head (``_suspend_linear_exit``).
        before = set(self._consumed)
        branch_results: list[set[str]] = []
        # Roadmap S1: track each non-diverging branch's surviving
        # linear obligations too. A value must be consumed on EVERY
        # path, so the post-if live set is the UNION of survivors --
        # a value still live after any reachable branch is still an
        # outstanding obligation (and one consumed on some-but-not-all
        # paths therefore surfaces here, since it survives on the
        # paths that didn't consume it). Diverging branches (return /
        # break / continue) are excluded: that path doesn't reach the
        # merge, and the consume obligation it carried is its own
        # (a diverging branch that drops a linear value is caught by
        # the function/loop exit checks on that path, not here).
        before_live = dict(self._live_linear)
        branch_live: list[dict] = []
        # Connection C: per-FIELD discharge is INTERSECTION-merged (a field
        # counts as moved-at-scope-exit only if moved on ALL reachable
        # paths), the opposite lattice to ``_consumed`` above. Each branch
        # starts from the pre-if snapshot; the merge intersects the
        # non-diverging branches, so a field consumed in one branch but not
        # another stays outstanding.
        before_field_moved = set(self._linear_field_moved)
        branch_field_moved: list[set[str]] = []
        # Branch-scoped container-mutation taint: each branch starts from the
        # pre-if snapshot in isolation, and every non-diverging branch's
        # additions are unioned back after the if, so a push in one branch is
        # not seen by a mutually-exclusive sibling branch's read but is seen
        # by a read after the if.
        before_ct = dict(self._container_taint_map())
        branch_ct: list[dict] = []

        # Roadmap S2.implicit: each branch body is guarded by all the
        # conditions evaluated to reach it, so the pc-label rises by the
        # join of those condition labels. ``acc_pc`` accumulates them:
        # the then-block sees ``cond``; each elif sees ``cond`` plus the
        # earlier elif conditions; the else sees all of them. A sink
        # under a secret pc is an implicit-flow leak (checked in
        # ``_check_ifc_sink``). Conditions themselves are evaluated
        # under the outer pc; only the bodies are raised.
        saved_pc = self._pc_label
        acc_pc = L.join(saved_pc, self._label_of(s.cond))

        self._consumed = set(before)
        self._live_linear = dict(before_live)
        self._linear_field_moved = set(before_field_moved)
        self._pc_label = acc_pc
        self._container_isolate(before_ct)
        self._check_block(s.then_block)
        if not _block_diverges(s.then_block):
            branch_results.append(self._consumed)
            branch_live.append(dict(self._live_linear))
            branch_field_moved.append(set(self._linear_field_moved))
            branch_ct.append(self._container_taint)
        else:
            self._suspend_linear_exit(s.then_block)

        for cond, blk in s.elif_arms:
            self._consumed = set(before)
            self._live_linear = dict(before_live)
            self._linear_field_moved = set(before_field_moved)
            self._pc_label = saved_pc
            cty = self._check_expr(cond)
            if not compatible(TyBool, cty):
                self._err(
                    f"elif condition must be Bool, got {ty_str(cty)}",
                    cond.pos,
                )
            self._ct_reject(self._label_of(cond), cond.pos, "an elif-condition")
            acc_pc = L.join(acc_pc, self._label_of(cond))
            self._pc_label = acc_pc
            self._container_isolate(before_ct)
            self._check_block(blk)
            if not _block_diverges(blk):
                branch_results.append(self._consumed)
                branch_live.append(dict(self._live_linear))
                branch_field_moved.append(set(self._linear_field_moved))
                branch_ct.append(self._container_taint)
            else:
                self._suspend_linear_exit(blk)

        if s.else_block is not None:
            self._consumed = set(before)
            self._live_linear = dict(before_live)
            self._linear_field_moved = set(before_field_moved)
            self._pc_label = acc_pc
            self._container_isolate(before_ct)
            self._check_block(s.else_block)
            if not _block_diverges(s.else_block):
                branch_results.append(self._consumed)
                branch_live.append(dict(self._live_linear))
                branch_field_moved.append(set(self._linear_field_moved))
                branch_ct.append(self._container_taint)
            else:
                self._suspend_linear_exit(s.else_block)
        else:
            # No else: the all-conditions-false path falls
            # through and consumes nothing additional.
            branch_results.append(before)
            branch_live.append(dict(before_live))
            branch_field_moved.append(set(before_field_moved))

        if branch_results:
            merged: set[str] = set()
            for s_set in branch_results:
                merged |= s_set
            self._consumed = merged
            # Union of surviving obligations across reachable branches.
            merged_live: dict = {}
            for live in branch_live:
                merged_live.update(live)
            self._live_linear = merged_live
            # Intersection of per-field moves: a field is discharged past
            # the if only if moved on every reachable branch.
            self._linear_field_moved = set.intersection(*branch_field_moved)
        else:
            # Every branch diverges; the code after this if is
            # unreachable. Keep state at the pre-if snapshot so any
            # further (unreachable) analysis sees no spurious change.
            self._consumed = before
            self._live_linear = before_live
            self._linear_field_moved = before_field_moved

        # Restore the pc-label: the implicit-flow raise scoped only to
        # the branch bodies (roadmap S2.implicit).
        self._pc_label = saved_pc
        # Union each reachable branch's container-mutation taint back into
        # the enclosing scope (deferred). If every branch diverged, the
        # baseline stands (nothing reached the merge).
        self._container_merge(before_ct, branch_ct)

    def _check_while(self, s: A.WhileStmt) -> None:
        # Roadmap S2.implicit: the body runs under a pc raised by the
        # controlling condition, and the condition is re-evaluated on
        # every iteration, so its label is part of the loop's state: it
        # is evaluated ONCE, by the real pass, AFTER the fixpoint has
        # stabilised the labels the body writes, and its label is joined
        # into the body pc there (a value the body makes secret makes the
        # iteration count secret). That one evaluation carries the
        # condition's diagnostics (its type, the constant-time rule, a
        # sink reached through it), under the entry pc. The speculative
        # passes walk the body alone: a label the condition would raise
        # in them is raised by the real pass, whose pc subsumes every
        # in-body effect of the condition being secret.
        entry_pc = self._pc_label

        def real(head_pc):
            self._pc_label = entry_pc
            cty = self._check_expr(s.cond)
            if not compatible(TyBool, cty):
                self._err(
                    f"while condition must be Bool, got {ty_str(cty)}",
                    s.cond.pos,
                )
            # Roadmap S4: a @constant_time function cannot loop on a
            # secret (the iteration count would leak it).
            self._ct_reject(
                self._label_of(s.cond), s.cond.pos, "a while-condition",
            )
            self._pc_label = L.join(head_pc, self._label_of(s.cond))
            return self._check_block(s.body)

        self._check_loop(entry_pc, lambda: self._check_block(s.body), real)

    def _check_for(self, s: A.ForStmt) -> None:
        iter_ty = self._check_expr(s.iter)
        # Roadmap S2: an element drawn from a tainted iterable is
        # tainted, so the loop variable inherits the iterable's
        # WHOLE-VALUE label (mirrors the element-of-tainted-container rule
        # for indexing). Iterating observes each element's PRESENCE, not
        # only its value, so over a ``filter`` on a secret predicate the
        # loop variable is tainted by the secret STRUCTURE (which / how
        # many elements are present discloses the predicate). Only a
        # STRUCTURE query (length / is_empty) reads the lower structure
        # label.
        iter_label = self._label_of(s.iter)
        elem_ty: Ty = TyUnknown
        # Capa's iterables are exactly ``List<T>``, ``Set<T>``,
        # ``Range`` and ``String`` (code-point-by-code-point). Each
        # collection exposes its element type as its single type
        # argument; ``String`` iterates Unicode code points, each
        # bound as a one-codepoint ``String`` (Capa models a Char as
        # a one-codepoint String, and the Python backend yields
        # one-character strings). A future ``Iterable`` trait would
        # consolidate this dispatch, but the enumeration is sound
        # until it lands. Anything else has no sound lowering on
        # either backend, so reject it here rather than let the
        # Python backend silently iterate a Map's keys or crash,
        # while the Wasm backend emits a clean error.
        if (
            isinstance(iter_ty, TyName)
            and iter_ty.name in ("List", "Set", "Range") and iter_ty.args
        ):
            elem_ty = iter_ty.args[0]
        elif isinstance(iter_ty, TyName) and iter_ty.name == "String":
            # Each iteration yields a one-codepoint String, so the
            # loop variable is typed ``String``; the body can use it
            # as a String (interpolate, compare, concatenate, pass to
            # a String-typed parameter). A tuple-destructuring pattern
            # has no tuple element to bind here, so reject it cleanly
            # rather than bind its components to ``Unknown``.
            elem_ty = TyString
            if isinstance(s.pattern, A.TuplePat):
                self._err(
                    "cannot destructure a String element with a tuple "
                    "pattern: each iteration yields a one-codepoint "
                    "String, not a tuple",
                    s.pattern.pos,
                )
        elif isinstance(iter_ty, TyName) and iter_ty.name in (
            "List", "Set", "Range"
        ):
            # Iterable shapes whose element type we don't pin here
            # (a bare ``Range`` without args). The loop variable stays
            # ``Unknown``; downstream dispatch falls back to runtime
            # typing.
            elem_ty = TyUnknown
        elif iter_ty is TyUnknown:
            # Inference could not resolve the iterable's type (a
            # prior error, or an untyped expression). Don't pile a
            # spurious not-iterable error on top.
            elem_ty = TyUnknown
        elif isinstance(iter_ty, TyName) and iter_ty.name == "Map":
            # A Map is not iterable directly: the Python backend
            # would silently iterate its keys (plain form) or crash
            # on a leaked host ``ValueError`` (the ``for (k, v)``
            # destructuring form), while the Wasm backend errors.
            # Point the user at the keys()/values() views instead.
            self._err(
                f"cannot iterate a {ty_str(iter_ty)} directly; iterate "
                f"its keys with '.keys()' or its values with '.values()'",
                s.iter.pos,
            )
        else:
            # Any other type (numeric / boolean scalar, struct,
            # tuple, ...) is not iterable.
            self._err(
                f"cannot iterate: {ty_str(iter_ty)} is not iterable "
                f"(Capa iterables are List, Set, Range, and String)",
                s.iter.pos,
            )

        # Roadmap S2.implicit: whether (and how many times) the body
        # runs depends on the iterated collection, so the body runs under
        # a pc raised by the collection expression's label. A secret
        # collection makes a public sink in the body an implicit leak
        # (the iteration count reveals information about the secret).
        # The iterable is evaluated ONCE, before the loop, so its label
        # is read once here and is not part of the fixpoint state (unlike
        # a ``while`` condition). Restored in the ``finally`` so the raise
        # scopes to the body only; strict-gated downstream, so the default
        # tier is unaffected.
        saved_pc = self._pc_raise(s.iter)
        self._reject_nested_struct_in_binding(s.pattern)

        def walk():
            self._push_scope()
            try:
                self._bind_pattern(
                    s.pattern, elem_ty, mutable=False, init_expr=s.iter,
                )
                self._label_pattern_binds(s.pattern, iter_label, elem_ty)
                return self._check_stmt_seq(s.body.stmts)
            finally:
                self._pop_scope()

        def real(head_pc):
            self._pc_label = head_pc
            return walk()

        try:
            self._check_loop(self._pc_label, walk, real)
        finally:
            self._pc_label = saved_pc

    def _check_return(self, s: A.ReturnStmt) -> None:
        if s.value is None:
            actual = TyUnit
        else:
            actual = self._check_expr(s.value)
        expected = self.current_return_type or TyUnit
        ret_ok = (
            self._assignable(expected, actual, s.value)
            if s.value is not None
            else compatible(expected, actual)
        )
        if not ret_ok:
            self._err(
                f"return: expected {ty_str(expected)}, got {ty_str(actual)}",
                s.pos,
            )
        # Higher-order IFC: returning a secret-returning closure as a
        # public-returning function result launders the captured secret to
        # the caller, who can invoke it at a public sink. Flag it here.
        if s.value is not None:
            self._check_closure_ret_flow(
                expected, actual, s.pos, "returned",
            )
        # Roadmap S1: ``return <value>`` transfers the linear obligation to
        # the caller -- discharge it here so it isn't reported as a leak at
        # function exit.
        self._discharge_return_operand(s.value, s.pos)

    def _discharge_return_operand(self, value: A.Expr, pos: Pos) -> None:
        """Transfer the linear/typestate obligation a returned operand carries
        to the caller, at the ``return`` site. A bare Ident naming a live or
        borrowed value routes into the discharge guard (a borrowed one is
        rejected -- the caller still owns it); a spent husk Ident is rejected
        (returning it re-transfers an already-moved field); a field projection
        moves the field's subtree out through the ONE field-projection mover.

        E3: a ``Call`` / ``MethodCall`` operand whose result LAUNDERS a
        linear/typestate argument (``return id(x)``) moves the aliased
        argument off its source through the ONE move seam, so the transfer is
        accounted for exactly once."""
        self._move_transfer_operand(value, pos)
