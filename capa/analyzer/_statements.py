"""Statement-level checking mixin.

Implements ``_check_block`` and ``_check_stmt`` plus the
per-shape checkers:

- ``_check_let`` / ``_check_var``: binding introductions with
  inference and capability-flow exceptions for call-returned
  fresh capabilities.
- ``_check_assign``: assignment with mutability validation
  (immutable ``let``s, constants, and parameters cannot be
  reassigned).
- ``_check_if``: branch-aware ``_consumed`` snapshot + merge.
- ``_check_while``, ``_check_for``: two-pass dry-run / real-run
  analysis so capabilities consumed in body iteration N are
  flagged as consumed before iteration N+1 sees them.
- ``_check_return``: validate the return value against the
  current function's expected return type.
- ``_snapshot_for_dry_run`` / ``_restore_after_dry_run``: the
  flow-analysis bookkeeping the loop checkers rely on.

The mixin assumes ``self`` has the analyzer state set up and
pulls helpers from the other mixins (``_check_expr``,
``_bind_pattern``, ``_resolve_type``, ``_check_no_capability``,
``_err``, ``_push_scope``, ``_pop_scope``).
"""

from __future__ import annotations

from .. import capa_ast as A
from .. import _labels as L
from ..typesys import (
    Ty, TyBool, TyName, TyString, TyUnit, TyUnknown,
    compatible, ty_str,
)


class _StatementsMixin:
    def _check_block(self, block: A.Block) -> None:
        self._push_scope()
        for stmt in block.stmts:
            self._check_stmt(stmt)
            # Roadmap S2.implicit (strict only): a divergence (return /
            # break / continue / panic) that runs under a secret pc makes
            # the fall-through control-dependent on the secret -- reaching
            # the statements AFTER it reveals that the divergence did NOT
            # fire (audit 2026-06-17). ``var x = "y"; if secret > 0:
            # return; sink("leak")`` leaks the predicate bit through the
            # sink's mere execution. The per-statement pc raises and
            # restores around its own body, so we re-raise the ENCLOSING
            # block's pc here for the remaining statements. Monotonic
            # (never lowers); strict-only, so the default tier is
            # unchanged.
            if getattr(self, "_strict_ifc", False):
                secret_div = self._secret_conditioned_divergence(stmt)
                if secret_div is not None:
                    self._pc_label = L.join(self._pc_label, secret_div)
        self._pop_scope()

    def _secret_conditioned_divergence(self, stmt: A.Stmt):
        """The pc-label under which ``stmt`` could DIVERGE (return / break
        / continue / panic) out of the enclosing block when that
        divergence is conditioned on a @secret value, or ``None`` when
        ``stmt`` carries no such secret-conditioned divergence. Strict-only
        helper for ``_check_block``'s post-statement pc raise.

        Covers the conditional shapes that can host an early divergence:
        an ``if`` (any branch ending in return / break / continue, or a
        bare ``panic(...)`` statement), and a ``while`` / ``for`` whose
        body diverges. The returned label is the join of the guarding
        condition labels; only a @secret guard raises the block pc."""
        if isinstance(stmt, A.IfStmt):
            guards = [stmt.cond] + [c for c, _ in stmt.elif_arms]
            guard_label = L.join_all(self._label_of(c) for c in guards)
            if L.normalize(guard_label) != L.SECRET:
                return None
            arms = (
                [stmt.then_block]
                + [b for _, b in stmt.elif_arms]
                + ([stmt.else_block] if stmt.else_block is not None else [])
            )
            if any(self._block_has_divergence(b) for b in arms):
                return guard_label
            return None
        if isinstance(stmt, (A.WhileStmt, A.ForStmt)):
            ctrl = stmt.cond if isinstance(stmt, A.WhileStmt) else stmt.iter
            ctrl_label = self._label_of(ctrl)
            if L.normalize(ctrl_label) != L.SECRET:
                return None
            if self._block_has_divergence(stmt.body):
                return ctrl_label
            return None
        return None

    def _block_has_divergence(self, block) -> bool:
        """True if ``block`` contains a divergence (return / break /
        continue, or a bare ``panic(...)`` call statement) on some path.
        Conservative: any nested occurrence counts, since reaching past
        the enclosing branch reveals the divergence did not fire."""
        if block is None:
            return False
        for st in block.stmts:
            if isinstance(st, (A.ReturnStmt, A.BreakStmt, A.ContinueStmt)):
                return True
            if isinstance(st, A.ExprStmt) and self._is_panic_call(st.expr):
                return True
            if isinstance(st, A.IfStmt):
                arms = (
                    [st.then_block]
                    + [b for _, b in st.elif_arms]
                    + ([st.else_block] if st.else_block is not None else [])
                )
                if any(self._block_has_divergence(b) for b in arms):
                    return True
            if isinstance(st, (A.WhileStmt, A.ForStmt)):
                if self._block_has_divergence(st.body):
                    return True
        return False

    def _is_panic_call(self, e) -> bool:
        """True if ``e`` is a call to the built-in ``panic`` (a divergent
        abort that writes to stderr). Mirrors ``_is_declassify_call``'s
        builtin-position guard so a user function named ``panic`` is not
        treated as divergent here."""
        from ..builtins import BUILTIN_POS
        if not isinstance(e, A.Call):
            return False
        if not isinstance(e.callee, A.Ident) or e.callee.name != "panic":
            return False
        sym = self.bindings.get(id(e.callee))
        return sym is not None and sym.pos == BUILTIN_POS

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
                # (record the node's type, label it) since we bypassed
                # it to pass the expected element type.
                self.types[id(s.value)] = actual
                self._label_expr(s.value)
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
        self._bind_pattern(s.pattern, actual, mutable=False)
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
            self._label_pattern_binds(s.pattern, self._label_of(s.value))
        # Roadmap S1: a ``let h = open()`` of a linear-typed value
        # opens a must-consume obligation under the bound name. Only
        # a simple identifier pattern carries it (a destructure of a
        # linear value is not in S1's scope). If the RHS is itself a
        # bare identifier we treated as a move below in
        # ``_check_ident``; here the common ``let h = <call>`` case is
        # the obligation source.
        if isinstance(s.pattern, A.IdentPat):
            # ``let h2 = h`` aliasing a live linear value MOVES the
            # obligation onto the new name (poisoning the source) so the
            # value stays single-owner; without this the source and alias
            # would each be independently consumable -> double-consume.
            self._linear_transfer_if_alias(s.value)
            self._linear_bind(s.pattern.name, actual, s.pos)
        elif isinstance(s.pattern, A.WildcardPat):
            # ``let _ = open()`` drops a linear value into a slot that
            # holds no obligation; flag it like a named leak.
            self._linear_check_anonymous_drop(s.value, actual, s.pos)

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
            actual = declared
        if not isinstance(s.value, (A.MethodCall, A.Call)):
            self._check_no_capability(actual, s.pos, "a 'var' binding")
        if self.scope.lookup_local(s.name) is not None:
            self._err(f"duplicate declaration of {s.name!r}", s.pos)
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
        self.scope.define(sym)
        # Roadmap S2 (two-hop closure-by-name): record a lambda-literal
        # RHS on the fresh ``var`` binding. A subsequent reassignment in
        # ``_check_assign`` poisons it (the denotation becomes ambiguous),
        # so only a never-reassigned ``var`` stays precise.
        self._record_binding_lambda(sym, s.value, fresh=True)
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
        self._linear_transfer_if_alias(s.value)
        self._linear_bind(s.name, actual, s.pos)

    def _check_assign(self, s: A.AssignStmt) -> None:
        from . import SymbolKind

        # Roadmap S1: the left side of ``h = ...`` is a WRITE target, not
        # a use, so reading a poisoned (already-consumed) linear name here
        # must not raise use-after-consume -- ``close(h); h = open()`` is
        # the legitimate re-arm. Lift the poison on a bare-identifier
        # target before evaluating it; ``_linear_reassign`` below restores
        # the correct obligation state from the fresh RHS.
        if isinstance(s.target, A.Ident) and s.target.name in self._consumed:
            self._consumed.discard(s.target.name)
            self._linear_names.discard(s.target.name)
        target_ty = self._check_expr(s.target)
        value_ty = self._check_expr(s.value)
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
            # Roadmap S1: re-assigning a name (``h = open()``) that still
            # holds a live linear obligation drops the old value (a leak);
            # the fresh RHS re-arms the obligation if it is itself linear.
            # Only the legal-mutation case (an immutable ``let`` was not
            # rejected above) reaches a useful state, but running this
            # unconditionally is harmless: a poisoned/consumed name simply
            # is not in ``_live_linear`` and the fresh value re-binds.
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
        # Roadmap S2 (per-field IFC): a field store ``p.f = x`` raises
        # that field's per-field label monotonically (and the binding's
        # collapsed label), so a field made secret by a later assignment
        # is tracked precisely while never lowering an already-secret
        # field. Only ``=`` is handled here; an augmented ``+=`` already
        # reads the old (tracked) field on its RHS, so the join is sound.
        if isinstance(s.target, A.FieldAccess):
            self._ifc_field_store(s.target, s.value)

    def _snapshot_for_dry_run(self) -> dict:
        """Capture mutable analyzer state before a speculative
        pass. Used by loop analysis: we run the body once
        silently to discover which caps will be consumed, then
        replay the run for real after pre-marking those caps."""
        return {
            "consumed": self._consumed.copy(),
            "errors_len": len(self.errors),
            "warnings_len": len(self.warnings),
            "bindings_keys": set(self.bindings.keys()),
            "types_keys": set(self.types.keys()),
        }

    def _restore_after_dry_run(self, snap: dict) -> None:
        """Reverse :meth:`_snapshot_for_dry_run`. Added bindings /
        types are removed by key; new errors are truncated;
        ``_consumed`` reverts."""
        self._consumed = snap["consumed"]
        self.errors = self.errors[: snap["errors_len"]]
        # Drop any IFC warnings emitted during the speculative pass so
        # the real pass below is the single source of each diagnostic
        # (otherwise a sink in a loop body warns twice).
        self.warnings = self.warnings[: snap["warnings_len"]]
        for k in list(self.bindings.keys()):
            if k not in snap["bindings_keys"]:
                del self.bindings[k]
        for k in list(self.types.keys()):
            if k not in snap["types_keys"]:
                del self.types[k]

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
        # uses (see _check_match_expr).
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
        self._pc_label = acc_pc
        self._check_block(s.then_block)
        if not _block_diverges(s.then_block):
            branch_results.append(self._consumed)
            branch_live.append(dict(self._live_linear))

        for cond, blk in s.elif_arms:
            self._consumed = set(before)
            self._live_linear = dict(before_live)
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
            self._check_block(blk)
            if not _block_diverges(blk):
                branch_results.append(self._consumed)
                branch_live.append(dict(self._live_linear))

        if s.else_block is not None:
            self._consumed = set(before)
            self._live_linear = dict(before_live)
            self._pc_label = acc_pc
            self._check_block(s.else_block)
            if not _block_diverges(s.else_block):
                branch_results.append(self._consumed)
                branch_live.append(dict(self._live_linear))
        else:
            # No else: the all-conditions-false path falls
            # through and consumes nothing additional.
            branch_results.append(before)
            branch_live.append(dict(before_live))

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
        else:
            # Every branch diverges; the code after this if is
            # unreachable. Keep state at the pre-if snapshot so any
            # further (unreachable) analysis sees no spurious change.
            self._consumed = before
            self._live_linear = before_live

        # Restore the pc-label: the implicit-flow raise scoped only to
        # the branch bodies (roadmap S2.implicit).
        self._pc_label = saved_pc

    def _check_while(self, s: A.WhileStmt) -> None:
        cty = self._check_expr(s.cond)
        if not compatible(TyBool, cty):
            self._err(
                f"while condition must be Bool, got {ty_str(cty)}",
                s.cond.pos,
            )
        # Roadmap S4: a @constant_time function cannot loop on a secret
        # (the iteration count would leak it).
        self._ct_reject(self._label_of(s.cond), s.cond.pos, "a while-condition")
        # Roadmap S2.implicit: the loop body runs under a pc raised by
        # the controlling condition -- whether (and how many times) the
        # body executes depends on ``cond``, so a public sink inside a
        # secret-conditioned loop leaks the same one bit an ``if`` would.
        # ``_pc_raise`` joins the condition's label into pc and returns
        # the previous value; restore it in the ``finally`` so the raise
        # scopes only to the loop body (no pc leak into later statements).
        # Harmless to the default tier: the implicit-sink clause it feeds
        # is itself strict-gated.
        saved_pc = self._pc_raise(s.cond)
        # Two-pass fixed-point flow analysis. Pass 1 (dry-run):
        # visit the body silently to discover which caps will be
        # consumed. Pass 2 (real): pre-mark those caps and run
        # the body for real, so use-after-consume across loop
        # iterations is caught in a single static analysis.
        self._loop_depth += 1
        try:
            snap = self._snapshot_for_dry_run()
            self._check_block(s.body)
            consumed_in_body = self._consumed - snap["consumed"]
            self._restore_after_dry_run(snap)

            self._consumed |= consumed_in_body
            self._check_block(s.body)
        finally:
            self._loop_depth -= 1
            self._pc_label = saved_pc

    def _check_for(self, s: A.ForStmt) -> None:
        iter_ty = self._check_expr(s.iter)
        # Roadmap S2: an element drawn from a tainted iterable is
        # tainted, so the loop variable inherits the iterable's label
        # (mirrors the element-of-tainted-container rule for indexing).
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
        # Restored in the ``finally`` so the raise scopes to the body
        # only; strict-gated downstream, so the default tier is unaffected.
        saved_pc = self._pc_raise(s.iter)
        self._reject_nested_struct_in_binding(s.pattern)
        # Same two-pass dry-run / real-run dance as ``_check_while``.
        self._loop_depth += 1
        try:
            snap = self._snapshot_for_dry_run()
            self._push_scope()
            self._bind_pattern(s.pattern, elem_ty, mutable=False)
            self._label_pattern_binds(s.pattern, iter_label)
            for stmt in s.body.stmts:
                self._check_stmt(stmt)
            self._pop_scope()
            consumed_in_body = self._consumed - snap["consumed"]
            self._restore_after_dry_run(snap)

            self._consumed |= consumed_in_body
            self._push_scope()
            self._bind_pattern(s.pattern, elem_ty, mutable=False)
            self._label_pattern_binds(s.pattern, iter_label)
            for stmt in s.body.stmts:
                self._check_stmt(stmt)
            self._pop_scope()
        finally:
            self._loop_depth -= 1
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
        # Roadmap S1: ``return h`` transfers the linear obligation to
        # the caller -- discharge it here so it isn't reported as a
        # leak at function exit.
        if isinstance(s.value, A.Ident) and s.value.name in self._live_linear:
            self._linear_discharge(s.value.name)
