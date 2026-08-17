"""Pattern binding and match-exhaustiveness mixin.

Five methods that together handle the pattern-matching parts of
the analyzer:

- ``_bind_pattern``: introduce a pattern's names into the
  current scope with the type they receive from the scrutinee.
  Handles wildcards, identifier patterns, literals, variants
  (with payload substitution), structs (with field destructuring
  and shorthand), tuples (with arity check), and or-patterns
  (with cross-alternative consistency).
- ``_pattern_has_binding``: predicate used to enforce the v0
  restriction that or-patterns cannot bind names.
- ``_pattern_is_catchall``: predicate used by exhaustiveness.
- ``_flatten_or_pat``: linearise or-pattern alternatives for
  exhaustiveness collection.
- ``_check_match_exhaustiveness``: enforce that ``match`` covers
  every case the scrutinee's type admits.

The mixin assumes ``self`` has the analyzer state (``scope``,
``global_scope``, ``errors`` + ``_err``, ``_hint_did_you_mean``,
``_variant_names``, ``_check_expr``) set up.
"""

from __future__ import annotations

from .. import capa_ast as A
from ..typesys import (
    Ty, TyName, TyTuple, TyUnit, TyUnknown, TyVar,
    compatible, substitute, ty_str,
)


class _PatternsMixin:
    def _check_match_exhaustiveness(
        self, s: A.MatchExpr, scrutinee_ty: Ty,
    ) -> None:
        """Check that the match covers all possible cases.

        Conservative strategy for v1:

        - If any arm has ``WildcardPat`` or ``IdentPat`` without
          a guard, the match is exhaustive (that arm captures
          everything). OK.
        - If the scrutinee has type ``Bool``, require coverage
          of both ``true`` and ``false``.
        - If the scrutinee has a sum type, check that every
          variant appears as a ``VariantPat`` in some arm
          without a guard.
        - Other cases (Int, structs) are not checked: Int has
          2^64 values and structs do not have alternatives.
        - Arms with a guard do NOT count toward coverage (the
          guard may fail).
        - Any arm following a guardless catch-all is unreachable
          and reported as an error before exhaustiveness runs.
        """
        # Unreachable-arm check: walk arms in order, track what has
        # already been covered by a guardless arm, and report each
        # arm that cannot match. Three sources of unreachability:
        #
        #   - A previous arm is a guardless catch-all (`_` or a bare
        #     ident pattern); it has matched every possible value.
        #   - A previous arm already named the same payload-less
        #     variant.
        #   - A previous arm already named the same literal value.
        #
        # Guarded arms (``x if cond -> ...``) do not register coverage
        # because the guard may fail and let later arms match.
        seen_catchall = False
        seen_variants: set[str] = set()
        seen_literals: set = set()
        for arm in s.arms:
            if seen_catchall:
                self._err(
                    "unreachable match arm: a previous arm is a "
                    "catch-all (`_` or a bare binding) without a "
                    "guard and captures every value already",
                    arm.pattern.pos,
                )
                continue
            if arm.guard is None:
                # Report duplicate variant / literal coverage before
                # the registration step so the SECOND occurrence is
                # the one flagged, not the first. Tracking happens
                # both across earlier arms (the global ``seen_*``
                # sets) and within this arm's own or-pattern (the
                # local ``arm_*`` sets), so ``Vermelho | Vermelho``
                # inside a single arm is flagged too.
                arm_variants: set[str] = set()
                arm_literals: set = set()
                for sub in self._flatten_or_pat(arm.pattern):
                    if (
                        isinstance(sub, A.VariantPat)
                        and not sub.payloads
                    ):
                        if (
                            sub.name in seen_variants
                            or sub.name in arm_variants
                        ):
                            self._err(
                                f"unreachable match arm: variant "
                                f"{sub.name!r} is already covered "
                                f"by an earlier arm",
                                sub.pos,
                            )
                        arm_variants.add(sub.name)
                    elif isinstance(sub, A.LiteralPat):
                        key = self._literal_pattern_key(sub.value)
                        if key is not None and (
                            key in seen_literals or key in arm_literals
                        ):
                            self._err(
                                f"unreachable match arm: literal "
                                f"value already covered by an "
                                f"earlier arm",
                                sub.pos,
                            )
                        if key is not None:
                            arm_literals.add(key)
            if arm.guard is None and self._pattern_is_catchall(arm.pattern):
                seen_catchall = True
                continue
            if arm.guard is None:
                for sub in self._flatten_or_pat(arm.pattern):
                    if (
                        isinstance(sub, A.VariantPat)
                        and not sub.payloads
                    ):
                        seen_variants.add(sub.name)
                    elif isinstance(sub, A.LiteralPat):
                        key = self._literal_pattern_key(sub.value)
                        if key is not None:
                            seen_literals.add(key)

        # Catch-all arm without guard? Exhaustive by definition.
        for arm in s.arms:
            if arm.guard is not None:
                continue
            if self._pattern_is_catchall(arm.pattern):
                return

        if isinstance(scrutinee_ty, TyName) and scrutinee_ty.name == "Bool":
            covered_bool: set[bool] = set()
            for arm in s.arms:
                if arm.guard is not None:
                    continue
                for sub in self._flatten_or_pat(arm.pattern):
                    if isinstance(sub, A.LiteralPat) and isinstance(
                        sub.value, A.BoolLit
                    ):
                        covered_bool.add(sub.value.value)
            missing_bool = {True, False} - covered_bool
            if missing_bool:
                missing_str = ", ".join(
                    "true" if m else "false"
                    for m in sorted(missing_bool, reverse=True)
                )
                self._err(
                    f"non-exhaustive match on Bool: missing "
                    f"{missing_str} (add '_ -> ...' to handle "
                    f"remaining cases)",
                    s.pos,
                )
            return

        from . import SymbolKind
        type_sym = (
            self.global_scope.lookup(scrutinee_ty.name)
            if isinstance(scrutinee_ty, TyName) else None
        )
        # A type is a sum (for exhaustiveness) when it carries variants.
        # User ``type ... = A | B`` is registered as ``TYPE_SUM``; the
        # built-in ``Option`` / ``Result`` are registered as
        # ``TYPE_STRUCT`` for historical reasons but still carry their
        # variants in ``sum_variants``, so key off that dict rather than
        # the symbol kind alone.
        is_sum = type_sym is not None and (
            type_sym.kind == SymbolKind.TYPE_SUM
            or bool(type_sym.sum_variants)
        )
        if not is_sum:
            # Bool, sum types, and a single irrefutable catch-all arm
            # are already handled above. What remains here is a value
            # match whose scrutinee is an open scalar domain (Int /
            # String / Float / Char) with no catch-all: it cannot be
            # exhausted by enumerating arms, so a miss has no defined
            # result (the Python backend crashes with UnboundLocalError,
            # the Wasm backend returns a zero value). Reject it in VALUE
            # position; in statement position the value is discarded and
            # a miss is a legal no-op, so stay lenient.
            #
            # Product / aggregate scrutinees (tuples, structs) and
            # unresolved types are intentionally left lenient: proving
            # exhaustiveness over the cross-product of their components
            # (e.g. ``(true, x) | (false, x)`` covering ``(Bool, Int)``)
            # is out of scope here, and the single-irrefutable-arm case
            # is already covered by the catch-all short-circuit above.
            OPEN_SCALARS = {"Int", "String", "Float", "Char"}
            scalar = (
                isinstance(scrutinee_ty, TyName)
                and scrutinee_ty.name in OPEN_SCALARS
            )
            if not scalar:
                return
            if id(s) in self._stmt_position_matches:
                return
            self._err(
                f"non-exhaustive match expression on "
                f"{ty_str(scrutinee_ty)}: a match used for its value "
                f"must cover every case; add '_ -> ...' (or a bare "
                f"binding) to handle the remaining cases",
                s.pos,
            )
            return

        # Statement-position coverage is enforced for true ``TYPE_SUM``
        # types (the historical behaviour) but NOT for the built-in
        # variant-carrying ``TYPE_STRUCT`` types (Option / Result): a
        # bare ``match opt`` whose value is discarded was always allowed
        # to omit a variant, and tightening that here would be an
        # unrelated regression. Value-position matches always require
        # full variant coverage.
        if (
            id(s) in self._stmt_position_matches
            and type_sym.kind != SymbolKind.TYPE_SUM
        ):
            return

        covered: set[str] = set()
        for arm in s.arms:
            if arm.guard is not None:
                continue
            for sub in self._flatten_or_pat(arm.pattern):
                if isinstance(sub, A.VariantPat):
                    covered.add(sub.name)

        all_variants = set(type_sym.sum_variants.keys())
        missing = all_variants - covered
        if missing:
            self._err(
                f"non-exhaustive match on {scrutinee_ty.name!r}: "
                f"missing variants {', '.join(sorted(missing))} "
                f"(add '_ -> ...' to handle remaining cases)",
                s.pos,
            )

    def _pattern_is_catchall(self, p: A.Pattern) -> bool:
        """``True`` iff the pattern is irrefutable: it matches every
        value of its type and so makes the match exhaustive.

        - A wildcard ``_`` or a bare ident binder matches anything.
        - An or-pattern is irrefutable when any alternative is.
        - A tuple pattern is irrefutable when every element pattern is
          (a product type is covered once each field is covered): so
          ``(x, y)`` or ``(g, _)`` catches all tuples, while ``(1, y)``
          does not (the first slot is a refutable literal).
        - A struct pattern is irrefutable when every field sub-pattern
          is (shorthand ``{field}`` binds, so it is irrefutable too).
          Structs are single-variant, so an all-irrefutable field
          destructure covers every value of the struct type.
        """
        if isinstance(p, (A.WildcardPat, A.IdentPat)):
            return True
        if isinstance(p, A.OrPat):
            return any(self._pattern_is_catchall(a) for a in p.alternatives)
        if isinstance(p, A.TuplePat):
            return all(self._pattern_is_catchall(e) for e in p.elements)
        if isinstance(p, A.StructPat):
            return all(
                fp is None or self._pattern_is_catchall(fp)
                for _, fp in p.fields
            )
        return False

    def _flatten_or_pat(self, p: A.Pattern) -> list[A.Pattern]:
        """Linearise the alternatives of an or-pattern. For
        non-Or patterns, return ``[p]``."""
        if isinstance(p, A.OrPat):
            result: list[A.Pattern] = []
            for a in p.alternatives:
                result.extend(self._flatten_or_pat(a))
            return result
        return [p]

    def _literal_pattern_key(self, value):
        """Return a hashable key for a literal pattern's value, used
        by the unreachable-arm check to detect duplicates. Returns
        ``None`` for shapes the check should not track (anything
        that is not one of the five literal expression types)."""
        if isinstance(value, (A.IntLit, A.FloatLit, A.StringLit,
                              A.CharLit, A.BoolLit)):
            return (type(value).__name__, value.value)
        return None

    def _duplicate_binding_message(self, name: str, prev) -> str:
        """Build the rich message for a duplicate ``let`` / ``var``
        binding: name the previous-definition location so the user
        does not have to scan for it, and remind them of the
        ``var`` + bare-assignment idiom for the common case ("I
        meant to update the value, not redeclare it")."""
        return (
            f"duplicate binding {name!r} (previous binding at "
            f"line {prev.pos.line}, col {prev.pos.col}); use "
            f"`var {name}` for a mutable binding and `{name} = ...` "
            f"to reassign, or rename if you want a distinct value"
        )

    def _enclosing_scope_local(self, name: str, bind_pos, init_expr=None):
        """Return the Symbol a binding of ``name`` at ``bind_pos`` inside a
        LAMBDA body would shadow from an ENCLOSING scope in a way the two
        backends compile differently, or ``None`` when the shadow is safe.
        ``init_expr`` is the binding's initializer (its ``let`` / ``var``
        RHS or a ``for`` iterable), consulted for the CONST / FUNCTION case.

        Only fires inside a lambda body: the nearest function-root scope on
        the current chain must be a lambda root (``is_lambda_root``). The
        lookup starts one scope OUTSIDE that lambda root and walks the full
        parent chain, so a name bound in ANY enclosing scope is found. Each
        nested lambda is checked in its own right against ITS enclosing
        scopes. The PLAIN-function analogue for a module const / function
        shadow is handled once, as a whole-function post-pass, by
        ``_check_module_shadow_divergence`` in ``_items.py``.

        Two divergence classes, distinguished by what the name binds to:

        - An enclosing PARAMETER or LOCAL (``PARAM`` / ``LOCAL`` /
          ``LOCAL_VAR``) ALWAYS diverges (the Wasm lowerer captures the
          enclosing local into the closure env while the Python transpiler
          function-scopes the redeclared name, disagreeing even when the
          outer value is never read -- the M1 no-free-read case). A blanket
          reject.

        - An enclosing module-level CONST or FUNCTION is a global on the
          Wasm side, so shadowing it inside the lambda is safe UNLESS the
          name is read OUTWARD: within the binding's own initializer
          (``let S = S`` reads the enclosing const, since ``S`` is not yet
          in scope in its own RHS), or BEFORE the shadowing binding in the
          closure body (a read masked by a nested closure that captured the
          global). An ordinary shadow that does neither (``let X = 3``)
          stays legal and byte-identical.

        A name bound WITHIN the same lambda (a parameter or a prior local)
        is handled separately by the same-function block-shadow check
        (``lookup_within_function``), which stops at this lambda root; this
        helper deliberately looks only OUTSIDE it, so the two checks do not
        overlap.
        """
        from . import SymbolKind
        scope = self.scope
        while scope is not None and not scope.is_function_root:
            scope = scope.parent
        if scope is None or not scope.is_lambda_root:
            return None
        outer = scope.parent
        if outer is None:
            return None
        sym = outer.lookup(name)
        if sym is None:
            return None
        if sym.kind in (
            SymbolKind.PARAM, SymbolKind.LOCAL, SymbolKind.LOCAL_VAR,
        ):
            return sym
        if sym.kind in (SymbolKind.CONSTANT, SymbolKind.FUNCTION):
            # A read of the module const / function INSIDE the binding's own
            # initializer is an OUTWARD read: the binding is not yet in
            # scope during its own RHS, so ``let S = S`` reads the enclosing
            # global. Wasm keeps that lexical global while Python
            # function-scopes the whole body, so the two diverge.
            if init_expr is not None and self._reads_symbol(
                init_expr, sym, lambda ident: True,
            ):
                return sym
            # A read of the global BEFORE the shadowing binding in the
            # closure body diverges too (a nested closure captured the
            # global; Python later function-scopes the redeclared name).
            if self._lambda_ast_stack:
                lam_body = self._lambda_ast_stack[-1].body
                if self._reads_symbol(
                    lam_body, sym,
                    lambda ident: self._pos_before(ident.pos, bind_pos),
                ):
                    return sym
            return None
        return None

    def _first_symbol_read(self, node, sym):
        """The first ``A.Ident`` reachable from ``node`` that RESOLVES to
        ``sym`` (via ``self.bindings``), or ``None``. Names the read site
        in the module-shadow divergence diagnostic. ``_reads_symbol`` stops
        at the first accepted ident, so the recorded one is the first."""
        found = [None]

        def accept(ident) -> bool:
            found[0] = ident
            return True

        self._reads_symbol(node, sym, accept)
        return found[0]

    @staticmethod
    def _pos_before(pos, bind_pos) -> bool:
        """``True`` iff source position ``pos`` is strictly before
        ``bind_pos`` (line then column). A missing position is treated as
        not-before (conservative toward legal)."""
        if pos is None:
            return False
        return (pos.line, pos.col) < (bind_pos.line, bind_pos.col)

    def _reads_symbol(self, node, sym, accept) -> bool:
        """``True`` iff some ``A.Ident`` reachable from ``node`` RESOLVES to
        ``sym`` (via the analyzer's already-computed name resolution,
        ``self.bindings``) and satisfies ``accept``.

        Resolution-based rather than name-based on purpose: a read whose
        name matches ``sym`` but that the analyzer bound to a DIFFERENT
        symbol -- a ``match`` arm bind, a ``for`` variable, a nested-block
        ``let``, or a nested lambda parameter of the same name -- is
        correctly excluded, because it does not resolve to the module const
        / function being shadowed and so is not a divergence. Reads before
        the shadowing binding have already been resolved by the in-order
        walk, so their bindings are populated when this runs.
        """
        import dataclasses

        hit = [False]

        def walk(n) -> None:
            if hit[0] or n is None or isinstance(n, str):
                return
            if isinstance(n, A.Ident):
                if self.bindings.get(id(n)) is sym and accept(n):
                    hit[0] = True
                return
            if dataclasses.is_dataclass(n):
                for f in dataclasses.fields(n):
                    walk(getattr(n, f.name))
                return
            if isinstance(n, (list, tuple)):
                for x in n:
                    walk(x)

        walk(node)
        return hit[0]

    def _closure_shadow_message(self, name: str, prev) -> str:
        """Build the diagnostic for a binding that shadows a name from an
        enclosing scope in a backend-divergent way (inside a lambda body, or
        a self-referential / read-before shadow of a module const / function
        at plain function scope). Names the previous-definition site and
        states why the shadow is rejected: the two runtime backends compile
        it differently, so accepting it would let ``--check`` pass a program
        the backends disagree on. The wording does not assert a specific
        per-backend failure, because which backend is 'wrong' varies (for an
        enclosing parameter the Python result is correct and the Wasm one
        wrong; for a read-before / self-referential shadow Python raises
        while Wasm discloses the outer value)."""
        return (
            f"binding {name!r} may not shadow {name!r} from an enclosing "
            f"scope (previous binding at line {prev.pos.line}, col "
            f"{prev.pos.col}); the two runtime backends compile this shadow "
            f"differently, so rename the inner binding to a distinct name"
        )

    def _bind_pattern(
        self, p: A.Pattern, ty: Ty, mutable: bool, init_expr=None,
    ) -> None:
        """Bind the pattern's names to the current scope with
        the type they receive from the scrutinee. The full
        pattern grammar is supported (wildcard, ident, literal,
        variant, struct with shorthand, tuple, or).

        ``init_expr`` is the binding's initializer (the ``let`` / ``for``
        source expression), threaded through unchanged to every bound name
        so the closure-shadow check can spot a self-referential shadow of a
        module const / function (``let S = S``); ``None`` when there is no
        single initializer (a ``match`` arm)."""
        from . import Scope, Symbol, SymbolKind
        if isinstance(p, A.WildcardPat):
            return
        if isinstance(p, A.IdentPat):
            kind = SymbolKind.LOCAL_VAR if mutable else SymbolKind.LOCAL
            prev = self.scope.lookup_local(p.name)
            if prev is not None:
                self._err(
                    self._duplicate_binding_message(p.name, prev),
                    p.pos,
                )
            else:
                # Block-scope shadowing of a function-local
                # (parameter, prior ``let``, prior ``var``, or a
                # bound pattern in an enclosing block within the
                # same function or lambda) cannot be preserved by
                # the Python transpilation: Python has function
                # scope, not block scope, so the inner assignment
                # overwrites the outer binding for the rest of the
                # function. Reject the shadow here with a precise
                # message rather than silently emit code whose
                # runtime value disagrees with the source.
                #
                # The walk stops at the first ``is_function_root``
                # scope (set on FunDecl and LambdaExpr entry), so it
                # detects only shadowing WITHIN the same function or
                # lambda body. Module-level shadowing (CONSTANT,
                # FUNCTION, etc.) is fine because Python's function
                # scope makes the function-local rebind the module name
                # within the body without affecting the module-level
                # binding.
                prev_outer = self.scope.lookup_within_function(p.name)
                if prev_outer is not None and prev_outer.kind in (
                    SymbolKind.PARAM,
                    SymbolKind.LOCAL,
                    SymbolKind.LOCAL_VAR,
                ):
                    self._err(
                        f"binding {p.name!r} would shadow an outer-scope "
                        f"local of the same function (previous binding at "
                        f"line {prev_outer.pos.line}, col {prev_outer.pos.col}); "
                        f"the Python transpilation cannot preserve "
                        f"block-scope shadowing -- rename one of the bindings",
                        p.pos,
                    )
                else:
                    # A binding inside a lambda body that shadows a name
                    # from an ENCLOSING scope crosses the lambda boundary
                    # that the same-function walk stops at, and the two
                    # backends compile the shadow differently (the Wasm
                    # lowerer keeps the inner closure's lexical capture; the
                    # Python transpiler function-scopes the redeclared
                    # name). ``_enclosing_scope_local`` decides which
                    # enclosing shadows actually diverge (always for a
                    # parameter / local; for a module const / function only
                    # when the name is read before the binding or inside the
                    # binding's own initializer), so reject it here to keep
                    # ``--check`` from passing a program the backends run
                    # differently.
                    enclosing = self._enclosing_scope_local(
                        p.name, p.pos, init_expr,
                    )
                    if enclosing is not None:
                        self._err(
                            self._closure_shadow_message(p.name, enclosing),
                            p.pos,
                        )
            self.scope.define(
                Symbol(name=p.name, kind=kind, pos=p.pos, ty=ty)
            )
            return
        if isinstance(p, A.LiteralPat):
            lit_ty = self._check_expr(p.value)
            # The literal pattern only matches values of the same
            # type as the literal itself; matching ``"hello"``
            # against an Int scrutinee is dead code at best and a
            # typo at worst. ``compatible`` is permissive on
            # TyUnknown / TyVar, so generic code where the
            # scrutinee type is not fully resolved still passes.
            if not compatible(ty, lit_ty):
                self._err(
                    f"pattern: literal of type {ty_str(lit_ty)} "
                    f"cannot match a scrutinee of type {ty_str(ty)}",
                    p.pos,
                )
            return
        if isinstance(p, A.VariantPat):
            sym = self.scope.lookup(p.name)
            if sym is None:
                hint = self._hint_did_you_mean(
                    p.name, self._variant_names(ty),
                )
                self._err(f"unknown variant {p.name!r}{hint}", p.pos)
                for sub in p.payloads:
                    self._bind_pattern(sub, TyUnknown, mutable, init_expr)
                return
            if sym.kind != SymbolKind.VARIANT:
                self._err(f"{p.name!r} is not a variant", p.pos)
                for sub in p.payloads:
                    self._bind_pattern(sub, TyUnknown, mutable, init_expr)
                return
            payload_tys = sym.variant_payload_tys
            # Substitute the owner's type params (e.g. ``T`` in
            # ``Some<T>(T)``) with the scrutinee's args.
            subst: dict[str, Ty] = {}
            if (
                sym.variant_owner is not None
                and isinstance(ty, TyName)
                and ty.name == sym.variant_owner.name
                and len(ty.args) == len(sym.variant_owner.type_params)
            ):
                subst = dict(zip(sym.variant_owner.type_params, ty.args))
            # Arity check
            if p.payloads and len(p.payloads) != len(payload_tys):
                self._err(
                    f"variant {p.name!r} expects {len(payload_tys)} "
                    f"sub-pattern(s), got {len(p.payloads)}",
                    p.pos,
                )
            if p.payloads:
                for sub, pty in zip(p.payloads, payload_tys):
                    bound_ty = substitute(pty, subst) if subst else pty
                    if ty is TyUnknown and isinstance(bound_ty, TyVar):
                        bound_ty = TyUnknown
                    self._bind_pattern(sub, bound_ty, mutable, init_expr)
            elif payload_tys:
                self._err(
                    f"variant {p.name!r} requires {len(payload_tys)} "
                    f"sub-pattern(s)",
                    p.pos,
                )
            return
        if isinstance(p, A.StructPat):
            sym = self.scope.lookup(p.type_name)
            if sym is None or sym.kind != SymbolKind.TYPE_STRUCT:
                self._err(
                    f"{p.type_name!r} is not a struct type", p.pos,
                )
                return
            # Type-check the destructuring pattern against the scrutinee.
            #
            # A struct-destructuring pattern (``let Other { a } = t``,
            # ``for Other { a } in xs``, or a ``match`` arm) binds each
            # named field with the type it has in the PATTERN's struct
            # (``sym.struct_fields`` below), never the scrutinee's. When
            # the pattern names a DIFFERENT struct than the value has,
            # that rebinds the scrutinee's field under the twin's label:
            # a public-twin pattern over a ``@secret`` value launders the
            # secret into a public binding, silently, under ``@strict_ifc``
            # and on both backends, and a pattern naming a field the value
            # lacks passes ``--check`` and then faults at runtime. One
            # reject upstream, here in the binder, closes both: a rejected
            # program never reaches the IFC summary or codegen.
            #
            # Laundering is closed EXACTLY when the scrutinee's static type
            # is a CONCRETE struct in the module type table. Struct-ness is
            # resolved through ``self.global_scope`` (the type registry, the
            # same table ``_check_field_access`` consults), NOT ``self.scope``
            # (the value+type scope): a local ``let`` / ``var`` / ``param`` /
            # ``for`` binder named like the struct type must not be able to
            # shadow the type away. Head-name comparison only, ignoring
            # generic arguments and typestate, mirroring the ``VariantPat``
            # arm above.
            #
            # A generic struct field is now handled: the field-binding loop
            # below substitutes the scrutinee's generic ARGUMENTS into the
            # field types, so a field declared at a type parameter (``v: T``
            # in ``Box<T>``) binds at its instantiated CONCRETE type
            # (``v: ASecret`` for a ``Box<ASecret>`` scrutinee). A downstream
            # public-twin destructure then resolves a concrete struct and the
            # guard above fires, closing the launder that ran through any
            # generic-typed struct field from ordinary concrete code.
            #
            # DISCLOSED OPEN RESIDUALS (not closed here; each accepted today):
            #   - A RIGID generic TYPE-PARAMETER scrutinee. When the scrutinee
            #     itself is a bare type parameter (``fun f<T>(t: T)`` then
            #     ``let Other { a } = t``), or an intermediate whose field
            #     type substitutes to itself (``fun f<T>(b: Box<T>)``, where
            #     ``v: T`` stays a ``TyVar``), no concrete struct resolves, so
            #     the guard does not fire. The substitution below only helps
            #     when the scrutinee carries concrete generic arguments.
            #   - A TRAIT-typed scrutinee (``s: Shape`` then
            #     ``let Circle { r } = s``): ``ty.name`` resolves to a TRAIT,
            #     not a struct, so the legitimate downcast stays accepted and
            #     a public-twin downcast is not caught (Python leak / Wasm
            #     crash). Needs a runtime tag check.
            #   - A SUM / primitive scrutinee (``let Other { a } = <sum>``):
            #     ``ty`` is not a struct in the table, so the mismatch is not
            #     caught here; it faults LOUD on both backends at runtime (a
            #     pre-existing D1-cousin, no silent leak).
            if isinstance(ty, TyName) and ty.name != p.type_name:
                scrut_sym = self.global_scope.lookup(ty.name)
                if (
                    scrut_sym is not None
                    and scrut_sym.kind == SymbolKind.TYPE_STRUCT
                ):
                    self._err(
                        f"destructuring pattern names {p.type_name!r}, "
                        f"but the value has type {ty_str(ty)}",
                        p.pos,
                    )
                    # Emit-and-continue: fall through to bind the pattern's
                    # fields so this single diagnostic is the only one, with
                    # no cascade of undefined-name errors on the binders.
            known = sym.struct_fields
            # Substitute the scrutinee's generic ARGUMENTS into the field
            # types before binding. A field declared at a type parameter
            # (``v: T`` in ``Box<T>``) must bind at the instantiated type
            # (``v: ASecret`` for a ``Box<ASecret>`` scrutinee), not the raw
            # ``TyVar``: an un-substituted ``TyVar`` slips the concrete-struct
            # guard on a downstream public-twin destructure and launders the
            # secret. The ``ty.name == p.type_name`` predicate keeps this off
            # the mismatch / emit-and-continue path above (where the pattern
            # names a DIFFERENT struct); mirrors the ``VariantPat`` arm and
            # generic-struct field access, so the destructure now agrees with
            # a field read.
            field_subst: dict[str, Ty] = {}
            if (
                isinstance(ty, TyName)
                and ty.name == p.type_name
                and sym.type_params
                and len(ty.args) == len(sym.type_params)
            ):
                field_subst = dict(zip(sym.type_params, ty.args))
            seen: set[str] = set()
            for fname, fpat in p.fields:
                if fname in seen:
                    self._err(f"duplicate field {fname!r} in pattern", p.pos)
                seen.add(fname)
                if fname not in known:
                    self._err(
                        f"struct {p.type_name!r} has no field {fname!r}",
                        p.pos,
                    )
                    fty: Ty = TyUnknown
                else:
                    fty = known[fname]
                    if field_subst:
                        fty = substitute(fty, field_subst)
                if fpat is None:
                    # shorthand ``field`` -> bind ``field: same-name``.
                    # This binds directly (not via ``_bind_pattern``), so
                    # the closure-shadow check is applied here too: a
                    # shorthand field name that shadows an enclosing scope
                    # in a lambda body diverges exactly like a plain ``let``
                    # would (the Wasm backend disclosed the outer value
                    # while Python bound the field).
                    prev = self.scope.lookup_local(fname)
                    if prev is not None:
                        self._err(
                            self._duplicate_binding_message(fname, prev),
                            p.pos,
                        )
                    else:
                        enclosing = self._enclosing_scope_local(
                            fname, p.pos, init_expr,
                        )
                        if enclosing is not None:
                            self._err(
                                self._closure_shadow_message(fname, enclosing),
                                p.pos,
                            )
                    self.scope.define(
                        Symbol(
                            name=fname,
                            kind=SymbolKind.LOCAL,
                            pos=p.pos,
                            ty=fty,
                        )
                    )
                else:
                    self._bind_pattern(fpat, fty, mutable, init_expr)
            return
        if isinstance(p, A.TuplePat):
            if len(p.elements) == 0:
                if ty is not TyUnit and ty is not TyUnknown:
                    self._err(
                        f"tuple pattern () expects Unit, got {ty_str(ty)}",
                        p.pos,
                    )
                return
            if isinstance(ty, TyTuple):
                if len(p.elements) != len(ty.elements):
                    self._err(
                        f"tuple pattern has {len(p.elements)} elements, "
                        f"but type is {ty_str(ty)}",
                        p.pos,
                    )
                    for i, sub in enumerate(p.elements):
                        sub_ty: Ty = (
                            ty.elements[i] if i < len(ty.elements)
                            else TyUnknown
                        )
                        self._bind_pattern(sub, sub_ty, mutable, init_expr)
                    return
                for sub, sub_ty in zip(p.elements, ty.elements):
                    self._bind_pattern(sub, sub_ty, mutable, init_expr)
                return
            for sub in p.elements:
                self._bind_pattern(sub, TyUnknown, mutable)
            return
        if isinstance(p, A.OrPat):
            # Or-patterns: every alternative must match the
            # scrutinee's type. Bindings are allowed if every
            # alternative binds the same set of names with
            # compatible types. Trial-bind in a temporary scope
            # for each alternative, check consistency, then real-
            # bind in the current scope using the first
            # alternative.
            if not p.alternatives:
                return
            trial_scopes = []
            for alt in p.alternatives:
                trial = Scope(parent=self.scope)
                saved = self.scope
                self.scope = trial
                try:
                    self._bind_pattern(alt, ty, mutable, init_expr)
                finally:
                    self.scope = saved
                trial_scopes.append(trial.symbols)
            first_names = set(trial_scopes[0].keys())
            for i, others in enumerate(trial_scopes[1:], start=1):
                other_names = set(others.keys())
                if first_names != other_names:
                    missing = first_names - other_names
                    extra = other_names - first_names
                    parts = []
                    if missing:
                        parts.append(
                            f"missing {', '.join(sorted(missing))}"
                        )
                    if extra:
                        parts.append(f"extra {', '.join(sorted(extra))}")
                    self._err(
                        f"or-pattern: alternative {i} binds different "
                        f"names than alternative 0 ({'; '.join(parts)})",
                        p.alternatives[i].pos,
                    )
                    continue
                for name in first_names:
                    t1 = trial_scopes[0][name].ty
                    t2 = others[name].ty
                    if not compatible(t1, t2):
                        self._err(
                            f"or-pattern: name {name!r} has type "
                            f"{ty_str(t1)} in alternative 0 but "
                            f"{ty_str(t2)} in alternative {i}",
                            p.alternatives[i].pos,
                        )
            self._bind_pattern(p.alternatives[0], ty, mutable, init_expr)
            return
        self._err(f"unknown pattern type {type(p).__name__}", p.pos)

    def _reject_nested_struct_in_binding(self, p: A.Pattern) -> None:
        """Reject a struct sub-pattern nested inside a ``let`` / ``for``
        binding pattern.

        A top-level struct-pattern in a ``let`` / ``for`` is fine
        (``let Point { x, y } = p``), and so are its field binders in
        shorthand, rename, or wildcard form (``Point { x }``,
        ``Point { x: a }``, ``Point { x: _ }``). What neither backend
        can lower is a struct-pattern *inside* a field (or inside a
        tuple element), e.g. ``let Outer { inner: Inner { a } } = o``:
        the transpiler raises ``nested struct-pattern in let/for`` and
        the IR lowerer raises ``UnsupportedInIR``. ``match`` arms do
        support that nesting and go through ``_bind_pattern``, not this
        guard, so they are unaffected.

        Walk the binding pattern and emit a precise diagnostic for each
        nested struct-pattern so ``--check`` and ``--run`` agree
        (both reject) instead of ``--check`` greenlighting a program
        the backends crash on. Reported at the nested struct-pattern's
        own source position, with a fix suggestion (bind the field to a
        name, then destructure it in a separate ``let``).
        """

        def walk(node: A.Pattern, nested: bool) -> None:
            if isinstance(node, A.StructPat):
                if nested:
                    self._err(
                        "nested struct-pattern in a 'let' / 'for' binding "
                        "is not supported; bind the field to a name first, "
                        "then destructure it in a separate binding (e.g. "
                        "`let Outer { inner } = o` followed by "
                        "`let Inner { a } = inner`)",
                        node.pos,
                    )
                    return
                for fname, fpat in node.fields:
                    if fpat is None or isinstance(
                        fpat, (A.WildcardPat, A.IdentPat)
                    ):
                        continue
                    walk(fpat, nested=True)
                return
            if isinstance(node, A.TuplePat):
                for sub in node.elements:
                    walk(sub, nested=True)
                return

        walk(p, nested=False)

    def _pattern_has_binding(self, p: A.Pattern) -> bool:
        """``True`` iff the pattern binds at least one name
        (rather than just matching). Used to enforce the v0
        restriction that or-patterns cannot bind names."""
        if isinstance(p, A.WildcardPat):
            return False
        if isinstance(p, A.LiteralPat):
            return False
        if isinstance(p, A.IdentPat):
            return True
        if isinstance(p, A.VariantPat):
            return any(self._pattern_has_binding(s) for s in p.payloads)
        if isinstance(p, A.StructPat):
            return any(
                fp is None or self._pattern_has_binding(fp)
                for _, fp in p.fields
            )
        if isinstance(p, A.TuplePat):
            return any(self._pattern_has_binding(sub) for sub in p.elements)
        if isinstance(p, A.OrPat):
            return any(self._pattern_has_binding(a) for a in p.alternatives)
        return False
