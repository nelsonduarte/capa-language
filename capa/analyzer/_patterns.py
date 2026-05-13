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
        """
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

        if not isinstance(scrutinee_ty, TyName):
            return
        from . import SymbolKind
        type_sym = self.global_scope.lookup(scrutinee_ty.name)
        if type_sym is None or type_sym.kind != SymbolKind.TYPE_SUM:
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
        """A pattern captures all values when it is a wildcard,
        a binding ident, or an or-pattern whose alternatives
        include at least one catch-all."""
        if isinstance(p, (A.WildcardPat, A.IdentPat)):
            return True
        if isinstance(p, A.OrPat):
            return any(self._pattern_is_catchall(a) for a in p.alternatives)
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

    def _bind_pattern(
        self, p: A.Pattern, ty: Ty, mutable: bool,
    ) -> None:
        """Bind the pattern's names to the current scope with
        the type they receive from the scrutinee. The full
        pattern grammar is supported (wildcard, ident, literal,
        variant, struct with shorthand, tuple, or)."""
        from . import Scope, Symbol, SymbolKind
        if isinstance(p, A.WildcardPat):
            return
        if isinstance(p, A.IdentPat):
            kind = SymbolKind.LOCAL_VAR if mutable else SymbolKind.LOCAL
            if self.scope.lookup_local(p.name) is not None:
                self._err(f"duplicate binding {p.name!r}", p.pos)
            self.scope.define(
                Symbol(name=p.name, kind=kind, pos=p.pos, ty=ty)
            )
            return
        if isinstance(p, A.LiteralPat):
            self._check_expr(p.value)
            return
        if isinstance(p, A.VariantPat):
            sym = self.scope.lookup(p.name)
            if sym is None:
                hint = self._hint_did_you_mean(
                    p.name, self._variant_names(ty),
                )
                self._err(f"unknown variant {p.name!r}{hint}", p.pos)
                if p.payload is not None:
                    self._bind_pattern(p.payload, TyUnknown, mutable)
                return
            if sym.kind != SymbolKind.VARIANT:
                self._err(f"{p.name!r} is not a variant", p.pos)
                if p.payload is not None:
                    self._bind_pattern(p.payload, TyUnknown, mutable)
                return
            payload_ty: Ty = sym.variant_payload_ty or TyUnknown
            # Substitute the owner's type params (e.g. ``T`` in
            # ``Some<T>(T)``) with the scrutinee's args.
            if (
                sym.variant_owner is not None
                and isinstance(ty, TyName)
                and ty.name == sym.variant_owner.name
                and len(ty.args) == len(sym.variant_owner.type_params)
            ):
                subst = dict(zip(sym.variant_owner.type_params, ty.args))
                payload_ty = substitute(payload_ty, subst)
            elif ty is TyUnknown:
                # No info from the scrutinee: collapse abstract
                # TyVars to TyUnknown so later checks don't fail
                # on them.
                if isinstance(payload_ty, TyVar):
                    payload_ty = TyUnknown
            if p.payload is not None:
                self._bind_pattern(p.payload, payload_ty, mutable)
            elif sym.variant_payload_ty is not None:
                self._err(
                    f"variant {p.name!r} requires a payload", p.pos,
                )
            return
        if isinstance(p, A.StructPat):
            sym = self.scope.lookup(p.type_name)
            if sym is None or sym.kind != SymbolKind.TYPE_STRUCT:
                self._err(
                    f"{p.type_name!r} is not a struct type", p.pos,
                )
                return
            known = sym.struct_fields
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
                if fpat is None:
                    # shorthand ``field`` -> bind ``field: same-name``
                    if self.scope.lookup_local(fname) is not None:
                        self._err(f"duplicate binding {fname!r}", p.pos)
                    self.scope.define(
                        Symbol(
                            name=fname,
                            kind=SymbolKind.LOCAL,
                            pos=p.pos,
                            ty=fty,
                        )
                    )
                else:
                    self._bind_pattern(fpat, fty, mutable)
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
                        self._bind_pattern(sub, sub_ty, mutable)
                    return
                for sub, sub_ty in zip(p.elements, ty.elements):
                    self._bind_pattern(sub, sub_ty, mutable)
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
                    self._bind_pattern(alt, ty, mutable)
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
            self._bind_pattern(p.alternatives[0], ty, mutable)
            return
        self._err(f"unknown pattern type {type(p).__name__}", p.pos)

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
            return p.payload is not None and self._pattern_has_binding(p.payload)
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
