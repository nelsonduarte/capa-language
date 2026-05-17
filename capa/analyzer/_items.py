"""Phase-2 item-checking mixin.

Once :class:`_DeclarationsMixin` has populated the global scope
with every top-level name and its type, this mixin walks the
module again to check each item's body:

- ``_check_item``: top-level dispatcher.
- ``_check_const``: verify the const's RHS matches its declared
  type.
- ``_check_fun``: enter the parameter scope, check the body,
  enforce the "capability parameter must be used" rule.
- ``_check_impl``: validate the impl target / trait references,
  then descend into each method.
- ``_check_function_attributes``: validate ``@security`` /
  ``@deprecated`` / ``@audited`` names and keys against a small
  schema.

The mixin assumes ``self`` has the analyzer state set up and
pulls helpers (``_check_expr``, ``_check_block``,
``_resolve_type``, ``_push_scope``, ``_pop_scope``,
``_push_type_params``, ``_pop_type_params``, ``_substitute_self``,
``_method_type_from_decl``, ``_err``) from the other mixins.
"""

from __future__ import annotations

from .. import capa_ast as A
from ..typesys import (
    Ty, TyFun, TyName, TyUnit, TyUnknown, TyVar,
    compatible, contains_capability, ty_str,
)


class _ItemsMixin:
    # Attribute schema for ``@security`` / ``@deprecated`` /
    # ``@audited``. v1 ships a fixed catalogue; unknown names
    # and unknown keys are rejected so downstream consumers
    # (``--manifest``, future audit tooling) can rely on a
    # stable shape.
    _ATTRIBUTE_SCHEMA: dict[str, set[str]] = {
        "security":   {"cve", "cwe", "severity", "fixed_in", "description"},
        "deprecated": {"reason", "since", "use", "removed_in"},
        "audited":    {"date", "by", "scope", "notes"},
        "vex":        {"cve", "status", "justification", "detail"},
    }

    def _check_item(self, item: A.Item) -> None:
        if isinstance(item, A.Import):
            return
        if isinstance(item, A.ConstDecl):
            self._check_const(item)
            return
        if isinstance(item, A.FunDecl):
            self._check_fun(item)
            return
        if isinstance(item, A.ImplBlock):
            self._check_impl(item)
            return
        # TypeStruct, TypeSum, TraitDecl: handled in Phase 1.

    def _check_const(self, c: A.ConstDecl) -> None:
        sym = self.global_scope.lookup(c.name)
        expected = sym.ty if sym is not None else TyUnknown
        actual = self._check_expr(c.value)
        if not compatible(expected, actual):
            self._err(
                f"constant {c.name!r}: expected {ty_str(expected)}, "
                f"got {ty_str(actual)}",
                c.value.pos,
            )

    def _check_function_attributes(self, fn: A.FunDecl) -> None:
        """Validate attribute names and keys against
        :data:`_ATTRIBUTE_SCHEMA`. The parser already guarantees
        argument values are string literals."""
        seen_names: set[str] = set()
        for attr in fn.attributes:
            allowed_keys = self._ATTRIBUTE_SCHEMA.get(attr.name)
            if allowed_keys is None:
                known = ", ".join(sorted(self._ATTRIBUTE_SCHEMA))
                self._err(
                    f"unknown attribute '@{attr.name}'; "
                    f"known attributes are: {known}",
                    attr.pos,
                )
                continue
            if attr.name in seen_names:
                self._err(
                    f"attribute '@{attr.name}' appears more than once on "
                    f"function {fn.name!r}",
                    attr.pos,
                )
                continue
            seen_names.add(attr.name)
            seen_keys: set[str] = set()
            for key, _value in attr.args:
                if key not in allowed_keys:
                    keys_str = ", ".join(sorted(allowed_keys))
                    self._err(
                        f"unknown key '{key}' in '@{attr.name}'; "
                        f"allowed keys are: {keys_str}",
                        attr.pos,
                    )
                    continue
                if key in seen_keys:
                    self._err(
                        f"key '{key}' appears more than once in "
                        f"'@{attr.name}'",
                        attr.pos,
                    )
                seen_keys.add(key)

    def _check_fun(self, fn: A.FunDecl) -> None:
        from . import Symbol, SymbolKind

        # Attribute validation is fast, scope-free, and a
        # precondition for ``--manifest`` to trust the AST.
        if fn.attributes:
            self._check_function_attributes(fn)

        self._push_type_params(fn.type_params)
        self._push_scope()

        # Capability parameters: collected so the analyzer can
        # warn at the end of the body if any are declared but
        # never used.
        cap_param_syms: list[Symbol] = []

        for p in fn.params:
            if p.name == "self":
                if self.self_type is None:
                    self._err(
                        "'self' parameter is only valid inside an impl",
                        p.pos,
                    )
                psym = Symbol(
                    name="self", kind=SymbolKind.PARAM, pos=p.pos,
                    ty=self.self_type if self.self_type is not None else TyUnknown,
                )
            else:
                pty = (
                    self._resolve_type(p.type_expr)
                    if p.type_expr else TyUnknown
                )
                psym = Symbol(
                    name=p.name, kind=SymbolKind.PARAM, pos=p.pos, ty=pty,
                )
                if contains_capability(pty) is not None:
                    cap_param_syms.append(psym)
            if self.scope.lookup_local(p.name) is not None:
                self._err(
                    f"duplicate parameter name {p.name!r}", p.pos,
                )
            self.scope.define(psym)

        # Snapshot bindings to detect unused capability params.
        bindings_before = set(self.bindings.keys())

        # Fresh ``_consumed`` set for the function body.
        prev_consumed = self._consumed
        self._consumed = set()
        # Fresh TyVar substitution universe for the function.
        prev_subs = self._ty_subs
        self._ty_subs = {}

        prev_ret = self.current_return_type
        ret = (
            self._resolve_type(fn.return_type)
            if fn.return_type else TyUnit
        )
        self.current_return_type = ret
        self._check_block(fn.body)
        self.current_return_type = prev_ret

        # If the function declares a non-Unit return type, every
        # code path must end in ``return``. A function that just
        # has ``"hello"`` as its last statement when declared
        # ``-> String`` would otherwise compile cleanly and silently
        # return None at runtime, producing a None where a String
        # was promised. Caught here so the user sees a precise
        # message instead of a downstream type confusion.
        if ret is not TyUnit and not _block_always_returns(fn.body):
            # Point at the function's name (or the body's open
            # position when the name span is unavailable) so the
            # caret lands somewhere visible in the editor.
            err_pos = getattr(fn, "name_pos", None) or fn.pos
            self._err(
                f"function {fn.name!r} declares return type but not "
                f"every path ends in `return`; the function will "
                f"fall through and return None at runtime",
                err_pos,
            )

        self._consumed = prev_consumed
        self._ty_subs = prev_subs

        new_bindings = {
            k: v for k, v in self.bindings.items()
            if k not in bindings_before
        }
        used_sym_ids = {id(s) for s in new_bindings.values()}

        # Capability params must be referenced in the body
        # (otherwise the function declared an authority it does
        # not exercise, which is a smell). Names starting with
        # ``_`` silence the warning, in the fine tradition of
        # Rust and Haskell.
        for psym in cap_param_syms:
            if id(psym) in used_sym_ids:
                continue
            if psym.name.startswith("_"):
                continue
            self._err(
                f"capability parameter {psym.name!r} is declared but never "
                f"used; prefix the name with '_' to silence this check",
                psym.pos,
            )

        self._pop_scope()
        self._pop_type_params()

    def _check_impl(self, impl: A.ImplBlock) -> None:
        from . import SymbolKind
        from . import _signatures_match

        target = self.global_scope.lookup(impl.type_name)
        if target is None or target.kind not in (
            SymbolKind.TYPE_STRUCT, SymbolKind.TYPE_SUM
        ):
            self._err(
                f"impl target {impl.type_name!r} is not a known type",
                impl.pos,
            )
            return

        # ``trait X`` and ``capability X`` are both valid here:
        # they share the ``trait_methods`` / ``trait_method_sigs``
        # shape on the Symbol.
        if impl.trait_name is not None:
            trait = self.global_scope.lookup(impl.trait_name)
            if trait is None or trait.kind not in (
                SymbolKind.TRAIT, SymbolKind.CAPABILITY,
            ):
                self._err(
                    f"trait {impl.trait_name!r} is not defined",
                    impl.pos,
                )
            else:
                impl_method_names = {m.name for m in impl.methods}
                missing = trait.trait_methods - impl_method_names
                if missing:
                    self._err(
                        f"impl of trait {impl.trait_name!r} for "
                        f"{impl.type_name!r} is missing methods: "
                        f"{', '.join(sorted(missing))}",
                        impl.pos,
                    )
                self_args_check = tuple(TyVar(p) for p in target.type_params)
                self_ty_concrete = TyName(impl.type_name, self_args_check)
                for method in impl.methods:
                    if method.name not in trait.trait_method_sigs:
                        continue   # extra (helper) method: allowed
                    expected = trait.trait_method_sigs[method.name]
                    expected_concrete = self._substitute_self(
                        expected, self_ty_concrete,
                    )
                    self._push_type_params(target.type_params)
                    prev_self = self.self_type
                    self.self_type = self_ty_concrete
                    actual = self._method_type_from_decl(method)
                    self.self_type = prev_self
                    self._pop_type_params()
                    if (
                        isinstance(actual, TyFun)
                        and isinstance(expected_concrete, TyFun)
                    ):
                        if not _signatures_match(expected_concrete, actual):
                            self._err(
                                f"impl method {method.name!r} for trait "
                                f"{impl.trait_name!r}: expected signature "
                                f"{ty_str(expected_concrete)}, got "
                                f"{ty_str(actual)}",
                                method.pos,
                            )

        self_args = tuple(TyVar(p) for p in target.type_params)
        prev_self = self.self_type
        self.self_type = TyName(impl.type_name, self_args)
        self._push_type_params(target.type_params)

        for method in impl.methods:
            self._check_fun(method)

        self._pop_type_params()
        self.self_type = prev_self


def _block_always_returns(block) -> bool:
    """True iff every code path through block ends in a
    return. Used to flag a non-Unit-returning function whose
    body could fall through without producing a value.

    The check is conservative on purpose: a block whose last
    statement is a return is fine; an if whose then and
    else (plus every elif) branches all always-return is
    fine; an exhaustive match whose every arm-body always-
    returns is fine. Anything else returns False even when a
    more sophisticated flow analysis could prove return; the
    fix is to add a trailing return (which is harmless) or
    restructure.
    """
    from .. import capa_ast as A
    if not block.stmts:
        return False
    return _stmt_always_returns(block.stmts[-1])


def _stmt_always_returns(s) -> bool:
    from .. import capa_ast as A
    if isinstance(s, A.ReturnStmt):
        return True
    if isinstance(s, A.IfStmt):
        # Without an else branch, control may fall through.
        if s.else_block is None:
            return False
        for _cond, blk in s.elif_arms:
            if not _block_always_returns(blk):
                return False
        return (
            _block_always_returns(s.then_block)
            and _block_always_returns(s.else_block)
        )
    if isinstance(s, A.ExprStmt) and isinstance(s.expr, A.MatchExpr):
        for arm in s.expr.arms:
            if not _arm_always_returns(arm):
                return False
        # The analyser's exhaustiveness pass runs elsewhere; if it
        # did not flag the match, the arms cover the scrutinee.
        return True
    return False


def _arm_always_returns(arm) -> bool:
    from .. import capa_ast as A
    body = arm.body
    if isinstance(body, A.Block):
        return _block_always_returns(body)
    # Single-expression arm body (no explicit return). Could only
    # satisfy "always returns" via an early-return expression,
    # which Capa does not have. Conservative: False.
    return False

