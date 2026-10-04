"""Built-in names mixin: the reservation, and the analyzer's reads of
built-in identity.

Built-in global names are reserved (see :mod:`capa._builtin_identity`).
This mixin enforces that at the analyzer's binder doors and answers
"is this call the built-in?" for the analyzer's own consumers:

- ``_define_local``: the ONE door every lexical binder goes through
  (parameters, lambda parameters, ``let`` / ``var`` / ``for`` / ``match``
  pattern binders, struct-pattern shorthands). A reserved name is
  refused here; nothing else defines a local.
- ``_refuse_reserved_item``: the module-level twin, for every name a
  top-level item declares in any linked file (read off the one item
  table, ``capa._builtin_identity.item_declarations``), judged by the
  name its author wrote and, for an ``import ... (x as y)`` alias, by
  the alias itself. A value declaration may not take any built-in name;
  a type-namespace declaration may not take a built-in function's name
  (``is_reserved_for``).
- ``_refuse_builtin_value``: a built-in FUNCTION used as a value.
- ``_is_builtin_call``: built-in identity for a call, decided by
  :func:`capa._builtin_identity.builtin_call` over the module's top-level
  names, with the analyzer's own binding checked to agree.
- ``_assert_module_scope_agrees``: a fail-closed guard that the AST-side
  enumeration of top-level names matches what the analyzer registered.
"""

from __future__ import annotations

from .. import capa_ast as A
from .._builtin_identity import (
    builtin_call,
    builtin_value_message,
    is_builtin_symbol,
    is_reserved_for,
    item_declarations,
    module_scope_names,
    reserved_name_message,
)


class _BuiltinNamesMixin:

    def _refuse_reserved(
        self, name: str, binder: str, pos, kind: str = "",
    ) -> None:
        """Record the reserved-name diagnostic when a binder of ``kind``
        (default: a value binder) may not take ``name``. The single rule
        every door below applies."""
        if is_reserved_for(name, kind or binder):
            self._err(reserved_name_message(name, binder), pos)

    def _define_local(self, sym) -> None:
        """Define a lexical binder in the current scope. Every local
        binder kind reaches the scope through here, so the reserved-name
        rule cannot be bypassed by a binder kind."""
        from . import SymbolKind
        binder = "parameter" if sym.kind == SymbolKind.PARAM else "variable"
        self._refuse_reserved(sym.name, binder, sym.pos)
        self.scope.define(sym)

    def _refuse_reserved_item(self, item) -> None:
        """Refuse every name a top-level ``item`` declares that its kind
        may not take, in whichever linked file declares it."""
        for d in item_declarations(item):
            self._refuse_reserved(d.source_name, d.kind, d.pos)
            if d.name != d.source_name and d.alias_pos is not None:
                self._refuse_reserved(
                    d.name, "import alias", d.alias_pos, kind=d.kind,
                )

    def _refuse_builtin_value(self, e: A.Ident, sym) -> None:
        """A built-in function may only be called, never used as a value
        (``let f = to_int``, ``xs.map(panic)``)."""
        from . import SymbolKind
        if sym.kind == SymbolKind.FUNCTION and is_builtin_symbol(sym):
            self._err(builtin_value_message(e.name), e.pos)

    def _is_builtin_call(self, e, name=None) -> bool:
        """True when ``e`` is a call of the built-in (``name`` when given).

        Decided once, from module scope. The binding the analyzer recorded
        must agree; on a program that already has errors (a refused
        reserved name can make them differ) the check is skipped, since
        that program never reaches a backend."""
        bindings = None if self.errors else self.bindings
        return builtin_call(e, self._module_scope_names, name, bindings=bindings)

    def _assert_module_scope_agrees(self) -> None:
        """Fail closed when the top-level names the identity decision reads
        (``module_scope_names``) differ from the user symbols the analyzer
        registered. Checked only on a module whose globals collected
        without error."""
        from ..builtins import BUILTIN_POS
        if self.errors:
            return
        registered = {
            n for n, s in self.global_scope.symbols.items()
            if s.pos != BUILTIN_POS
        }
        if registered != set(self._module_scope_names):
            raise AssertionError(
                "module_scope_names disagrees with the analyzer's global "
                f"scope: only in the scope {sorted(registered - set(self._module_scope_names))}, "
                f"only in module_scope_names "
                f"{sorted(set(self._module_scope_names) - registered)}"
            )

    def _init_module_scope(self, module: A.Module) -> None:
        self._module_scope_names = module_scope_names(module)
