"""Built-in identity, decided in one place.

The built-in global names (the free functions, the capabilities, the
built-in types, ``JsonValue`` and the built-in variants: everything
:func:`capa.builtins.register_builtins` installs in the global scope) are
RESERVED. No variable, parameter, lambda parameter, pattern binder, loop
variable, constant or module-level function may take one, in the root
program or in any dependency, and a built-in function may not be used as
a value (the analyzer refuses all of these; see
``capa.analyzer._builtin_names``).

Because no lexical binder can take a built-in name, whether an
identifier names the built-in never depends on lexical scope. It is a
MODULE-SCOPE fact: a built-in-named identifier is the built-in exactly
when the linked module declares no top-level item of that name. That
fact exists on every path and in every phase without the analyzer's
bindings: the cross-function summary pass (which runs before bindings
exist), IR lowering (including the internal lowerings that run without
an analysis), the Python transpiler, the manifest. This module states it
once:

- :func:`module_scope_names` -- the names a module declares at top level;
- :func:`builtin_callee` / :func:`builtin_call` -- the decision;
- :func:`is_builtin_symbol` -- the analyzer-side view of the same fact
  (a binding whose position is the built-in position). Where a caller
  has both, they must agree, and :func:`check_agreement` fails closed
  when they do not;
- :func:`item_declarations` -- the one table of what each top-level item
  declares, read by both the decision and the reservation;
- :func:`is_reserved_name` / :func:`is_reserved_for` and the two
  diagnostics -- the reservation the decision relies on.

The IR carries the decision on every ``Call`` as a declared field
(``Call.callee_kind``), so the backends read it instead of re-deciding
by name.

A type-namespace declaration (a struct or sum type, a variant, a
typestate, a trait, a capability, an extern component) may not take a
built-in FUNCTION name either. Declaring one with a built-in TYPE name
(``type Range { ... }``) is a separate matter and is not refused here;
such a declaration is a top-level item, so the decision above already
treats the name as the user's.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import Callable, Iterable, Optional

from . import capa_ast as A
from .tokens import Pos


# ---------------------------------------------------------------------------
# The reserved set, read off the built-in registration itself.
# ---------------------------------------------------------------------------


@lru_cache(maxsize=None)
def builtin_global_names() -> frozenset[str]:
    """Every name :func:`capa.builtins.register_builtins` installs in the
    global scope, obtained by RUNNING it against a recording scope, so the
    set cannot drift from what the analyzer binds. Computed lazily: the
    registration imports the analyzer's ``Symbol``, which in turn imports
    this module."""
    from .builtins import register_builtins
    table: dict = {}

    def define(sym) -> None:
        table[sym.name] = sym

    register_builtins(define, table.get)
    return frozenset(table)


def is_reserved_name(name: str) -> bool:
    """True when ``name`` is a built-in global name, which no value
    binder may take."""
    return name in builtin_global_names()


#: Declaration kinds in the TYPE namespace. They may not take a built-in
#: FUNCTION name (a call of that name would otherwise reach the
#: declaration). Built-in TYPE names (``Range``) are a separate class and
#: are not reserved for them.
TYPE_NAMESPACE_KINDS = frozenset({
    "type", "variant", "typestate", "trait", "capability",
    "extern component",
})


def is_reserved_for(name: str, kind: str) -> bool:
    """True when a declaration of ``kind`` may not take ``name``: a
    type-namespace declaration may not take a built-in function's name,
    every other binder (value declarations, locals, parameters, aliases of
    values) may not take any built-in global name."""
    if kind in TYPE_NAMESPACE_KINDS:
        from .builtins import FREE_FUNCTIONS
        return name in FREE_FUNCTIONS
    return is_reserved_name(name)


def reserved_name_message(name: str, binder: str) -> str:
    """The one diagnostic for a binder that takes a built-in name."""
    from .builtins import FREE_FUNCTIONS
    what = "function" if name in FREE_FUNCTIONS else "name"
    article = "an" if binder[:1] in "aeiou" else "a"
    return (
        f"{name!r} is the name of a built-in {what} and is reserved, so it "
        f"cannot name {article} {binder}; rename the {binder}"
    )


def builtin_value_message(name: str) -> str:
    """The one diagnostic for a built-in function used as a value."""
    return (
        f"the built-in function {name!r} cannot be used as a value; call "
        f"it directly, or wrap the call in a lambda"
    )


# ---------------------------------------------------------------------------
# Module scope.
# ---------------------------------------------------------------------------


class UnknownItemError(TypeError):
    """A top-level AST item class is not registered in :data:`_ITEM_DECLS`.

    Raised rather than skipped: an unregistered item could declare a name
    the identity decision would then not see."""


@dataclass(frozen=True)
class Declaration:
    """One module-scope name a top-level item declares.

    - ``name``: the visible (linked) name, the one calls resolve to;
    - ``source_name``: the name its author wrote (they differ when the
      loader renamed the declaration while linking);
    - ``kind``: what is declared (``"function"``, ``"constant"``,
      ``"type"``, ``"variant"``, ``"typestate"``, ``"trait"``,
      ``"capability"``, ``"extern component"``);
    - ``pos``: where the name is written;
    - ``alias_pos``: where an ``import ... (x as y)`` alias bound
      ``name``, or ``None``."""

    name: str
    source_name: str
    kind: str
    pos: Pos
    alias_pos: Optional[Pos]


def _declaration(node, kind: str) -> Declaration:
    return Declaration(
        name=node.name,
        source_name=node.declared_name or node.name,
        kind=kind,
        pos=node.name_pos or node.pos,
        alias_pos=node.alias_pos,
    )


def _as(kind: str) -> Callable[[A.Item], tuple[Declaration, ...]]:
    return lambda item: (_declaration(item, kind),)


def _trait(item: A.TraitDecl) -> tuple[Declaration, ...]:
    return (_declaration(
        item, "capability" if item.is_capability else "trait",
    ),)


def _sum(item: A.TypeSum) -> tuple[Declaration, ...]:
    # A sum type declares its own name and each variant constructor.
    return (
        _declaration(item, "type"),
        *(_declaration(v, "variant") for v in item.variants),
    )


def _nothing(item) -> tuple[Declaration, ...]:
    return ()


#: EVERY top-level item class, mapped to the module-scope names it
#: declares. The ONE table both the identity decision
#: (:func:`module_scope_names`) and the reserved-name refusal
#: (``capa.analyzer._builtin_names``) read. The analyzer asserts it agrees
#: with the analyzer's own global registration on every program that
#: collects without error (``_BuiltinNamesMixin._assert_module_scope_agrees``).
_ITEM_DECLS: dict[type, Callable[[A.Item], tuple[Declaration, ...]]] = {
    A.Import: _nothing,
    A.ImplBlock: _nothing,
    A.ConstDecl: _as("constant"),
    A.FunDecl: _as("function"),
    A.TypeStruct: _as("type"),
    A.TypestateDecl: _as("typestate"),
    A.ExternComponent: _as("extern component"),
    A.TraitDecl: _trait,
    A.TypeSum: _sum,
}


def item_declarations(item: A.Item) -> tuple[Declaration, ...]:
    """The module-scope declarations of one top-level ``item``."""
    handler = _ITEM_DECLS.get(type(item))
    if handler is None:
        raise UnknownItemError(
            f"{type(item).__name__} is not registered in "
            f"capa._builtin_identity._ITEM_DECLS; register the names it "
            f"declares (``_nothing`` when it declares none)"
        )
    return handler(item)


def module_scope_names(module: A.Module) -> frozenset[str]:
    """Every name ``module`` declares at top level (the linked, visible
    names, so a selective-import alias counts under its alias)."""
    return frozenset(
        d.name for item in module.items for d in item_declarations(item)
    )


# ---------------------------------------------------------------------------
# The decision.
# ---------------------------------------------------------------------------


def builtin_callee(name: str, module_names: Iterable[str]) -> bool:
    """True when an identifier ``name`` denotes the BUILT-IN of that name
    in a module whose top-level names are ``module_names``."""
    return is_reserved_name(name) and name not in module_names


def builtin_call(
    node,
    module_names: Iterable[str],
    name: Optional[str] = None,
    *,
    bindings=None,
) -> bool:
    """True when ``node`` is a call whose callee is the built-in (the
    built-in ``name`` when one is given).

    ``bindings`` (the analyzer's ``id(Ident) -> Symbol`` map), when the
    caller has it, is not a second way to decide: it is checked to AGREE
    with the decision (:func:`check_agreement`)."""
    if not isinstance(node, A.Call) or not isinstance(node.callee, A.Ident):
        return False
    callee = node.callee.name
    if name is not None and callee != name:
        return False
    decided = builtin_callee(callee, module_names)
    check_agreement(node.callee, decided, bindings)
    return decided


def is_builtin_symbol(sym) -> bool:
    """True when ``sym`` is a BUILT-IN binding (its position is the
    synthetic built-in position rather than a real source location)."""
    if sym is None:
        return False
    from .builtins import BUILTIN_POS
    return getattr(sym, "pos", None) == BUILTIN_POS


class IdentityDisagreement(AssertionError):
    """The analyzer's binding and the module-scope decision disagree on an
    identifier in a program that took no reserved name. Name reservation
    makes that impossible, so this is a compiler defect, raised rather
    than compiled."""


def check_agreement(ident: A.Ident, decided: bool, bindings) -> None:
    """Fail closed when ``bindings`` (the analyzer's ``id(Ident) ->
    Symbol`` map) resolves ``ident`` differently from ``decided``."""
    if bindings is None:
        return
    sym = bindings.get(id(ident))
    if sym is None:
        return
    if is_builtin_symbol(sym) != decided:
        raise IdentityDisagreement(
            f"builtin identity of {ident.name!r} at {ident.pos}: the "
            f"analyzer binding says "
            f"{'built-in' if is_builtin_symbol(sym) else 'user'}, the "
            f"module-scope decision says "
            f"{'built-in' if decided else 'user'}"
        )
