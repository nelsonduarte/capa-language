"""Shared helpers for typed foreign components (feature #4, F1).

A typed foreign component (``extern component Bureau from "b.wasm"``) is a
reference to an external Wasm Component Model artifact plus the method
signatures Capa may call across the boundary. This module holds the small
AST-level queries that both the manifest builder and the CLI need:

- which foreign components a module declares, and
- where a program actually INVOKES one (``Bureau.submit(...)``).

The runtime that would SANDBOX such a call is a separate later increment
(F2). Until it lands, a program that invokes a foreign component cannot be
run or codegen'd, and its boundary composes as authority-unknown TOP in
the SBOM (claiming a bound nothing enforces would be unsound).
"""

from __future__ import annotations

from typing import Callable

from . import capa_ast as A
from .tokens import Pos
from .typesys import CAPABILITY_NAMES
from .manifest._strings import _root_type_name


def extern_components(module: A.Module) -> list[A.ExternComponent]:
    """Every ``extern component`` declaration in the module, in order."""
    return [it for it in module.items if isinstance(it, A.ExternComponent)]


def extern_component_names(module: A.Module) -> set[str]:
    """The set of names bound by ``extern component`` declarations."""
    return {it.name for it in extern_components(module)}


def declared_capabilities(method: A.MethodSig) -> list[str]:
    """The built-in host capabilities a foreign-component method's
    signature grants (its explicit capability parameter types). These are
    the ONLY authority the component may receive; the crossing discipline
    (checked in the analyzer) guarantees no other capability can appear."""
    caps: list[str] = []
    for p in method.params:
        if p.name == "self" or p.type_expr is None:
            continue
        root = _root_type_name(p.type_expr)
        if root in CAPABILITY_NAMES:
            caps.append(root)
    return caps


def _walk(node: object, visit: Callable[[A.Node], None]) -> None:
    """Depth-first walk of an AST subtree, calling ``visit`` on every
    :class:`capa_ast.Node`. Mirrors the manifest's generic traversal so it
    descends into the same nesting the call records are collected from."""
    if isinstance(node, A.Node):
        visit(node)
        for f in node.__dataclass_fields__.values():
            if f.name == "pos":
                continue
            _walk(getattr(node, f.name), visit)
    elif isinstance(node, (list, tuple)):
        for item in node:
            _walk(item, visit)


def foreign_call_sites(
    node: object, names: set[str],
) -> list[tuple[str, str, Pos]]:
    """Every foreign-component invocation in ``node``'s subtree.

    A foreign call is a ``MethodCall`` whose receiver is a bare identifier
    naming one of ``names`` (``Bureau.submit(...)``). Returns a list of
    ``(component_name, method_name, pos)`` triples in source order. An
    empty ``names`` set short-circuits to no sites."""
    if not names:
        return []
    sites: list[tuple[str, str, Pos]] = []

    def visit(n: A.Node) -> None:
        if (
            isinstance(n, A.MethodCall)
            and isinstance(n.receiver, A.Ident)
            and n.receiver.name in names
        ):
            sites.append((n.receiver.name, n.method, n.pos))

    _walk(node, visit)
    return sites


def module_invokes_foreign_component(module: A.Module) -> bool:
    """True if any function / method body in the module invokes a foreign
    component. The signature-only declaration alone is inert (``--check`` /
    ``--manifest`` work); only an actual invocation needs the F2 runtime."""
    names = extern_component_names(module)
    if not names:
        return False
    return bool(foreign_call_sites(module, names))
