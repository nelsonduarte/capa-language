"""The single source of truth for what counts as a declassification.

``declassify(value, reason: "...")`` is the auditable ``@secret ->
@public`` bridge (roadmap S2.5). Three subsystems need to answer the
SAME question about it:

- the ANALYZER's intra-procedural walk, which makes the call's result
  ``@public`` and validates the call shape
  (``_IfcMixin._is_declassify_call`` / ``_check_declassify``);
- the ANALYZER's cross-function summary pass, where a flow through a
  declassify breaks the sink-reaching chain
  (``_SummaryBuilder._is_declassify``);
- the ARTIFACT PIPELINE, which records every site in ``--manifest`` and
  rolls the counts up into ``--compose-sbom``, ``--check-policies`` and
  ``--conformance-report``.

They used to answer it by walking the AST with THREE DIFFERENT rules,
and they disagreed in both directions:

- the artifact walk only descended into ``FunDecl`` bodies and
  ``ImplBlock`` methods, so a ``declassify`` hoisted into a top-level
  ``const`` initializer was invisible to every artifact while the
  analyzer honoured it. A signed conformance report asserted
  ``no-declassification`` for a program that printed a credential;
- the artifact walk matched on the callee NAME, so a user-defined
  ``fun declassify(...)`` produced a PHANTOM declassification record.
  The analyzer, which guards on the callee binding being the BUILT-IN
  symbol, still reported the leak, so the artifact simultaneously
  asserted an audited declassification and an un-audited secret sink at
  the same position. The summary pass had a third rule again (the name,
  minus a top-level ``fun`` of that name), blind to a ``const`` shadow.

This module owns every half of the answer so the three cannot drift
again:

- :func:`is_declassify_call` -- the identity predicate. The analyzer's
  ``_is_declassify_call`` delegates here, and so does the manifest
  collector.
- :func:`declassification_site` -- the identity predicate plus the
  RECORDABLE shape and the "the value really is ``@secret``" filter,
  returning the raw parts of a manifest record.
- :func:`item_expression_roots` / :func:`module_expression_roots` -- the
  EXHAUSTIVE enumeration of expression-bearing top-level items. Every
  ``Item`` subclass must be registered in :data:`_ITEM_ROOTS`; an
  unregistered one raises :class:`UnknownItemError` rather than being
  silently skipped, so a new expression-bearing item cannot quietly fall
  outside the artifact walk.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

from . import _labels as L
from . import capa_ast as A
from .tokens import Pos

#: The built-in's source-level name. Matching this name is NECESSARY but
#: never SUFFICIENT: identity of the binding decides (see
#: :func:`is_declassify_call`).
DECLASSIFY = "declassify"

#: Expression-root kinds whose sites the manifest attributes to a
#: per-FUNCTION record. Every other kind is module-scope and is recorded
#: in the manifest's ``module_declassifications`` block.
FUNCTION_KINDS = frozenset({"function", "method"})


class UnknownItemError(TypeError):
    """A top-level AST item class is not registered in
    :data:`_ITEM_ROOTS`.

    Raised rather than skipped on purpose: a silent skip is exactly the
    failure that let a ``const``-level ``declassify`` out of the artifact
    walk. A new expression-bearing item must be registered here (with a
    kind string) before it can appear in a compiled program."""


@dataclass(frozen=True)
class ExprRoot:
    """One expression-bearing root of a top-level item.

    - ``kind`` -- ``"function"`` / ``"method"`` / ``"const"``.
    - ``name`` -- the declared name (the loader-time, possibly mangled
      identifier, matching what the manifest keys on).
    - ``decl`` -- the declaring node (the ``FunDecl`` for a
      function/method, the ``ConstDecl`` for a const). Its ``pos`` is the
      declaration site the manifest attributes sites to.
    - ``node`` -- the node to WALK for declassification sites.
    """

    kind: str
    name: str
    decl: A.Node
    node: A.Node


def _fun_roots(item: A.FunDecl) -> tuple[ExprRoot, ...]:
    return (ExprRoot("function", item.name, item, item.body),)


def _impl_roots(item: A.ImplBlock) -> tuple[ExprRoot, ...]:
    return tuple(
        ExprRoot("method", m.name, m, m.body) for m in item.methods
    )


def _const_roots(item: A.ConstDecl) -> tuple[ExprRoot, ...]:
    return (ExprRoot("const", item.name, item, item.value),)


def _no_roots(item: A.Item) -> tuple[ExprRoot, ...]:
    return ()


#: EVERY top-level item class, mapped to the expression roots it carries.
#: An item that carries no expression maps to :func:`_no_roots` -- an
#: EXPLICIT "nothing to walk here", not an omission. Keep this table in
#: sync with ``capa.capa_ast._items``;
#: ``tests/test_declassification_sites.py`` pins the two together by
#: enumerating ``A.Item.__subclasses__()``.
_ITEM_ROOTS: dict[type, Callable[[A.Item], tuple[ExprRoot, ...]]] = {
    A.Import: _no_roots,
    A.ConstDecl: _const_roots,
    A.TypeStruct: _no_roots,
    A.TypeSum: _no_roots,
    A.TypestateDecl: _no_roots,
    A.TraitDecl: _no_roots,
    A.ExternComponent: _no_roots,
    A.FunDecl: _fun_roots,
    A.ImplBlock: _impl_roots,
}


def item_expression_roots(item: A.Item) -> tuple[ExprRoot, ...]:
    """The expression-bearing roots of one top-level ``item``.

    Raises :class:`UnknownItemError` for an item class absent from
    :data:`_ITEM_ROOTS`. That is the loud failure the artifact walk needs:
    an unregistered item would otherwise contribute zero sites to a
    regulatory artifact that claims to count all of them."""
    handler = _ITEM_ROOTS.get(type(item))
    if handler is None:
        raise UnknownItemError(
            f"{type(item).__name__} is not registered in "
            f"capa._declassify._ITEM_ROOTS, so the artifact walk cannot "
            f"know whether it carries expressions. Register it (with "
            f"'_no_roots' when it carries none) before it can appear in a "
            f"compiled program."
        )
    return handler(item)


def module_expression_roots(module: A.Module) -> list[ExprRoot]:
    """Every expression-bearing root in ``module``, in source order."""
    roots: list[ExprRoot] = []
    for item in module.items:
        roots.extend(item_expression_roots(item))
    return roots


def is_builtin_symbol(sym) -> bool:
    """True when ``sym`` is a BUILT-IN binding (its position is the
    synthetic built-in position rather than a real source location).

    The one encoding of "this name still means the built-in", shared by
    every caller below."""
    if sym is None:
        return False
    from .builtins import BUILTIN_POS
    return getattr(sym, "pos", None) == BUILTIN_POS


def is_declassify_call(
    node,
    bindings: Optional[dict[int, object]] = None,
    *,
    module_scope=None,
) -> bool:
    """True when ``node`` is a call to the BUILT-IN ``declassify``.

    The name is NECESSARY but never SUFFICIENT: a user-defined
    ``fun declassify(...)`` (or any other shadowing binding) is NOT a
    declassification, and treating it as one puts a phantom audited
    disclosure into a conformance artifact alongside the un-audited leak
    the analyzer correctly reports -- a self-contradictory claim.

    Identity is established from the most precise source the caller has:

    - ``bindings`` -- the analyzer's ``id(Ident) -> Symbol`` map
      (``AnalysisResult.bindings``). PER CALL SITE, so it sees a LOCAL
      shadow too. What the analyzer's body walk and the manifest use.
    - ``module_scope`` -- anything with ``.lookup(name)`` (the analyzer's
      global scope). MODULE SCOPE only, for the cross-function summary
      pass, which runs BEFORE the body walk populates ``bindings``.
    - neither -- the name alone. A floor, NOT audit-grade, used only by
      the analysis-free manifest callers (docgen, the LSP code lens, the
      Wasm capability side-table, the migrator), none of which read the
      declassification surface. Every artifact-producing CLI path
      supplies ``bindings``."""
    if not isinstance(node, A.Call):
        return False
    if not isinstance(node.callee, A.Ident) or node.callee.name != DECLASSIFY:
        return False
    if bindings is not None:
        return is_builtin_symbol(bindings.get(id(node.callee)))
    if module_scope is not None:
        return is_builtin_symbol(module_scope.lookup(DECLASSIFY))
    return True


@dataclass(frozen=True)
class SiteParts:
    """The raw parts of one recordable declassification site.

    ``value`` is the declassified expression (the caller stringifies it
    for the artifact), ``reason`` the verbatim ``reason:`` literal, and
    ``pos`` the call site."""

    value: A.Expr
    reason: str
    pos: Pos


def declassification_site(
    node,
    *,
    bindings: Optional[dict[int, object]] = None,
    expr_labels: Optional[dict[int, str]] = None,
) -> Optional[SiteParts]:
    """The recordable declassification site ``node`` is, or ``None``.

    Three conditions, all necessary:

    1. ``node`` is a call to the BUILT-IN ``declassify``
       (:func:`is_declassify_call`);
    2. it has the RECORDABLE shape -- the value positionally, then
       ``reason:`` as a plain string literal. The analyzer rejects every
       other shape with a hard error, so this is defensive: a malformed
       call never reaches a manifest, and if one somehow does it is
       skipped rather than recorded with a fabricated reason;
    3. the declassified value is genuinely ``@secret``. ``expr_labels``
       is the analyzer's ``id(expr) -> label`` map; a declassify of an
       already-public value is a no-op the analyzer warns about, and
       counting it would inflate ``declassification_sites`` with
       disclosures that never happen. When ``expr_labels`` is ``None``
       (an analysis-free manifest) every syntactic site is recorded, the
       historical behaviour."""
    if not is_declassify_call(node, bindings):
        return None
    if len(node.args) != 2 or len(node.arg_names) != 2:
        return None
    if node.arg_names[1] != "reason":
        return None
    if not isinstance(node.args[1], A.StringLit):
        return None
    if (
        expr_labels is not None
        and expr_labels.get(id(node.args[0])) != L.SECRET
    ):
        return None
    return SiteParts(
        value=node.args[0], reason=node.args[1].value, pos=node.pos,
    )
