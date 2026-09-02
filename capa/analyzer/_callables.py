"""Single source of truth for the user-callable KEY convention and the
module enumeration that walks it.

A "user callable" is a free function, an impl / trait method, or a lambda
literal. Two cross-function passes summarise every one of them -- the IFC
sink/return-effect fixpoint (:mod:`._ifc_summary`) and the E3 return-origin
pass (:mod:`._return_origin`) -- and the analyzer's main walk resolves a
call site back to a callable key at every consult. Those three producers and
the call-site resolver used to spell the key tuples and re-derive the
enumeration by hand; the walks drifted (a duplicated enumeration diverged
from the IFC pass), so the classification is centralised here. There is
exactly one key convention and one enumeration; a second copy anywhere is a
bug.

Keys (the ONE convention):

* ``("fun", name)``                  -- a free function
* ``("method", type_name, method)``  -- an impl / trait method
* ``("lambda", id(lambda_expr))``    -- a lambda literal

``iter_user_callables`` yields each unique callable once (methods keyed by
``(type, name)`` are de-duplicated exactly as the summary builders require),
so a consumer never seeds a table for one kind of callable but not another.
"""

from __future__ import annotations

import dataclasses
from typing import Iterator, Optional

from .. import capa_ast as A


def fun_key(name: str) -> tuple:
    """The callable key of a free function ``name``."""
    return ("fun", name)


def method_key(type_name: str, method: str) -> tuple:
    """The callable key of the method ``method`` on type ``type_name``
    (an impl method keyed by its concrete owner, or a trait method keyed
    by the trait name)."""
    return ("method", type_name, method)


def lambda_key(lam: A.LambdaExpr) -> tuple:
    """The callable key of a lambda literal, stable for the single parsed
    module the builder and the main walk share (the AST node ``id``)."""
    return ("lambda", id(lam))


@dataclasses.dataclass(frozen=True)
class UserCallable:
    """One enumerated user callable and everything the summary builders
    need to seed a table for it, in the canonical parameter order the
    analyzer uses (``self`` at index 0 for a method, then the explicit
    parameters).

    ``kind`` is ``"fun"`` / ``"method"`` / ``"trait_method"`` / ``"lambda"``;
    ``node`` is the underlying ``FunDecl`` / method ``FunDecl`` / trait
    signature / ``LambdaExpr``; ``owner`` is the impl / trait owner type
    (``None`` for a free function or a lambda); ``by_name`` marks an impl
    method that the receiver-type-unknown over-approximation groups by name
    (a trait signature is deliberately excluded); ``return_type`` is the
    declared return ``TypeExpr`` (``None`` when absent)."""

    key: tuple
    params: list
    is_method: bool
    kind: str
    node: object
    owner: Optional[str] = None
    by_name: bool = False
    return_type: object = None
    type_params: tuple = ()


def iter_user_callables(module: A.Module) -> Iterator[UserCallable]:
    """Yield every user callable in ``module`` exactly once, under the ONE
    key convention. Free functions, then impl methods (de-duplicated by
    ``(type, name)``), then trait-method signatures (de-duplicated), then
    every lambda literal reachable anywhere (a nested lambda inside another
    lambda's body gets its own key). The order matches the IFC summary
    builder's historic collection order so its fixpoint is unchanged."""
    seen_methods: set = set()
    for item in module.items:
        if isinstance(item, A.FunDecl):
            yield UserCallable(
                key=fun_key(item.name), params=item.params, is_method=False,
                kind="fun", node=item, return_type=item.return_type,
                type_params=tuple(item.type_params),
            )
        elif isinstance(item, A.ImplBlock):
            impl_tps = tuple(getattr(item, "type_args", None) or ())
            impl_tp_names = tuple(
                getattr(a, "name", None) for a in impl_tps
                if getattr(a, "name", None) is not None
            )
            for method in item.methods:
                key = method_key(item.type_name, method.name)
                if key in seen_methods:
                    continue
                seen_methods.add(key)
                yield UserCallable(
                    key=key, params=method.params, is_method=True,
                    kind="method", node=method, owner=item.type_name,
                    by_name=True, return_type=method.return_type,
                    type_params=impl_tp_names + tuple(method.type_params),
                )
        elif isinstance(item, A.TraitDecl):
            trait_tps = tuple(item.type_params)
            for sig in item.methods:
                key = method_key(item.name, sig.name)
                if key in seen_methods:
                    continue
                seen_methods.add(key)
                yield UserCallable(
                    key=key, params=sig.params, is_method=True,
                    kind="trait_method", node=sig, owner=item.name,
                    by_name=False, return_type=sig.return_type,
                    type_params=trait_tps + tuple(sig.type_params),
                )
    for lam in _iter_lambdas(module):
        yield UserCallable(
            key=lambda_key(lam), params=lam.params, is_method=False,
            kind="lambda", node=lam, return_type=lam.return_type,
        )


def _iter_lambdas(node) -> Iterator[A.LambdaExpr]:
    """Yield every ``LambdaExpr`` reachable from ``node`` (a nested lambda
    inside another lambda's body is yielded too). A dataclass walk shared by
    both summary passes so the lambda enumeration cannot drift."""
    if isinstance(node, A.LambdaExpr):
        yield node
    if dataclasses.is_dataclass(node):
        for f in dataclasses.fields(node):
            yield from _iter_lambdas(getattr(node, f.name))
    elif isinstance(node, (list, tuple)):
        for x in node:
            yield from _iter_lambdas(x)
