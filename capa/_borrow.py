"""The ``borrow`` parameter modifier: invoke-only verification.

A ``Fun``-typed parameter marked ``borrow`` is a promise that the
function only INVOKES the callback and never retains it: it may not
store the callback in a field or module state, return it, alias it,
pass it on to another function, or capture it inside a lambda that
outlives the call. When that promise holds, the higher-order function
does not have to charge the callback's authority to its OWN package
ceiling; the closure's authority is already accounted at its creation
site (the caller that built the closure captured that authority as a
named parameter, and Capa's discipline forbids capabilities anywhere
else). So the callee's ceiling can stay honest while the product SBOM
still sees every capability the handler exercises.

The property is checked LOCALLY and SYNTACTICALLY over the function
body, and it fails CLOSED: the ONLY accepted occurrences of a borrow
parameter are as the direct callee of a call at the top level of the
body, ``handler(...)``, and (see FORWARDING below) as an argument that
lands in a parameter position of a statically resolved same-module
callee that is ITSELF declared ``borrow``. Every other syntactic
occurrence is treated as an escape and rejected, including:

- returning it, or binding it (``let f = handler``) -- a bare alias is
  rejected rather than proven safe;
- placing it in a struct / list / tuple literal;
- passing it as an argument to another call (``other(handler)``) whose
  target position is NOT declared ``borrow``;
- using it as a method-call receiver or field access (``handler.x``);
- ANY occurrence inside a lambda body (``fun () => handler(x)``), even
  as a callee, because the lambda closes over it and can itself escape.

FORWARDING (intra-module). Passing a ``borrow`` parameter as an argument
into a call ``f(..., handler, ...)`` is NOT an escape when ALL of the
following hold; otherwise it stays an escape:

- ``f`` is a direct, named call (an ``Ident`` callee), not a first-class
  call through a ``Fun``-typed value and not a dynamically dispatched
  method (those have no static ``borrow`` signature);
- ``f`` statically resolves to a function DECLARED IN THE SAME MODULE
  (same source file). ``borrow``-ness is not carried across the module
  boundary (it is not in the exported interface), so a cross-module
  forward fails closed;
- the parameter of ``f`` at that argument position is itself declared
  ``borrow``. A bare-``Fun`` target position may legally retain or return
  the callback, so forwarding into one stays rejected.

This is sound because ``borrow`` is SELF-VERIFYING: a callee declaring
``borrow cb`` that leaked it would itself be a compile error, so a caller
may trust the callee's signature without reading its body. The check is a
per-call-site signature lookup; no fixpoint and no callee-body inspection.

Being wrong in the permissive direction reopens the higher-order
ceiling hole; being wrong in the restrictive direction merely leaves a
valid program failing its ceiling. So the rule errs restrictive.

Both the analyzer (which reports each escape as a compile error) and
the manifest builder (which needs the invoke-only verdict to compute
the ceiling signal) use these helpers, so the two never disagree.
"""

from __future__ import annotations

from typing import Callable, Optional

from . import capa_ast as A
from .tokens import Pos

# A "resolve callee borrow positions" resolver. Given the name of a
# direct call's callee, it returns the callee's per-positional-parameter
# ``(param_name, is_borrow)`` list (``self`` stripped, so positional index
# lines up with the call's positional argument index), or ``None`` when the
# name does NOT statically resolve to a same-module function declaration.
# Both the analyzer and the manifest supply one so their verdicts agree.
BorrowResolver = Callable[[str], Optional[list[tuple[str, bool]]]]


def is_fun_typed_param(type_expr) -> bool:
    """True when ``type_expr`` is directly a ``Fun(...) -> ...`` type.

    ``borrow`` is only meaningful on a function-typed parameter; a
    ``Fun`` nested inside a tuple or generic is deliberately NOT
    accepted (the invoke-only rule names the parameter itself, not a
    component of it), so such a parameter is reported as an error.
    """
    return isinstance(type_expr, A.FunType)


def borrow_escapes(
    body,
    name: str,
    *,
    resolve_borrow_params: Optional[BorrowResolver] = None,
    local_names: Optional[list[str]] = None,
) -> list[Pos]:
    """Return the positions where ``name`` escapes invoke-only use.

    An empty list means the parameter is used ONLY as the direct callee
    of a top-level call, or forwarded into a ``borrow`` position (see the
    module docstring), i.e. the invoke-only property holds. Any other
    occurrence is recorded, in source order, so the caller can report
    each escape site.

    ``resolve_borrow_params`` enables the intra-module FORWARDING
    relaxation; when ``None`` (the default) no forwarding is accepted and
    every argument occurrence stays an escape, exactly as before.

    ``local_names`` names the enclosing function's own parameters. Along
    with the ``let`` / ``var`` / ``for`` / lambda bindings collected from
    the body, they form the set of names that could SHADOW a same-module
    function at a call site; a callee whose name is shadowed is not
    resolved (fail closed), so a local ``Fun``-typed value that happens to
    share a top-level function's name is never mistaken for it.
    """
    escapes: list[Pos] = []
    shadowed: set[str] = set()
    if resolve_borrow_params is not None:
        _collect_bound_names(body, shadowed)
        if local_names:
            shadowed.update(local_names)
    _walk(
        body, name, escapes, in_lambda=False,
        resolve=resolve_borrow_params, shadowed=shadowed,
    )
    return escapes


def _collect_bound_names(node, acc: set[str]) -> None:
    """Collect every name a binding introduces anywhere under ``node``.

    Conservative and position-insensitive: it gathers pattern binders
    (``let`` / ``for`` / ``var`` and match arms) and lambda/nested
    parameters regardless of scope, so any name that could shadow a
    same-module function is excluded from resolution.
    """
    if node is None:
        return
    if isinstance(node, A.IdentPat):
        acc.add(node.name)
    elif isinstance(node, A.VarStmt):
        acc.add(node.name)
    elif isinstance(node, A.Param):
        acc.add(node.name)
    if isinstance(node, A.Node):
        for f in node.__dataclass_fields__.values():
            if f.name == "pos":
                continue
            v = getattr(node, f.name)
            if isinstance(v, A.Node):
                _collect_bound_names(v, acc)
            elif isinstance(v, list):
                for item in v:
                    if isinstance(item, A.Node):
                        _collect_bound_names(item, acc)
                    elif isinstance(item, tuple):
                        for it in item:
                            if isinstance(it, A.Node):
                                _collect_bound_names(it, acc)


def _forwards_into_borrow(targets, index: int, arg_names) -> bool:
    """True when the argument at ``index`` lands in a ``borrow`` parameter
    of the resolved callee (``targets``), by name for a named argument or
    by position otherwise. False when the callee did not resolve."""
    if targets is None:
        return False
    arg_name = arg_names[index] if index < len(arg_names) else None
    if arg_name is not None:
        for param_name, borrowing in targets:
            if param_name == arg_name:
                return borrowing
        return False
    if index < len(targets):
        return targets[index][1]
    return False


def _walk(
    node,
    name: str,
    escapes: list[Pos],
    *,
    in_lambda: bool,
    resolve: Optional[BorrowResolver],
    shadowed: set[str],
) -> None:
    if node is None:
        return

    # A lambda closes over the borrow parameter: any occurrence inside
    # its body (even an invocation) lets the callback outlive the call
    # if the lambda escapes, so the whole body is walked as "captured".
    if isinstance(node, A.LambdaExpr):
        _walk(
            node.body, name, escapes, in_lambda=True,
            resolve=resolve, shadowed=shadowed,
        )
        return

    if isinstance(node, A.Call):
        callee = node.callee
        # The one directly accepted shape: a top-level call ``name(...)``.
        # The callee occurrence is NOT an escape.
        self_invoke = (
            isinstance(callee, A.Ident)
            and callee.name == name
            and not in_lambda
        )
        # FORWARDING: look up the callee's per-position borrow signature,
        # but only for a direct, named, non-shadowed call outside a lambda.
        # A call inside a lambda captures the callback, so no forward there.
        targets = None
        if (
            resolve is not None
            and not in_lambda
            and isinstance(callee, A.Ident)
            and callee.name not in shadowed
        ):
            targets = resolve(callee.name)
        if not self_invoke:
            _walk(
                callee, name, escapes, in_lambda=in_lambda,
                resolve=resolve, shadowed=shadowed,
            )
        arg_names = node.arg_names or []
        for i, arg in enumerate(node.args):
            if (
                not in_lambda
                and isinstance(arg, A.Ident)
                and arg.name == name
                and _forwards_into_borrow(targets, i, arg_names)
            ):
                # Forwarded into a ``borrow`` position of a resolved
                # same-module callee: not an escape.
                continue
            _walk(
                arg, name, escapes, in_lambda=in_lambda,
                resolve=resolve, shadowed=shadowed,
            )
        return

    # Any other reference to the name is an escape.
    if isinstance(node, A.Ident):
        if node.name == name:
            escapes.append(node.pos)
        return

    # Generic traversal over Node-typed and list-of-Node fields, mirroring
    # the manifest's call walker (struct-field / match-arm tuples included).
    if isinstance(node, A.Node):
        for f in node.__dataclass_fields__.values():
            if f.name == "pos":
                continue
            v = getattr(node, f.name)
            if isinstance(v, A.Node):
                _walk(
                    v, name, escapes, in_lambda=in_lambda,
                    resolve=resolve, shadowed=shadowed,
                )
            elif isinstance(v, list):
                for item in v:
                    if isinstance(item, A.Node):
                        _walk(
                            item, name, escapes, in_lambda=in_lambda,
                            resolve=resolve, shadowed=shadowed,
                        )
                    elif isinstance(item, tuple):
                        for it in item:
                            if isinstance(it, A.Node):
                                _walk(
                                    it, name, escapes, in_lambda=in_lambda,
                                    resolve=resolve, shadowed=shadowed,
                                )
