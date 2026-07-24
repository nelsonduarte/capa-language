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
body, and it fails CLOSED: the ONLY accepted occurrence of a borrow
parameter is as the direct callee of a call at the top level of the
body, ``handler(...)``. Every other syntactic occurrence is treated as
an escape and rejected, including:

- returning it, or binding it (``let f = handler``) -- a bare alias is
  rejected rather than proven safe;
- placing it in a struct / list / tuple literal;
- passing it as an argument to another call (``other(handler)``);
- using it as a method-call receiver or field access (``handler.x``);
- ANY occurrence inside a lambda body (``fun () => handler(x)``), even
  as a callee, because the lambda closes over it and can itself escape.

Being wrong in the permissive direction reopens the higher-order
ceiling hole; being wrong in the restrictive direction merely leaves a
valid program failing its ceiling. So the rule errs restrictive.

Both the analyzer (which reports each escape as a compile error) and
the manifest builder (which needs the invoke-only verdict to compute
the ceiling signal) use these helpers, so the two never disagree.
"""

from __future__ import annotations

from . import capa_ast as A
from .tokens import Pos


def is_fun_typed_param(type_expr) -> bool:
    """True when ``type_expr`` is directly a ``Fun(...) -> ...`` type.

    ``borrow`` is only meaningful on a function-typed parameter; a
    ``Fun`` nested inside a tuple or generic is deliberately NOT
    accepted (the invoke-only rule names the parameter itself, not a
    component of it), so such a parameter is reported as an error.
    """
    return isinstance(type_expr, A.FunType)


def borrow_escapes(body, name: str) -> list[Pos]:
    """Return the positions where ``name`` escapes invoke-only use.

    An empty list means the parameter is used ONLY as the direct callee
    of a top-level call, i.e. the invoke-only property holds. Any other
    occurrence is recorded, in source order, so the caller can report
    each escape site.
    """
    escapes: list[Pos] = []
    _walk(body, name, escapes, in_lambda=False)
    return escapes


def _walk(node, name: str, escapes: list[Pos], *, in_lambda: bool) -> None:
    if node is None:
        return

    # A lambda closes over the borrow parameter: any occurrence inside
    # its body (even an invocation) lets the callback outlive the call
    # if the lambda escapes, so the whole body is walked as "captured".
    if isinstance(node, A.LambdaExpr):
        _walk(node.body, name, escapes, in_lambda=True)
        return

    # The one accepted shape: a direct top-level call ``name(...)``.
    # The callee occurrence is NOT an escape; the arguments are still
    # walked so ``name(name)`` (passing itself) is caught.
    if isinstance(node, A.Call):
        callee = node.callee
        if (
            isinstance(callee, A.Ident)
            and callee.name == name
            and not in_lambda
        ):
            for arg in node.args:
                _walk(arg, name, escapes, in_lambda=in_lambda)
            return
        _walk(callee, name, escapes, in_lambda=in_lambda)
        for arg in node.args:
            _walk(arg, name, escapes, in_lambda=in_lambda)
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
                _walk(v, name, escapes, in_lambda=in_lambda)
            elif isinstance(v, list):
                for item in v:
                    if isinstance(item, A.Node):
                        _walk(item, name, escapes, in_lambda=in_lambda)
                    elif isinstance(item, tuple):
                        for it in item:
                            if isinstance(it, A.Node):
                                _walk(it, name, escapes, in_lambda=in_lambda)
