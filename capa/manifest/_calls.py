"""Call-site extraction for the manifest.

Walks a function body and records every call (plain function or
method) found anywhere in expression position, including inside
nested expressions. Each record carries:

- ``kind``:    ``"fn"`` or ``"method"``
- ``callee``:  function name, or ``"receiver.method"`` for method
  calls
- ``pos``:     ``"line:col"`` of the call site
- ``args``:    list of source-like stringifications of the argument
  expressions, truncated to ``_MAX_ARG_REPR`` characters

The call list is the audit primitive: a CRA reviewer sees, for each
function in the program, *what other functions it invokes and with
what arguments*, including restrictions applied via
``restrict_to(...)`` calls visible directly in the argument
expressions.

:func:`_collect_declassifications` alongside it is the declassification
walker. It takes ANY expression-bearing root, not just a function body
(a top-level ``const`` initializer carries one too), and it does not
decide what counts as a declassification: :mod:`capa._declassify` does,
for the analyzer and this walker alike.
"""

from __future__ import annotations

from typing import Any, Optional

from .. import capa_ast as A
from .._declassify import declassification_site

from ._flow import _arg_flow
from ._strings import _stringify_expr


def _collect_calls(
    node,
    calls: list[dict[str, Any]],
    *,
    attenuation_map: Optional[dict[str, list[dict[str, Any]]]] = None,
) -> None:
    """Recursively collect Call/MethodCall expressions from any node.

    When ``attenuation_map`` is supplied, each recorded call also
    carries an ``args_flow`` parallel list. For arguments that are
    plain identifiers tracked in the map, the corresponding entry
    is a dict ``{"name": str, "attenuations": [...]}``; for other
    arguments it is ``None``. This is the data-flow surface of the
    manifest: an auditor sees not just that ``api`` was passed to
    ``fetch_user``, but that ``api`` was a ``Net`` narrowed via
    ``restrict_to("api.example.com")``.
    """
    if node is None:
        return

    if isinstance(node, A.Call):
        if isinstance(node.callee, A.Ident):
            callee_name = node.callee.name
        else:
            callee_name = _stringify_expr(node.callee)
        record: dict[str, Any] = {
            "kind": "fn",
            "callee": callee_name,
            "pos": f"{node.pos.line}:{node.pos.col}",
            "args": [_stringify_expr(a) for a in node.args],
        }
        if attenuation_map is not None:
            record["args_flow"] = [
                _arg_flow(a, attenuation_map) for a in node.args
            ]
        calls.append(record)
        # Recurse into the callee expression (so f(g(x)) records g too)
        # and into each argument.
        _collect_calls(node.callee, calls, attenuation_map=attenuation_map)
        for arg in node.args:
            _collect_calls(arg, calls, attenuation_map=attenuation_map)
        return

    if isinstance(node, A.MethodCall):
        receiver_str = _stringify_expr(node.receiver)
        record = {
            "kind": "method",
            "callee": f"{receiver_str}.{node.method}",
            "pos": f"{node.pos.line}:{node.pos.col}",
            "args": [_stringify_expr(a) for a in node.args],
        }
        if attenuation_map is not None:
            record["args_flow"] = [
                _arg_flow(a, attenuation_map) for a in node.args
            ]
        calls.append(record)
        _collect_calls(node.receiver, calls, attenuation_map=attenuation_map)
        for arg in node.args:
            _collect_calls(arg, calls, attenuation_map=attenuation_map)
        return

    # Generic AST traversal: visit every direct child node (shared
    # enumeration, byte-identical to the former inline dataclass walk).
    if isinstance(node, A.Node):
        for child in A.children(node):
            _collect_calls(child, calls, attenuation_map=attenuation_map)


def _collect_declassifications(
    node,
    sites: list[dict[str, Any]],
    *,
    bindings: Optional[dict[int, Any]] = None,
    expr_labels: Optional[dict[int, str]] = None,
) -> None:
    """Recursively collect ``declassify(value, reason: "...")`` call
    sites from an expression-bearing root (roadmap S2.5).

    Each site records the ``reason`` string verbatim, the source-like
    stringification of the declassified value, and the position. This
    is the regulatory centerpiece of the IFC work: an SBOM consumer
    reads off every point where the program deliberately lets a
    ``@secret`` value cross to ``@public``, and the stated reason.

    WHAT counts as a site is NOT decided here: it is decided by
    :func:`capa._declassify.declassification_site`, the single source of
    truth this walker shares with the analyzer. This function only walks
    and formats. ``bindings`` (the analyzer's ``id(Ident) -> Symbol``
    map) and ``expr_labels`` (its ``id(expr) -> label`` map) are passed
    straight through: the former makes IDENTITY rather than the callee's
    NAME decide (a user-defined ``fun declassify`` is not a
    declassification), the latter drops the no-op declassify of an
    already-public value.

    The root may be a function body OR any other expression-bearing item
    root -- a top-level ``const`` initializer above all, whose sites were
    invisible to every artifact before this walk was generalised."""
    if node is None:
        return

    parts = declassification_site(
        node, bindings=bindings, expr_labels=expr_labels,
    )
    if parts is not None:
        sites.append({
            "reason": parts.reason,
            "value": _stringify_expr(parts.value),
            "pos": f"{parts.pos.line}:{parts.pos.col}",
        })

    # Always keep walking: a declassify can be nested anywhere, and a
    # declassified value may itself contain a nested declassify.
    if isinstance(node, A.Node):
        for child in A.children(node):
            _collect_declassifications(
                child, sites, bindings=bindings, expr_labels=expr_labels,
            )
