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
"""

from __future__ import annotations

from typing import Any, Optional

from .. import capa_ast as A

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

    # Generic AST traversal: visit any Node-typed or list-of-Node field.
    if isinstance(node, A.Node):
        for f in node.__dataclass_fields__.values():
            if f.name == "pos":
                continue
            v = getattr(node, f.name)
            if isinstance(v, A.Node):
                _collect_calls(v, calls, attenuation_map=attenuation_map)
            elif isinstance(v, list):
                for item in v:
                    if isinstance(item, A.Node):
                        _collect_calls(
                            item, calls, attenuation_map=attenuation_map,
                        )
                    elif isinstance(item, tuple):
                        # struct field pairs (name, Expr), match arms etc.
                        for it in item:
                            if isinstance(it, A.Node):
                                _collect_calls(
                                    it, calls,
                                    attenuation_map=attenuation_map,
                                )


def _collect_declassifications(
    node,
    sites: list[dict[str, Any]],
    *,
    expr_labels: Optional[dict[int, str]] = None,
) -> None:
    """Recursively collect ``declassify(value, reason: "...")`` call
    sites from a function body (roadmap S2.5).

    Each site records the ``reason`` string verbatim, the source-like
    stringification of the declassified value, and the position. This
    is the regulatory centerpiece of the IFC work: an SBOM consumer
    reads off every point where the program deliberately lets a
    ``@secret`` value cross to ``@public``, and the stated reason.

    ``expr_labels`` is the analyzer's ``id(expr) -> label`` map. When
    supplied, a ``declassify`` whose value argument is provably NOT
    ``@secret`` is skipped: such a call is a no-op (the analyzer already
    warns on it), and counting it would inflate the manifest's
    ``declassification_sites`` with disclosures that never happen,
    contradicting the field's definition ("every point where @secret
    crosses to @public"). When ``expr_labels`` is ``None`` (a manifest
    built without an accompanying analysis), every syntactic declassify
    is recorded, the historical behaviour.

    The analyzer has already enforced the call shape (a required
    ``reason:`` string literal), so this walker trusts it; a
    defensively malformed node is skipped rather than recorded."""
    if node is None:
        return

    if (
        isinstance(node, A.Call)
        and isinstance(node.callee, A.Ident)
        and node.callee.name == "declassify"
        and len(node.args) == 2
        and len(node.arg_names) == 2
        and node.arg_names[1] == "reason"
        and isinstance(node.args[1], A.StringLit)
    ):
        # Only a declassify of a genuinely @secret value is a real
        # disclosure. With label info, drop the no-op case.
        is_real = True
        if expr_labels is not None:
            label = expr_labels.get(id(node.args[0]))
            is_real = label == "secret"
        if is_real:
            sites.append({
                "reason": node.args[1].value,
                "value": _stringify_expr(node.args[0]),
                "pos": f"{node.pos.line}:{node.pos.col}",
            })

    # Always keep walking: a declassify can be nested anywhere, and a
    # declassified value may itself contain a nested declassify.
    if isinstance(node, A.Node):
        for f in node.__dataclass_fields__.values():
            if f.name == "pos":
                continue
            v = getattr(node, f.name)
            if isinstance(v, A.Node):
                _collect_declassifications(v, sites, expr_labels=expr_labels)
            elif isinstance(v, list):
                for item in v:
                    if isinstance(item, A.Node):
                        _collect_declassifications(
                            item, sites, expr_labels=expr_labels,
                        )
                    elif isinstance(item, tuple):
                        for it in item:
                            if isinstance(it, A.Node):
                                _collect_declassifications(
                                    it, sites, expr_labels=expr_labels,
                                )
