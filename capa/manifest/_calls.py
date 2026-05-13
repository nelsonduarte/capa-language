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
