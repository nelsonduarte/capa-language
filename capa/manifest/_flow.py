"""Per-call data-flow tracking for the manifest.

Capa's manifest reports, for each call site, the *syntactic* form of
every argument. This module adds a parallel ``args_flow`` field that
tracks, by binding, what attenuations were applied to a capability
before it was handed to the callee.

v1 scope (deliberately small):

- only ``let x = <chain of .restrict_to*(args)>`` patterns where the
  root of the chain is an Ident
- propagation across consecutive let bindings:

      let a = net.restrict_to("h1")
      let b = a.restrict_to("h2")    -> b carries [h1, h2]

- method names matched: those in ``_ATTENUATION_METHODS``
- traversal stops at function boundaries; this is intra-function

Out of scope (v1): struct-field flow, match-arm rebinding, var-stmt
reassignment, inter-procedural propagation (resolving ``mailer.send``
to a specific ``impl`` of ``SendEmail``). Out-of-scope cases simply
yield no ``args_flow`` entry for those arguments; the syntactic
``args`` field is still emitted.
"""

from __future__ import annotations

from typing import Any, Optional

from .. import capa_ast as A

from ._strings import _stringify_expr


# Method names the data-flow tracker recognises as attenuation. A
# call to any of these on a tracked capability produces a derived
# binding that the manifest follows. The first three are the
# `restrict_to*` family on Net / Fs / Env / Clock; `with_seed`
# is the analogue on Random (deterministic seeding).
_ATTENUATION_METHODS: frozenset[str] = frozenset({
    "restrict_to",
    "restrict_to_keys",
    "restrict_to_after",
    "with_seed",
})


def _build_attenuation_map(
    body,
) -> dict[str, list[dict[str, Any]]]:
    """Walk a function body and record, per binding name, the list of
    restriction calls applied to its value (in source order).

    Only top-level ``LetStmt``s inside the body and its immediate
    blocks are considered. Patterns are intentionally simple to
    keep the surface tight; richer flow tracking can come later.
    """
    out: dict[str, list[dict[str, Any]]] = {}

    def visit(n) -> None:
        if n is None:
            return
        if isinstance(n, A.LetStmt) and isinstance(n.pattern, A.IdentPat):
            name = n.pattern.name
            root, atts = _flatten_restrict_chain(n.value)
            if not atts:
                # Not an attenuation chain; nothing to record. (We do
                # *not* clear an existing entry, since Capa's let is
                # immutable and shadowing in the same scope is unusual.)
                return
            if isinstance(root, A.Ident) and root.name in out:
                # Chain off an already-tracked binding: prepend its
                # restrictions so the new binding carries the full
                # history.
                out[name] = out[root.name] + atts
            else:
                out[name] = atts
            return
        if isinstance(n, A.Node):
            for f in n.__dataclass_fields__.values():
                if f.name == "pos":
                    continue
                v = getattr(n, f.name)
                if isinstance(v, A.Node):
                    visit(v)
                elif isinstance(v, list):
                    for it in v:
                        if isinstance(it, A.Node):
                            visit(it)
                        elif isinstance(it, tuple):
                            for tt in it:
                                if isinstance(tt, A.Node):
                                    visit(tt)

    visit(body)
    return out


def _flatten_restrict_chain(expr):
    """Walk a method-call expression that may chain attenuation
    calls (any method named in ``_ATTENUATION_METHODS``). Returns
    ``(innermost_receiver, [attenuation, ...])`` in source order.
    If the expression is not such a chain, returns ``(expr, [])``.
    """
    atts: list[dict[str, Any]] = []
    cur = expr
    while (
        isinstance(cur, A.MethodCall)
        and cur.method in _ATTENUATION_METHODS
    ):
        atts.insert(0, {
            "method": cur.method,
            "args": [_stringify_expr(a) for a in cur.args],
        })
        cur = cur.receiver
    return cur, atts


def _arg_flow(
    arg,
    attenuation_map: dict[str, list[dict[str, Any]]],
):
    """If ``arg`` is an Ident that names a tracked binding, return a
    flow record. Otherwise return None.
    """
    if isinstance(arg, A.Ident) and arg.name in attenuation_map:
        return {
            "name": arg.name,
            "attenuations": list(attenuation_map[arg.name]),
        }
    return None
