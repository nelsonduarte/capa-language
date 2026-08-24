"""Free-variable analysis for CIR lambdas (single source).

Both closure emitters need the same answer to one question: which
names does a ``MakeLambda`` body reference that must come from an
enclosing scope? The Wasm emitter uses the set to lay out the
closure's env record; the Python emitter uses it to rebind each
capture as a default argument (``def _lam(x, i=i): ...``) so a loop
variable is bound by value at def-execution time, matching Wasm
instead of Python's late-binding closure semantics.

Keeping one walk here means a capture the analysis learns to see (a
match-guard prelude reference, a nested-lambda propagation, a
higher-order callee captured from the enclosing scope) is seen by
both backends at once, rather than drifting between two hand-synced
copies.

The one backend-specific decision is threaded in as a callback:
whether a bare ``Call`` callee name (which is not a :class:`Value`,
so the value walk never sees it) counts as a capture. The Wasm
emitter answers via its capture-type resolution (a name that
resolves to a ``Fun`` type in the enclosing scope); the Python
emitter answers via enclosing-scope membership.
"""

from __future__ import annotations

from typing import Callable, NamedTuple

from ._nodes import (
    Instr, Value, MakeLambda, For, If, While, Match,
    Pattern, PatIdent, PatVariant,
)


def values_of(instr: Instr) -> list[Value]:
    """Return every :class:`Value`-typed slot on ``instr``.

    The single enumeration of an instruction's value operands, shared
    by the Wasm discovery pass (string interning) and the free-variable
    walk below so the two never disagree about which slots carry a
    reference."""
    out: list[Value] = []
    for attr in (
        "src", "value", "left", "right",
        "operand", "receiver", "iter", "cond", "index",
    ):
        v = getattr(instr, attr, None)
        if isinstance(v, Value):
            out.append(v)
    for v in getattr(instr, "args", []) or []:
        if isinstance(v, Value):
            out.append(v)
    for fname_v in getattr(instr, "fields", []) or []:
        if isinstance(fname_v, tuple) and len(fname_v) == 2:
            v = fname_v[1]
            if isinstance(v, Value):
                out.append(v)
    for v in getattr(instr, "elements", []) or []:
        if isinstance(v, Value):
            out.append(v)
    for part in getattr(instr, "parts", []) or []:
        if isinstance(part, Value):
            out.append(part)
    return out


def pattern_names(pat: Pattern, out: set[str]) -> None:
    """Add every name a pattern binds to ``out``. Covers the pattern
    shapes that introduce a binding inside a lambda body (``PatIdent``
    directly, ``PatVariant`` through its payloads); literal / wildcard
    patterns bind nothing."""
    if isinstance(pat, PatIdent):
        out.add(pat.name)
        return
    if isinstance(pat, PatVariant):
        for sub in pat.payloads:
            pattern_names(sub, out)
        return


class LambdaVars(NamedTuple):
    """Result of :func:`analyze_lambda`.

    ``free`` is the set of names the lambda captures from an enclosing
    scope; ``defined`` is the set of names the lambda's own body binds
    (its locals, loop variables, and pattern binders), which the Wasm
    emitter reuses to type the lifted function's locals."""
    free: set[str]
    defined: set[str]


def _collect_defs(instrs: list[Instr], out: set[str]) -> None:
    """Add every name bound inside ``instrs`` to ``out``: instruction
    destinations, ``For`` loop variables, and match-arm pattern
    binders (including each arm's guard-prelude temporaries)."""
    for i in instrs:
        dst = getattr(i, "dst", None)
        if dst:
            out.add(dst)
        if isinstance(i, For):
            out.add(i.name)
            _collect_defs(i.body, out)
        elif isinstance(i, If):
            _collect_defs(i.then_body, out)
            _collect_defs(i.else_body, out)
        elif isinstance(i, While):
            _collect_defs(i.cond_setup, out)
            _collect_defs(i.body, out)
        elif isinstance(i, Match):
            for arm in i.arms:
                if getattr(arm, "guard_setup", None):
                    _collect_defs(arm.guard_setup, out)
                _collect_defs(arm.body, out)
                pattern_names(arm.pattern, out)


def analyze_lambda(
    lam: MakeLambda,
    *,
    callee_is_capture: Callable[[str], bool],
) -> LambdaVars:
    """Compute the captured (free) names and the body-defined names of
    one ``MakeLambda``.

    A name is captured when it is referenced in the body (as a
    ``local`` / ``param`` :class:`Value`, or as a ``Call`` callee for
    which ``callee_is_capture`` returns True) but is neither one of the
    lambda's own parameters nor bound anywhere in its body. A nested
    lambda contributes the free names it cannot satisfy itself, per the
    standard rule ``free(outer) = free(direct) ∪ (free(nested) -
    nested.params - nested.locals)``: an inner closure's unbound names
    must be supplied by some enclosing scope, so if the outer is that
    scope it must capture them too."""
    own_params: set[str] = {p.name for p in lam.params}
    defined_in_body: set[str] = set()
    _collect_defs(lam.body, defined_in_body)

    def free_vars(
        body_instrs: list[Instr],
        shadow_params: set[str],
        shadow_locals: set[str],
    ) -> set[str]:
        out: set[str] = set()

        def collect(v: Value) -> None:
            if v.kind in ("local", "param") and v.name:
                if v.name in shadow_params or v.name in shadow_locals:
                    return
                out.add(v.name)

        def collect_callee(callee) -> None:
            # A ``Call``'s callee is a bare name, not a Value, so the
            # value walk never yields it. A higher-order function
            # captured from an enclosing scope (``compose(f, g) =>
            # fun(x) => g(f(x))`` where ``f`` / ``g`` appear only as
            # call targets) would then be missed. Add it iff it is not
            # shadowed by the lambda's own params / locals and the
            # backend's callback certifies it as an enclosing capture.
            if not callee:
                return
            if callee in shadow_params or callee in shadow_locals:
                return
            if callee_is_capture(callee):
                out.add(callee)

        def walk(instrs: list[Instr]) -> None:
            for i in instrs:
                if isinstance(i, MakeLambda):
                    inner_params = {p.name for p in i.params}
                    inner_defs: set[str] = set()
                    _collect_defs(i.body, inner_defs)
                    nested_free = free_vars(
                        i.body, inner_params, inner_defs,
                    )
                    for n in nested_free:
                        if (n not in shadow_params
                                and n not in shadow_locals):
                            out.add(n)
                    # The MakeLambda dst is not a reference; skip the
                    # standard value walk for it.
                    continue
                collect_callee(getattr(i, "callee_name", None))
                for v in values_of(i):
                    collect(v)
                if isinstance(i, If):
                    collect(i.cond)
                    walk(i.then_body)
                    walk(i.else_body)
                elif isinstance(i, While):
                    walk(i.cond_setup)
                    collect(i.cond)
                    walk(i.body)
                elif isinstance(i, For):
                    collect(i.iter)
                    walk(i.body)
                elif isinstance(i, Match):
                    collect(i.scrutinee)
                    for arm in i.arms:
                        # A guard (and its ANF prelude) can read a
                        # captured name the arm body never touches
                        # (``Some(n) if n > threshold`` reads the
                        # enclosing ``threshold`` only in the guard),
                        # so both must be walked or the capture is
                        # dropped.
                        if getattr(arm, "guard_setup", None):
                            walk(arm.guard_setup)
                        if getattr(arm, "guard", None) is not None:
                            collect(arm.guard)
                        walk(arm.body)

        walk(body_instrs)
        return out

    free = free_vars(lam.body, own_params, defined_in_body)
    return LambdaVars(free=free, defined=defined_in_body)
