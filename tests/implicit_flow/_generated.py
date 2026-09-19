"""The secret-conditioned early-exit class, enumerated BY CONSTRUCTION.

THE RULE (stated once; the tests reference it and never restate it):

  A MEMBER is a program in which, inside a ``@strict_ifc`` function, a
  SECRET-guarded early exit (``return`` / ``break`` / ``continue``) is
  nested under zero or more PUBLIC-guarded enclosing constructs, and a
  public sink executes LATER in an enclosing body that the exit can leave
  early. The sink's execution then depends on the secret, so the program
  must be REFUSED.

  A NEGATIVE is the same program with the sink placed BEFORE the exit, or
  with the exit unable to reach the sink's body (a ``break`` / ``continue``
  is consumed by the nearest enclosing loop; a lambda body is its own
  frame), so it must be ACCEPTED. One exception, itself a member: a sink
  BEFORE a secret-guarded ``break`` still leaks, because the number of
  times it runs is the number of iterations, which the secret decides.

AXES, taken as a FULL CROSS PRODUCT (this is what makes it an enumeration):

  kind   in {return, break, continue}
  chain  = every tuple of length 0..depth over {if, match, while, for,
           lambda}: the constructs between the sink's body and the exit,
           OUTERMOST first
  sink   in {after, before}
  arm    in {then, else, elif, guard}: WHICH arm of a branching construct
           carries the nested exit (ignored for non-branching constructs;
           ``elif`` exists only on ``if``, ``guard`` only on ``match``)

:func:`generate` emits the cross product for one depth with the arm axis
applied uniformly to every branching level (depth 2: 146 programs without
the arm axis, 342 with it; depth 3 without it: 652). :func:`generate_mixed`
emits the depth-2 programs whose two branching levels take DIFFERENT arms,
which the uniform product does not contain (156). Every program carries
its expected verdict, computed by the rule above as a predicate.
"""

from __future__ import annotations

import itertools

KINDS = ("return", "break", "continue")
WRAP = ("if", "match", "while", "for", "lambda")
ARMS = ("then", "else", "elif", "guard")

REFUSE = "REFUSE"
ACCEPT = "ACCEPT"


def _indent(lines, n=1):
    return ["    " * n + ln for ln in lines]


def _wrap(inner, construct, level, arm):
    """Wrap the INNER line-list in ``construct``, placing it in ``arm``."""
    if construct == "if":
        if arm == "else":
            return ["if p == 2"] + _indent(["let _w = 0"]) + ["else"] + _indent(inner)
        if arm == "elif":
            return (
                ["if p == 2"] + _indent(["let _w = 0"])
                + ["elif p == 1"] + _indent(inner)
                + ["else"] + _indent(["let _w2 = 0"])
            )
        return ["if p == 1"] + _indent(inner)
    if construct == "match":
        if arm == "else":
            return (
                ["match p"] + _indent(["2 ->"]) + _indent(["let _w = 0"], 2)
                + _indent(["_ ->"]) + _indent(inner, 2)
            )
        if arm == "guard":
            # One binder name per nesting level: a reused name is a
            # shadowing error the language rejects.
            return (
                ["match p"] + _indent([f"n{level} if n{level} == 1 ->"])
                + _indent(inner, 2) + _indent(["_ ->"]) + _indent(["let _w = 0"], 2)
            )
        return (
            ["match p"] + _indent(["1 ->"]) + _indent(inner, 2)
            + _indent(["_ ->"]) + _indent(["let _w = 0"], 2)
        )
    if construct == "while":
        return ["while q < 1", "    q = q + 1"] + _indent(inner)
    if construct == "for":
        return [f"for z{level} in 0..1"] + _indent(inner)
    if construct == "lambda":
        return ["let _f = fun () -> Unit =>"] + _indent(inner) + ["_f()"]
    raise AssertionError(construct)


def _loop_between(chain):
    """Is a loop nested between the sink's body and the exit? Then that
    loop, not the sink's body, consumes a ``break`` / ``continue``."""
    return any(c in ("while", "for") for c in chain)


def expect(kind, chain, sink):
    """THE RULE as a predicate. ``chain`` is OUTERMOST first."""
    if sink == "before":
        return REFUSE if (
            kind == "break" and "lambda" not in chain and not _loop_between(chain)
        ) else ACCEPT
    if "lambda" in chain:
        return ACCEPT
    if kind == "return":
        return REFUSE
    return ACCEPT if _loop_between(chain) else REFUSE


def _build(kind, chain, sink, arms):
    inner = ['if k.starts_with("s")', f"    {kind}"]
    for i, (construct, arm) in enumerate(zip(reversed(chain), reversed(arms))):
        inner = _wrap(inner, construct, i + 1, arm)
    sinkline = 'stdio.println("reached")'
    body = ([sinkline] + inner) if sink == "before" else (inner + [sinkline])
    # A break / continue must sit inside a loop: when the chain has none,
    # an outermost loop carries the sink too, so the sink stays in the
    # exit's own body.
    if kind in ("break", "continue") and not _loop_between(chain):
        body = ["for z0 in 0..3"] + _indent(body)
    head = [
        "@strict_ifc()",
        "fun main(env: Env, stdio: Stdio)",
        '    let k = env.get("API_KEY").unwrap_or("none")',
        "    let p: Int = 1",
        "    var q: Int = 0",
    ]
    return "\n".join(head + _indent(body)) + "\n"


def _arm_applies(arm, chain):
    if arm == "then":
        return True
    if not any(c in ("if", "match") for c in chain):
        return False
    if arm == "guard":
        return "match" in chain
    if arm == "elif":
        return "if" in chain
    return True


def generate(depth, arm_axis):
    """Every (kind, chain, sink[, arm]) program up to ``depth``, the arm
    applied uniformly to every level. Yields ``(name, source, verdict)``."""
    arms = ARMS if arm_axis else ("then",)
    for kind in KINDS:
        for d in range(0, depth + 1):
            for chain in itertools.product(WRAP, repeat=d):
                if kind in ("break", "continue") and "lambda" in chain:
                    # A lambda body is a function body: a break / continue
                    # cannot cross it. Ill-formed, excluded BY THE RULE.
                    continue
                for sink in ("after", "before"):
                    for arm in arms:
                        if not _arm_applies(arm, chain):
                            continue
                        name = f"g_{kind}_{'-'.join(chain) or 'flat'}_{sink}"
                        if arm != "then":
                            name += f"_{arm}"
                        src = _build(kind, chain, sink, [arm] * len(chain))
                        yield name, src, expect(kind, chain, sink)


def _arms_for(construct):
    if construct == "if":
        return ("then", "else", "elif")
    if construct == "match":
        return ("then", "else", "guard")
    return ("then",)


def generate_mixed():
    """The depth-2 chains with two branching constructs whose two levels
    take DIFFERENT arms (the uniform product already has the equal ones)."""
    for kind in KINDS:
        for chain in itertools.product(WRAP, repeat=2):
            if kind in ("break", "continue") and "lambda" in chain:
                continue
            if sum(1 for c in chain if c in ("if", "match")) < 2:
                continue
            for sink in ("after", "before"):
                for arms in itertools.product(*[_arms_for(c) for c in chain]):
                    if len(set(arms)) < 2:
                        continue
                    name = f"g5_{kind}_{'-'.join(chain)}_{sink}_{'-'.join(arms)}"
                    yield name, _build(kind, chain, sink, list(arms)), expect(kind, chain, sink)
