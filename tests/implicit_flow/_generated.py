"""The secret-conditioned early-exit class, enumerated BY CONSTRUCTION.

THE RULE (stated once; the tests reference it and never restate it):

  A MEMBER is a program in which, inside a ``@strict_ifc`` function, a
  SECRET-guarded early exit (``return`` / ``break`` / ``continue``) is
  nested under zero or more PUBLIC-guarded enclosing constructs, and a
  public sink executes LATER in an enclosing body that the exit can leave
  early. The sink's execution then depends on the secret, so the program
  must be REFUSED.

  A NEGATIVE is the same program with the sink placed BEFORE the exit
  outside every loop the exit is in, or with the exit unable to reach the
  sink's body (a ``break`` / ``continue`` is consumed by the nearest
  enclosing loop; a lambda body is its own frame), so it must be ACCEPTED.

  A sink placed BEFORE the exit and INSIDE the loop the exit ENDS is a
  member: it runs once per iteration until the exit fires, so the number
  of times it runs is the number of iterations, which the secret decides.
  Both kinds END a loop: a ``break`` leaves the loop and a ``return``
  leaves the whole frame. A ``continue`` does not: it skips the rest of
  one iteration without changing how many there are.

  Every loop this module synthesises runs ``TRIP_COUNT`` times, so a
  member at that position really does run its sink a different number of
  times under a secret key than under a public one. At a trip count of
  one the verdict would be right and the leak unobservable, which is a
  corpus that cannot tell a correct rule from one that over-rejects.

AXES, taken as a FULL CROSS PRODUCT (this is what makes it an enumeration):

  kind   in KINDS, the kinds that end a loop plus the one that does not,
           declared once for the package in ``_loop_ending``
  chain  = every tuple of length 0..depth over {if, match, while, for,
           lambda}: the constructs between the sink's body and the exit,
           OUTERMOST first
  sink   in {after, before, before_in_loop}: after the exit in the
           outermost body, before it in the outermost body, or before it
           inside the INNERMOST loop that encloses it
  arm    in {then, else, elif, guard}: WHICH arm of a branching construct
           carries the nested exit (ignored for non-branching constructs;
           ``elif`` exists only on ``if``, ``guard`` only on ``match``)

:func:`generate` emits the cross product for one depth with the arm axis
applied uniformly to every branching level (depth 2: 219 programs without
the arm axis, 513 with it; depth 3 without it: 978). :func:`generate_mixed`
emits the depth-2 programs whose two branching levels take DIFFERENT arms,
which the uniform product does not contain (234). Every program carries
its expected verdict, computed by the rule above as a predicate, and
``test_generated_class`` asserts each of those four sizes, so a change to
an axis that silently shrinks a corpus fails rather than scoring less.
"""

from __future__ import annotations

import itertools

from tests.implicit_flow._loop_ending import (
    LOOP_ENDING_KINDS, NON_ENDING_KINDS,
)

#: Every kind by which a statement can leave a body: the loop-ending ones
#: (``LOOP_ENDING_KINDS``, which the rule below reads) and the one that is
#: not. Built from the two declared halves so this cross product and the
#: head-pc pins enumerate the same kinds.
KINDS = tuple(sorted(LOOP_ENDING_KINDS + NON_ENDING_KINDS))
WRAP = ("if", "match", "while", "for", "lambda")
ARMS = ("then", "else", "elif", "guard")
SINKS = ("after", "before", "before_in_loop")
LOOPS = ("while", "for")
#: How many times a synthesised chain loop runs. It has to be more than
#: one: at a trip count of 1 a sink inside the loop runs exactly once
#: whether the exit fires or not, so the member is verdict-correct but
#: its leak cannot be observed at runtime, and a rule that over-rejected
#: this position would score the same as the right one. Each synthesised
#: loop also carries its OWN counter, so an enclosing wrap re-enters it.
TRIP_COUNT = 3

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
        # Its own counter, so an outer wrap re-enters this loop rather
        # than finding a shared counter already past its bound.
        return [
            f"var q{level}: Int = 0",
            f"while q{level} < {TRIP_COUNT}",
            f"    q{level} = q{level} + 1",
        ] + _indent(inner)
    if construct == "for":
        return [f"for z{level} in 0..{TRIP_COUNT}"] + _indent(inner)
    if construct == "lambda":
        return ["let _f = fun () -> Unit =>"] + _indent(inner) + ["_f()"]
    raise AssertionError(construct)


def _loop_between(chain):
    """Is a loop nested between the sink's body and the exit? Then that
    loop, not the sink's body, consumes a ``break`` / ``continue``."""
    return any(c in LOOPS for c in chain)


def _lambda_below_the_innermost_loop(chain):
    """Does a lambda sit between the innermost loop of ``chain`` and the
    exit? Then the exit leaves the lambda's frame, not that loop, so it
    does not decide how many times the loop runs. With no loop in the
    chain the innermost loop is the one ``_build`` synthesises, outside
    the whole chain, so any lambda in it is below that loop."""
    if not _loop_between(chain):
        return "lambda" in chain
    innermost = max(i for i, c in enumerate(chain) if c in LOOPS)
    return "lambda" in chain[innermost:]


def expect(kind, chain, sink):
    """THE RULE as a predicate. ``chain`` is OUTERMOST first."""
    if sink == "before_in_loop":
        # The sink sits inside the innermost loop the exit is in, ahead
        # of it: refused exactly when that exit ENDS that loop.
        return REFUSE if (
            kind in LOOP_ENDING_KINDS
            and not _lambda_below_the_innermost_loop(chain)
        ) else ACCEPT
    if sink == "before":
        # The sink sits in the OUTERMOST body, ahead of the whole chain,
        # so only the loop ``_build`` synthesises around it can carry it:
        # a chain with a loop of its own puts the exit out of reach.
        return REFUSE if (
            kind == "break" and "lambda" not in chain
            and not _loop_between(chain)
        ) else ACCEPT
    if "lambda" in chain:
        return ACCEPT
    if kind == "return":
        return REFUSE
    return ACCEPT if _loop_between(chain) else REFUSE


def _innermost_loop_level(chain):
    """How many chain levels sit INSIDE the innermost loop of ``chain``,
    counting from the exit outwards. ``None`` when the chain has no
    loop."""
    if not _loop_between(chain):
        return None
    return len(chain) - 1 - max(i for i, c in enumerate(chain) if c in LOOPS)


def _build(kind, chain, sink, arms):
    sinkline = 'stdio.println("reached")'
    inner = ['if k.starts_with("s")', f"    {kind}"]
    # ``before_in_loop`` puts the sink ahead of the exit at the level the
    # innermost loop of the chain opens, so the loop's body holds both.
    at_level = _innermost_loop_level(chain) if sink == "before_in_loop" else None
    for i, (construct, arm) in enumerate(zip(reversed(chain), reversed(arms))):
        if i == at_level:
            inner = [sinkline] + inner
        inner = _wrap(inner, construct, i + 1, arm)
    if sink == "after":
        body = inner + [sinkline]
    elif sink == "before":
        body = [sinkline] + inner
    elif at_level is not None:
        body = inner
    else:
        # No loop in the chain: the synthesised loop below carries both.
        body = [sinkline] + inner
    # A break / continue must sit inside a loop: when the chain has none,
    # an outermost loop carries the sink too, so the sink stays in the
    # exit's own body. A ``return`` at the ``before_in_loop`` position
    # needs that loop for the same reason: without it there is no
    # iteration count for the sink to leak.
    needs_loop = kind in ("break", "continue") or sink == "before_in_loop"
    if needs_loop and not _loop_between(chain):
        body = [f"for z0 in 0..{TRIP_COUNT}"] + _indent(body)
    head = [
        "@strict_ifc()",
        "fun main(env: Env, stdio: Stdio)",
        '    let k = env.get("API_KEY").unwrap_or("none")',
        "    let p: Int = 1",
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


def position_of(name):
    """The sink position a generated program's NAME encodes. One source
    for the naming scheme, so a consumer never re-derives it."""
    for position in sorted(SINKS, key=len, reverse=True):
        if f"_{position}" in name:
            return position
    raise AssertionError(f"no sink position in {name!r}")


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
                for sink in SINKS:
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
            for sink in SINKS:
                for arms in itertools.product(*[_arms_for(c) for c in chain]):
                    if len(set(arms)) < 2:
                        continue
                    name = f"g5_{kind}_{'-'.join(chain)}_{sink}_{'-'.join(arms)}"
                    yield name, _build(kind, chain, sink, list(arms)), expect(kind, chain, sink)
