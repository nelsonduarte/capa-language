"""The exit kinds that END a loop, and the programs that vary only in which
one of them a loop ends by.

The walker's head-pc rule is quantified over a SET of exit kinds: a loop's
head pc joins the label of every kind that ends the loop, because each of
them decides how many iterations there are. A pin written for one member
of that set leaves the other members untested, and a rule that forgets one
of them then passes the suite: the shapes below are therefore built ONCE
and emitted per kind, so a kind added to :data:`LOOP_ENDING_KINDS` extends
the net by construction instead of leaving a hole.

The set is declared here rather than imported from the compiler, so an
expectation is never derived from the implementation it scores; a guard in
``test_guards`` asserts the two agree, which turns a silent divergence
into a failure.

:data:`NON_ENDING_KINDS` is the other half of the bound. A ``continue``
skips the rest of one iteration without changing how many there are, so
the same shape spelled with it must stay ACCEPTED: without those members a
rule that simply raises the pc for every exit would score as well as the
right one.
"""

from __future__ import annotations

#: The exit kinds that end the loop they are taken in.
LOOP_ENDING_KINDS = ("break", "return")

#: The exit kinds that leave a body WITHOUT ending the loop: the negatives
#: that bound the rule from the over-rejection side.
NON_ENDING_KINDS = ("continue",)

#: The kinds that leave the whole FRAME, not just one loop: the only ones
#: an inner loop does not consume, so the only ones that end an enclosing
#: loop as well. Every frame-leaving kind ends a loop.
_FRAME_LEAVING_KINDS = ("return",)

REFUSE = "REFUSE"
ACCEPT = "ACCEPT"

_HEAD = (
    "@strict_ifc()\n"
    "fun main(env: Env, {stdio}: Stdio)\n"
    '    let k = env.get("API_KEY").unwrap_or("none")\n'
)


def _program(body: str, stdio: str = "stdio") -> str:
    return _HEAD.format(stdio=stdio) + body


def _var_read_next_iteration(kind: str, guard: str) -> str:
    """A variable written under the loop's head pc and read by a sink
    EARLIER in the body, so the read sees the PREVIOUS iteration's write:
    the value the sink prints is the one the head pc made secret."""
    return _program(
        "    var n: Int = 0\n"
        "    var m: Int = 0\n"
        "    while n < 9\n"
        "        n = n + 1\n"
        '        stdio.println("m=${m}")\n'
        "        m = n\n"
        f"        if {guard}\n"
        f"            {kind}\n"
    )


def _container_read_next_iteration(kind: str, guard: str) -> str:
    """The same chain through the container-mutation channel: the length a
    sink reads is the length the previous iteration's push left."""
    return _program(
        "    var n: Int = 0\n"
        "    var lst: List<Int> = []\n"
        "    while n < 9\n"
        "        n = n + 1\n"
        '        stdio.println("len=${lst.length()}")\n'
        "        lst.push(n)\n"
        f"        if {guard}\n"
        f"            {kind}\n"
    )


def _condition_mutation(kind: str, guard: str) -> str:
    """A container MUTATED by the ``while`` condition, which runs once per
    iteration plus once: under a head pc the exit kind made secret, the
    length a sink reads after the loop is secret too."""
    return _program(
        "    var lst: List<Int> = [1, 2, 3, 4, 5, 6, 7]\n"
        "    var n: Int = 0\n"
        "    while lst.pop().is_some() and n < 5\n"
        "        n = n + 1\n"
        f"        if {guard}\n"
        f"            {kind}\n"
        '    stdio.println("len=${lst.length()}")\n'
    )


def _write_without_a_sink(kind: str, guard: str) -> str:
    """The CONTROL of the two chain shapes: the same write under the same
    head pc, with no sink reading it, so the program is accepted whatever
    the exit kind is."""
    return _program(
        "    var n: Int = 0\n"
        "    var m: Int = 0\n"
        "    var t: Int = 0\n"
        "    while n < 9\n"
        "        n = n + 1\n"
        "        t = t + m\n"
        "        m = n\n"
        f"        if {guard}\n"
        f"            {kind}\n",
        stdio="_stdio",
    )


#: shape name -> builder. Each shape places a sink where it reads a value
#: the head pc raised, so the REFUSAL carries the head pc's own VALUE
#: diagnostic, not only a control-flow one: a pass that desyncs from the
#: seam still refuses these programs for their control flow and drops
#: exactly that value error, which a verdict alone would not notice.
_CHAIN_SHAPES = {
    "var_read_next_iteration": _var_read_next_iteration,
    "container_read_next_iteration": _container_read_next_iteration,
    "condition_mutation_read_after_the_loop": _condition_mutation,
}

#: The guard spellings: a secret one makes the exit's kind decide the
#: iteration count, a public one does not.
_SECRET_GUARD = 'k.starts_with("s")'
_PUBLIC_GUARD = "n == 4"


def _sink_before_while(kind: str) -> str:
    """The sink runs once per iteration AHEAD of the exit, so how many
    times it runs is how many iterations there are."""
    return _program(
        "    var n: Int = 0\n"
        "    while n < 5\n"
        '        stdio.println("tick")\n'
        "        n = n + 1\n"
        f"        if {_SECRET_GUARD}\n"
        f"            {kind}\n"
    )


def _sink_before_for(kind: str) -> str:
    """The same in the ``for`` form."""
    return _program(
        "    var n: Int = 0\n"
        "    for i in 0..5\n"
        '        stdio.println("tick")\n'
        "        n = n + 1\n"
        f"        if {_SECRET_GUARD}\n"
        f"            {kind}\n"
    )


def _sink_before_match_arm(kind: str) -> str:
    """The same with the exit spelled as a ``match`` arm rather than an
    ``if`` branch: the spelling does not change which kinds end a loop."""
    return _program(
        "    var n: Int = 0\n"
        "    while n < 5\n"
        '        stdio.println("tick")\n'
        "        n = n + 1\n"
        f"        match {_SECRET_GUARD}\n"
        "            v0 if v0 ->\n"
        f"                {kind}\n"
        "            _ ->\n"
        "                let _z = 0\n"
    )


def _sink_before_inner_loop_exit(kind: str) -> str:
    """The exit sits in an INNER loop and the sink in the OUTER body: an
    inner loop consumes its own ``break`` / ``continue``, so only a kind
    that leaves the whole frame ends the outer loop too. The shape is
    therefore a member for those kinds and a negative for the rest."""
    return _program(
        "    var i: Int = 0\n"
        "    while i < 3\n"
        "        i = i + 1\n"
        '        stdio.println("outer")\n'
        "        var j: Int = 0\n"
        "        while j < 2\n"
        "            j = j + 1\n"
        f"            if {_SECRET_GUARD}\n"
        f"                {kind}\n"
    )


def _sink_after_the_exit(kind: str) -> str:
    """The CONTROL of the position: the same exit with the sink AFTER it,
    where the body's normal-termination label already covers it, so the
    program is refused whatever the kind is."""
    return _program(
        "    var n: Int = 0\n"
        "    while n < 5\n"
        "        n = n + 1\n"
        f"        if {_SECRET_GUARD}\n"
        f"            {kind}\n"
        '        stdio.println("tick")\n'
    )


#: shape name -> (builder, the kinds that END the loop the SINK sits in).
#: The second element is what makes the expectation DERIVED instead of
#: written per kind: for a sink in the exit's own loop that is every
#: loop-ending kind, and for a sink in the body OUTSIDE the loop that
#: carries the exit it is only the frame-leaving ones.
_SINK_BEFORE_SHAPES = {
    "while": (_sink_before_while, LOOP_ENDING_KINDS),
    "for": (_sink_before_for, LOOP_ENDING_KINDS),
    "match_arm": (_sink_before_match_arm, LOOP_ENDING_KINDS),
    "inner_loop_exit": (_sink_before_inner_loop_exit, _FRAME_LEAVING_KINDS),
}


def sink_before_programs():
    """Every (name, source, verdict) of the sink-BEFORE-the-exit position:
    each shape once per exit kind, refused exactly when that kind ends the
    loop the sink sits in, plus the sink-AFTER control, refused for every
    kind because the body norm covers it whatever the exit is."""
    for kind in LOOP_ENDING_KINDS + NON_ENDING_KINDS:
        for shape, (build, ending) in _SINK_BEFORE_SHAPES.items():
            yield (
                f"sb_{kind}_{shape}",
                build(kind),
                REFUSE if kind in ending else ACCEPT,
            )
        yield (
            f"sa_{kind}_sink_after_the_exit_control",
            _sink_after_the_exit(kind),
            REFUSE,
        )


def head_pc_members():
    """Every (name, source) the head-pc rule must REFUSE with its value
    diagnostic: each chain shape, once per loop-ending kind."""
    for kind in LOOP_ENDING_KINDS:
        for shape, build in _CHAIN_SHAPES.items():
            yield f"hp_{kind}_{shape}", build(kind, _SECRET_GUARD)


def head_pc_negatives():
    """Every (name, source) the same rule must ACCEPT: the same shapes
    spelled with a kind that does NOT end the loop, the same shapes under
    a PUBLIC guard, and the write with no sink reading it, for every kind
    of both sets."""
    for kind in NON_ENDING_KINDS:
        for shape, build in _CHAIN_SHAPES.items():
            yield f"hpn_{kind}_{shape}", build(kind, _SECRET_GUARD)
    for kind in LOOP_ENDING_KINDS + NON_ENDING_KINDS:
        for shape, build in _CHAIN_SHAPES.items():
            yield f"hpp_{kind}_{shape}_public_guard", build(kind, _PUBLIC_GUARD)
        yield (
            f"hpc_{kind}_write_without_a_sink",
            _write_without_a_sink(kind, _SECRET_GUARD),
        )
