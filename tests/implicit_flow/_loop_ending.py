"""The exit FORMS that END a loop, and the programs that vary only in which
one of them a loop ends by.

The walker's head-pc rule is quantified over a set of exit KINDS: a loop's
head pc joins the label of every kind that ends the loop, because each of
them decides how many iterations there are. A pin written for one member
of that set leaves the other members untested, and a rule that forgets one
of them then passes the suite: the shapes below are therefore built ONCE
and emitted per exit form, so a form added to :data:`EXIT_FORMS` extends
the net by construction instead of leaving a hole.

:data:`LOOP_ENDING_KINDS` is declared here rather than imported from the
compiler, so an expectation is never derived from the implementation it
scores; a guard in ``test_guards`` asserts the two agree, which turns a
silent divergence into a failure.

A KIND is not a FORM, and conflating them is how the net grows a hole.
The kind is the channel by which control leaves a body, which is what the
head-pc rule quantifies over; the form is the SYNTAX that takes that
exit, which is what a generated program must actually spell. Several
forms share the kind ``return``: the ``return`` statement and a builtin
``panic``, which the generator makes depend on the secret through an
enclosing guard, and the ``?`` operator, an expression whose own operand
can carry that dependence and which has no keyword to substitute. A
generator parameterised by the kind NAME can emit only the keyword forms,
so the ``?`` would be a member the net cannot express even while the kind
sets agree.

:data:`NON_ENDING_KINDS` is the other half of the bound. A ``continue``
skips the rest of one iteration without changing how many there are, so
the same shape spelled with it must stay ACCEPTED: without those members a
rule that simply raises the pc for every exit would score as well as the
right one.
"""

from __future__ import annotations

from typing import NamedTuple

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


class ExitForm(NamedTuple):
    """One syntactic way to take an exit, and everything a program needs
    to spell it.

    ``kind`` is the channel control leaves by, so an expectation reads the
    kind sets above and never the form's name. ``stmt`` is the statement
    the shape places at the exit's position. ``guarded`` says whether the
    generated program supplies the secret dependence through an enclosing
    guard: a statement jump is unconditional and needs one, while the
    ``?`` form takes it from its own operand, so the generator emits it
    with a secret operand and no guard around it. The flag records how
    this net spells a form; it says nothing about what a construct around
    a ``?`` would add. ``ret`` is the enclosing function's declared return
    type and ``prelude`` the declarations the statement refers to,
    because a form can need a signature the bare keywords do not.

    ``observable`` marks a form whose exit is ITSELF something outside
    the program can see: a ``panic`` writes to stderr, so taking it under
    a secret guard discloses the secret whether or not anything later
    reads a value. The no-sink control asks what a head pc costs when
    nothing observes it, which is not a question that arises for such a
    form, so that one control is not built for it."""

    name: str
    kind: str
    stmt: str
    guarded: bool
    ret: str = ""
    prelude: str = ""
    tail: str = ""
    observable: bool = False


def _jump_form(kind: str) -> ExitForm:
    """The statement form of an exit kind: the keyword itself, taken
    under an enclosing guard. Derived from the kind so the keyword forms
    cannot drift from the kind sets they come from."""
    return ExitForm(name=kind, kind=kind, stmt=kind, guarded=True)


#: The operand of the ``?`` form: a call that returns ``Err`` exactly when
#: the secret key has the tested shape, so the exit's occurrence depends
#: on the secret without an enclosing guard supplying that dependence.
_TRY_PRELUDE = (
    "fun may(k: String) -> Result<Int, String>\n"
    '    if k.starts_with("s")\n'
    '        return Err("no")\n'
    "    return Ok(1)\n"
    "\n"
)

#: Every exit FORM the shapes below can spell. The keyword forms are
#: derived from the kind sets; the other two are spellings of the
#: ``return`` kind that no keyword can express: a builtin ``panic``,
#: which leaves the frame by aborting, and a ``?``, which leaves it when
#: its operand is an ``Err`` and here takes its secret dependence from
#: that operand.
EXIT_FORMS = tuple(
    [_jump_form(kind) for kind in LOOP_ENDING_KINDS + NON_ENDING_KINDS]
    + [
        ExitForm(
            name="panic",
            kind="return",
            stmt='panic("no")',
            guarded=True,
            observable=True,
        ),
        ExitForm(
            name="try",
            kind="return",
            stmt="let _v = may(k)?",
            guarded=False,
            ret=" -> Result<Unit, String>",
            prelude=_TRY_PRELUDE,
            tail="    return Ok(())\n",
        ),
    ]
)

#: The forms that END the loop they are taken in, and the ones that leave
#: the whole frame: both derived from the KIND sets, so a form's side is
#: never written twice.
LOOP_ENDING_FORMS = tuple(f for f in EXIT_FORMS if f.kind in LOOP_ENDING_KINDS)
_FRAME_LEAVING_FORMS = tuple(
    f for f in EXIT_FORMS if f.kind in _FRAME_LEAVING_KINDS
)

_HEAD = (
    "{prelude}"
    "@strict_ifc()\n"
    "fun main(env: Env, {stdio}: Stdio){ret}\n"
    '    let k = env.get("API_KEY").unwrap_or("none")\n'
)


def _program(body: str, form: ExitForm, stdio: str = "stdio") -> str:
    """The program of one shape's ``body`` under one exit form: the head
    the form's signature needs, the body, and the tail that signature
    obliges."""
    head = _HEAD.format(prelude=form.prelude, stdio=stdio, ret=form.ret)
    return head + body + form.tail


def _exit(form: ExitForm, guard: str, indent: str) -> str:
    """The exit itself at ``indent``, wrapped in ``guard`` only when the
    form needs one to depend on the secret."""
    if form.guarded:
        return f"{indent}if {guard}\n{indent}    {form.stmt}\n"
    return f"{indent}{form.stmt}\n"


def _var_read_next_iteration(form: ExitForm, guard: str) -> str:
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
        + _exit(form, guard, "        "),
        form,
    )


def _container_read_next_iteration(form: ExitForm, guard: str) -> str:
    """The same chain through the container-mutation channel: the length a
    sink reads is the length the previous iteration's push left."""
    return _program(
        "    var n: Int = 0\n"
        "    var lst: List<Int> = []\n"
        "    while n < 9\n"
        "        n = n + 1\n"
        '        stdio.println("len=${lst.length()}")\n'
        "        lst.push(n)\n"
        + _exit(form, guard, "        "),
        form,
    )


def _condition_mutation(form: ExitForm, guard: str) -> str:
    """A container MUTATED by the ``while`` condition, which runs once per
    iteration plus once: under a head pc the exit kind made secret, the
    length a sink reads after the loop is secret too."""
    return _program(
        "    var lst: List<Int> = [1, 2, 3, 4, 5, 6, 7]\n"
        "    var n: Int = 0\n"
        "    while lst.pop().is_some() and n < 5\n"
        "        n = n + 1\n"
        + _exit(form, guard, "        ")
        + '    stdio.println("len=${lst.length()}")\n',
        form,
    )


def _write_without_a_sink(form: ExitForm, guard: str) -> str:
    """The CONTROL of the two chain shapes: the same write under the same
    head pc, with no sink reading it, so the program is accepted whatever
    the exit form is."""
    return _program(
        "    var n: Int = 0\n"
        "    var m: Int = 0\n"
        "    var t: Int = 0\n"
        "    while n < 9\n"
        "        n = n + 1\n"
        "        t = t + m\n"
        "        m = n\n"
        + _exit(form, guard, "        "),
        form,
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


def _public_variant(form: ExitForm) -> ExitForm:
    """The same form with its secret dependence removed, for the negatives.

    A guarded form takes its dependence from the enclosing guard, so the
    caller supplies a public one and the form itself is unchanged. An
    unguarded form carries its own, so removing it means changing the
    form: the ``?`` reads a PUBLIC operand instead of a secret-derived
    one. That is the negative that makes the rule label-sensitive rather
    than syntax-blind, and it belongs with the form because the form is
    where the dependence lives."""
    if form.guarded:
        return form
    return form._replace(stmt=form.stmt.replace("may(k)", 'may("pub")'))


def _sink_before_while(form: ExitForm) -> str:
    """The sink runs once per iteration AHEAD of the exit, so how many
    times it runs is how many iterations there are."""
    return _program(
        "    var n: Int = 0\n"
        "    while n < 5\n"
        '        stdio.println("tick")\n'
        "        n = n + 1\n"
        + _exit(form, _SECRET_GUARD, "        "),
        form,
    )


def _sink_before_for(form: ExitForm) -> str:
    """The same in the ``for`` form."""
    return _program(
        "    var n: Int = 0\n"
        "    for i in 0..5\n"
        '        stdio.println("tick")\n'
        "        n = n + 1\n"
        + _exit(form, _SECRET_GUARD, "        "),
        form,
    )


def _sink_before_match_arm(form: ExitForm) -> str:
    """The same with the exit carried by a ``match`` arm rather than by an
    ``if`` branch: the spelling does not change which exits end a loop.

    An unguarded form has no ``if`` to replace, so the arm carries the
    exit statement itself under a public scrutinee: the dependence is
    still the form's own, and the arm is only the position it sits in."""
    scrutinee = _SECRET_GUARD if form.guarded else "n == 4"
    return _program(
        "    var n: Int = 0\n"
        "    while n < 5\n"
        '        stdio.println("tick")\n'
        "        n = n + 1\n"
        f"        match {scrutinee}\n"
        "            v0 if v0 ->\n"
        f"                {form.stmt}\n"
        "            _ ->\n"
        "                let _z = 0\n",
        form,
    )


def _sink_before_inner_loop_exit(form: ExitForm) -> str:
    """The exit sits in an INNER loop and the sink in the OUTER body: an
    inner loop consumes its own ``break`` / ``continue``, so only an exit
    that leaves the whole frame ends the outer loop too. The shape is
    therefore a member for those forms and a negative for the rest."""
    return _program(
        "    var i: Int = 0\n"
        "    while i < 3\n"
        "        i = i + 1\n"
        '        stdio.println("outer")\n'
        "        var j: Int = 0\n"
        "        while j < 2\n"
        "            j = j + 1\n"
        + _exit(form, _SECRET_GUARD, "            "),
        form,
    )


def _sink_after_the_exit(form: ExitForm) -> str:
    """The CONTROL of the position: the same exit with the sink AFTER it,
    where the body's normal-termination label already covers it, so the
    program is refused whatever the exit form is."""
    return _program(
        "    var n: Int = 0\n"
        "    while n < 5\n"
        "        n = n + 1\n"
        + _exit(form, _SECRET_GUARD, "        ")
        + '        stdio.println("tick")\n',
        form,
    )


#: shape name -> (builder, the FORMS that END the loop the SINK sits in).
#: The second element is what makes the expectation DERIVED instead of
#: written per form: for a sink in the exit's own loop that is every
#: loop-ending form, and for a sink in the body OUTSIDE the loop that
#: carries the exit it is only the frame-leaving ones.
_SINK_BEFORE_SHAPES = {
    "while": (_sink_before_while, LOOP_ENDING_FORMS),
    "for": (_sink_before_for, LOOP_ENDING_FORMS),
    "match_arm": (_sink_before_match_arm, LOOP_ENDING_FORMS),
    "inner_loop_exit": (_sink_before_inner_loop_exit, _FRAME_LEAVING_FORMS),
}


def sink_before_programs():
    """Every (name, source, verdict) of the sink-BEFORE-the-exit position:
    each shape once per exit form, refused exactly when that form ends the
    loop the sink sits in, plus the sink-AFTER control, refused for every
    form because the body norm covers it whatever the exit is."""
    for form in EXIT_FORMS:
        for shape, (build, ending) in _SINK_BEFORE_SHAPES.items():
            yield (
                f"sb_{form.name}_{shape}",
                build(form),
                REFUSE if form in ending else ACCEPT,
            )
        yield (
            f"sa_{form.name}_sink_after_the_exit_control",
            _sink_after_the_exit(form),
            REFUSE,
        )


def loop_ending_probes():
    """Every (form, source) a guard can put to the walker directly: the
    ``while`` shape once per exit form, so the question "does this form
    end a loop" is asked of the same program the pins score rather than
    of a copy that could drift from it."""
    for form in EXIT_FORMS:
        yield form, _sink_before_while(form)


def head_pc_members():
    """Every (name, source) the head-pc rule must REFUSE with its value
    diagnostic: each chain shape, once per loop-ending exit form."""
    for form in LOOP_ENDING_FORMS:
        for shape, build in _CHAIN_SHAPES.items():
            yield f"hp_{form.name}_{shape}", build(form, _SECRET_GUARD)


def head_pc_negatives():
    """Every (name, source) the same rule must ACCEPT: the same shapes
    spelled with a form that does NOT end the loop, the same shapes with
    the secret dependence removed, and the write with no sink reading it
    for every form whose exit is not itself observable."""
    for form in EXIT_FORMS:
        if form.kind in NON_ENDING_KINDS:
            for shape, build in _CHAIN_SHAPES.items():
                yield f"hpn_{form.name}_{shape}", build(form, _SECRET_GUARD)
    for form in EXIT_FORMS:
        public = _public_variant(form)
        for shape, build in _CHAIN_SHAPES.items():
            yield (
                f"hpp_{form.name}_{shape}_public_guard",
                build(public, _PUBLIC_GUARD),
            )
        if not form.observable:
            yield (
                f"hpc_{form.name}_write_without_a_sink",
                _write_without_a_sink(form, _SECRET_GUARD),
            )
