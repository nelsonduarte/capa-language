"""Verdict pins for the implicit-flow discipline, one test case per class.

Under ``@strict_ifc`` a statement that can leave its body early (``return``
/ ``break`` / ``continue`` / a bare ``panic``) under a secret condition makes
every later statement of that body, and of every enclosing body the exit
can leave, run only when the secret said "do not leave"; a public sink there
leaks that bit by its mere execution. A secret-conditioned exit that ENDS
the loop (a ``break``, or a ``return`` leaving the whole frame) also makes
the loop's iteration count secret, so a sink BEFORE it in the body, and a
counter incremented in the body, leak too.

The analyzer answers this with ONE statement walker that carries the
normal-termination label along every body (the pc of statement i+1 is the
label under which statement i terminated normally), ONE loop rule (a
``continue`` merges at the loop head; a ``break`` merges at the loop exit
and a ``return`` escapes the frame, and both END the loop, so either one
taken under a secret guard makes the iteration count secret), and ONE label
fixpoint per loop that re-walks the body until nothing the next iteration
can read has changed (the binding labels, the container-mutation channel,
the loop's controlling expression, the exit map).

Each test case below is one CLASS of member programs plus the negatives
that bound it, scored from a table of fixture names or, where the rule is
quantified over a set, from members BUILT once per element of that set so
a new element extends the net instead of leaving a hole. The tables were
RED on the two-pass analyzer this walker replaced for every member marked
with a leak in its name, and the negatives were GREEN before and after.
"""

import unittest

import capa

from tests.implicit_flow._harness import (
    ACCEPT, REFUSE, assert_table, assert_verdict, check_fixture, check_source,
    ifc_errors, provenance_ok, read_fixture, value_errors,
)
from tests.implicit_flow._loop_ending import (
    EXIT_FORMS, LOOP_ENDING_FORMS, head_pc_members, head_pc_negatives,
    loop_ending_probes, sink_before_programs,
)


def _derived(source: str, edits) -> str:
    """``source`` with each ``(old, new)`` of ``edits`` substituted exactly
    once. An anchor that is absent or ambiguous raises instead of
    returning a program other than the one the edits describe."""
    for old, new in edits:
        if source.count(old) != 1:
            raise ValueError(
                f"anchor found {source.count(old)} times, expected once: {old!r}"
            )
        source = source.replace(old, new)
    return source


def assert_disclosed_residual(tc, twin, twin_source, member, edits):
    """Score a DISCLOSED residual whose program is not written out.

    A residual pin records a program the discipline ACCEPTS although
    its behaviour depends on the secret, so that the day the residual
    is closed the pin goes RED and the decision is visible. Such a
    program is not kept on disk: the pin holds a TWIN the walker
    REFUSES and the substitutions that turn the twin into the member,
    and both verdicts are asserted, so the derivation is shown to
    start inside the net and to end outside it. ``twin_source`` is
    the refused program, ``edits`` the ``(old, new)`` pairs applied
    exactly once each (a twin that changed spelling fails here rather
    than silently pinning another program), and ``member`` names the
    derived program in the subtest."""
    tc.assertTrue(provenance_ok(), f"wrong compiler under test: {capa.__file__}")
    assert_verdict(tc, twin, check_source(twin_source), REFUSE)
    source = _derived(twin_source, edits)
    with tc.subTest(program=member):
        assert_verdict(tc, member, check_source(source), ACCEPT)


class BodyPositions(unittest.TestCase):
    """One refused member per BODY POSITION: every AST field that holds a
    statement sequence (the eight positions ``test_guards`` derives
    reflectively). A secret-conditioned exit followed by a public sink in
    that same body."""

    TABLE = {
        "pos_fundecl_body": REFUSE,
        "pos_whilestmt_body": REFUSE,
        "pos_forstmt_body": REFUSE,
        "pos_ifstmt_then": REFUSE,
        "pos_ifstmt_else": REFUSE,
        "pos_ifstmt_elif": REFUSE,
        "pos_matcharm_body": REFUSE,
        "pos_lambdaexpr_body": REFUSE,
    }

    def test_table(self):
        assert_table(self, "positions", self.TABLE)


class ExitKinds(unittest.TestCase):
    """One refused member per EXIT KIND, in both loop forms where the kind
    is loop-bound: ``break`` (the iteration count), ``continue`` (the rest
    of the body), ``return`` (the rest of the frame), and a bare ``panic``
    in a match arm (modelled as ``return``).

    "This block leaves" is ONE question with one answer, so the answer is
    read at every site that asks it: the information-flow rules, the merge
    of a branch's linear state, the typing of a ``match``'s arms and the
    falls-through check of a function body that declares a return type."""

    TABLE = {
        "p01_while_itercount": REFUSE,
        "p01_for_itercount": REFUSE,
        "p07_while": REFUSE,
        "p07_for": REFUSE,
        "w_matcharm3": REFUSE,
        "w_matcharm": REFUSE,
        "w_matcharm2": REFUSE,
        "w_lambda": REFUSE,
        "panic_arm": REFUSE,
    }

    #: A ``panic`` in an ``if``-EXPRESSION branch under a secret condition
    #: is an exit of the statement carrying the expression: the panic under
    #: a secret pc AND the sink after it are both refused.
    IF_EXPRESSION = {
        "ifx1_ifexpr_secret_cond_panic_arm_then_sink": REFUSE,
        "ifx3_ifexpr_public_cond_panic_arm_then_sink_control": ACCEPT,
    }

    #: The SAME exit test everywhere a block can end: a block arm that
    #: ends in ``panic`` reaches no merge, so its TYPE does not have to
    #: agree with the other arms of the ``match`` that carries it, and
    #: a function body that ends in ``panic`` falls through on no path,
    #: so a declared return type is satisfied. The refused members are
    #: the information-flow side: the panic exit under a secret guard
    #: makes the statements after it secret.
    PANIC_ENDS_A_BLOCK = {
        "panic_arm_typing_match_block_arm_ends_in_panic": ACCEPT,
        "panic_ending_function_body_declares_a_return_type": ACCEPT,
        "panic_ending_branch_function_declares_a_return_type": ACCEPT,
        "panic_arm_secret_scrutinee_sink_after": REFUSE,
        "panic_branch_in_loop_body_sink_after": REFUSE,
    }

    def test_table(self):
        assert_table(self, "exit_kinds", self.TABLE)

    def test_if_expression_panic_arm(self):
        assert_table(self, "match_exits", self.IF_EXPRESSION)
        r = check_fixture("match_exits", "ifx1_ifexpr_secret_cond_panic_arm_then_sink")
        self.assertEqual(len(r.errors), 2, [e.message for e in r.errors])

    def test_panic_ends_a_block_everywhere(self):
        assert_table(self, "exit_kinds", self.PANIC_ENDS_A_BLOCK, ifc_only=False)
        # The refused members carry only information-flow errors, not a
        # typing error beside them: the panic under the secret guard, the
        # sink after it, and, in the loop form, the counter the secret
        # iteration count made secret.
        for name, total in (
            ("panic_arm_secret_scrutinee_sink_after", 2),
            ("panic_branch_in_loop_body_sink_after", 3),
        ):
            with self.subTest(program=name):
                r = check_fixture("exit_kinds", name)
                messages = [e.message for e in r.errors]
                self.assertEqual(len(r.errors), total, messages)
                self.assertEqual(len(ifc_errors(r)), total, messages)


class NestedUnderPublicGuards(unittest.TestCase):
    """A secret-conditioned exit one or more PUBLIC constructs deeper than
    the sink's body. The normal-termination label propagates OUTWARD through
    every enclosing body, with all-paths exclusion: a branch that exits on
    every path under a secret guard inside a public construct does not make
    the public construct's normal termination secret (``fpn01`` / ``fpn03``
    / ``a03`` stay accepted), while one that exits on some paths does
    (``fpn04``). A ``for`` whose body may ``break`` or ``continue`` under a
    guard is refused even when that guard is statically dead (``a02``,
    ``fpn02``): the walker is path-insensitive by design."""

    TABLE = {
        "q01_nested_public": REFUSE,
        "q01_if_pub_if_secret_return_sink_after": REFUSE,
        "q02_while_if_secret_return_sink_after": REFUSE,
        "q03_for_if_secret_return_sink_after": REFUSE,
        "q04_match_pub_arm_if_secret_return_sink_after": REFUSE,
        "q05_while_if_pub_if_secret_break_body_sink_after": REFUSE,
        "q06_if_secret_return_sink_after": REFUSE,
        "q07_lambda_if_pub_if_secret_return_sink_in_lambda_after": REFUSE,
        "x02_nested_inner_return_outer_sink_after_inner": REFUSE,
        "x03_nested_both_levels_sinks": REFUSE,
        "x03b_nested_inner_break_only_outer_sink_after_inner_itercount": REFUSE,
        "x04_break_in_match_in_for_sink_after_match": REFUSE,
        "x05_break_in_if_in_for_sink_after_if": REFUSE,
        "x06_continue_in_match_in_for_sink_after_match": REFUSE,
        "x06b_continue_in_if_in_for_sink_after_if": REFUSE,
        "x07_for_secret_return_itercount_after_loop": REFUSE,
        "x07b_while_secret_return_sink_after_loop": REFUSE,
        "x08a_two_kinds_live_sink_after_both": REFUSE,
        "x08b_two_kinds_one_stmt_elif": REFUSE,
        "x08c_sink_before_secret_break_itercount": REFUSE,
        "x08d_continue_then_break_sink_between": REFUSE,
        "x08e_sink_before_continue_and_before_break": ACCEPT,
        "x10_lambda_defined_after_secret_continue_sink_inside": REFUSE,
        "x10b_lambda_with_secret_return_defined_in_loop_then_body_sink": ACCEPT,
        "x11_while_secret_return_sink_in_body_after": REFUSE,
        "a01_for_sink_before_pub_if_secret_break": REFUSE,
        "a02_for_pub_if_secret_continue_only_sink_after": REFUSE,
        "a03_pub_match_secret_match_all_return_sink_after": ACCEPT,
        "a04_three_pub_levels_secret_return_sink_after": REFUSE,
        "a05_for_pub_if_secret_continue_sink_before": ACCEPT,
        "a06_for_pub_if_LIVE_secret_continue_sink_after": REFUSE,
        "fpn01_pub_if_secret_if_both_return_sink_after": ACCEPT,
        "fpn02_for_pub_if_secret_if_break_else_continue_sink_after": REFUSE,
        "fpn03_pub_if_secret_match_all_arms_return_sink_after": ACCEPT,
        "fpn04_pub_if_secret_if_one_returns_sink_after": REFUSE,
        "fpn05_secret_if_both_return_then_dead_sink": REFUSE,
        # A dead statement after an all-paths-exiting inner if: the outer
        # branch still terminates on no path, so the sink after stays public.
        "mayn1_pub_if_secret_if_both_return_then_dead_stmt_sink_after": ACCEPT,
        "gap01_else_arm_secret_return": REFUSE,
        "gap02_elif_arm_secret_return": REFUSE,
        "gap03_elif_cond_secret_return": REFUSE,
        "gap04_match_guard_secret_return": REFUSE,
        "gap05_match_guard_secret_under_pub_if": REFUSE,
        "gap06b_let_match_secret_panic_unit_arms": REFUSE,
        "gap06c_let_match_secret_block_arm_panic_then_value": REFUSE,
        "gap07b_let_match_secret_panic_unit_under_pub_if": REFUSE,
        "gap07c_let_match_secret_block_arm_panic_under_pub_if": REFUSE,
        "gap08b_expr_stmt_match_secret_panic_under_pub_if": REFUSE,
        "gap09_member_wrapped_in_while": REFUSE,
        "gap10_member_wrapped_in_lambda_break": REFUSE,
        "gap11_member_wrapped_in_lambda_return": REFUSE,
        "gap12_member_wrapped_in_match_arm": REFUSE,
        "gap13_a06_wrapped_in_for": REFUSE,
        "gap14_lambda_return_in_loop_sink_in_loop": ACCEPT,
        "gap16_sibling_else_sink_only": ACCEPT,
        "gap16b_sibling_else_sink_then_after_sink": REFUSE,
        "gap17_pub_else_also_exits": REFUSE,
        "gap18_panic_nested_under_pub_if": REFUSE,
        "gap19_try_under_pub_if": REFUSE,
        "gap24_member_with_public_stmts_around": REFUSE,
        "gap25_deep_else_chain": REFUSE,
        "gap26_secret_if_with_else_both_arms_nonexit_then_nested_exit": REFUSE,
        "lc01_loopcarried_while": REFUSE,
        "lc02_loopcarried_for": REFUSE,
        "lc03_loopcarried_public": ACCEPT,
        "lc08_loopcarried_continue_sink_after": REFUSE,
    }

    def test_table(self):
        assert_table(self, "nested", self.TABLE)


class LoopCarriedChains(unittest.TestCase):
    """A secret reaches a guard, a jump or a sink only after N iterations:
    the body assigns a chain of variables one link per trip round the loop.
    The label fixpoint re-walks the body until the binding labels and the
    exit map stop changing, so any chain length is seen (8 links here).
    Loop-free programs whose chains feed no exit (``lcs*``) stay accepted."""

    TABLE = {
        "lc04_loopcarried_break_for_itercount": REFUSE,
        "lc04c_onelink_carried_break_itercount": REFUSE,
        "lc05_loopcarried_break_while_itercount": REFUSE,
        "lc06_loopcarried_break_sink_before": REFUSE,
        "lc07_loopcarried_continue_sink_before": ACCEPT,
        "lc09_twolink_carried_break_itercount": REFUSE,
        "lc10_threelink_carried_break_itercount": REFUSE,
        "lc11_twolink_carried_continue_sink_after": REFUSE,
        "lc12_twolink_carried_return_sink_after_loop": REFUSE,
        "lc13_twolink_carried_return_sink_in_body": REFUSE,
        "lc14_onelink_carried_return_sink_in_body_control": REFUSE,
        "lc15_twolink_carried_break_while": REFUSE,
        "lc16_fourlink_break": REFUSE,
        "lc17_fivelink_break": REFUSE,
        "lc18_sixlink_break": REFUSE,
        "lc19_eightlink_break": REFUSE,
        "lcd01_twolink_label_chain_no_jump": REFUSE,
        "lcd01b_twolink_label_chain_bool": REFUSE,
        "lcd02_onelink_label_chain_no_jump": REFUSE,
        "lcd03_threelink_label_chain_bool": REFUSE,
        "lcd04_fourlink_label_chain_bool": REFUSE,
        "lcf1_struct_field_twolink_break": REFUSE,
        "lcn1_nested_inner_two_links": REFUSE,
        "lcn2_nested_alternating": REFUSE,
        "lcn3_three_nested": REFUSE,
        "lcs1_swap_in_loop": ACCEPT,
        "lcs2_rotate_in_loop": ACCEPT,
        "lcs3_twolink_chain_no_exit_sink": ACCEPT,
    }

    def test_table(self):
        assert_table(self, "loop_chains", self.TABLE)


class HeadPcOverEveryLoopEndingForm(unittest.TestCase):
    """The loop's head pc, scored ONCE PER FORM that ends a loop.

    The head pc joins the label of EVERY exit kind that ends the loop,
    because each of them decides how many iterations there are, and it
    governs the speculative passes as well as the real one: a variable or
    a container written under it is secret for the NEXT iteration, so a
    sink reading it earlier in the body reports a secret VALUE beside the
    control-flow error, and a container the ``while`` condition mutates is
    mutated a secret number of times.

    The same pc decides how many times a sink placed AHEAD of the exit in
    the loop's body runs, so that position is scored per form too, with
    the shape whose exit sits in an INNER loop refused only for the forms
    that leave the whole frame.

    Scored per FORM and not per kind: the head-pc rule quantifies over
    kinds, but a program has to SPELL the exit, and one kind has more than
    one spelling. The ``return`` kind is taken by the keyword under an
    enclosing guard, and also by a ``?``, whose own operand can carry the
    secret dependence and which no keyword can express. A net
    parameterised by the kind name scores the keyword spelling only, and
    its kind-set guard stays green while the ``?`` is unreachable.

    Every program here is built by ``_loop_ending`` from one shape per
    channel applied to every form, so a form added there is pinned by
    construction rather than by remembering to write its fixtures. That
    matters for a defect a verdict alone cannot see: a pass that reads the
    seam for one form and hand-writes the join for another still refuses
    the program and loses only that form's VALUE diagnostic, which is why
    the value error is counted and not just the verdict.

    The negatives bound the rule from the other side, and all are
    accepted: the same shapes spelled with a form that does NOT end the
    loop, the same shapes with the secret dependence removed for every
    form, and the same write with no sink reading it for every form whose
    exit is not itself observable."""

    def test_every_loop_ending_form_raises_the_head_pc(self):
        self.assertTrue(provenance_ok(), f"wrong compiler: {capa.__file__}")
        members = list(head_pc_members())
        self.assertEqual(
            {name.split("_")[1] for name, _ in members},
            {form.name for form in LOOP_ENDING_FORMS},
            "a declared loop-ending form has no member",
        )
        for name, source in members:
            with self.subTest(program=name):
                result = check_source(source)
                assert_verdict(self, name, result, REFUSE)
                # The VALUE error, not only the control-flow one: it is
                # the half a desynced pass drops.
                self.assertEqual(
                    len(value_errors(result)), 1,
                    [e.message for e in result.errors],
                )

    def test_the_sink_before_the_exit_leaks_exactly_the_ending_forms(self):
        # The sink AHEAD of the exit runs once per iteration, so its
        # execution count is the iteration count. Each shape is built once
        # per form and refused exactly when that form ends the loop the
        # sink sits in, which for a sink in the body OUTSIDE the exit's
        # loop is only the frame-leaving forms.
        programs = list(sink_before_programs())
        self.assertEqual(
            {name.split("_")[1] for name, _, _ in programs},
            {form.name for form in EXIT_FORMS},
            "a declared form has no sink-before program",
        )
        self.assertEqual(
            {verdict for _, _, verdict in programs}, {ACCEPT, REFUSE},
            "the position collapsed to one verdict",
        )
        for name, source, want in programs:
            with self.subTest(program=name):
                assert_verdict(self, name, check_source(source), want)

    def test_the_negatives_of_every_form_stay_accepted(self):
        negatives = list(head_pc_negatives())
        self.assertTrue(negatives, "empty negative set")
        self.assertEqual(
            {name.split("_")[1] for name, _ in negatives},
            {form.name for form in EXIT_FORMS},
            "a declared form has no negative",
        )
        for name, source in negatives:
            with self.subTest(program=name):
                assert_verdict(self, name, check_source(source), ACCEPT)


class ContainerMutationChannel(unittest.TestCase):
    """The loop-carried chain runs through the branch-scoped container
    mutation channel: a push under a secret pc makes a later structure
    query (``is_empty`` / ``contains`` / ``length``) secret, and that query
    guards the exit. The fixpoint observes that channel because the label
    store's accessor enumerates it (see ``test_guards``)."""

    TABLE = {
        "lcc0_list_push_under_secret_pc_guard_onelink_sink_after": REFUSE,
        "lcc0b_list_push_under_secret_pc_guard_onelink_sink_in_body": REFUSE,
        "lcc1_list_push_twolink": REFUSE,
        "lcc2_struct_field_list_push_onelink": REFUSE,
        "lcc4_list_contains_guard_onelink": REFUSE,
        "lcc5_list_length_guard_return_onelink": REFUSE,
    }

    def test_table(self):
        assert_table(self, "container_channel", self.TABLE)


class ControllingExpression(unittest.TestCase):
    """A ``while`` condition is re-evaluated every iteration, so its label
    is part of the loop's fixpoint state: a chain that raises the condition
    after N iterations makes the iteration count secret. The condition's
    diagnostics are the REAL pass's, emitted once under the stabilised
    labels: a sink reached through a helper called in the condition
    (``lq*``) and a constant-time branch on the condition (``ctw*``) are
    refused when the chain raises it, and a condition secret at entry
    reports exactly what it did before (the controls).

    The condition also EXECUTES once per iteration plus once, so it runs
    under the pc the loop rule assigns to the iteration count: the entry pc
    joined with the stabilised label of every exit kind that ENDS the loop,
    not the condition's own label. A public sink called from the condition
    with a secret-conditioned ``break``, or a secret-conditioned ``return``
    from the body, therefore leaks how many times the condition ran
    (``wcb*``, ``wcr2``); a public exit of either kind, or a secret
    ``continue``, does not. Whatever the condition DOES also happens under
    that pc: a container it mutates becomes secret, which
    ``HeadPcOverEveryLoopEndingForm`` scores for every form that ends a
    loop.

    A ``for`` has no such condition: its iterable is evaluated ONCE,
    before the loop, so a mutation of the container being iterated,
    made in the body under a secret pc, is a channel no rule here
    models. That is a DISCLOSED residual of this class, pinned
    ACCEPTED by ``test_disclosed_residual`` so a change of that
    decision is visible; the member is derived there from its refused
    ``while`` twin rather than kept as a program."""

    TABLE = {
        "lcw0_while_cond_onelink": REFUSE,
        "lcw0b_while_cond_onelink_sink_in_body": REFUSE,
        "lcw1_while_cond_twolink": REFUSE,
        "lcw3_while_cond_container": REFUSE,
        "lcw4_while_cond_onelink_control_secret_at_entry": REFUSE,
        "lq0_sink_in_cond_via_helper_loopcarried": REFUSE,
        "lq1_sink_in_cond_via_helper_twolink": REFUSE,
        "lq0c_sink_in_cond_via_helper_secret_at_entry": REFUSE,
        "lq0d_sink_in_cond_via_helper_straightline": REFUSE,
        "lq2_sink_in_cond_body_has_sink_too": REFUSE,
        "ctw0_ct_while_cond_loopcarried": REFUSE,
        "ctw0b_ct_while_cond_loopcarried_break": REFUSE,
        "ctw4_ct_while_cond_secret_at_entry": REFUSE,
        "ctw5_ct_if_secret_straightline": REFUSE,
        "ctw6_ct_len_compare_alone": ACCEPT,
    }

    #: The condition's execution count, governed by the head pc. Both
    #: exit kinds that END the loop raise it: a ``break`` (``wcb*``) and
    #: a ``return`` from the body (``wcr2``). A public exit of either
    #: kind, and a ``continue`` (which skips an iteration without
    #: changing how many there are), leave it public.
    CONDITION_EXECUTION = {
        "wcb0_cond_sink_helper_secret_break_in_body": REFUSE,
        "wcb1_cond_sink_helper_loopcarried_secret_break": REFUSE,
        "wcb2_cond_sink_direct_secret_break": REFUSE,
        "wcb5_cond_sink_helper_secret_break_in_match_arm": REFUSE,
        "wcr2_cond_sink_helper_secret_return_in_body": REFUSE,
        "wcb3_control_cond_sink_public_break": ACCEPT,
        "wcb4_control_cond_sink_secret_continue_only": ACCEPT,
        "wcr3_control_cond_sink_public_return": ACCEPT,
    }

    #: The substitutions that turn ``lcw3`` (a ``while`` whose condition
    #: reads a container the body pushes under a secret pc, REFUSED
    #: because the condition is re-evaluated every iteration and the
    #: rule sees it) into the ``for`` twin that iterates the container
    #: itself: seeded so the loop is entered, and bounded in the guard
    #: since there is no condition to bound it in.
    ITERATED_CONTAINER_TWIN = (
        ("    var lst: List<Int> = []\n", "    var lst: List<Int> = [0]\n"),
        ("    while lst.is_empty() and n < 5\n", "    for x in lst\n"),
        ('        if k.starts_with("s")\n',
         '        if k.starts_with("s") and n < 3\n'),
    )

    def test_table(self):
        assert_table(self, "loop_condition", self.TABLE)

    def test_condition_execution_count(self):
        assert_table(self, "loop_condition", self.CONDITION_EXECUTION)

    def test_disclosed_residual(self):
        twin = "lcw3_while_cond_container"
        assert_disclosed_residual(
            self, twin, read_fixture("loop_condition", twin),
            "for_over_the_container_mutated_in_the_body",
            self.ITERATED_CONTAINER_TWIN,
        )

    def test_condition_diagnostics_are_reported_once(self):
        # The condition's sink error and the body's sink error: one each.
        r = check_fixture("loop_condition", "lq2_sink_in_cond_body_has_sink_too")
        self.assertEqual(len(r.errors), 2, [e.message for e in r.errors])
        # A condition secret at entry reports its one error once, not once
        # per fixpoint pass.
        r = check_fixture("loop_condition", "lq0c_sink_in_cond_via_helper_secret_at_entry")
        self.assertEqual(len(r.errors), 1, [e.message for e in r.errors])

    def test_warn_tier_warning_and_manifest_agree(self):
        # Outside strict mode the same flow is a warning, and the manifest
        # fact it feeds must name the same sink at the same position.
        r = check_fixture("loop_condition", "lq0w_warn_tier_sink_in_cond_loopcarried")
        self.assertTrue(r.ok, [e.message for e in r.errors])
        warnings = [w for w in r.warnings if "information-flow" in w.message]
        self.assertEqual(len(warnings), 1, [w.message for w in r.warnings])
        # The manifest builder de-duplicates the recorded facts by
        # (capability, position); the de-duplicated set must be exactly
        # the warning's sink.
        recorded = {
            (cap, (pos.line, pos.col))
            for facts in r.unaudited_secret_sinks.values()
            for cap, pos in facts
        }
        self.assertEqual(
            recorded, {("Stdio", (warnings[0].pos.line, warnings[0].pos.col))},
        )


class MatchArmExits(unittest.TestCase):
    """A ``match`` whose arm jumps is an exit statement of its body by the
    arm's KIND: a bare ``match`` statement, a let / assign / return-carried
    match, and a match nested inside a larger expression (``1 + match``,
    ``not match``, a comparison) all contribute their arms' ``break`` /
    ``continue`` to the loop's exit map. A ``return``-carried match whose
    arm breaks exits the LOOP, not the frame. The ``if`` twins pin that the
    two spellings of one program get one verdict."""

    TABLE = {
        "lcm0_bare_match_secret_scrutinee_break_itercount": REFUSE,
        "lcm0b_let_carried_match_secret_scrutinee_break_itercount": REFUSE,
        "lcm0c_bare_match_secret_scrutinee_break_sink_before_in_body": REFUSE,
        "lcm0d_bare_match_literal_arm_secret_scrutinee_break_itercount": REFUSE,
        "lcm0e_if_twin_control": REFUSE,
        "lcm0f_bare_match_secret_scrutinee_continue_sink_after_in_body": REFUSE,
        "lcm0g_bare_match_public_scrutinee_secret_if_break_in_arm_itercount": REFUSE,
        "lcm1_match_guard_break_twolink": REFUSE,
        "lcm2a_assign_carried_match_break": REFUSE,
        "lcm2d_nested_match_inner_break": REFUSE,
        "lcm2e_arms_disagree_break_continue": REFUSE,
        "lcm2f4_return_match_break_arm_env_inside": REFUSE,
        "lcm2f5_if_break_else_continue_env_inside": REFUSE,
        "lcm2f6_return_match_break_arm_else_value": REFUSE,
        "p01_let_direct": REFUSE,
        "p02_assign_direct": REFUSE,
        "p04_binop_lhs": REFUSE,
        "p08_return_direct": REFUSE,
        "p17_nested_if_in_arm_value": REFUSE,
        "p18_continue_arm": ACCEPT,
        "ifbc0_if_break_only": REFUSE,
        "ifbc1_if_break_else_continue": REFUSE,
        "ifbc2_if_break_else_stmt": REFUSE,
        "ifbc3_if_break_else_return": REFUSE,
        "ifbc4_if_continue_else_break": REFUSE,
        "ifbc5_match_break_continue_arms_while": REFUSE,
        "ifbc6_if_break_else_continue_sink_in_body": REFUSE,
    }

    #: The match sits inside a larger expression; the jump is found by the
    #: reflective expression walk, not by a directly-carried-match test.
    EXPRESSION_NESTED = {
        "lcm2b_binop_wrapped_match_break": REFUSE,
        "lcm2b2_binop_wrapped_match_break_sink_after": REFUSE,
        "p03_binop_rhs": REFUSE,
        "p05_unary_not": REFUSE,
        "p13_let_binop": REFUSE,
        "p14_compare": REFUSE,
        "p15_expr_stmt_binop": REFUSE,
        "r04_binop_rhs_sink_in_body_before": REFUSE,
        # The jumping match sits in an if-EXPRESSION branch: the
        # if-expression's condition is the guard the arm's exit is under.
        "ifx6_ifexpr_secret_cond_else_match_break_itercount": REFUSE,
        "ifx8_ifexpr_secret_cond_then_match_break_itercount": REFUSE,
        "ifx7_ifexpr_public_cond_else_match_break_control": ACCEPT,
    }

    #: An exit taken under a pc raised EARLIER in the same body: the break
    #: fires only when the secret-conditioned continue before it did not,
    #: so the iteration count is secret although the break's own guard is
    #: public. The exit label is the guard joined with the prefix's
    #: normal-termination label.
    PREFIX_CONDITIONED = {
        "pb0_continue_under_secret_then_public_break_itercount": REFUSE,
        "pb1_control_public_continue_then_public_break": ACCEPT,
    }

    def test_table(self):
        assert_table(self, "match_exits", self.TABLE)

    def test_expression_nested(self):
        assert_table(self, "match_exits", self.EXPRESSION_NESTED)

    def test_prefix_conditioned_exit(self):
        assert_table(self, "match_exits", self.PREFIX_CONDITIONED)


class PreciseExitKinds(unittest.TestCase):
    """An exit the collector cannot attribute to THIS body is no exit of
    it: an inner loop's own ``break`` / ``continue`` under a secret ``if``
    does not make the statements after the ``if`` secret (``fc01``, ``fc02``,
    ``fc06`` to ``fc09`` accepted), while a ``return`` that escapes the inner
    loop, or a diverging arm expression, still does."""

    TABLE = {
        "fc01_secret_if_inner_for_break_only_then_sink": ACCEPT,
        "fc02_secret_if_inner_while_continue_only_then_sink": ACCEPT,
        "fc03_secret_if_inner_for_break_and_return": REFUSE,
        "fc04_secret_if_inner_for_return_inside": REFUSE,
        "fc05_secret_match_arm_expr_ifexpr_panic": REFUSE,
        "fc06_for_secret_if_inner_for_break_only_sink_in_outer_body": ACCEPT,
        "fc07_while_secret_if_inner_while_continue_only_sink_in_outer_body": ACCEPT,
        "fc08_for_secret_if_inner_for_break_only_sink_before_in_outer_body": ACCEPT,
        "fc09_for_secret_if_inner_for_break_AND_outer_sink_after_loop": ACCEPT,
    }

    def test_table(self):
        assert_table(self, "fail_closed", self.TABLE)


class DeadBranchCost(unittest.TestCase):
    """The walker is path-insensitive: a secret-conditioned exit under a
    guard that is statically false is still an exit, and the sink after it
    is refused. This is the accepted cost of the rule, pinned so a change
    is visible, not a claim that these programs leak."""

    TABLE = {
        "d01_literal_false_guard": REFUSE,
        "d02_const_flag_false": REFUSE,
        "d03_arith_dead_in_loop": REFUSE,
        "d04_match_dead_arm": REFUSE,
        "d05_feature_flag_realistic": REFUSE,
        "d06_control_dead_inner_under_secret": REFUSE,
    }

    def test_table(self):
        assert_table(self, "dead_branch", self.TABLE)


class Negatives(unittest.TestCase):
    """Programs that leak nothing and must stay accepted: a lambda whose
    body exits is its own frame (its exits never govern the definition's
    successors); a sink BEFORE a secret-conditioned ``continue`` runs every
    iteration; a public guard; a sink after a loop whose exits are all
    consumed by the loop."""

    TABLE = {
        "f01_lambda_escape": ACCEPT,
        "f01_lambda_secret_return_then_public_sink_in_main": ACCEPT,
        "f02_lambda_uncalled": ACCEPT,
        "f02_lambda_secret_return_never_called_public_sink": ACCEPT,
        "f13_for_sink_before_secret_break_itercount": REFUSE,
        "f17_typed_lambda_secret_return_public_sink_after": ACCEPT,
        "f18_lambda_in_while_secret_return_body_sink_after": ACCEPT,
        "f21_for_sinkbefore": ACCEPT,
        "f21_while_sinkbefore": ACCEPT,
        "f21f_for_sink_before_secret_continue_no_leak": ACCEPT,
        "f21w_while_sink_before_secret_continue_no_leak": ACCEPT,
        "n01_public_cond": ACCEPT,
        "n02_no_jump": REFUSE,
        "n03_after_loop_public": ACCEPT,
        "n04_public_break_nested_if_sink_after": ACCEPT,
        "n05_secret_value_only_no_jump_sink_after_loop": ACCEPT,
        "x01_nested_inner_break_outer_sink_after_inner": ACCEPT,
        "x09_lambda_inner_loop_break_then_sink_in_lambda": ACCEPT,
    }

    def test_table(self):
        assert_table(self, "negatives", self.TABLE)


class TryExitForm(unittest.TestCase):
    """The ``?`` operator as an exit form, at the expression positions
    pinned below.

    A ``?`` that runs leaves the enclosing frame when its operand is an
    ``Err`` (or a ``None``), so it ends a loop the way a ``return`` does.
    It differs from the statement exits in where a secret dependence CAN
    come from: a ``return`` statement leaves whenever it is reached, so
    its dependence on a secret comes from what decides that, such as an
    enclosing guard, while a ``?`` is an expression whose own operand can
    carry the dependence with no guard around it. The walker therefore
    reaches it as an expression, which is why the positions below are
    members: each puts a ``?`` with a secret operand in one of these
    expression positions, the interpolation one in both of its
    spellings, and each ends the loop the sink runs in.

    Each member was scored against a runtime oracle before being used as
    one: stripped of the annotation and run under two keys, each prints
    its sink a different number of times on the legacy, ``--ir`` and
    ``--wasm`` backends, so the refusal answers a real difference in
    observable behaviour and not a syntactic guess.

    The negatives bound the rule. A PUBLIC operand is the discriminating
    one: it makes the rule label-sensitive rather than blind to the
    syntax, and it ran its sink the same number of times under both keys
    on the same three backends. A ``?`` INSIDE a lambda body returns from
    the LAMBDA, so it does not end an enclosing loop; a ``?`` applied to
    a lambda CALL does, and ``tf11`` pins that direction so the boundary
    is read as being about where the ``?`` is and not about the presence
    of a lambda."""

    #: One member for each of these expression positions (the
    #: interpolation position in both of its spellings), a sample of
    #: where a ``?`` can sit rather than an enumeration of the grammar,
    #: each with the sink AHEAD of it in the loop body, so how many times
    #: the sink runs is how many iterations there are.
    TABLE = {
        "tf01_interpolation_embedded_sink_before": REFUSE,
        "tf02_interpolation_bare_sink_before": REFUSE,
        "tf03_bare_expression_statement_sink_before": REFUSE,
        "tf04_binop_operand_sink_before": REFUSE,
        "tf05_call_argument_sink_before": REFUSE,
        "tf06_index_subject_sink_before": REFUSE,
        "tf07_list_literal_element_sink_before": REFUSE,
        "tf08_match_scrutinee_sink_before": REFUSE,
        "tf09_assignment_source_sink_before": REFUSE,
        "tf10_if_condition_sink_before": REFUSE,
        "tf11_try_on_a_lambda_call_sink_before": REFUSE,
    }

    NEGATIVES = {
        "tn01_public_operand_stays_accepted": ACCEPT,
        "tn02_secret_try_with_no_sink": ACCEPT,
        "tn03_try_inside_a_lambda_in_the_loop": ACCEPT,
        "tn04_not_strict_stays_accepted": ACCEPT,
    }

    #: The residual of this class, DISCLOSED and PINNED: the walker
    #: reasons about the exits a body SPELLS, so an abort the program
    #: never spells (an operation that fails at run time on a value the
    #: secret decided) is attributed no exit, and a loop it ends keeps a
    #: public head pc while its iteration count is secret. The member is
    #: not written out: it is the generator's sink-before-``while`` member
    #: for the ``panic`` form, REFUSED because that abort is spelled,
    #: with the spelled abort replaced by an unspelled one and the guard
    #: moved to decide the value it fails on before the loop. Pinned
    #: ACCEPTED so the residual is disclosed rather than implied to be
    #: covered, and so a change that closes it flips this deliberately.
    UNSPELLED_ABORT_TWIN = (
        ('        if k.starts_with("s")\n            panic("no")\n',
         "        let _q = 10 / d\n"),
        ('    let k = env.get("API_KEY").unwrap_or("none")\n',
         '    let k = env.get("API_KEY").unwrap_or("none")\n'
         "    var d: Int = 1\n"
         '    if k.starts_with("s")\n'
         "        d = 0\n"),
    )

    def test_the_sampled_positions_are_members(self):
        assert_table(self, "exit_forms", self.TABLE)

    def test_the_negatives_stay_accepted(self):
        assert_table(self, "exit_forms", self.NEGATIVES)

    def test_disclosed_residual(self):
        spelled = next(
            source for form, source in loop_ending_probes()
            if form.name == "panic"
        )
        assert_disclosed_residual(
            self, "sb_panic_while", spelled,
            "unspelled_abort_ends_the_loop", self.UNSPELLED_ABORT_TWIN,
        )

    def test_the_declared_return_type_rule_is_unmoved(self):
        # A ``?`` MAY leave and MAY continue, so a body whose last
        # statement is one does NOT end in a return: a function declaring
        # a return type can still fall through, and that is a compile
        # error. Treating the ``?`` as an unconditional exit instead would
        # silence this, and the program would then be accepted and print
        # nothing at runtime where an error is correct.
        source = (
            "fun may(k: String) -> Result<Int, String>\n"
            '    if k.starts_with("s")\n'
            '        return Err("no")\n'
            "    return Ok(1)\n"
            "\n"
            "fun f(k: String) -> Result<Int, String>\n"
            "    let v = may(k)?\n"
        )
        result = check_source(source)
        self.assertFalse(
            result.ok,
            "a body ending in `?` does not end in a return, so a declared "
            "return type must still be refused",
        )
        self.assertTrue(
            any("not every path ends in" in e.message for e in result.errors),
            [e.message for e in result.errors],
        )

    def test_match_arm_typing_is_unmoved(self):
        # A second rule the ``?`` must not move: match arm typing. An arm
        # whose body is a ``?`` expression is typed by that expression's
        # value, so the arms unify and the program is accepted.
        source = (
            "fun may(k: String) -> Result<Int, String>\n"
            '    if k.starts_with("s")\n'
            '        return Err("no")\n'
            "    return Ok(1)\n"
            "\n"
            "fun f(k: String) -> Result<Int, String>\n"
            "    let v = match k.length()\n"
            "        0 -> may(k)?\n"
            "        _ -> 1\n"
            "    return Ok(v)\n"
        )
        result = check_source(source)
        self.assertTrue(result.ok, [e.message for e in result.errors])


class SpeculativePassSeam(unittest.TestCase):
    """State a speculative loop pass must not leak into the real pass: the
    diagnostic dedup sets (a capability or a linear value packed in a
    container inside a loop body is reported once, not lost) and the
    deferred empty-container reads (reported once, not once per fixpoint
    pass)."""

    def _errors(self, name):
        return [e.message for e in check_fixture("dedup_seam", name).errors]

    def test_capability_in_container_inside_a_loop_is_refused(self):
        for name in (
            "dd07_cap_in_list_expr_position_in_for_body",
            "dd08_cap_in_list_expr_position_in_while_body",
        ):
            with self.subTest(program=name):
                errs = self._errors(name)
                self.assertEqual(len(errs), 1, errs)
                self.assertIn("container", errs[0])

    def test_container_error_is_not_lost_beside_the_binding_error(self):
        for name in (
            "dd02_cap_in_list_in_for_body",
            "dd03_cap_in_list_in_while_body",
            "dd04_cap_in_tuple_in_for_body",
            "dd05_cap_in_list_in_nested_for_body",
        ):
            with self.subTest(program=name):
                errs = self._errors(name)
                self.assertEqual(len(errs), 2, errs)

    def test_linear_in_container_inside_a_loop_is_refused(self):
        for name in (
            "ldd07_linear_in_list_expr_position_in_for_body",
            "ldd08_linear_in_list_expr_position_in_while_body",
        ):
            with self.subTest(program=name):
                errs = self._errors(name)
                self.assertEqual(len(errs), 1, errs)
                self.assertIn("container of single-owner values", errs[0])

    def test_flat_forms_unchanged(self):
        self.assertEqual(len(self._errors("dd01_cap_in_list_flat")), 2)
        self.assertEqual(len(self._errors("dd06_cap_in_list_expr_position_flat")), 1)
        self.assertEqual(len(self._errors("ldd06_linear_in_list_expr_position_flat")), 1)

    def test_deferred_element_read_is_reported_once(self):
        elem = "cannot determine the element type"
        for name, total in (
            ("dfr0_empty_container_read_in_loop_flat", 1),
            ("dfr1_empty_container_read_in_loop", 1),
            ("dfr2_empty_container_read_in_loop_with_chain", 2),
            ("dfr3_untyped_lambda_in_loop_with_chain", 2),
        ):
            with self.subTest(program=name):
                errs = self._errors(name)
                self.assertEqual(len(errs), total, errs)
                self.assertLessEqual(sum(1 for e in errs if elem in e), 1, errs)

    def test_chain_member_beside_the_deferred_read_is_still_refused(self):
        r = check_fixture("dedup_seam", "dfr2_empty_container_read_in_loop_with_chain")
        self.assertEqual(len(ifc_errors(r)), 1, [e.message for e in r.errors])


if __name__ == "__main__":
    unittest.main()
