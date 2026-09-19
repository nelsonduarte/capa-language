"""The linear discipline across loop exits: exit-keyed, one frame per loop.

A branch that consumes a capability / linear value and then ``break``s
does not reach the merge after its ``if``, but it DOES reach the loop's
exit: the value is consumed for everything after the loop. A branch that
``continue``s reaches the loop's head: the value is consumed for the next
iteration. Only a ``return`` branch reaches nothing else in the frame.
Discarding the branch's consumed set at the ``if`` (as the merge of
non-diverging branches must) therefore let the same value be consumed
twice: once in the jumping branch and once after the loop or on the next
iteration.

The suspended consumed sets are keyed by exit kind and kept in a frame
PER LOOP, so an inner loop consumes only what its own body suspended and
an outer loop's ``break`` branch is not pre-marked at the inner loop's exit
(the ``ln01`` / ``ln02`` / ``b02`` / ``b05`` false positives of a flat
frame). The search idiom (consume once, then leave) stays accepted.
"""

import unittest

from tests.implicit_flow._harness import ACCEPT, REFUSE, assert_table, check_fixture


class LinearLoopExits(unittest.TestCase):
    """Double consumes through ``break`` / ``continue``, and the valid
    idioms that must stay accepted."""

    TABLE = {
        "l01_break_double": REFUSE,
        "l02b_nojump_double": REFUSE,
        "l02c_continue_double": REFUSE,
        "l03_handle_close_break_close_after": REFUSE,
        "l04b_handle_close_continue_close_after": REFUSE,
        "l09_while_true_close_break_idiom": REFUSE,
        "l10_search_idiom": ACCEPT,
        "l11_for_break_double": REFUSE,
        "ln03_consume_break_one_branch_sink_continue_other": ACCEPT,
        "ln04_search_idiom_for": ACCEPT,
        "ln05_nested_if_break_double": REFUSE,
        "ln06_linear_var_close_reassign_continue": ACCEPT,
        "ln11_typestate_consume_break_double": REFUSE,
        "ln12_consume_self_break_double": REFUSE,
        "ln13_cap_by_reference_in_break_branch_use_after": ACCEPT,
        "ln14_consume_continue_branch_use_next_iteration": REFUSE,
        "ln15_inner_for_break_consume_then_use_in_outer_body": REFUSE,
        "ln16_consume_break_then_use_in_dead_tail_after_break": REFUSE,
        "ln17_elif_break_consume_double": REFUSE,
        "ln18_else_continue_consume_double": REFUSE,
        "ld01_for_body_consume_no_jump": REFUSE,
        "ld02_while_body_consume_no_jump": REFUSE,
        "ld03_consume_continue_reexec_no_use": REFUSE,
        "ld04_consume_break_only": ACCEPT,
        "ld05_consume_before_loop_then_break_branch_consume": REFUSE,
        "ld06_chain_guarded_consume_then_use_in_body": REFUSE,
        "ld07_chain_guarded_break_consume_no_use": ACCEPT,
        "ld08_chain_guarded_break_consume_use_after_loop": REFUSE,
        "ld11_chain_guarded_continue_consume_use_next_iteration": REFUSE,
        "ld12_consume_in_else_of_break_branch_if": ACCEPT,
        "b01_break_consume_then_sibling_loop_after_then_use": REFUSE,
        "b04_outer_continue_consume_inner_loop_then_use": REFUSE,
        "b06_break_consume_then_use_after_loop_no_sibling": REFUSE,
    }

    def test_table(self):
        assert_table(self, "linear", self.TABLE, ifc_only=False)


class PerLoopFrame(unittest.TestCase):
    """An outer loop's ``break``-branch consume followed by an UNRELATED
    inner loop: the inner loop must not consume the outer loop's suspended
    state at its own exit. Every program here is valid and runs cleanly."""

    TABLE = {
        "ln01_outer_break_consume_inner_while_then_use": ACCEPT,
        "ln02_outer_break_consume_inner_for_then_use": ACCEPT,
        "ln02b_outer_break_consume_inner_loop_no_use_after": ACCEPT,
        "b02_three_levels_outer_break_consume_inner_two_loops": ACCEPT,
        "b03_matcharm_break_consume_inner_loop_then_use": ACCEPT,
        "b05_for_outer_break_consume_inner_for_then_use": ACCEPT,
        "ld09_break_branch_consume_then_stmt_then_break_inner_loop": ACCEPT,
        "ld10_chain_guarded_break_consume_inner_loop_then_use": ACCEPT,
    }

    def test_table(self):
        assert_table(self, "linear", self.TABLE, ifc_only=False)


class MatchArmSpelling(unittest.TestCase):
    """The same rule at the match-arm gate: a match arm that consumes and
    ``break``s is the ``if``-branch program in another spelling, and the
    two spellings get one verdict because both gates suspend through the
    one seam."""

    TABLE = {
        "l07_matcharm_break": REFUSE,
        "l07_handle_match_break_close_after": REFUSE,
    }

    def test_table(self):
        assert_table(self, "linear", self.TABLE, ifc_only=False)


class ErrorPosition(unittest.TestCase):
    """A refusal names the SECOND consume, never the consume that ends a
    ``break`` branch of a loop that is not itself inside a loop."""

    def test_break_branch_consume_is_not_the_reported_site(self):
        r = check_fixture("linear", "l01_break_double")
        self.assertFalse(r.ok)
        lines = sorted(e.pos.line for e in r.errors if "consumed earlier" in e.message)
        self.assertEqual(lines, [10], [e.message for e in r.errors])


if __name__ == "__main__":
    unittest.main()
