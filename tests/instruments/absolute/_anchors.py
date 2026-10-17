"""The ANCHORS of instrument (a): one or more per clause, each with an
expected output written BY HAND from the clause text, never computed. The
evaluator must reproduce every anchor before a corpus is written, and the
anchor programs run on every backend against the same hand-written
expectation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

from tests.instruments._outcome import ABORT, OK
from tests.instruments.absolute._gen import Gen
from tests.instruments.absolute._rule import CLAUSES, HEADER, MAIN, fmt


# ---- ANCHORS: expected output written BY HAND from the clause text ----
@dataclass(frozen=True)
class Anchor:
    clause: str
    title: str
    lines: tuple
    evaluate: Callable
    expected_exit: str
    expected_stdout: str

    @property
    def slug(self) -> str:
        return "".join(c if c.isalnum() else "_" for c in self.title).strip("_").lower()

    @property
    def source(self) -> str:
        return HEADER + MAIN + "\n".join(self.lines) + "\n"


def expr_anchor(clause, title, built, markers, value) -> Anchor:
    """An expression anchor: ``let v = <expr>`` then ``v`` printed. ``value``
    is the hand-written result, or ``None`` for an abort; ``markers`` is the
    stdout the expression writes before that."""
    src, ev = built

    def evaluate(out):
        v = ev(out)
        out.append(" v=%s\n" % fmt(v))
    expected = markers if value is None else markers + " v=%s\n" % fmt(value)
    return Anchor(clause, title, ("    let v = %s" % src, '    stdio.println(" v=${v}")'),
                  evaluate, ABORT if value is None else OK, expected)


def stmt_anchor(clause, title, built, expected_stdout, expected_exit=OK) -> Anchor:
    lines, ev = built
    return Anchor(clause, title, tuple(lines), ev, expected_exit, expected_stdout)


def anchors(g: Gen) -> list:
    L, B, C = g.b_leaf, g.b_bleaf, g.b_lit
    MAX = 9223372036854775807
    A = [
        expr_anchor("R1", "R1 operands left to right", g.b_bin("+", L(1), L(2)), "[1][2]", 3),
        expr_anchor("R1", "R1 call arguments in written order", g.b_call(L(3), L(4)), "[3][4]", 34),
        expr_anchor("R1", "R1 struct fields in written order y first", g.b_struct(L(5), L(6), True), "[6][5]", 21),
        expr_anchor("R1", "R1 struct fields evaluated before a field is read", g.b_field(L(5), L(6), True, "x"), "[6][5]", 5),
        expr_anchor("R1", "R1 interpolation segments left to right", g.b_interp(L(7), L(8)), "[7][8]", 3),
        stmt_anchor("R1", "R1 tuple elements left to right", g.s_tuple(1, L(1), L(2)), "[1][2] tup=12\n"),
        expr_anchor("R2", "R2 and short-circuits on false", g.b_and(B(1, False), B(2, True)), "[1]", False),
        expr_anchor("R2", "R2 or short-circuits on true", g.b_or(B(1, True), B(2, False)), "[1]", True),
        expr_anchor("R2", "R2 and evaluates the right operand when the left is true", g.b_and(B(1, True), B(2, False)), "[1][2]", False),
        expr_anchor("R3", "R3 if expression evaluates only the then branch", g.b_ife(B(9, True), L(1), L(2)), "[9][1]", 1),
        expr_anchor("R3", "R3 if expression evaluates only the else branch", g.b_ife(B(9, False), L(1), L(2)), "[9][2]", 2),
        stmt_anchor("R3", "R3 if statement runs only the chosen arm", g.s_if_stmt(B(1, False), B(2, True), L(3), L(4), L(5)), "[1][2][4] B4\n"),
        stmt_anchor("R3", "R3 elif stops at the first condition that holds", g.s_elif(60, 10), "[60] e=1\n"),
        stmt_anchor("R3", "R3 elif conditions in order", g.s_elif(10, 60), "[10][60] e=2\n"),
        stmt_anchor("R3", "R3 return ends main at once",
                    (g.s_early_return(7, True)[0] + ['    stdio.println(" after")'],
                     lambda out, ev=g.s_early_return(7, True)[1]: (ev(out), out.append(" after\n"))),
                    "[7]"),
        expr_anchor("R4", "R4 match scrutinee once and only the chosen arm", g.b_match(L(2), [L(10), L(11), L(12)], [1, 2]), "[2][11]", 11),
        stmt_anchor("R4", "R4 match statement guard holds", g.s_match_variant(1, L(5), "Circ"), "[5] bigcirc\n"),
        stmt_anchor("R4", "R4 match statement guard fails falls through", g.s_match_variant(1, L(2), "Circ"), "[2] circ=2\n"),
        stmt_anchor("R4", "R4 match or pattern", g.s_match_or(L(1), 0), "[1] lo\n"),
        stmt_anchor("R4", "R4 match struct pattern with guard", g.s_match_struct(1, L(2), L(2)), "[2][2] eq=2\n"),
        stmt_anchor("R4", "R4 guard runs only after its pattern matched", g.s_match_guard_effect(L(3), 0, 11, 12, True), "[3][12] g2\n"),
        stmt_anchor("R4", "R4 guard that fails falls to the next arm", g.s_match_guard_effect(L(0), 0, 11, 12, False), "[0][11][12] g3\n"),
        expr_anchor("R6", "R6 lambda body runs per call", g.b_lam(L(5), L(1)), "[1][5]", 6),
        stmt_anchor("R6", "R6 lambda body runs once per call not at definition", g.s_lam_twice(1, L(5)), "[5][5] l=13\n"),
        stmt_anchor("R7", "R7 while condition before every iteration and once at exit", g.s_while(1, 2), "[0][1][2] w=2\n"),
        stmt_anchor("R7", "R7 while match condition re-evaluated", g.s_while_match(1, 1), "[0][1] wm=1\n"),
        stmt_anchor("R7", "R7 continue re-tests and break leaves", g.s_break_continue(1, 4, 2, 3), "{1} k=3\n"),
        stmt_anchor("R8", "R8 for over a list iterable evaluated once", g.s_for(1, [L(1), L(2), L(3)]), "[1][2][3]<1><2><3> f=6\n"),
        stmt_anchor("R8", "R8 range a to b minus one", g.s_for_range(1, L(1), 3), "[1]<1><2><3> fr=6\n"),
        expr_anchor("R9", "R9 overflow aborts", g.b_bin("+", C(MAX), C(1)), "", None),
        expr_anchor("R9", "R9 floored division minus 7 over 2 is minus 4", g.b_bin("/", g.b_neg(C(7)), C(2)), "", -4),
        expr_anchor("R9", "R9 modulo takes the divisor sign minus 7 mod 3 is 2", g.b_bin("%", g.b_neg(C(7)), C(3)), "", 2),
        expr_anchor("R9", "R9 modulo 7 mod minus 3 is minus 2", g.b_bin("%", C(7), g.b_neg(C(3))), "", -2),
        expr_anchor("R9", "R9 division by zero aborts", g.b_bin("/", C(7), C(0)), "", None),
        stmt_anchor("R9", "R9 multiplication overflow aborts in a statement", g.s_ovf(4611686018427387904, "*", L(2)), "[2]", ABORT),
        expr_anchor("R10", "R10 index out of bounds aborts", g.b_index([L(1), L(2), L(3)], 3), "[1][2][3]", None),
        expr_anchor("R10", "R10 index in bounds", g.b_index([L(1), L(2), L(3)], 1), "[1][2][3]", 2),
        stmt_anchor("R11", "R11 question mark returns early on Err", g.s_try_call(L(3), L(2)), "[3][2][3] err=odd\n"),
        stmt_anchor("R11", "R11 question mark continues on Ok", g.s_try_call(L(2), L(4)), "[2][4][2][4] ok=12\n"),
        expr_anchor("R12", "R12 abort keeps the stdout written before it", g.b_bin("+", g.b_bin("+", L(1), C(MAX)), L(2)), "[1]", None),
        expr_anchor("R13", "R13 less or equal holds on equality", g.b_cmp("<=", L(3), L(3)), "[3][3]", True),
        expr_anchor("R13", "R13 greater or equal holds on equality", g.b_cmp(">=", L(3), L(3)), "[3][3]", True),
        expr_anchor("R13", "R13 less than fails on equality", g.b_cmp("<", L(3), L(3)), "[3][3]", False),
        expr_anchor("R13", "R13 not equal", g.b_cmp("!=", L(3), L(4)), "[3][4]", True),
        expr_anchor("R13", "R13 not negates", g.b_not(B(1, True)), "[1]", False),
        expr_anchor("R14", "R14 list get out of range yields the default", g.b_list([L(1), L(2), L(3)], 3), "[1][2][3]", 0),
        expr_anchor("R14", "R14 list get in range yields the element", g.b_list([L(1), L(2), L(3)], 1), "[1][2][3]", 2),
        expr_anchor("R14", "R14 string length counts characters", g.b_strlen("abc"), "", 3),
        expr_anchor("R14", "R14 empty string length is zero", g.b_strlen(""), "", 0),
    ]
    return A


def check_anchors(g: Gen, anchor_list: Optional[list] = None) -> list:
    """Every anchor through the evaluator; returns the failures as
    ``(anchor, wanted, got)``. Empty means the evaluator agrees with every
    hand-written expectation."""
    fails = []
    for a in (anchors(g) if anchor_list is None else anchor_list):
        got = g.evaluate([a.evaluate])
        want = (a.expected_exit, a.expected_stdout)
        if got != want:
            fails.append((a, want, got))
    return fails


def clauses_without_anchor(anchor_list: list, kinds: dict) -> dict:
    """Clause ids no anchor pins, mapped to the loaded kinds that exercise
    them. A clause none of the loaded kinds exercises is a documented gap of
    the loaded grammar; one that a loaded kind exercises is a hole."""
    anchored = {a.clause for a in anchor_list}
    out = {}
    for c in CLAUSES:
        if c.id not in anchored:
            out[c.id] = sorted(k.name for k in kinds.values() if c.id in k.clauses)
    return out
