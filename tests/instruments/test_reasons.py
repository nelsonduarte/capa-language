"""The words of instrument (a)'s register: the walker, the table, the one
predicate and the one check (``absolute/_reasons``), with no compiler run.

The walker is pinned on generated programs whose shapes are known by hand,
so a check that passes is not passing because the walker went blind or
reports a shape everywhere. The table machinery is pinned on rows built
here, so each clause can be shown to bite. The public register itself is
checked against the public rows on a real run in ``test_absolute``.
"""

import random
import shutil
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path

from tests.instruments._outcome import BROKEN, WRONG
from tests.instruments._register import entry_key, member_id
from tests.instruments.absolute import _anchors as AN, _kinds as K
from tests.instruments.absolute import _reasons as R
from tests.instruments.absolute._corpus import source_text, write_anchor_programs, write_program
from tests.instruments.absolute._gen import Gen
from tests.instruments.absolute._rule import HEADER, MAIN

_GUARD_WITH_CALL = ("match 1", "    n if tb(stdio, 1, true) -> stdio.println(\"a\")", "    _ -> stdio.println(\"b\")")
_GUARD_WITHOUT = ("match 1", "    n if n > 0 -> stdio.println(\"a\")", "    _ -> stdio.println(\"b\")")


def _body(*lines: str) -> str:
    return MAIN + "".join("    " + line + "\n" for line in lines)


class _Work(unittest.TestCase):
    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix="capa_reasons_"))

    def tearDown(self):
        shutil.rmtree(self.work, ignore_errors=True)


class ShapeWalker(_Work):
    def test_the_header_alone_claims_no_shape(self):
        self.assertEqual(R.body_shapes(HEADER + MAIN + "    stdio.println(\"x\")\n", R.PUBLIC.detectors), frozenset())

    def test_a_guard_carrying_a_call(self):
        self.assertIn(R.GUARD_CALL, R.body_shapes(_body(*_GUARD_WITH_CALL), R.PUBLIC.detectors))
        self.assertNotIn(R.GUARD_CALL, R.body_shapes(_body(*_GUARD_WITHOUT), R.PUBLIC.detectors))

    def test_the_shapes_of_generated_anchors_known_by_hand(self):
        # Through program_shapes, the entry point the check uses, on the
        # generated programs themselves: the walker is checked on its own
        # input, not only on bodies written here.
        anchors = write_anchor_programs(self.work, AN.anchors(Gen(random.Random(0), dict(K.PUBLIC_KINDS))))
        by_name = {p.name: p for p in anchors}
        known = {
            "anchor_r4_guard_runs_only_after_its_pattern_matched.capa": True,
            "anchor_r4_guard_that_fails_falls_to_the_next_arm.capa": True,
            "anchor_r4_match_statement_guard_holds.capa": False,
            "anchor_r4_match_struct_pattern_with_guard.capa": False,
            "anchor_r1_operands_left_to_right.capa": False,
        }
        for name, has_guard_call in known.items():
            with self.subTest(anchor=name):
                self.assertEqual(R.GUARD_CALL in R.PUBLIC.program_shapes(by_name[name]), has_guard_call)

    def test_a_program_without_the_header_is_refused(self):
        p = write_program(self.work, "no_header", MAIN + "    stdio.println(\"x\")\n", "OK", "x\n")
        with self.assertRaises(ValueError):
            R.PUBLIC.program_shapes(p)


@dataclass(frozen=True)
class _Separated(R.Reason):
    def separated_from(self, other) -> bool:
        return True


def _row(key, needs, excludes=(), legs=("ir",), outcome=WRONG, observed=None, cls=R.Reason):
    return cls(key, "text of " + key, "some step", legs, outcome, frozenset(needs), frozenset(excludes), observed)


def _table(*rows, observations=None) -> R.ReasonTable:
    return R.ReasonTable(tuple(rows), {"a": lambda n: False, "b": lambda n: False},
                         {"holds": lambda row, exp: row.get("ok", False)} if observations is None else observations)


class TheTable(unittest.TestCase):
    def test_the_public_table_is_well_formed(self):
        self.assertEqual(R.PUBLIC.problems(), [])

    def test_two_rows_that_can_match_one_entry_are_named(self):
        self.assertEqual(_table(_row("X", {"a"}), _row("Y", {"a"})).problems(), ["X and Y can both match one entry"])
        self.assertEqual(_table(_row("X", {"a"}), _row("Y", {"a", "b"})).problems(),
                         ["X and Y can both match one entry"])

    def test_rows_kept_apart_are_accepted(self):
        for rows in ((_row("X", {"a"}, excludes={"b"}), _row("Y", {"a", "b"})),
                     (_row("X", {"a"}), _row("Y", {"a"}, legs=("wasm",))),
                     (_row("X", {"a"}), _row("Y", {"a"}, outcome=BROKEN)),
                     (_row("X", {"a"}), _row("Y", {"a"}, cls=_Separated))):
            with self.subTest(rows=[r.key for r in rows]):
                self.assertEqual(_table(*rows).problems(), [])

    def test_an_unknown_shape_or_observation_and_a_duplicate_text_are_named(self):
        self.assertEqual(_table(_row("X", {"c"})).problems(), ["X names a shape the walker does not report"])
        self.assertEqual(_table(_row("X", {"a"}, observed="nope")).problems(), ["X names an unknown observation nope"])
        dup = _row("X", {"a"})
        self.assertEqual(_table(dup, dup).problems()[0], "duplicate reason text")

    def test_an_extension_may_not_redefine_a_shape_or_an_observation(self):
        with self.assertRaises(ValueError):
            R.PUBLIC.extended(detectors={R.GUARD_CALL: lambda n: False})
        with self.assertRaises(ValueError):
            R.PUBLIC.extended(observations={"unsupported_in_ir": lambda row, exp: True})
        ext = R.PUBLIC.extended(rows=(_row("X", {"x"}),), detectors={"x": lambda n: False})
        self.assertEqual(ext.rows[:len(R.PUBLIC.rows)], R.PUBLIC.rows)
        self.assertEqual(set(ext.detectors), {R.GUARD_CALL, "x"})

    def test_each_clause_of_a_row_is_judged(self):
        t = _table()
        r = _row("X", {"a"}, excludes={"b"}, observed="holds")
        self.assertEqual(t.failures(r, "ir", "WRONG:k", frozenset({"a"}), ({"ok": True}, None)), [])
        for leg, outcome, shapes, observation in (
                ("wasm", "WRONG:k", {"a"}, None), ("ir", "BROKEN", {"a"}, None), ("ir", "WRONG:k", set(), None),
                ("ir", "WRONG:k", {"a", "b"}, None), ("ir", "WRONG:k", {"a"}, ({"ok": False}, None))):
            with self.subTest(leg=leg, outcome=outcome, shapes=sorted(shapes), observation=observation):
                self.assertEqual(len(t.failures(r, leg, outcome, frozenset(shapes), observation)), 1)


class TheCheck(_Work):
    """``check`` on entries written here, against the public table."""

    GUARD = R.PUBLIC.rows[0]

    def _program(self, name, *lines):
        p = write_program(self.work, name, HEADER + _body(*lines), "OK", "a\n")
        return member_id(p.name, source_text(p)), p

    def _entry(self, reason=None, closes_in=None, outcome="BROKEN"):
        return {"outcome": outcome, "reason": self.GUARD.text if reason is None else reason,
                "closes_in": self.GUARD.closes_in if closes_in is None else closes_in}

    def _check(self, entry, lines=_GUARD_WITH_CALL, row=None):
        mid, p = self._program("p", *lines)
        row = {"outcome": "BROKEN", "exc": "UnsupportedInIR: x"} if row is None else row
        return R.PUBLIC.check({entry_key("absolute", mid, "ir"): entry}, {mid: p}, {(mid, "ir"): (row, ("OK", "a\n"))})

    def test_a_matching_entry_is_judged_and_passes(self):
        res = self._check(self._entry())
        self.assertEqual((res.checked, res.judged_observations, res.mismatches, res.moved), (1, 1, [], []))

    def test_each_way_an_entry_can_disagree_is_a_mismatch(self):
        for label, entry, lines, row in (
                ("a reason outside the table", self._entry(reason="no row says this"), _GUARD_WITH_CALL, None),
                ("another closes_in", self._entry(closes_in="some other step"), _GUARD_WITH_CALL, None),
                ("a body without the shape", self._entry(), _GUARD_WITHOUT, None),
                ("an observation that does not hold", self._entry(), _GUARD_WITH_CALL,
                 {"outcome": "BROKEN", "exc": "NameError: x"})):
            with self.subTest(label):
                self.assertEqual(len(self._check(entry, lines, row).mismatches), 1)

    def test_a_claimed_observation_that_was_not_run_is_a_mismatch(self):
        mid, p = self._program("p", *_GUARD_WITH_CALL)
        res = R.PUBLIC.check({entry_key("absolute", mid, "ir"): self._entry()}, {mid: p}, {})
        self.assertEqual(len(res.mismatches), 1)

    def test_an_entry_whose_outcome_moved_is_listed_not_judged(self):
        res = self._check(self._entry(), row={"outcome": "OK", "stdout": "a\n", "exc": ""})
        self.assertEqual((len(res.moved), res.judged_observations, res.mismatches), (1, 0, []))


if __name__ == "__main__":
    unittest.main()
