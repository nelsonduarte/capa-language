"""The strict condition-position family, ``--check`` only, against the
register.

The table lives in ``tests.implicit_flow._generated`` (the secret at the
construct's own condition); a private extension may add positions, merged
in ONE place (``_positions``). Every secret program must be REFUSED with an
information-flow error and every public twin ACCEPTED; a position that does
not hold is a registered entry.
"""

import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.implicit_flow._generated import CONDITION_POSITIONS, REFUSE
from tests.instruments import release_differential as D
from tests.instruments._outcome import ACCEPT, REFUSE_IFC, check_outcome
from tests.instruments._positions import positions, write_programs
from tests.instruments._private import ENV_VAR
from tests.instruments._provenance import REPO_ROOT, provenance_ok
from tests.instruments._register import diff, load_merged, member_id
from tests.instruments._runner import run_leg

INSTRUMENT = "strict_positions"


class StrictConditionPositions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = Path(tempfile.mkdtemp(prefix="capa_pos_"))
        cls.programs, cls.expected = [], {}
        for program, src, verdict in write_programs(cls.work):
            cls.programs.append(program)
            cls.expected[program.name] = (REFUSE_IFC if verdict == REFUSE else ACCEPT, src)
        cls.rows = run_leg(REPO_ROOT, "check", cls.programs, workdir=cls.work)
        cls.outcomes = {(member_id(name, src), "check"): check_outcome(want, cls.rows[name])
                        for name, (want, src) in cls.expected.items()}

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.work, ignore_errors=True)

    def test_compiler_under_test_is_this_repository(self):
        self.assertTrue(provenance_ok())

    def test_both_verdicts_are_represented(self):
        self.assertEqual({w for w, _ in self.expected.values()}, {REFUSE_IFC, ACCEPT})

    def test_register_holds(self):
        d = diff(load_merged(), INSTRUMENT, self.outcomes, ("check",))
        self.assertTrue(d.green, d.report())

    def test_every_public_twin_is_accepted(self):
        # The false-positive control: a public condition is never refused.
        for name, (want, _src) in self.expected.items():
            if want == ACCEPT:
                with self.subTest(program=name):
                    self.assertEqual(self.rows[name]["outcome"], "OK", self.rows[name].get("errors"))


class OnePositionsTable(unittest.TestCase):
    """A position an extension adds reaches both readers of the family:
    this gate and the release differential's seeded negative corpus."""

    _EXT = "capa_instruments_private.strict_positions"

    def test_an_extension_position_reaches_both_readers(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, "strict_positions.py").write_text(
                "CONDITION_POSITIONS = %r\n" % {"planted_pos": '    if {C}\n        stdio.println("x")\n'},
                encoding="utf-8")
            saved = sys.modules.pop(self._EXT, None)
            try:
                with mock.patch.dict(os.environ, {ENV_VAR: d}):
                    names = set(positions())
                    gate = {p.name for p, _src, _v in write_programs(Path(d) / "gate")}
                    seeded = {p.name for p in D.seeded_negative_corpus(Path(d) / "seeded")}
            finally:
                sys.modules.pop(self._EXT, None)
                if saved is not None:
                    sys.modules[self._EXT] = saved
        self.assertEqual(names, set(CONDITION_POSITIONS) | {"planted_pos"})
        want = {n + twin + ".capa" for n in names for twin in ("_sec", "_pub")}
        self.assertEqual(gate, want)
        self.assertEqual(seeded, want)


if __name__ == "__main__":
    unittest.main()
