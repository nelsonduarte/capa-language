"""The strict condition-position family, ``--check`` only, against the
register.

The table lives in ``tests.implicit_flow._generated`` (the secret at the
construct's own condition); a private extension may add positions. Every
secret program must be REFUSED with an information-flow error and every
public twin ACCEPTED; a position that does not hold is a registered entry.
"""

import shutil
import tempfile
import unittest
from pathlib import Path

from tests.implicit_flow._generated import CONDITION_POSITIONS, REFUSE, generate_conditions
from tests.instruments._outcome import ACCEPT, REFUSE_IFC, check_outcome
from tests.instruments._private import load_module
from tests.instruments._provenance import REPO_ROOT, provenance_ok
from tests.instruments._register import diff, load_merged, member_id
from tests.instruments._runner import Program, run_leg

INSTRUMENT = "strict_positions"


def positions() -> dict:
    table = dict(CONDITION_POSITIONS)
    ext = load_module("strict_positions")
    if ext is not None:
        table.update(ext.CONDITION_POSITIONS)
    return table


class StrictConditionPositions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = Path(tempfile.mkdtemp(prefix="capa_pos_"))
        cls.programs, cls.expected = [], {}
        for name, src, verdict in generate_conditions(positions()):
            p = cls.work / (name + ".capa")
            p.write_text(src, encoding="utf-8", newline="\n")
            cls.programs.append(Program(p.name, p))
            cls.expected[p.name] = (REFUSE_IFC if verdict == REFUSE else ACCEPT, src)
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


if __name__ == "__main__":
    unittest.main()
