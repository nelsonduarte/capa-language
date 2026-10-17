"""The outcome type and the normaliser: what moves a key and what does not."""

import unittest

from tests.instruments import _outcome as O


class _Trap(Exception):
    pass


_Trap.__name__ = "Trap"


class NormaliserTests(unittest.TestCase):
    def test_line_endings_do_not_move_the_key(self):
        self.assertEqual(O.key(O.run_vector("OK", "a\r\nb\r\n")), O.key(O.run_vector("OK", "a\nb\n")))

    def test_a_changed_byte_of_stdout_moves_the_key(self):
        self.assertNotEqual(O.key(O.run_vector("OK", "one\n")), O.key(O.run_vector("OK", "two\n")))

    def test_a_changed_exit_class_moves_the_key(self):
        self.assertNotEqual(O.key(O.run_vector("OK", "x")), O.key(O.run_vector("ABORT:OverflowError", "x")))

    def test_python_abort_is_the_exception_class_only(self):
        self.assertEqual(O.exit_class_from_exception(OverflowError("Int addition overflows: 1 + 2")),
                         "ABORT:OverflowError")

    def test_wasm_trap_offsets_are_replaced(self):
        a = O.exit_class_from_exception(_Trap("error while executing\nwasm trap: unreachable at 0x5d1\n  at 0x1f"))
        b = O.exit_class_from_exception(_Trap("error while executing\nwasm trap: unreachable at 0x5d6\n  at 0x2a"))
        self.assertEqual(a, b)
        self.assertEqual(a, "ABORT:wasm trap: unreachable at 0x?")

    def test_command_line_abort_is_the_return_code(self):
        self.assertEqual(O.exit_class_from_rc(0), "OK")
        self.assertEqual(O.exit_class_from_rc(1), "ABORT:rc1")

    def test_key_is_sixteen_hex_characters(self):
        k = O.key(["OK", ""])
        self.assertEqual(len(k), 16)
        int(k, 16)


class RuleComparisonTests(unittest.TestCase):
    def test_expected_abort_matches_any_abort_kind(self):
        self.assertTrue(O.matches("ABORT", "before\n", "ABORT:OverflowError", "before\n"))
        self.assertTrue(O.matches("ABORT", "before\n", "ABORT:wasm trap: unreachable", "before\r\n"))
        self.assertFalse(O.matches("ABORT", "before\n", "OK", "before\n"))

    def test_expected_ok_needs_ok_and_equal_stdout(self):
        self.assertTrue(O.matches("OK", "a\n", "OK", "a\r\n"))
        self.assertFalse(O.matches("OK", "a\n", "OK", "b\n"))
        self.assertFalse(O.matches("OK", "a\n", "ABORT:X", "a\n"))

    def test_run_outcome_classes(self):
        exp = ("OK", "a\n")
        self.assertEqual(O.run_outcome(exp, {"outcome": "OK", "stdout": "a\n"}), O.CORRECT)
        self.assertEqual(O.outcome_type(O.run_outcome(exp, {"outcome": "OK", "stdout": "b\n"})), O.WRONG)
        for o in (O.REFUSED, O.TIMEOUT, O.BROKEN, O.VOID):
            self.assertEqual(O.run_outcome(exp, {"outcome": o, "stdout": ""}), o)

    def test_check_outcome_classes(self):
        self.assertEqual(O.check_outcome(O.ACCEPT, {"outcome": "OK"}), O.CORRECT)
        self.assertEqual(O.check_outcome(O.ACCEPT, {"outcome": O.REFUSED}), O.REFUSED)
        self.assertEqual(O.check_outcome(O.REFUSE_IFC, {"outcome": O.REFUSED, "ifc_errors": 1}), O.CORRECT)
        accepted = O.check_outcome(O.REFUSE_IFC, {"outcome": "OK"})
        other = O.check_outcome(O.REFUSE_IFC, {"outcome": O.REFUSED, "ifc_errors": 0})
        self.assertEqual(O.outcome_type(accepted), O.WRONG)
        self.assertEqual(O.outcome_type(other), O.WRONG)
        self.assertNotEqual(accepted, other)
        self.assertEqual(O.check_outcome(O.ACCEPT, {"outcome": O.TIMEOUT}), O.TIMEOUT)

    def test_expectation_round_trip(self):
        self.assertEqual(O.expected_of(O.expectation_text("ABORT", "x\n")), ("ABORT", "x\n"))

    def test_is_valid(self):
        self.assertTrue(O.is_valid("CORRECT"))
        self.assertTrue(O.is_valid("WRONG:" + "a" * 16))
        self.assertFalse(O.is_valid("WRONG"))
        self.assertFalse(O.is_valid("FIXED"))
        self.assertFalse(O.is_valid("BROKEN:x"))


if __name__ == "__main__":
    unittest.main()
