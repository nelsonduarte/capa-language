"""The register: member identity, the diff classes, the ratchet, the file."""

import json
import os
import tempfile
import unittest
from pathlib import Path

from tests.instruments import _register as R
from tests.instruments._outcome import CORRECT, wrong
from tests.instruments._private import ENV_VAR

INST = "absolute"
H1 = "0123456789abcdef"
H2 = "fedcba9876543210"
W_A = wrong(["OK", "a"])
W_B = wrong(["OK", "b"])


def _entry(outcome, **extra):
    e = {"outcome": outcome, "reason": "recorded", "closes_in": "step 2"}
    e.update(extra)
    return e


def _k(name, h, leg):
    return R.entry_key(INST, "%s#%s" % (name, h), leg)


class MemberIdentityTests(unittest.TestCase):
    def test_hash_is_line_ending_insensitive_and_content_sensitive(self):
        self.assertEqual(R.member_id("p.capa", "a\r\nb"), R.member_id("p.capa", "a\nb"))
        self.assertNotEqual(R.member_id("p.capa", "a"), R.member_id("p.capa", "a "))

    def test_split_round_trip(self):
        k = _k("p.capa", H1, "ir")
        inst, mid, leg = R.split_key(k)
        self.assertEqual((inst, leg), (INST, "ir"))
        self.assertEqual(R.split_member(mid), ("p.capa", H1))


class DiffTests(unittest.TestCase):
    def diff(self, entries, outcomes, legs=("ir",)):
        return R.diff(entries, INST, outcomes, legs)

    def test_green_when_every_registered_outcome_holds(self):
        reg = {_k("p.capa", H1, "ir"): _entry(W_A)}
        d = self.diff(reg, {("p.capa#" + H1, "ir"): W_A, ("q.capa#" + H2, "ir"): CORRECT})
        self.assertTrue(d.green, d.report())

    def test_fixed(self):
        d = self.diff({_k("p.capa", H1, "ir"): _entry(W_A)}, {("p.capa#" + H1, "ir"): CORRECT})
        self.assertEqual(d.counts()["FIXED"], 1)

    def test_changed(self):
        d = self.diff({_k("p.capa", H1, "ir"): _entry(W_A)}, {("p.capa#" + H1, "ir"): W_B})
        self.assertEqual(d.counts()["CHANGED"], 1)

    def test_new(self):
        d = self.diff({}, {("p.capa#" + H1, "ir"): W_A})
        self.assertEqual(d.counts()["NEW"], 1)

    def test_a_registered_wrong_that_stops_running_is_a_regression_never_fixed(self):
        for o in ("REFUSED", "TIMEOUT", "BROKEN", "VOID"):
            with self.subTest(outcome=o):
                d = self.diff({_k("p.capa", H1, "ir"): _entry(W_A)}, {("p.capa#" + H1, "ir"): o})
                self.assertEqual(d.counts()["REGRESSION"], 1, d.report())
                self.assertEqual(d.counts()["FIXED"], 0)

    def test_an_unregistered_not_run_outcome_is_a_regression(self):
        d = self.diff({}, {("p.capa#" + H1, "ir"): "TIMEOUT"})
        self.assertEqual(d.counts()["REGRESSION"], 1)

    def test_a_registered_broken_that_holds_is_green(self):
        d = self.diff({_k("p.capa", H1, "ir"): _entry("BROKEN")}, {("p.capa#" + H1, "ir"): "BROKEN"})
        self.assertTrue(d.green)

    def test_stale(self):
        d = self.diff({_k("p.capa", H1, "ir"): _entry(W_A)}, {})
        self.assertEqual(d.counts()["STALE"], 1)

    def test_regenerated_program_cannot_inherit_its_entry(self):
        # The same file name with a different program hash and the SAME
        # wrong outcome: the gate must not read this as GREEN.
        reg = {_k("p.capa", H1, "ir"): _entry(W_A)}
        d = self.diff(reg, {("p.capa#" + H2, "ir"): W_A})
        self.assertFalse(d.green)
        self.assertEqual(d.counts()["REGENERATED"], 1, d.report())
        self.assertEqual(d.counts()["NEW"], 1, d.report())

    def test_legs_not_run_are_not_judged(self):
        reg = {_k("p.capa", H1, "wasm"): _entry(W_A)}
        d = self.diff(reg, {("p.capa#" + H1, "ir"): CORRECT}, legs=("ir",))
        self.assertTrue(d.green, d.report())

    def test_other_instruments_are_not_judged(self):
        reg = {R.entry_key("other", "p.capa#" + H1, "ir"): _entry(W_A)}
        d = self.diff(reg, {("p.capa#" + H1, "ir"): CORRECT})
        self.assertTrue(d.green, d.report())


class RatchetTests(unittest.TestCase):
    def test_bootstrap_without_a_base(self):
        r = R.ratchet(None, {_k("p.capa", H1, "ir"): _entry(W_A)})
        self.assertTrue(r.green)
        self.assertTrue(r.bootstrap)

    def test_added_entry_is_red_whatever_the_counts(self):
        base = {_k(n, H1, "ir"): _entry(W_A) for n in ("a.capa", "b.capa", "c.capa")}
        cand = {_k("z.capa", H1, "ir"): _entry(W_A)}
        r = R.ratchet(base, cand)
        self.assertFalse(r.green, r.report())
        self.assertEqual(len(r.added), 1)
        self.assertEqual(len(r.removed), 3)

    def test_removed_entries_are_fine(self):
        base = {_k("a.capa", H1, "ir"): _entry(W_A), _k("b.capa", H1, "ir"): _entry(W_A)}
        r = R.ratchet(base, {_k("a.capa", H1, "ir"): _entry(W_A)})
        self.assertTrue(r.green)

    def test_redescribed_entry_is_red(self):
        base = {_k("a.capa", H1, "ir"): _entry(W_A)}
        r = R.ratchet(base, {_k("a.capa", H1, "ir"): _entry(W_B)})
        self.assertFalse(r.green)
        self.assertEqual(len(r.redescribed), 1)

    def test_reveal_broken_to_wrong_is_accepted_only_when_declared(self):
        base = {_k("a.capa", H1, "ir"): _entry("BROKEN")}
        undeclared = R.ratchet(base, {_k("a.capa", H1, "ir"): _entry(W_A)})
        self.assertFalse(undeclared.green)
        declared = R.ratchet(base, {_k("a.capa", H1, "ir"): _entry(
            W_A, accepted_as="REVEAL", from_outcome="BROKEN", reason="the gap closed; the wrong answer underneath")})
        self.assertTrue(declared.green, declared.report())
        self.assertEqual(len(declared.accepted), 1)
        wrong_from = R.ratchet(base, {_k("a.capa", H1, "ir"): _entry(
            W_A, accepted_as="REVEAL", from_outcome="TIMEOUT", reason="x")})
        self.assertFalse(wrong_from.green)
        not_from_broken = R.ratchet({_k("a.capa", H1, "ir"): _entry(W_B)}, {_k("a.capa", H1, "ir"): _entry(
            W_A, accepted_as="REVEAL", from_outcome=W_B, reason="x")})
        self.assertFalse(not_from_broken.green)

    def test_regenerated_entry_is_accepted_only_when_it_names_its_predecessor(self):
        base = {_k("a.capa", H1, "ir"): _entry(W_A)}
        undeclared = R.ratchet(base, {_k("a.capa", H2, "ir"): _entry(W_A)})
        self.assertFalse(undeclared.green)
        declared = R.ratchet(base, {_k("a.capa", H2, "ir"): _entry(
            W_A, accepted_as="REGENERATED", from_member=_k("a.capa", H1, "ir"), reason="generator change")})
        self.assertTrue(declared.green, declared.report())
        other_outcome = R.ratchet(base, {_k("a.capa", H2, "ir"): _entry(
            W_B, accepted_as="REGENERATED", from_member=_k("a.capa", H1, "ir"), reason="generator change")})
        self.assertFalse(other_outcome.green)
        other_file = R.ratchet(base, {_k("b.capa", H2, "ir"): _entry(
            W_A, accepted_as="REGENERATED", from_member=_k("a.capa", H1, "ir"), reason="generator change")})
        self.assertFalse(other_file.green)


class FileTests(unittest.TestCase):
    def test_public_register_loads_and_validates(self):
        entries = R.load(R.PUBLIC_REGISTER)
        self.assertIsInstance(entries, dict)
        for k in entries:
            R.split_key(k)

    def test_correct_entries_are_rejected(self):
        with self.assertRaises(ValueError):
            R.validate({_k("a.capa", H1, "ir"): _entry(CORRECT)})

    def test_vectors_must_key_to_the_outcome(self):
        vectors = {"run": ["OK", "1\n"], "ir": ["OK", "1\n"], "wasm": ["OK", "2\n"]}
        good = {_k("a.capa", H1, "three_backends"): _entry(wrong(R.composite_vector(vectors)), vectors=vectors)}
        R.validate(good)
        bad = {_k("a.capa", H1, "three_backends"): _entry(W_A, vectors=vectors)}
        with self.assertRaises(ValueError):
            R.validate(bad)

    def test_save_then_load(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "r.json"
            entries = {_k("a.capa", H1, "ir"): _entry(W_A)}
            R.save(p, entries)
            self.assertEqual(R.load(p), entries)
            doc = json.loads(p.read_text(encoding="utf-8"))
            self.assertEqual(doc["format"], R.FORMAT)

    def test_merged_rejects_a_key_in_both_registers(self):
        with tempfile.TemporaryDirectory() as d:
            pub = Path(d) / "pub.json"
            priv = Path(d) / "priv"
            priv.mkdir()
            entries = {_k("a.capa", H1, "ir"): _entry(W_A)}
            R.save(pub, entries)
            R.save(priv / R.PRIVATE_REGISTER_NAME, entries)
            saved = os.environ.get(ENV_VAR)
            os.environ[ENV_VAR] = str(priv)
            try:
                with self.assertRaises(ValueError):
                    R.load_merged(pub)
            finally:
                if saved is None:
                    del os.environ[ENV_VAR]
                else:
                    os.environ[ENV_VAR] = saved


if __name__ == "__main__":
    unittest.main()
