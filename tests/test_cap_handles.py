"""Tests for the capability handle table foundation
(``capa.runtime._cap_handles``). Audit slice 25.1 (2026-05-30):
landing the foundation alone so the wiring slices (25.2 - 25.8)
have a stable target."""

import unittest

from capa.runtime._cap_handles import (
    CapHandleError,
    CapHandleTable,
    bootstrap_root_handles,
)
from capa.runtime._capabilities import (
    Clock,
    Env,
    Fs,
    Net,
    Random,
    Stdio,
    Unsafe,
)


class TestCapHandleTable(unittest.TestCase):

    def test_alloc_assigns_monotonic_handles_starting_at_one(self):
        # Handle 0 is reserved as the "no cap" sentinel; real
        # handles start at 1 and grow monotonically.
        t = CapHandleTable()
        h1 = t.alloc(Fs())
        h2 = t.alloc(Fs())
        h3 = t.alloc(Net())
        self.assertEqual([h1, h2, h3], [1, 2, 3])

    def test_lookup_returns_inserted_cap(self):
        t = CapHandleTable()
        fs = Fs()
        h = t.alloc(fs)
        self.assertIs(t.lookup(h, Fs), fs)

    def test_lookup_unknown_handle_raises(self):
        t = CapHandleTable()
        with self.assertRaises(CapHandleError) as ctx:
            t.lookup(999, Fs)
        self.assertIn("unknown capability handle", str(ctx.exception))

    def test_lookup_zero_sentinel_raises(self):
        # Handle 0 must never resolve to a real cap, even after a
        # full table fill - it's the "no cap" sentinel that catches
        # an emitter bug emitting a zero handle.
        t = CapHandleTable()
        t.alloc(Fs())
        with self.assertRaises(CapHandleError):
            t.lookup(0, Fs)

    def test_lookup_wrong_type_raises(self):
        # A Net handle passed where Fs is expected must fail loud
        # at the host bridge - quiet cross-cap escalation would be
        # a much worse failure mode than a runtime error.
        t = CapHandleTable()
        h = t.alloc(Net())
        with self.assertRaises(CapHandleError) as ctx:
            t.lookup(h, Fs)
        msg = str(ctx.exception)
        self.assertIn("resolves to Net", msg)
        self.assertIn("expected Fs", msg)

    def test_restrict_fs_intersects_with_parent(self):
        # restrict_to never widens authority. After two narrowing
        # steps, the resulting cap's allowed-prefix set is the
        # intersection (delegates to Fs.restrict_to's existing
        # monotonicity).
        t = CapHandleTable()
        root = t.alloc(Fs())
        narrow1 = t.restrict_fs(root, "/tmp/a")
        narrow2 = t.restrict_fs(narrow1, "/tmp/a/inner")
        n2 = t.lookup(narrow2, Fs)
        self.assertTrue(n2.allows("/tmp/a/inner/x.txt"))
        # Widening to a parent prefix from a child handle must NOT
        # restore the parent's broader authority - the intersection
        # ensures the child's restriction wins.
        widen_attempt = t.restrict_fs(narrow2, "/tmp/a")
        wa = t.lookup(widen_attempt, Fs)
        self.assertFalse(wa.allows("/tmp/a/outside_inner.txt"))

    def test_restrict_net_chains(self):
        # Net.allows takes a parsed hostname (Net.get does the
        # urlparse before the check). The handle table just hands
        # the restriction logic to Net.restrict_to; this confirms
        # the round-trip preserves Net's existing host-equality
        # semantics.
        t = CapHandleTable()
        root = t.alloc(Net())
        narrow = t.restrict_net(root, "api.example.com")
        n = t.lookup(narrow, Net)
        self.assertTrue(n.allows("api.example.com"))
        self.assertFalse(n.allows("attacker.invalid"))

    def test_restrict_env_chains_and_canonicalises(self):
        # Env case-insensitive on Windows (F4 fix); the handle
        # table delegates to Env.restrict_to_keys which already
        # canonicalises - confirm that survives the alloc round
        # trip.
        t = CapHandleTable()
        root = t.alloc(Env())
        h = t.restrict_env(root, ["NEVER_SET_KEY_12345"])
        env = t.lookup(h, Env)
        self.assertFalse(env.allows("PATH"))
        self.assertFalse(env.allows("path"))

    def test_bootstrap_root_handles(self):
        t = CapHandleTable()
        roots = bootstrap_root_handles(
            t, stdio=Stdio(), fs=Fs(), net=Net(), clock=Clock(),
            random=Random(seed=42), unsafe=Unsafe(),
        )
        # Only the caps that were passed are in the result.
        self.assertEqual(
            sorted(roots.keys()),
            ["clock", "fs", "net", "random", "stdio", "unsafe"],
        )
        # Handles are real (in the table) and type-correct.
        self.assertIsInstance(t.lookup(roots["stdio"], Stdio), Stdio)
        self.assertIsInstance(t.lookup(roots["fs"], Fs), Fs)
        self.assertIsInstance(t.lookup(roots["net"], Net), Net)
        # Absent caps are simply absent from the dict; the
        # discovery walker enforces that ``main`` doesn't ask for
        # them separately.
        self.assertNotIn("db", roots)
        self.assertNotIn("proc", roots)
        self.assertNotIn("env", roots)

    def test_table_len_reflects_allocations(self):
        t = CapHandleTable()
        self.assertEqual(len(t), 0)
        t.alloc(Fs())
        t.alloc(Net())
        t.restrict_fs(1, "/tmp")
        self.assertEqual(len(t), 3)


if __name__ == "__main__":
    unittest.main()
