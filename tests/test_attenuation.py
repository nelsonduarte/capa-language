"""Tests for capability attenuation: ``Fs.restrict_to(prefix)``,
``Env.restrict_to_keys([...])``, and the already-implemented
``Net.restrict_to(host)``.

These are runtime-level unit tests on the capability objects
themselves — they exercise the narrowing logic, the
information-hiding properties (denied access looks like absent
data), and the monotonic intersection guarantee.

Tests that exercise the same features from inside a Capa
program (declarations, attenuation in the program body) live in
``test_transpiler.py``.
"""

import os
import tempfile
import unittest

import time

from capa.runtime import Fs, Env, Net, Clock, Ok, Err, None_


# =============================================================
# Fs attenuation
# =============================================================

class TestFsAttenuation(unittest.TestCase):
    def test_unrestricted_allows_everything(self):
        fs = Fs()
        self.assertTrue(fs.allows("/anywhere"))
        self.assertTrue(fs.allows("/etc/passwd"))
        self.assertTrue(fs.allows("relative/path"))

    def test_restrict_narrows_to_prefix(self):
        fs = Fs().restrict_to("/tmp/")
        self.assertTrue(fs.allows("/tmp/foo"))
        self.assertTrue(fs.allows("/tmp/foo/bar"))
        self.assertFalse(fs.allows("/etc/passwd"))

    def test_chained_restrict_narrows_further(self):
        fs = Fs().restrict_to("/tmp/").restrict_to("/tmp/myapp/")
        self.assertTrue(fs.allows("/tmp/myapp/x"))
        self.assertFalse(fs.allows("/tmp/other"))

    def test_conflicting_restrict_yields_empty_authority(self):
        # /tmp/ AND /etc/ — no path can satisfy both, so the result
        # is an Fs that allows nothing.
        fs = Fs().restrict_to("/tmp/").restrict_to("/etc/")
        self.assertFalse(fs.allows("/tmp/x"))
        self.assertFalse(fs.allows("/etc/x"))
        self.assertFalse(fs.allows("/var/x"))

    def test_restrict_returns_fresh_instance(self):
        fs1 = Fs()
        fs2 = fs1.restrict_to("/tmp/")
        self.assertIsNot(fs1, fs2)
        # The original is untouched (no aliasing of restrictions).
        self.assertTrue(fs1.allows("/etc"))
        self.assertFalse(fs2.allows("/etc"))

    def test_read_denied_returns_err_without_touching_disk(self):
        fs = Fs().restrict_to("/tmp/")
        # /etc/passwd may or may not exist on this system. The point
        # is that a denied path returns Err *before* any open() call,
        # so the test passes uniformly regardless of platform.
        result = fs.read("/etc/passwd")
        self.assertIsInstance(result, Err)
        self.assertIn("does not permit", str(result.error))

    def test_read_allowed_path_works(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False, encoding="utf-8"
        ) as tf:
            tf.write("hello attenuation")
            path = tf.name
        try:
            prefix = os.path.dirname(path) + os.sep
            fs = Fs().restrict_to(prefix)
            r = fs.read(path)
            self.assertIsInstance(r, Ok)
            self.assertEqual(r.value, "hello attenuation")
        finally:
            os.unlink(path)

    def test_write_denied_returns_err(self):
        fs = Fs().restrict_to("/tmp/")
        r = fs.write("/etc/should-not-write", "x")
        self.assertIsInstance(r, Err)

    def test_exists_denied_returns_false_not_leaking_presence(self):
        # Even if the file actually exists, a denied Fs should report
        # False — otherwise it leaks the existence of paths outside
        # its allowed set.
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            outside_path = tf.name
        try:
            fs = Fs().restrict_to("/tmp/this-prefix-does-not-cover-tempfile/")
            self.assertFalse(fs.exists(outside_path))
        finally:
            os.unlink(outside_path)


# =============================================================
# Env attenuation
# =============================================================

class TestEnvAttenuation(unittest.TestCase):
    def test_unrestricted_allows_any_key(self):
        env = Env()
        self.assertTrue(env.allows("ANY_KEY"))
        self.assertTrue(env.allows("SECRET_PASSWORD"))

    def test_restrict_narrows_to_listed_keys(self):
        env = Env().restrict_to_keys(["HOME", "PATH"])
        self.assertTrue(env.allows("HOME"))
        self.assertTrue(env.allows("PATH"))
        self.assertFalse(env.allows("SECRET"))

    def test_chained_restrict_intersects_keys(self):
        env = Env().restrict_to_keys(["HOME", "PATH", "USER"])
        env = env.restrict_to_keys(["HOME", "OTHER"])
        # Intersection: only HOME survives.
        self.assertTrue(env.allows("HOME"))
        self.assertFalse(env.allows("PATH"))
        self.assertFalse(env.allows("USER"))
        self.assertFalse(env.allows("OTHER"))

    def test_restrict_returns_fresh_instance(self):
        env1 = Env()
        env2 = env1.restrict_to_keys(["HOME"])
        self.assertIsNot(env1, env2)
        self.assertTrue(env1.allows("WHATEVER"))
        self.assertFalse(env2.allows("WHATEVER"))

    def test_get_denied_returns_none_not_leaking_presence(self):
        os.environ["CAPA_TEST_VAR"] = "secret"
        try:
            env = Env().restrict_to_keys(["UNRELATED_KEY"])
            # Denied: get returns the None_ singleton — identical to
            # the result the caller would see for a missing variable.
            # This is the information-hiding property: the Env cap
            # does not leak the existence of variables outside its
            # allowed set.
            self.assertIs(env.get("CAPA_TEST_VAR"), None_)
            self.assertFalse(env.get("CAPA_TEST_VAR").is_some())
        finally:
            del os.environ["CAPA_TEST_VAR"]

    def test_get_allowed_returns_value(self):
        os.environ["CAPA_TEST_VAR"] = "shown"
        try:
            env = Env().restrict_to_keys(["CAPA_TEST_VAR"])
            v = env.get("CAPA_TEST_VAR")
            self.assertTrue(v.is_some())
            self.assertEqual(v.value, "shown")
        finally:
            del os.environ["CAPA_TEST_VAR"]

    def test_accepts_capalist_input(self):
        # The Capa surface passes keys as a Capa list; the runtime
        # should accept any iterable so the bridge is transparent.
        from capa.runtime import CapaList
        env = Env().restrict_to_keys(CapaList(["HOME", "PATH"]))
        self.assertTrue(env.allows("HOME"))
        self.assertFalse(env.allows("SECRET"))


# =============================================================
# Clock attenuation
# =============================================================

class TestClockAttenuation(unittest.TestCase):
    def test_unrestricted_allows(self):
        self.assertTrue(Clock().allows())

    def test_past_threshold_allows_now(self):
        # Threshold one second in the past: the cap is already
        # active.
        c = Clock().restrict_to_after(time.time() - 1)
        self.assertTrue(c.allows())

    def test_future_threshold_denies_now(self):
        # Threshold an hour in the future: the cap is not yet
        # active.
        c = Clock().restrict_to_after(time.time() + 3600)
        self.assertFalse(c.allows())

    def test_chained_restrict_takes_max(self):
        c1 = Clock().restrict_to_after(1000.0)
        c2 = c1.restrict_to_after(2000.0)
        # 2000 is the more restrictive threshold.
        self.assertEqual(c2._not_before, 2000.0)

    def test_chained_restrict_never_widens(self):
        c1 = Clock().restrict_to_after(1000.0)
        c2 = c1.restrict_to_after(500.0)
        # A lower threshold cannot widen authority; the existing
        # 1000 stays.
        self.assertEqual(c2._not_before, 1000.0)

    def test_restrict_returns_fresh_instance(self):
        c1 = Clock()
        c2 = c1.restrict_to_after(time.time() + 60)
        self.assertIsNot(c1, c2)
        self.assertTrue(c1.allows())
        self.assertFalse(c2.allows())

    def test_sleep_is_noop_when_denied(self):
        c = Clock().restrict_to_after(time.time() + 3600)
        start = time.monotonic()
        c.sleep(2.0)
        # The denied sleep returns immediately, so wall time
        # elapsed is well under the requested sleep duration.
        self.assertLess(time.monotonic() - start, 0.2)

    def test_sleep_works_when_allowed(self):
        # An unrestricted Clock sleeps normally. Use a short
        # duration so the test stays fast.
        c = Clock()
        start = time.monotonic()
        c.sleep(0.05)
        self.assertGreaterEqual(time.monotonic() - start, 0.04)

    def test_now_secs_works_regardless(self):
        # now_secs is a query, not gated. A denied Clock still
        # reports the current time.
        c = Clock().restrict_to_after(time.time() + 3600)
        self.assertGreater(c.now_secs(), 0)


# =============================================================
# Net attenuation regression
# =============================================================

class TestNetAttenuationStillWorks(unittest.TestCase):
    """Light regression check: the Fs/Env work touched the runtime
    file. Make sure ``Net.restrict_to`` still behaves the same."""

    def test_net_restrict_to_intersects(self):
        n = Net().restrict_to("api.example.com")
        self.assertTrue(n.allows("api.example.com"))
        self.assertFalse(n.allows("evil.example.com"))

        n2 = n.restrict_to("other.example.com")
        # Intersection of {api.example.com} and {other.example.com}
        # is empty.
        self.assertFalse(n2.allows("api.example.com"))
        self.assertFalse(n2.allows("other.example.com"))


if __name__ == "__main__":
    unittest.main()
