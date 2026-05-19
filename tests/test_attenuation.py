"""Tests for capability attenuation: ``Fs.restrict_to(prefix)``,
``Env.restrict_to_keys([...])``, and the already-implemented
``Net.restrict_to(host)``.

These are runtime-level unit tests on the capability objects
themselves, they exercise the narrowing logic, the
information-hiding properties (denied access looks like absent
data), and the monotonic intersection guarantee.

Tests that exercise the same features from inside a Capa
program (declarations, attenuation in the program body) live in
``test_transpiler.py``.
"""

import os
import sys
import tempfile
import time
import unittest

from capa.runtime import Fs, Env, Net, Clock, Random, Ok, Err, None_


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
        # /tmp/ AND /etc/, no path can satisfy both, so the result
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
        # False, otherwise it leaks the existence of paths outside
        # its allowed set.
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            outside_path = tf.name
        try:
            fs = Fs().restrict_to("/tmp/this-prefix-does-not-cover-tempfile/")
            self.assertFalse(fs.exists(outside_path))
        finally:
            os.unlink(outside_path)


class TestFsDirectoryOps(unittest.TestCase):
    """``Fs.mkdir``, ``Fs.list_dir``, and ``Fs.is_dir`` round out the
    surface so a Capa program no longer has to shell out for the
    most common directory chores. All three honour the attenuation
    set; denied operations behave like the path is absent (in the
    case of the queries) or return ``Err`` (in the case of mkdir).
    """

    def test_mkdir_creates_directory(self):
        with tempfile.TemporaryDirectory() as base:
            fs = Fs().restrict_to(base)
            target = os.path.join(base, "new")
            r = fs.mkdir(target)
            self.assertIsInstance(r, Ok)
            self.assertTrue(os.path.isdir(target))

    def test_mkdir_is_idempotent(self):
        # Calling mkdir twice on the same path is not an error.
        # Useful for CI scripts that run capa install repeatedly.
        with tempfile.TemporaryDirectory() as base:
            fs = Fs().restrict_to(base)
            target = os.path.join(base, "again")
            self.assertIsInstance(fs.mkdir(target), Ok)
            self.assertIsInstance(fs.mkdir(target), Ok)

    def test_mkdir_creates_parents(self):
        # Mirrors os.makedirs(exist_ok=True): nested missing
        # parents are created in one call.
        with tempfile.TemporaryDirectory() as base:
            fs = Fs().restrict_to(base)
            nested = os.path.join(base, "a", "b", "c")
            self.assertIsInstance(fs.mkdir(nested), Ok)
            self.assertTrue(os.path.isdir(nested))

    def test_mkdir_denied_returns_err_before_touching_disk(self):
        with tempfile.TemporaryDirectory() as inside:
            fs = Fs().restrict_to(inside)
            with tempfile.TemporaryDirectory() as outside:
                target = os.path.join(outside, "should-not-exist")
                r = fs.mkdir(target)
                self.assertIsInstance(r, Err)
                self.assertFalse(os.path.exists(target))

    def test_list_dir_returns_sorted_entries(self):
        with tempfile.TemporaryDirectory() as base:
            for name in ("c.txt", "a.txt", "b.txt"):
                open(os.path.join(base, name), "w").close()
            fs = Fs().restrict_to(base)
            r = fs.list_dir(base)
            self.assertIsInstance(r, Ok)
            self.assertEqual(list(r.value), ["a.txt", "b.txt", "c.txt"])

    def test_list_dir_denied_returns_err_not_leak(self):
        with tempfile.TemporaryDirectory() as inside:
            fs = Fs().restrict_to(inside)
            with tempfile.TemporaryDirectory() as outside:
                r = fs.list_dir(outside)
                self.assertIsInstance(r, Err)

    def test_is_dir_distinguishes_files_and_directories(self):
        with tempfile.TemporaryDirectory() as base:
            file_path = os.path.join(base, "f.txt")
            open(file_path, "w").close()
            sub = os.path.join(base, "sub")
            os.mkdir(sub)
            fs = Fs().restrict_to(base)
            self.assertTrue(fs.is_dir(sub))
            self.assertFalse(fs.is_dir(file_path))
            self.assertFalse(fs.is_dir(os.path.join(base, "missing")))

    def test_is_dir_denied_reports_false_not_leak(self):
        # Same convention as exists(): denied is indistinguishable
        # from absent, so the cap cannot leak the existence of
        # paths outside its allowed set.
        with tempfile.TemporaryDirectory() as inside:
            fs = Fs().restrict_to(inside)
            with tempfile.TemporaryDirectory() as outside:
                self.assertFalse(fs.is_dir(outside))


class TestFsPathCanonicalisation(unittest.TestCase):
    """``Fs`` resolves both stored prefixes and queried paths through
    ``os.path.realpath`` before comparing. These tests cover the
    classic traversal + symlink bypasses against a plain string-
    prefix implementation.
    """

    def test_traversal_with_dot_dot_is_denied(self):
        # Prefix is the temp dir; query uses ``..`` to escape.
        # A naive ``path.startswith(prefix)`` would have allowed
        # this since the string does start with the prefix.
        with tempfile.TemporaryDirectory() as base:
            fs = Fs().restrict_to(base)
            escape = os.path.join(base, "..", "etc", "passwd")
            self.assertFalse(fs.allows(escape))

    def test_traversal_returning_to_prefix_is_allowed(self):
        # ``data/sub/../file`` resolves back to ``data/file`` which
        # is still inside the prefix.
        with tempfile.TemporaryDirectory() as base:
            sub = os.path.join(base, "sub")
            os.mkdir(sub)
            fs = Fs().restrict_to(base)
            round_trip = os.path.join(base, "sub", "..", "file.txt")
            self.assertTrue(fs.allows(round_trip))

    def test_symlink_pointing_outside_is_denied(self):
        # POSIX-only: Windows symlinks need admin rights in most
        # configurations, so skip there.
        if not hasattr(os, "symlink") or sys.platform.startswith("win"):
            self.skipTest("symlinks not reliably available")
        with tempfile.TemporaryDirectory() as base:
            target_dir = tempfile.mkdtemp(prefix="capa-outside-")
            target = os.path.join(target_dir, "secret.txt")
            with open(target, "w") as f:
                f.write("nope")
            link = os.path.join(base, "shortcut")
            try:
                os.symlink(target, link)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation refused by OS")
            try:
                fs = Fs().restrict_to(base)
                self.assertFalse(fs.allows(link))
                self.assertIsInstance(fs.read(link), Err)
            finally:
                os.unlink(link)
                os.unlink(target)
                os.rmdir(target_dir)

    def test_symlink_inside_prefix_is_allowed(self):
        if not hasattr(os, "symlink") or sys.platform.startswith("win"):
            self.skipTest("symlinks not reliably available")
        with tempfile.TemporaryDirectory() as base:
            real = os.path.join(base, "real.txt")
            with open(real, "w") as f:
                f.write("inside")
            link = os.path.join(base, "alias")
            try:
                os.symlink(real, link)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation refused by OS")
            try:
                fs = Fs().restrict_to(base)
                self.assertTrue(fs.allows(link))
                self.assertIsInstance(fs.read(link), Ok)
            finally:
                os.unlink(link)
                os.unlink(real)

    def test_prefix_normalises_trailing_separator(self):
        # ``data`` and ``data/`` should behave identically.
        with tempfile.TemporaryDirectory() as base:
            fs1 = Fs().restrict_to(base)
            fs2 = Fs().restrict_to(base + os.sep)
            target = os.path.join(base, "x.txt")
            self.assertEqual(fs1.allows(target), fs2.allows(target))
            self.assertTrue(fs1.allows(target))

    def test_relative_prefix_canonicalised_against_cwd(self):
        # A relative prefix is resolved relative to the cwd at the
        # moment of ``restrict_to``.
        cwd = os.getcwd()
        fs = Fs().restrict_to("subdir")
        self.assertTrue(fs.allows(os.path.join(cwd, "subdir", "file")))
        self.assertFalse(fs.allows(os.path.join(cwd, "other", "file")))


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
            # Denied: get returns the None_ singleton, identical to
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
# Random attenuation (deterministic seeding)
# =============================================================

class TestRandomAttenuation(unittest.TestCase):
    def test_seeded_random_is_deterministic(self):
        # Two Random instances seeded with the same value produce
        # the same first draw.
        a = Random().with_seed(42)
        b = Random().with_seed(42)
        self.assertEqual(a.int_range(0, 1000), b.int_range(0, 1000))

    def test_different_seeds_produce_different_sequences(self):
        a = Random().with_seed(1)
        b = Random().with_seed(2)
        seq_a = [a.int_range(0, 100) for _ in range(5)]
        seq_b = [b.int_range(0, 100) for _ in range(5)]
        # Almost certainly different; if this ever flakes the
        # RNG has bigger problems.
        self.assertNotEqual(seq_a, seq_b)

    def test_chained_with_seed_uses_last(self):
        # ``r.with_seed(1).with_seed(2)`` is effectively re-seeding;
        # the last seed wins (it just creates a fresh Random).
        chained = Random().with_seed(1).with_seed(2)
        direct = Random().with_seed(2)
        self.assertEqual(
            chained.int_range(0, 1000),
            direct.int_range(0, 1000),
        )

    def test_with_seed_returns_fresh_instance(self):
        r = Random()
        seeded = r.with_seed(7)
        self.assertIsNot(r, seeded)

    def test_unseeded_still_generates(self):
        # The default-constructed (unseeded) Random still produces
        # a value in the requested range; just not reproducibly.
        v = Random().int_range(10, 20)
        self.assertGreaterEqual(v, 10)
        self.assertLess(v, 20)


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
