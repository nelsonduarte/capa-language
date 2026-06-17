"""Tests for the Db post-open TOCTOU hardening (symlink-swap race
between ``Db.allows`` and ``sqlite3.connect``).

The attack being closed: ``Db.allows()`` resolves the path with
``realpath`` and checks the prefixes, then ``sqlite3.connect``
reopens the *original* path; an attacker who swaps a symlink in
between lands SQLite on a file outside the sandbox. The fix opens
the file directly first (``_fs_guard.verify_path_open``) and
re-validates the kernel-reported true path of that handle against
the prefixes before SQLite connects.

The race is simulated deterministically: ``Db.allows`` is
monkeypatched to return ``True`` (the attacker's pre-check-time
view) and the test asserts the post-open verification still denies
the out-of-prefix target. The core denial tests need no symlinks
so they run on Windows too; the symlink-shaped variants carry the
same POSIX skip guard used in ``test_fs_toctou``.
"""

import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

from capa.runtime import Db, Ok, Err
from capa.runtime import _fs_guard


def _handle_paths_supported() -> bool:
    """True when this platform can resolve the true path of an open
    fd; the guard degrades to the pre-open check alone elsewhere."""
    with tempfile.NamedTemporaryFile() as tf:
        return _fs_guard.fd_true_path(tf.fileno()) is not None


def _symlinks_available() -> bool:
    # Same convention as test_fs_toctou: Windows symlinks need admin
    # rights in most configurations, so skip there.
    return hasattr(os, "symlink") and not sys.platform.startswith("win")


class TestLegitimateDbStillWorks(unittest.TestCase):
    """The guard must not break any in-prefix operation, including
    creating a brand-new ``.db`` (sqlite3.connect creates on open,
    and so does the verifying open)."""

    def setUp(self):
        self.inside = tempfile.mkdtemp(prefix="capa-db-inside-")

    def tearDown(self):
        shutil.rmtree(self.inside, ignore_errors=True)

    def test_create_new_db_in_prefix(self):
        db = Db().restrict_to(self.inside)
        path = os.path.join(self.inside, "fresh.db")
        self.assertFalse(os.path.exists(path))
        res = db.exec(path, "CREATE TABLE t(a); INSERT INTO t VALUES (1)")
        self.assertIsInstance(res, Ok)
        self.assertTrue(os.path.exists(path))

    def test_query_in_prefix(self):
        db = Db().restrict_to(self.inside)
        path = os.path.join(self.inside, "data.db")
        self.assertIsInstance(
            db.exec(path, "CREATE TABLE t(a); INSERT INTO t VALUES (7)"), Ok,
        )
        res = db.query(path, "SELECT a FROM t")
        self.assertIsInstance(res, Ok)
        self.assertEqual(res.value, '[["7"]]')

    def test_unrestricted_skips_guard(self):
        # A full-authority Db must not invoke the post-open verifier
        # at all.
        with mock.patch.object(
            _fs_guard, "verify_path_open",
            side_effect=AssertionError("guard must not run"),
        ):
            with tempfile.TemporaryDirectory() as outside:
                path = os.path.join(outside, "u.db")
                self.assertIsInstance(
                    Db().exec(path, "CREATE TABLE t(a)"), Ok,
                )


@unittest.skipUnless(
    _handle_paths_supported(),
    "platform has no handle-path mechanism; guard falls back to "
    "pre-open check only (documented residual)",
)
class TestPostOpenVerification(unittest.TestCase):
    """Deterministic race simulation: the pre-open ``allows()`` is
    forced True (the attacker's pre-check view) and the post-open
    verification must still deny the out-of-prefix file."""

    def setUp(self):
        self.inside = tempfile.mkdtemp(prefix="capa-db-inside-")
        self.outside = tempfile.mkdtemp(prefix="capa-db-outside-")
        self.secret = os.path.join(self.outside, "secret.db")
        # Seed a real SQLite file outside the prefix.
        Db().exec(self.secret, "CREATE TABLE s(x); INSERT INTO s VALUES (1)")
        self.db = Db().restrict_to(self.inside)

    def tearDown(self):
        shutil.rmtree(self.inside, ignore_errors=True)
        shutil.rmtree(self.outside, ignore_errors=True)

    def _race_won(self):
        return mock.patch.object(Db, "allows", lambda self, path: True)

    def test_exec_outside_denied_by_post_check(self):
        with self._race_won():
            res = self.db.exec(self.secret, "INSERT INTO s VALUES (2)")
        self.assertIsInstance(res, Err)
        self.assertIn("does not permit exec", res.error.message)

    def test_query_outside_denied_by_post_check(self):
        with self._race_won():
            res = self.db.query(self.secret, "SELECT x FROM s")
        self.assertIsInstance(res, Err)
        self.assertIn("does not permit query", res.error.message)

    def test_denial_message_matches_pre_check_denial(self):
        pre = self.db.query(self.secret, "SELECT x FROM s")  # ordinary deny
        with self._race_won():
            post = self.db.query(self.secret, "SELECT x FROM s")
        self.assertIsInstance(pre, Err)
        self.assertIsInstance(post, Err)
        self.assertEqual(pre.error, post.error)

    def test_exec_outside_does_not_mutate_target(self):
        # The out-of-prefix DB must be untouched: the verifying open
        # is read-create only and SQLite never connects on a denial.
        before = Db().query(self.secret, "SELECT x FROM s").value
        with self._race_won():
            self.db.exec(self.secret, "INSERT INTO s VALUES (99)")
        after = Db().query(self.secret, "SELECT x FROM s").value
        self.assertEqual(before, after)


@unittest.skipUnless(
    _handle_paths_supported(),
    "platform has no handle-path mechanism",
)
class TestSymlinkSwap(unittest.TestCase):
    """Symlink-shaped variants of the race (POSIX-only)."""

    def setUp(self):
        if not _symlinks_available():
            self.skipTest("symlinks not reliably available")
        self.inside = tempfile.mkdtemp(prefix="capa-db-inside-")
        self.outside = tempfile.mkdtemp(prefix="capa-db-outside-")
        self.secret = os.path.join(self.outside, "secret.db")
        Db().exec(self.secret, "CREATE TABLE s(x); INSERT INTO s VALUES (1)")
        self.db = Db().restrict_to(self.inside)

    def tearDown(self):
        shutil.rmtree(self.inside, ignore_errors=True)
        shutil.rmtree(self.outside, ignore_errors=True)

    def test_in_prefix_name_swapped_to_outside_link_denied(self):
        # The on-disk state the attacker creates after winning the
        # pre-check: an in-prefix name that is now a link out.
        link = os.path.join(self.inside, "data.db")
        try:
            os.symlink(self.secret, link)
        except (OSError, NotImplementedError):
            self.skipTest("symlink creation refused by OS")
        with mock.patch.object(Db, "allows", lambda self, path: True):
            res = self.db.query(link, "SELECT x FROM s")
        self.assertIsInstance(res, Err)
        self.assertIn("does not permit query", res.error.message)

    def test_intermediate_component_swapped_dir_denied(self):
        # inside/sub is swapped for a link to the outside directory;
        # the final component is a regular file, so only the
        # post-open handle check catches this.
        sub = os.path.join(self.inside, "sub")
        try:
            os.symlink(self.outside, sub)
        except (OSError, NotImplementedError):
            self.skipTest("symlink creation refused by OS")
        victim = os.path.join(sub, "secret.db")
        with mock.patch.object(Db, "allows", lambda self, path: True):
            res = self.db.exec(victim, "INSERT INTO s VALUES (2)")
        self.assertIsInstance(res, Err)

    def test_legitimate_in_prefix_symlink_still_works(self):
        # A link whose target is inside the prefix must read/write
        # normally on a restricted cap.
        real = os.path.join(self.inside, "real.db")
        self.assertIsInstance(
            self.db.exec(real, "CREATE TABLE t(a); INSERT INTO t VALUES (5)"),
            Ok,
        )
        link = os.path.join(self.inside, "alias.db")
        try:
            os.symlink(real, link)
        except (OSError, NotImplementedError):
            self.skipTest("symlink creation refused by OS")
        res = self.db.query(link, "SELECT a FROM t")
        self.assertIsInstance(res, Ok)
        self.assertEqual(res.value, '[["5"]]')


if __name__ == "__main__":
    unittest.main()
