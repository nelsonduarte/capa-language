"""Tests for the Fs read/write TOCTOU hardening (post-open handle
verification, ``capa.runtime._fs_guard``).

The attack being closed: ``Fs.allows()`` resolves the path and
checks prefixes, then ``open()`` runs; an attacker who swaps a
symlink in between lands the handle outside the sandbox. The fix
re-validates the kernel-reported true path of the already-open
handle before any byte moves.

The race itself is simulated deterministically: ``Fs.allows`` is
monkeypatched to return ``True`` (the state the attacker would
have created at pre-check time), and the test then asserts that
the post-open verification still denies the out-of-prefix target.
This needs no symlinks, so the core denial tests run on Windows
too; the symlink-shaped variants carry the same POSIX skip guard
used elsewhere in the suite (Windows symlink creation needs
privileges).
"""

import io
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from capa.runtime import Fs, Ok, Err
from capa.runtime import _fs_guard
from tests._posix_probe import symlinks_available


def _handle_paths_supported() -> bool:
    """True when this platform can resolve the true path of an open
    fd (all three CI platforms can; the guard degrades to the old
    pre-check-only behaviour elsewhere)."""
    with tempfile.NamedTemporaryFile() as tf:
        return _fs_guard.fd_true_path(tf.fileno()) is not None


class TestFdTruePath(unittest.TestCase):
    """Unit tests for the per-platform handle-path resolver."""

    def test_resolves_regular_file(self):
        with tempfile.TemporaryDirectory() as td:
            target = os.path.join(td, "plain.txt")
            with open(target, "w", encoding="utf-8") as f:
                f.write("x")
            fd = os.open(target, os.O_RDONLY | getattr(os, "O_BINARY", 0))
            try:
                true_path = _fs_guard.fd_true_path(fd)
            finally:
                os.close(fd)
            if true_path is None:
                if sys.platform in ("linux", "darwin", "win32"):
                    self.fail(
                        "fd_true_path returned None on a platform "
                        "that has a handle-path mechanism"
                    )
                self.skipTest("no handle-path mechanism on this platform")
            # Path equality is case-insensitive on Windows, which is
            # exactly the comparison semantics the guard itself uses.
            self.assertEqual(
                Path(true_path), Path(os.path.realpath(target)),
            )

    def test_resolves_symlink_to_target(self):
        if not symlinks_available():
            self.skipTest("symlinks not reliably available")
        with tempfile.TemporaryDirectory() as td:
            target = os.path.join(td, "real.txt")
            with open(target, "w", encoding="utf-8") as f:
                f.write("x")
            link = os.path.join(td, "alias")
            try:
                os.symlink(target, link)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation refused by OS")
            # Plain open (the guard's O_NOFOLLOW fallback path also
            # ends in a followed open): the handle must report the
            # *target*, not the link.
            fd = os.open(link, os.O_RDONLY)
            try:
                true_path = _fs_guard.fd_true_path(fd)
            finally:
                os.close(fd)
            if true_path is None:
                self.skipTest("no handle-path mechanism on this platform")
            self.assertEqual(
                Path(true_path), Path(os.path.realpath(target)),
            )


@unittest.skipUnless(
    _handle_paths_supported(),
    "platform has no handle-path mechanism; guard falls back to "
    "pre-open check only (documented residual)",
)
class TestPostOpenVerification(unittest.TestCase):
    """Deterministic race simulation: the pre-open ``allows()`` is
    forced to True (the attacker's pre-check-time view) and the
    post-open verification must still deny the out-of-prefix file.
    """

    def setUp(self):
        self.inside = tempfile.mkdtemp(prefix="capa-inside-")
        self.outside = tempfile.mkdtemp(prefix="capa-outside-")
        self.secret = os.path.join(self.outside, "secret.txt")
        with open(self.secret, "w", encoding="utf-8") as f:
            f.write("PRECIOUS DATA")
        self.fs = Fs().restrict_to(self.inside)

    def tearDown(self):
        shutil.rmtree(self.inside, ignore_errors=True)
        shutil.rmtree(self.outside, ignore_errors=True)

    def _race_won(self):
        """Context: pre-check passes everything, as if the attacker
        swapped the link after ``allows()`` resolved it in-prefix."""
        return mock.patch.object(Fs, "allows", lambda self, path: True)

    def test_read_outside_denied_by_post_check(self):
        with self._race_won():
            res = self.fs.read(self.secret)
        self.assertIsInstance(res, Err)
        self.assertIn("does not permit read", res.error.message)

    def test_write_outside_denied_and_target_not_truncated(self):
        # THE regression test: open(path, "w") truncates at the
        # syscall, so a naive post-check would verify an already
        # destroyed file. The guard opens without O_TRUNC and only
        # truncates after verification passes.
        with self._race_won():
            res = self.fs.write(self.secret, "evil")
        self.assertIsInstance(res, Err)
        self.assertIn("does not permit write", res.error.message)
        with open(self.secret, encoding="utf-8") as f:
            self.assertEqual(f.read(), "PRECIOUS DATA")

    def test_denial_message_matches_pre_check_denial(self):
        # Error semantics must be indistinguishable from the normal
        # pre-check deny: same IoError type, same message and cause.
        pre = self.fs.read(self.secret)  # ordinary deny
        with self._race_won():
            post = self.fs.read(self.secret)
        self.assertIsInstance(pre, Err)
        self.assertIsInstance(post, Err)
        self.assertEqual(pre.error, post.error)

    def test_unrestricted_fs_skips_the_guard(self):
        # Full-authority caps must not pay (or be affected by) the
        # verification at all.
        with mock.patch.object(
            _fs_guard, "open_verified_read",
            side_effect=AssertionError("guard must not run"),
        ), mock.patch.object(
            _fs_guard, "open_verified_write",
            side_effect=AssertionError("guard must not run"),
        ):
            fs = Fs()
            self.assertIsInstance(fs.read(self.secret), Ok)
            self.assertIsInstance(fs.write(self.secret, "PRECIOUS DATA"), Ok)

    def test_write_to_missing_outside_path_never_lands_content(self):
        ghost = os.path.join(self.outside, "ghost.txt")
        with self._race_won():
            res = self.fs.write(ghost, "evil")
        self.assertIsInstance(res, Err)
        # Documented residual: the open may have created the file,
        # but no byte of content may ever land in it.
        if os.path.exists(ghost):
            self.assertEqual(os.path.getsize(ghost), 0)


@unittest.skipUnless(
    _handle_paths_supported(),
    "platform has no handle-path mechanism",
)
class TestSymlinkSwap(unittest.TestCase):
    """Symlink-shaped variants of the race (POSIX-only)."""

    def setUp(self):
        if not symlinks_available():
            self.skipTest("symlinks not reliably available")
        self.inside = tempfile.mkdtemp(prefix="capa-inside-")
        self.outside = tempfile.mkdtemp(prefix="capa-outside-")
        self.secret = os.path.join(self.outside, "secret.txt")
        with open(self.secret, "w", encoding="utf-8") as f:
            f.write("PRECIOUS DATA")
        self.fs = Fs().restrict_to(self.inside)

    def tearDown(self):
        shutil.rmtree(self.inside, ignore_errors=True)
        shutil.rmtree(self.outside, ignore_errors=True)

    def test_final_component_swapped_link_read_denied(self):
        # The on-disk state the attacker creates after winning the
        # pre-check: an in-prefix name that is now a link out.
        link = os.path.join(self.inside, "data.txt")
        try:
            os.symlink(self.secret, link)
        except (OSError, NotImplementedError):
            self.skipTest("symlink creation refused by OS")
        with mock.patch.object(Fs, "allows", lambda self, path: True):
            res = self.fs.read(link)
        self.assertIsInstance(res, Err)
        self.assertIn("does not permit read", res.error.message)

    def test_final_component_swapped_link_write_keeps_target_intact(self):
        link = os.path.join(self.inside, "data.txt")
        try:
            os.symlink(self.secret, link)
        except (OSError, NotImplementedError):
            self.skipTest("symlink creation refused by OS")
        with mock.patch.object(Fs, "allows", lambda self, path: True):
            res = self.fs.write(link, "evil")
        self.assertIsInstance(res, Err)
        with open(self.secret, encoding="utf-8") as f:
            self.assertEqual(f.read(), "PRECIOUS DATA")

    def test_intermediate_component_swapped_dir_denied(self):
        # inside/sub is swapped for a link to the outside directory;
        # the queried path's final component is a regular file, so
        # O_NOFOLLOW alone would not catch this. Only the post-open
        # handle check does.
        sub = os.path.join(self.inside, "sub")
        try:
            os.symlink(self.outside, sub)
        except (OSError, NotImplementedError):
            self.skipTest("symlink creation refused by OS")
        victim = os.path.join(sub, "secret.txt")
        with mock.patch.object(Fs, "allows", lambda self, path: True):
            read_res = self.fs.read(victim)
            write_res = self.fs.write(victim, "evil")
        self.assertIsInstance(read_res, Err)
        self.assertIsInstance(write_res, Err)
        with open(self.secret, encoding="utf-8") as f:
            self.assertEqual(f.read(), "PRECIOUS DATA")

    def test_legitimate_in_prefix_symlink_still_works(self):
        # Functional behaviour preserved: a link whose target is
        # inside the prefix reads and writes normally on a
        # restricted cap (the O_NOFOLLOW defence retries without
        # the flag and the post-check passes).
        real = os.path.join(self.inside, "real.txt")
        with open(real, "w", encoding="utf-8") as f:
            f.write("inside")
        link = os.path.join(self.inside, "alias")
        try:
            os.symlink(real, link)
        except (OSError, NotImplementedError):
            self.skipTest("symlink creation refused by OS")
        res = self.fs.read(link)
        self.assertIsInstance(res, Ok)
        self.assertEqual(res.value, "inside")
        self.assertIsInstance(self.fs.write(link, "updated"), Ok)
        with open(real, encoding="utf-8") as f:
            self.assertEqual(f.read(), "updated")


class TestRestrictedWriteSemantics(unittest.TestCase):
    """The guarded write path (open-without-trunc + ftruncate) must
    be observationally identical to ``open(path, "w")``."""

    def test_overwrite_with_shorter_content_truncates(self):
        # Catches a missing ftruncate: without it the second, shorter
        # write would leave a tail of the first.
        with tempfile.TemporaryDirectory() as td:
            fs = Fs().restrict_to(td)
            target = os.path.join(td, "f.txt")
            self.assertIsInstance(fs.write(target, "a much longer body"), Ok)
            self.assertIsInstance(fs.write(target, "x"), Ok)
            self.assertEqual(fs.read(target).value, "x")

    def test_write_creates_new_file(self):
        with tempfile.TemporaryDirectory() as td:
            fs = Fs().restrict_to(td)
            target = os.path.join(td, "new.txt")
            self.assertIsInstance(fs.write(target, "fresh"), Ok)
            self.assertEqual(fs.read(target).value, "fresh")

    def test_utf8_and_newlines_match_plain_open(self):
        # Restricted (guarded fdopen) and unrestricted (plain open)
        # paths must produce byte-identical files and identical
        # read-back for non-ASCII text and newlines.
        content = "olá\nmundo ünïcødé\n"
        with tempfile.TemporaryDirectory() as td:
            guarded = os.path.join(td, "guarded.txt")
            plain = os.path.join(td, "plain.txt")
            self.assertIsInstance(
                Fs().restrict_to(td).write(guarded, content), Ok,
            )
            self.assertIsInstance(Fs().write(plain, content), Ok)
            with open(guarded, "rb") as f:
                guarded_bytes = f.read()
            with open(plain, "rb") as f:
                plain_bytes = f.read()
            self.assertEqual(guarded_bytes, plain_bytes)
            self.assertEqual(Fs().restrict_to(td).read(guarded).value, content)

    def test_read_missing_file_still_oserror_err(self):
        with tempfile.TemporaryDirectory() as td:
            fs = Fs().restrict_to(td)
            res = fs.read(os.path.join(td, "absent.txt"))
            self.assertIsInstance(res, Err)
            self.assertIn("failed to read", res.error.message)


def _has_wasm_tools() -> bool:
    return shutil.which("wasm-tools") is not None


def _has_wasmtime_py() -> bool:
    try:
        import wasmtime  # noqa: F401
        return True
    except ImportError:
        return False


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
@unittest.skipUnless(
    _handle_paths_supported(),
    "platform has no handle-path mechanism",
)
class TestWasmHostPostCheck(unittest.TestCase):
    """The core-Wasm host shims route file IO through the same
    ``Fs._open_read`` / ``Fs._open_write`` as the Python backend,
    so the post-open verification covers the Wasm backend too. This
    test runs a compiled Wasm program against the in-process host
    with the pre-check forced open (race won) and asserts the
    post-open check still denies."""

    def _run_blob(self, src: str) -> str:
        from capa import Lexer, Parser, analyze
        from capa.ir import compile_wasm
        from capa.runtime._wasm_host import WasmHost

        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        if not result.ok:
            raise AssertionError(f"analyzer errors: {result.errors}")
        blob = compile_wasm(module, types=result.types)
        host = WasmHost()
        out = io.StringIO()
        saved = sys.stdout
        sys.stdout = out
        try:
            host.run_main(blob)
        finally:
            sys.stdout = saved
        return out.getvalue()

    def test_wasm_restricted_read_outside_denied_post_open(self):
        with tempfile.TemporaryDirectory() as inside, \
                tempfile.TemporaryDirectory() as outside:
            secret = os.path.join(outside, "secret.txt")
            with open(secret, "w", encoding="utf-8") as f:
                f.write("PRECIOUS DATA")
            prefix = inside.replace("\\", "/")
            target = secret.replace("\\", "/")
            src = (
                "fun main(stdio: Stdio, fs: Fs)\n"
                f"    let inner = fs.restrict_to(\"{prefix}\")\n"
                f"    match inner.read(\"{target}\")\n"
                "        Ok(_) -> stdio.println(\"BUG-allowed\")\n"
                "        Err(_) -> stdio.println(\"denied\")\n"
            )
            with mock.patch.object(Fs, "allows", lambda self, path: True):
                output = self._run_blob(src)
            self.assertEqual(output, "denied\n")
            with open(secret, encoding="utf-8") as f:
                self.assertEqual(f.read(), "PRECIOUS DATA")

    def test_wasm_restricted_write_outside_denied_and_not_truncated(self):
        with tempfile.TemporaryDirectory() as inside, \
                tempfile.TemporaryDirectory() as outside:
            secret = os.path.join(outside, "secret.txt")
            with open(secret, "w", encoding="utf-8") as f:
                f.write("PRECIOUS DATA")
            prefix = inside.replace("\\", "/")
            target = secret.replace("\\", "/")
            src = (
                "fun main(stdio: Stdio, fs: Fs)\n"
                f"    let inner = fs.restrict_to(\"{prefix}\")\n"
                f"    match inner.write(\"{target}\", \"evil\")\n"
                "        Ok(_) -> stdio.println(\"BUG-allowed\")\n"
                "        Err(_) -> stdio.println(\"denied\")\n"
            )
            with mock.patch.object(Fs, "allows", lambda self, path: True):
                output = self._run_blob(src)
            self.assertEqual(output, "denied\n")
            with open(secret, encoding="utf-8") as f:
                self.assertEqual(f.read(), "PRECIOUS DATA")


if __name__ == "__main__":
    unittest.main()
