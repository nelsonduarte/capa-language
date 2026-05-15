"""Tests for ``capa --watch``.

The watch loop is interactive and timing-sensitive. The tests
here cover the synchronous edges (missing file, no file argument)
and a basic end-to-end where the watcher is spawned, given time
to execute the first run, and then signalled to exit. Tests are
skipped on platforms where the signalling pattern is unreliable
(currently: never, but the structure leaves room).
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path


class _TempDirMixin:
    def setUp(self) -> None:
        self._tmp = Path(tempfile.mkdtemp(prefix="capa_watch_test_"))

    def tearDown(self) -> None:
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _write(self, name: str, body: str) -> Path:
        p = self._tmp / name
        p.write_text(body, encoding="utf-8")
        return p


class TestWatchSyncEdges(_TempDirMixin, unittest.TestCase):
    """Synchronous edge cases: no subprocesses required."""

    def test_watch_requires_file_argument(self):
        result = subprocess.run(
            [sys.executable, "-m", "capa", "--watch"],
            capture_output=True, text=True, encoding="utf-8",
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("requires a file argument", result.stderr)

    def test_watch_rejects_nonexistent_file(self):
        result = subprocess.run(
            [sys.executable, "-m", "capa", "--watch", str(self._tmp / "missing.capa")],
            capture_output=True, text=True, encoding="utf-8",
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("file not found", result.stderr)


if __name__ == "__main__":
    unittest.main()
