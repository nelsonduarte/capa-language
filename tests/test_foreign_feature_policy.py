"""Foreign components and the engine's Wasm feature allow-list, end to end.

Rule under test: a foreign component (``extern component X from ...``) that
uses a Wasm feature outside Capa's allow-list is refused when it is loaded,
with the ``ForeignDenied`` diagnostic (``could not load artifact``), on the
fuel-metered child engine and on the parent engine that ``--foreign-fuel 0``
reuses. The refusal is a one-line diagnostic: no traceback and no output from
the child. A component that stays inside the allow-list still runs, within
the foreign store limits: a child with a second memory loads (multi-memory is
on) and is refused by the default memory-count limit, and runs once the
memory ceiling is opted out.

The children are the benign probes in ``tests/_wasm_feature_probes.py``.
Each program runs in its own ``capa`` process, as a user would run it, and
the assertions read its exit code, its diagnostic and its output.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from capa.cli import _wasm_tooling_available

from tests._wasm_feature_probes import (
    COMPOSED_CHILDREN, EXPECTED_ON, FOREIGN_CHILDREN,
)

_REPO_ROOT = Path(__file__).resolve().parent.parent

_PROG = (
    'extern component Bureau from "child.wasm"\n'
    "    fun submit(x: Int) -> Int\n"
    "\n"
    "fun main(stdio: Stdio)\n"
    "    let r = Bureau.submit(41)\n"
    '    stdio.println("result=${r}")\n'
)

_DIAGNOSTIC = "foreign component Bureau.submit:"
_REFUSAL = f"{_DIAGNOSTIC} could not load artifact"
_OVER_LIMIT = f"{_DIAGNOSTIC} exceeded its memory / resource limit"
_NO_MEMORY_CAP = ("--foreign-memory-cap", "0")


def _stage(td: str, text: str) -> Path:
    import wasmtime
    (Path(td) / "child.wasm").write_bytes(wasmtime.wat2wasm(text))
    prog = Path(td) / "prog.capa"
    prog.write_text(_PROG, encoding="utf-8")
    return prog


def _run_child_process(argv, cwd):
    proc = subprocess.run(
        [sys.executable, "-m", "capa", *argv],
        cwd=str(cwd), capture_output=True, text=True, encoding="utf-8",
        stdin=subprocess.DEVNULL, timeout=120,
        env={**os.environ, "PYTHONPATH": str(_REPO_ROOT)},
    )
    return proc.returncode, proc.stdout, proc.stderr


def _run_text(text, extra=()):
    with tempfile.TemporaryDirectory() as td:
        prog = _stage(td, text)
        return _run_child_process(["--wasm", "--run", *extra, str(prog)], td)


def _stderr_lines(err: str) -> list[str]:
    return [line for line in err.splitlines() if line.strip()]


@unittest.skipUnless(_wasm_tooling_available(), "wasm-tools / wasmtime missing")
class TestForeignFeaturePolicy(unittest.TestCase):

    def _run(self, child, extra=()):
        _rc, out, err = _run_text(FOREIGN_CHILDREN[child][1], extra)
        return out, err

    def _assert_refused(self, child, extra=()):
        out, err = self._run(child, extra)
        self.assertIn(_REFUSAL, err, f"{child}: {err[-600:]}")
        self.assertNotIn("result=", out, child)
        self.assertNotIn("Traceback (most recent call last)", err, child)

    def test_children_outside_the_allow_list_are_refused(self):
        for child in sorted(FOREIGN_CHILDREN):
            feature = FOREIGN_CHILDREN[child][0]
            if child == "plain" or feature in EXPECTED_ON:
                continue
            with self.subTest(child=child, feature=feature):
                self._assert_refused(child)

    def test_children_inside_the_allow_list_meet_the_store_limits(self):
        # The feature is on, so the child loads; the default foreign
        # limits allow one memory, so a second one is refused when the
        # store instantiates it, and runs with the ceiling opted out.
        inside = sorted(
            c for c, (feature, _text) in FOREIGN_CHILDREN.items()
            if feature in EXPECTED_ON
        )
        self.assertEqual(inside, ["multi_memory"])
        for child in inside:
            with self.subTest(child=child, limits="default"):
                out, err = self._run(child)
                self.assertIn(_OVER_LIMIT, err, err[-600:])
                self.assertNotIn(_REFUSAL, err)
                self.assertNotIn("result=", out)
                self.assertNotIn("Traceback (most recent call last)", err)
            with self.subTest(child=child, limits="memory cap off"):
                out, err = self._run(child, _NO_MEMORY_CAP)
                self.assertIn("result=42", out, err[-600:])

    def test_refused_on_the_parent_engine_too(self):
        # --foreign-fuel 0 runs the child on the parent's engine.
        for child in ("exceptions", "simd", "async_lift"):
            with self.subTest(child=child):
                self._assert_refused(child, ("--foreign-fuel", "0"))

    def test_child_inside_the_allow_list_still_runs(self):
        for extra in ((), ("--foreign-fuel", "0")):
            with self.subTest(extra=extra):
                out, err = self._run("plain", extra)
                self.assertIn("result=42", out, err)


@unittest.skipUnless(_wasm_tooling_available(), "wasm-tools / wasmtime missing")
class TestComposedChildren(unittest.TestCase):
    """A child composed from two components that each own a memory, passing
    a string or a list between them. Under the default foreign limits it is
    refused with the one-line foreign diagnostic (exit 1); with the memory
    ceiling opted out it runs (exit 0)."""

    def test_default_limits(self):
        for child, text in sorted(COMPOSED_CHILDREN.items()):
            with self.subTest(child=child):
                rc, out, err = _run_text(text)
                self.assertIn(rc, (0, 1), err[-400:])
                lines = _stderr_lines(err)
                if rc == 0:
                    self.assertIn("result=", out)
                    self.assertEqual(lines, [], err[-400:])
                else:
                    self.assertEqual(len(lines), 1, err[-400:])
                    self.assertTrue(
                        lines[0].startswith(f"capa: {_DIAGNOSTIC}"),
                        err[-400:],
                    )

    def test_memory_cap_opt_out_runs(self):
        for child, text in sorted(COMPOSED_CHILDREN.items()):
            with self.subTest(child=child):
                rc, out, err = _run_text(text, _NO_MEMORY_CAP)
                self.assertEqual(rc, 0, err[-400:])
                self.assertIn("result=46", out)
                self.assertEqual(_stderr_lines(err), [], err[-400:])


if __name__ == "__main__":
    unittest.main()
