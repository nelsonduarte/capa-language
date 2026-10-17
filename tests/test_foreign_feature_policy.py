"""Foreign components and the engine's Wasm feature allow-list, end to end.

Rule under test: a foreign component (``extern component X from ...``) that
uses a Wasm feature outside Capa's allow-list is refused when it is loaded,
with the ``ForeignDenied`` diagnostic (``could not load artifact``), on the
fuel-metered child engine and on the parent engine that ``--foreign-fuel 0``
reuses. The refusal is a one-line diagnostic: no traceback and no output from
the child. A component that stays inside the allow-list still runs.

The children are the benign probes in ``tests/_wasm_feature_probes.py``.
Each program runs in its own ``capa`` process, as a user would run it, and
the assertions read its diagnostic and its output.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from capa.cli import _wasm_tooling_available

from tests._wasm_feature_probes import FOREIGN_CHILDREN

_REPO_ROOT = Path(__file__).resolve().parent.parent

_PROG = (
    'extern component Bureau from "child.wasm"\n'
    "    fun submit(x: Int) -> Int\n"
    "\n"
    "fun main(stdio: Stdio)\n"
    "    let r = Bureau.submit(41)\n"
    '    stdio.println("result=${r}")\n'
)

_REFUSAL = "foreign component Bureau.submit: could not load artifact"


def _stage(td: str, child: str) -> Path:
    import wasmtime
    _feature, text = FOREIGN_CHILDREN[child]
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
    return proc.stdout, proc.stderr


@unittest.skipUnless(_wasm_tooling_available(), "wasm-tools / wasmtime missing")
class TestForeignFeaturePolicy(unittest.TestCase):

    def _run(self, child, extra=()):
        with tempfile.TemporaryDirectory() as td:
            prog = _stage(td, child)
            return _run_child_process(["--wasm", "--run", *extra, str(prog)], td)

    def _assert_refused(self, child, extra=()):
        out, err = self._run(child, extra)
        self.assertIn(_REFUSAL, err, f"{child}: {err[-600:]}")
        self.assertNotIn("result=", out, child)
        self.assertNotIn("Traceback (most recent call last)", err, child)

    def test_children_outside_the_allow_list_are_refused(self):
        for child in sorted(FOREIGN_CHILDREN):
            if child == "plain":
                continue
            with self.subTest(child=child, feature=FOREIGN_CHILDREN[child][0]):
                self._assert_refused(child)

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


if __name__ == "__main__":
    unittest.main()
