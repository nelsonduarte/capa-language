"""Feature #4 F2a: runtime sandbox enforcement of typed foreign
components for SCALAR crossing types (Int / Bool / Float).

The soundness increment. A ``Bureau.submit(net, x)`` call runs end-to-end
on the Wasm backend: the parent core module imports
``capa:foreign/Bureau`` and the host instantiates the external child
component with a RESTRICTED linker that binds ONLY the declared caps, so
the child physically cannot exceed the declared capability set. These
tests exercise the acceptance rows against hand-assembled fixture
components (see ``tests/fixtures/foreign/``):

- ``net_child.wasm`` imports ``capa:host/net`` and exports
  ``submit(x) = x + (allows("example.com")?1:0) + (allows("evil.com")?100:0)``.
  Backing a method that grants ``Net`` restricted to ``example.com``, it
  returns ``x + 1`` -- proving the host-bound Net is the caller's
  ATTENUATED cap (example.com allowed, evil.com denied, no widening).
- ``fs_child.wasm`` imports ``capa:host/fs``; backing a method that
  grants only ``Net`` it FAILS at instantiation (structural cap-set deny).
"""

from __future__ import annotations

import io
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from capa import Lexer, Parser, analyze
from capa.cli import _wasm_tooling_available, main
from capa.manifest import build_composed_sbom, build_manifest

_FIXTURES = Path(__file__).parent / "fixtures" / "foreign"


def _run_cli(argv, cwd):
    out, err = io.StringIO(), io.StringIO()
    patches = [
        mock.patch.object(sys, "argv", ["capa"] + list(argv)),
        mock.patch.object(sys, "stdout", out),
        mock.patch.object(sys, "stderr", err),
    ]
    original = os.getcwd()
    try:
        os.chdir(str(cwd))
        for p in patches:
            p.start()
        try:
            rc = main()
        except SystemExit as e:
            rc = e.code if isinstance(e.code, int) else (0 if e.code is None else 1)
        return rc, out.getvalue(), err.getvalue()
    finally:
        for p in reversed(patches):
            p.stop()
        os.chdir(original)


def _write(td: str, name: str, source: str) -> Path:
    p = Path(td) / name
    p.write_text(source, encoding="utf-8")
    return p


# A program calling a scalar foreign method backed by the net fixture,
# attenuating Net to example.com before the call and printing the result.
_NET_PROG = (
    'extern component Bureau from "net_child.wasm"\n'
    "    fun submit(net: Net, x: Int) -> Int\n"
    "\n"
    "fun main(net: Net, stdio: Stdio)\n"
    '    let safe = net.restrict_to("example.com")\n'
    "    let r = Bureau.submit(safe, 41)\n"
    '    stdio.println("result=${r}")\n'
)

# Same shape but backed by the fs fixture: the method grants only Net, so
# the fs-importing child must be denied at instantiation.
_FS_DENY_PROG = (
    'extern component Bad from "fs_child.wasm"\n'
    "    fun submit(net: Net, x: Int) -> Int\n"
    "\n"
    "fun main(net: Net)\n"
    "    let r = Bad.submit(net, 41)\n"
)

# A scalar foreign method (no aggregate) for the Python-backend + the
# --component guards.
_SCALAR_PROG = (
    'extern component Bureau from "net_child.wasm"\n'
    "    fun submit(net: Net, x: Int) -> Int\n"
    "\n"
    "fun main(net: Net) -> Int\n"
    "    return Bureau.submit(net, 41)\n"
)


@unittest.skipUnless(
    _wasm_tooling_available(), "wasm-tools / wasmtime missing",
)
class TestForeignScalarRuntime(unittest.TestCase):
    def test_scalar_foreign_call_runs_end_to_end(self):
        # The credibility row: a scalar foreign call runs on --wasm, the
        # result marshals back, and the host-bound Net is the caller's
        # ATTENUATED cap (submit returns 41 + 1[example.com allowed] +
        # 0[evil.com denied] = 42, proving no widening).
        with tempfile.TemporaryDirectory() as td:
            shutil.copy(_FIXTURES / "net_child.wasm", Path(td) / "net_child.wasm")
            p = _write(td, "prog.capa", _NET_PROG)
            rc, out, err = _run_cli(["--wasm", "--run", str(p)], cwd=td)
            self.assertEqual(rc, 0, err)
            self.assertIn("result=42", out)

    def test_bool_and_float_scalars_marshal(self):
        # Bool (i32 <-> bool) and Float (f64) crossing params + returns
        # marshal both directions. ``bf_child`` grants no caps: flip
        # negates a bool, scale doubles a float.
        prog = (
            'extern component BF from "bf_child.wasm"\n'
            "    fun flip(b: Bool) -> Bool\n"
            "    fun scale(f: Float) -> Float\n"
            "\n"
            "fun main(stdio: Stdio)\n"
            "    let r = BF.flip(true)\n"
            "    let s = BF.scale(2.5)\n"
            '    stdio.println("flip=${r} scale=${s}")\n'
        )
        with tempfile.TemporaryDirectory() as td:
            shutil.copy(_FIXTURES / "bf_child.wasm", Path(td) / "bf_child.wasm")
            p = _write(td, "prog.capa", prog)
            rc, out, err = _run_cli(["--wasm", "--run", str(p)], cwd=td)
            self.assertEqual(rc, 0, err)
            self.assertIn("flip=false", out)
            self.assertIn("scale=5", out)

    def test_ungranted_cap_fails_at_instantiation(self):
        # The structural host-enforced deny: the child imports
        # capa:host/fs but the method grants only Net, so instantiation
        # fails with a clean, actionable diagnostic (exit 1).
        with tempfile.TemporaryDirectory() as td:
            shutil.copy(_FIXTURES / "fs_child.wasm", Path(td) / "fs_child.wasm")
            p = _write(td, "prog.capa", _FS_DENY_PROG)
            rc, _out, err = _run_cli(["--wasm", "--run", str(p)], cwd=td)
            self.assertEqual(rc, 1)
            self.assertIn("instantiation denied", err)
            self.assertIn("capa:host/fs", err)

    def test_python_backend_requires_wasm(self):
        # A scalar foreign call on the Python backend is unsupported (the
        # Python backend cannot sandbox); clean "requires the Wasm
        # backend" error.
        with tempfile.TemporaryDirectory() as td:
            shutil.copy(_FIXTURES / "net_child.wasm", Path(td) / "net_child.wasm")
            p = _write(td, "prog.capa", _SCALAR_PROG)
            rc, _out, err = _run_cli(["--run", str(p)], cwd=td)
            self.assertEqual(rc, 1)
            self.assertIn("require the Wasm backend", err)

    def test_component_path_rejected(self):
        # F2a runs on the core --wasm path; the --component wrapping path
        # does not yet carry the capa:foreign imports.
        with tempfile.TemporaryDirectory() as td:
            shutil.copy(_FIXTURES / "net_child.wasm", Path(td) / "net_child.wasm")
            p = _write(td, "prog.capa", _SCALAR_PROG)
            rc, _out, err = _run_cli(
                ["--wasm", "--component", "--run", str(p)], cwd=td,
            )
            self.assertEqual(rc, 1)
            self.assertIn("core --wasm path", err)


class TestForeignSbomPosture(unittest.TestCase):
    """Item 5: the composed SBOM downgrades TOP -> BOUNDED ONLY under the
    Wasm-sandbox enforcement posture, never on the default / Python path."""

    def _compose(self, td: str, posture: str):
        (Path(td) / "capa.toml").write_text(
            '[package]\nname = "fdemo"\nversion = "0.1.0"\n', encoding="utf-8",
        )
        src = _SCALAR_PROG
        fp = str(Path(td) / "main.capa")
        toks = Lexer(src, filename="main.capa").lex()
        mod = Parser(toks, source=src, filename=fp).parse_module()
        res = analyze(mod, source=src, filename=fp)
        man = build_manifest(mod, filename=fp, expr_labels=res.expr_labels)
        return build_composed_sbom(mod, man, Path(td), enforcement=posture)

    def test_default_posture_is_top(self):
        with tempfile.TemporaryDirectory() as td:
            composed = self._compose(td, "none")
            pkg = composed["packages"][0]
            self.assertTrue(pkg["composed_authority_unknown"])
            self.assertEqual(composed["enforcement_posture"], "none")
            reasons = " ".join(
                r["reason"] for r in pkg["authority_unknown_reasons"]
            )
            self.assertIn("not runtime-enforced on this backend", reasons)

    def test_wasm_sandbox_posture_is_bounded(self):
        with tempfile.TemporaryDirectory() as td:
            composed = self._compose(td, "wasm-sandbox")
            pkg = composed["packages"][0]
            self.assertFalse(pkg["composed_authority_unknown"])
            self.assertIn("Net", pkg["composed_capabilities"])
            self.assertEqual(composed["enforcement_posture"], "wasm-sandbox")

    def test_bounded_claim_does_not_leak_to_default(self):
        # The bounded claim must NEVER appear under the default posture --
        # that would be the unsound over-claim the design forbids.
        with tempfile.TemporaryDirectory() as td:
            none = self._compose(td, "none")["packages"][0]
            wasm = self._compose(td, "wasm-sandbox")["packages"][0]
            self.assertTrue(none["composed_authority_unknown"])
            self.assertFalse(wasm["composed_authority_unknown"])


if __name__ == "__main__":
    unittest.main()
