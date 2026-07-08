"""Feature #4 F2b: runtime sandbox marshalling of the STRING crossing
type across a typed foreign-component boundary.

F2a landed SCALAR crossing types (Int / Bool / Float). F2b extends the
same sandbox-enforced boundary to carry TEXT: a foreign method
``submit(net: Net, s: String) -> String`` marshals the String argument
and the String return across the parent-import leg using the canonical
ABI (a (ptr, len) pair in linear memory for the argument, an 8-byte
indirect return area for the result, ``$alloc`` for the returned bytes),
reusing the exact machinery the WASI cap methods already use for strings.
The F2a confinement is untouched: the host still resolves the caller's
attenuated cap handles, instantiates the child in a bare store under a
restricted linker binding ONLY the granted caps, and a child importing an
un-granted cap still fails at instantiation. F2b changes ONLY which VALUE
types cross the (already-enforced) boundary; a String is plain data.

Fixtures (see ``tests/fixtures/foreign/``, with .wat / .wit sources):

- ``str_echo_child.wasm``: no caps. Exports ``echo(s: string) -> string``
  returning ``"[" + s`` -- proves a String arg reaches the child and a
  derived String return marshals back, value-correct.
- ``str_net_child.wasm``: imports ``capa:host/net``. Exports
  ``submit(s: string) -> string`` returning ``(allows("example.com") ?
  "ok:" : "no:") + s`` -- proves the host-bound Net is the caller's
  ATTENUATED cap (example.com allowed vs denied) AND that a cap coexists
  with String marshalling in one call.

An AGGREGATE crossing type (List / record / Option / Result / tuple) is
still rejected with a clean, specific error: it needs a general
host-side Capa-heap reader/writer that is a further sub-phase.
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


# A no-cap String method: echo the argument with a "[" marker prepended.
_ECHO_PROG = (
    'extern component E from "str_echo_child.wasm"\n'
    "    fun echo(s: String) -> String\n"
    "\n"
    "fun main(stdio: Stdio)\n"
    "    let name = \"abc\"\n"
    "    let r = E.echo(name)\n"
    '    let lit = E.echo("hi")\n'
    "    let empty = E.echo(\"\")\n"
    '    stdio.println("local=${r} lit=${lit} empty=[${empty}] chain=${r + "!"}")\n'
)

# A String method that ALSO grants Net: the child consults the
# host-bound (attenuated) cap and prefixes the echoed string accordingly.
_NET_STR_PROG = (
    'extern component B from "str_net_child.wasm"\n'
    "    fun submit(net: Net, s: String) -> String\n"
    "\n"
    "fun main(net: Net, stdio: Stdio)\n"
    '    let safe = net.restrict_to("example.com")\n'
    '    let r = B.submit(safe, "world")\n'
    '    stdio.println("submit=${r}")\n'
)

# Same, but the Net is attenuated to a host that is NOT example.com, so
# the child's allows("example.com") is false -- proving the child cannot
# widen past the caller's grant.
_NET_STR_DENY_PROG = (
    'extern component B from "str_net_child.wasm"\n'
    "    fun submit(net: Net, s: String) -> String\n"
    "\n"
    "fun main(net: Net, stdio: Stdio)\n"
    '    let narrow = net.restrict_to("other.example")\n'
    '    let r = B.submit(narrow, "world")\n'
    '    stdio.println("submit=${r}")\n'
)

# The str_net_child imports capa:host/net, but this method grants NO cap
# (a pure-String signature). The child must be denied at instantiation --
# the F2a structural cap-set deny, unchanged on the String path.
_STR_UNGRANTED_PROG = (
    'extern component B from "str_net_child.wasm"\n'
    "    fun submit(s: String) -> String\n"
    "\n"
    "fun main()\n"
    '    let _r = B.submit("world")\n'
)

# A NESTED aggregate crossing type: still rejected up front (feature #4
# F2c-2). F2c-1 lands FLAT scalar-leaf aggregates (List<Int> etc.), so
# the rejection case now uses a genuinely nested aggregate (List of
# Lists). The declaration + --check are unaffected.
# A Map crossing type is still rejected up front (F2c-2 STOP-report
# boundary): Map's String-keyed structure is out of the aggregate
# marshaller's scope. NESTED aggregates (List<List<Int>>, structs of
# lists, ...) DO marshal now (F2c-2); only Map and self-referential types
# stay rejected.
_AGG_PROG = (
    'extern component A from "str_echo_child.wasm"\n'
    "    fun mk(m: Map<String, Int>) -> Int\n"
    "\n"
    "fun main(stdio: Stdio)\n"
    "    let m = new_map()\n"
    "    let r = A.mk(m)\n"
    '    stdio.println("r=${r}")\n'
)


@unittest.skipUnless(
    _wasm_tooling_available(), "wasm-tools / wasmtime missing",
)
class TestForeignStringRuntime(unittest.TestCase):
    def test_string_echo_runs_end_to_end(self):
        # A String arg (literal, local, and empty) reaches the child and
        # the derived String return marshals back correctly; the returned
        # String is usable downstream (concatenation).
        with tempfile.TemporaryDirectory() as td:
            shutil.copy(
                _FIXTURES / "str_echo_child.wasm",
                Path(td) / "str_echo_child.wasm",
            )
            p = _write(td, "prog.capa", _ECHO_PROG)
            rc, out, err = _run_cli(["--wasm", "--run", str(p)], cwd=td)
            self.assertEqual(rc, 0, err)
            self.assertIn("local=[abc", out)
            self.assertIn("lit=[hi", out)
            self.assertIn("empty=[[]", out)
            self.assertIn("chain=[abc!", out)

    def test_string_with_cap_runs_end_to_end(self):
        # A String method that ALSO grants Net: the string round-trips
        # AND the host-bound Net is the caller's attenuated cap
        # (example.com allowed => the child prefixes "ok:").
        with tempfile.TemporaryDirectory() as td:
            shutil.copy(
                _FIXTURES / "str_net_child.wasm",
                Path(td) / "str_net_child.wasm",
            )
            p = _write(td, "prog.capa", _NET_STR_PROG)
            rc, out, err = _run_cli(["--wasm", "--run", str(p)], cwd=td)
            self.assertEqual(rc, 0, err)
            self.assertIn("submit=ok:world", out)

    def test_string_cap_attenuation_holds(self):
        # The child cannot widen past the caller's grant: a Net narrowed
        # to a host that is NOT example.com makes the child's
        # allows("example.com") false, so it prefixes "no:".
        with tempfile.TemporaryDirectory() as td:
            shutil.copy(
                _FIXTURES / "str_net_child.wasm",
                Path(td) / "str_net_child.wasm",
            )
            p = _write(td, "prog.capa", _NET_STR_DENY_PROG)
            rc, out, err = _run_cli(["--wasm", "--run", str(p)], cwd=td)
            self.assertEqual(rc, 0, err)
            self.assertIn("submit=no:world", out)

    def test_ungranted_cap_fails_on_string_path(self):
        # SECURITY REGRESSION CHECK: the structural cap-set deny still
        # fires on the String-marshalling path. The child imports
        # capa:host/net but the method grants no cap, so instantiation is
        # denied -- byte-for-byte the same enforcement as F2a.
        with tempfile.TemporaryDirectory() as td:
            shutil.copy(
                _FIXTURES / "str_net_child.wasm",
                Path(td) / "str_net_child.wasm",
            )
            p = _write(td, "prog.capa", _STR_UNGRANTED_PROG)
            rc, _out, err = _run_cli(["--wasm", "--run", str(p)], cwd=td)
            self.assertEqual(rc, 1)
            self.assertIn("instantiation denied", err)
            self.assertIn("capa:host/net", err)

    def test_aggregate_still_rejected(self):
        # A Map crossing type is still rejected up front with a clean,
        # specific error (feature #4 F2c-2 STOP-report boundary), on the
        # --wasm backend. Scalar-leaf aggregates -- FLAT and NESTED -- now
        # marshal; only Map and self-referential types stay rejected.
        with tempfile.TemporaryDirectory() as td:
            shutil.copy(
                _FIXTURES / "str_echo_child.wasm",
                Path(td) / "str_echo_child.wasm",
            )
            p = _write(td, "prog.capa", _AGG_PROG)
            rc, _out, err = _run_cli(["--wasm", "--run", str(p)], cwd=td)
            self.assertEqual(rc, 1)
            self.assertIn("Map crossing type", err)

    def test_aggregate_declaration_still_checks(self):
        # NON-REGRESSION: the aggregate boundary is inert at the
        # declaration level -- --check works fully (F1 unchanged).
        with tempfile.TemporaryDirectory() as td:
            p = _write(td, "prog.capa", _AGG_PROG)
            rc, out, _err = _run_cli(["--check", str(p)], cwd=td)
            self.assertEqual(rc, 0)
            self.assertIn("ok", out)


class TestForeignStringSbomPosture(unittest.TestCase):
    """The composed SBOM downgrade is unchanged by F2b: a String-bearing
    foreign method composes TOP by default and BOUNDED only under the
    wasm-sandbox posture, exactly like a scalar one."""

    def _compose(self, td: str, posture: str):
        (Path(td) / "capa.toml").write_text(
            '[package]\nname = "fdemo"\nversion = "0.1.0"\n', encoding="utf-8",
        )
        src = (
            'extern component B from "str_net_child.wasm"\n'
            "    fun submit(net: Net, s: String) -> String\n"
            "\n"
            "fun main(net: Net) -> String\n"
            '    return B.submit(net, "x")\n'
        )
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

    def test_wasm_sandbox_posture_is_bounded(self):
        with tempfile.TemporaryDirectory() as td:
            composed = self._compose(td, "wasm-sandbox")
            pkg = composed["packages"][0]
            self.assertFalse(pkg["composed_authority_unknown"])
            self.assertIn("Net", pkg["composed_capabilities"])
            self.assertEqual(composed["enforcement_posture"], "wasm-sandbox")


if __name__ == "__main__":
    unittest.main()
