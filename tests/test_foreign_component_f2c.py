"""Feature #4 F2c-1: runtime sandbox marshalling of FLAT, one-level,
scalar-leaf AGGREGATE crossing types across a typed foreign-component
boundary.

F2a landed scalars (Int / Bool / Float); F2b added String. F2c-1 lets a
foreign method take / return a FLAT aggregate of scalars: a struct of
scalars, ``List<scalar>``, a tuple of scalars, ``Option<scalar>`` and
``Result<scalar, scalar>``. The host reads the Capa heap value out of the
parent's linear memory into a plain Python value, hands it to the
sandboxed child through wasmtime's canonical ABI, and writes the child's
returned value back as a Capa heap record -- reusing the byte offsets the
core emitter's ``_layout.py`` computes (threaded to the host as a
serialised layout schema) so the reader and writer cannot disagree with
the backend.

The F2a/F2b confinement is UNTOUCHED: the host still resolves the
caller's attenuated cap handles, instantiates the child in a bare store
under a restricted linker binding ONLY the granted caps, and a child
importing an un-granted cap still fails at instantiation. F2c-1 changes
only which value SHAPES cross the already-enforced boundary; a crossing
aggregate is F1-quarantine-clean plain data (no Fun / cap / Unsafe
nested) and carries no authority.

Fixtures (see ``tests/fixtures/foreign/``, with .wat / .wit sources):

- ``agg_child.wasm``: no caps. Exports one method per shape:
  ``bump-point`` (record of Int / Bool / Float / String), ``list-inc``
  (list<s64>), ``list-tag`` (list<string> echo), ``list-not``
  (list<bool> negate -- the stride-4 element case), ``tup-bump``
  (tuple<s64, string>), ``opt-inc`` (option<s64>), ``res-inc``
  (result<s64, string>), and ``sum-hdr`` (a record backing a Capa struct
  that implements a multi-impl trait -- the 8-byte-header offset case).
- ``agg_net_child.wasm``: imports ``capa:host/net``. Exports
  ``submit(list<s64>) -> s64`` returning ``sum(xs) + (allows(
  "example.com") ? 1000 : 0)`` -- proves the host-bound Net is the
  caller's ATTENUATED cap AND that a cap coexists with aggregate
  marshalling.

A NESTED aggregate (List of structs, a struct with a List field, ...) is
still rejected with a clean feature #4 F2c-2 error.
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


def _copy_fixture(td: str, name: str) -> None:
    shutil.copy(_FIXTURES / name, Path(td) / name)


# A flat struct of scalars (Int / Bool / Float / String fields):
# ``bump-point`` returns x+1, !flag, ratio+1.0, label echoed. Each field
# is printed so a divergent field offset would corrupt exactly one value.
_STRUCT_PROG = (
    "type Point { x: Int, flag: Bool, ratio: Float, label: String }\n"
    "\n"
    'extern component Agg from "agg_child.wasm"\n'
    "    fun bump_point(p: Point) -> Point\n"
    "\n"
    "fun main(stdio: Stdio)\n"
    '    let p = Point { x: 5, flag: true, ratio: 2.5, label: "hi" }\n'
    "    let p2 = Agg.bump_point(p)\n"
    '    stdio.println("x=${p2.x} flag=${p2.flag} ratio=${p2.ratio} '
    'label=${p2.label}")\n'
)

# List<Int> arg + return, plus the empty-list case.
_LIST_INT_PROG = (
    'extern component Agg from "agg_child.wasm"\n'
    "    fun list_inc(xs: List<Int>) -> List<Int>\n"
    "\n"
    "fun main(stdio: Stdio)\n"
    "    let xs = Agg.list_inc([10, 20, 30])\n"
    '    stdio.println("a=${xs[0]} b=${xs[1]} c=${xs[2]} n=${xs.length()}")\n'
    "    let empty = Agg.list_inc([])\n"
    '    stdio.println("empty=${empty.length()}")\n'
)

# List<String> (packed-slot String encoding) vs List<Bool> (stride-4
# element) -- the two divergences that a flat-8-byte-slot assumption
# would miscompile. list-tag echoes the strings; list-not negates.
_LIST_DIVERGENCE_PROG = (
    'extern component Agg from "agg_child.wasm"\n'
    "    fun list_tag(xs: List<String>) -> List<String>\n"
    "    fun list_not(xs: List<Bool>) -> List<Bool>\n"
    "\n"
    "fun main(stdio: Stdio)\n"
    '    let ss = Agg.list_tag(["a", "bb", ""])\n'
    '    stdio.println("s0=${ss[0]} s1=${ss[1]} s2=[${ss[2]}] '
    'n=${ss.length()}")\n'
    "    let bs = Agg.list_not([true, false, true])\n"
    '    stdio.println("b0=${bs[0]} b1=${bs[1]} b2=${bs[2]}")\n'
)

# tuple(Int, String) arg + return.
_TUPLE_PROG = (
    'extern component Agg from "agg_child.wasm"\n'
    "    fun tup_bump(t: (Int, String)) -> (Int, String)\n"
    "\n"
    "fun main(stdio: Stdio)\n"
    '    let (a, b) = Agg.tup_bump((9, "zz"))\n'
    '    stdio.println("t0=${a} t1=${b}")\n'
)

# Option<Int> + Result<Int, String> arg + return, incl None / Err. These
# exercise the Some=0/None=1 and Ok=0/Err=1 tag convention.
_OPTRES_PROG = (
    'extern component Agg from "agg_child.wasm"\n'
    "    fun opt_inc(o: Option<Int>) -> Option<Int>\n"
    "    fun res_inc(r: Result<Int, String>) -> Result<Int, String>\n"
    "\n"
    "fun describe_opt(o: Option<Int>) -> String\n"
    "    return match o\n"
    '        Some(v) -> "Some(${v})"\n'
    '        None -> "None"\n'
    "\n"
    "fun describe_res(r: Result<Int, String>) -> String\n"
    "    return match r\n"
    '        Ok(v) -> "Ok(${v})"\n'
    '        Err(e) -> "Err(${e})"\n'
    "\n"
    "fun main(stdio: Stdio)\n"
    '    stdio.println("os=${describe_opt(Agg.opt_inc(Some(7)))}")\n'
    '    stdio.println("on=${describe_opt(Agg.opt_inc(None))}")\n'
    '    stdio.println("ro=${describe_res(Agg.res_inc(Ok(10)))}")\n'
    '    stdio.println("re=${describe_res(Agg.res_inc(Err("boom")))}")\n'
)

# A struct implementing a multi-impl trait reserves an 8-byte type-id
# header, shifting every field offset by 8. The host must read fields at
# the shifted offsets (schema ``has_header``). sum-hdr returns
# code + (active ? 1 : 0).
_HEADER_PROG = (
    "trait Named\n"
    "    fun name(self) -> String\n"
    "\n"
    "type Gadget { code: Int, active: Bool }\n"
    "type Widget { id: Int }\n"
    "\n"
    "impl Named for Gadget\n"
    "    fun name(self) -> String\n"
    '        return "gadget"\n'
    "\n"
    "impl Named for Widget\n"
    "    fun name(self) -> String\n"
    '        return "widget"\n'
    "\n"
    'extern component Agg from "agg_child.wasm"\n'
    "    fun sum_hdr(g: Gadget) -> Int\n"
    "\n"
    "fun main(stdio: Stdio)\n"
    "    let g = Gadget { code: 40, active: true }\n"
    '    stdio.println("name=${g.name()}")\n'
    '    stdio.println("sum=${Agg.sum_hdr(g)}")\n'
    "    let g2 = Gadget { code: 100, active: false }\n"
    '    stdio.println("sum2=${Agg.sum_hdr(g2)}")\n'
)

# An aggregate-carrying method that ALSO grants Net: proves the cap is the
# caller's attenuated one (example.com allowed => + 1000).
_NET_OK_PROG = (
    'extern component B from "agg_net_child.wasm"\n'
    "    fun submit(net: Net, xs: List<Int>) -> Int\n"
    "\n"
    "fun main(net: Net, stdio: Stdio)\n"
    '    let safe = net.restrict_to("example.com")\n'
    '    stdio.println("r=${B.submit(safe, [1, 2, 3])}")\n'
)

# Same, but Net narrowed to a host that is NOT example.com: the child's
# allows("example.com") is false (attenuation holds, no + 1000).
_NET_DENY_PROG = (
    'extern component B from "agg_net_child.wasm"\n'
    "    fun submit(net: Net, xs: List<Int>) -> Int\n"
    "\n"
    "fun main(net: Net, stdio: Stdio)\n"
    '    let narrow = net.restrict_to("other.example")\n'
    '    stdio.println("r=${B.submit(narrow, [1, 2, 3])}")\n'
)

# The child imports capa:host/net but this method grants NO cap: the child
# must be denied at instantiation (structural cap-set deny, unchanged).
_NET_UNGRANTED_PROG = (
    'extern component B from "agg_net_child.wasm"\n'
    "    fun submit(xs: List<Int>) -> Int\n"
    "\n"
    "fun main()\n"
    "    let _r = B.submit([1, 2, 3])\n"
)

# A NESTED aggregate: still F2c-2, rejected up front.
_NESTED_PROG = (
    'extern component A from "agg_child.wasm"\n'
    "    fun nest(xs: List<List<Int>>) -> Int\n"
    "\n"
    "fun main(stdio: Stdio)\n"
    "    let r = A.nest([[1], [2, 3]])\n"
    '    stdio.println("r=${r}")\n'
)


@unittest.skipUnless(
    _wasm_tooling_available(), "wasm-tools / wasmtime missing",
)
class TestForeignAggregateRuntime(unittest.TestCase):
    def _run(self, src: str, fixture: str = "agg_child.wasm"):
        with tempfile.TemporaryDirectory() as td:
            _copy_fixture(td, fixture)
            p = _write(td, "prog.capa", src)
            return _run_cli(["--wasm", "--run", str(p)], cwd=td)

    def test_flat_struct_roundtrips_byte_exact(self):
        # Each scalar field crosses value-correct in BOTH directions; a
        # divergent field offset would corrupt exactly one value.
        rc, out, err = self._run(_STRUCT_PROG)
        self.assertEqual(rc, 0, err)
        self.assertIn("x=6 flag=false ratio=3.5 label=hi", out)

    def test_list_int_roundtrips_including_empty(self):
        rc, out, err = self._run(_LIST_INT_PROG)
        self.assertEqual(rc, 0, err)
        self.assertIn("a=11 b=21 c=31 n=3", out)
        self.assertIn("empty=0", out)

    def test_list_string_and_bool_divergences(self):
        # List<String> (packed-slot String, stride 8) and List<Bool>
        # (stride 4) round-trip; a flat-8-byte assumption would miscompile
        # the Bool list.
        rc, out, err = self._run(_LIST_DIVERGENCE_PROG)
        self.assertEqual(rc, 0, err)
        self.assertIn("s0=a s1=bb s2=[] n=3", out)
        self.assertIn("b0=false b1=true b2=false", out)

    def test_tuple_roundtrips(self):
        rc, out, err = self._run(_TUPLE_PROG)
        self.assertEqual(rc, 0, err)
        self.assertIn("t0=10 t1=zz", out)

    def test_option_and_result_tag_convention(self):
        # Some / None and Ok / Err each round-trip, exercising the
        # Some=0/None=1 and Ok=0/Err=1 tag convention.
        rc, out, err = self._run(_OPTRES_PROG)
        self.assertEqual(rc, 0, err)
        self.assertIn("os=Some(8)", out)
        self.assertIn("on=None", out)
        self.assertIn("ro=Ok(11)", out)
        self.assertIn("re=Err(boom)", out)

    def test_multi_impl_trait_struct_header(self):
        # A struct implementing a multi-impl trait reserves an 8-byte
        # header; the host reads fields at the shifted offsets. A wrong
        # (no-header) offset would read garbage for code / active.
        rc, out, err = self._run(_HEADER_PROG)
        self.assertEqual(rc, 0, err)
        self.assertIn("name=gadget", out)
        self.assertIn("sum=41", out)
        self.assertIn("sum2=100", out)

    def test_cap_with_aggregate_attenuation_allowed(self):
        rc, out, err = self._run(_NET_OK_PROG, "agg_net_child.wasm")
        self.assertEqual(rc, 0, err)
        # sum(1,2,3)=6, +1000 because example.com is allowed.
        self.assertIn("r=1006", out)

    def test_cap_with_aggregate_attenuation_holds(self):
        # SECURITY REGRESSION CHECK: attenuation still fires on an
        # aggregate-carrying call -- the child cannot widen past the
        # caller's grant, so no + 1000.
        rc, out, err = self._run(_NET_DENY_PROG, "agg_net_child.wasm")
        self.assertEqual(rc, 0, err)
        self.assertIn("r=6", out)

    def test_ungranted_cap_denied_on_aggregate_path(self):
        # SECURITY REGRESSION CHECK: the structural cap-set deny still
        # fires on the aggregate-marshalling path -- byte-for-byte the same
        # enforcement as F2a/F2b.
        rc, _out, err = self._run(_NET_UNGRANTED_PROG, "agg_net_child.wasm")
        self.assertEqual(rc, 1)
        self.assertIn("instantiation denied", err)
        self.assertIn("capa:host/net", err)

    def test_nested_aggregate_rejected_f2c2(self):
        # A nested aggregate is rejected up front with the clean F2c-2
        # error; the boundary just moved one level out.
        rc, _out, err = self._run(_NESTED_PROG)
        self.assertEqual(rc, 1)
        self.assertIn("F2c-2", err)
        self.assertIn("aggregate nesting", err)

    def test_nested_aggregate_declaration_still_checks(self):
        # NON-REGRESSION: a nested-aggregate boundary is inert at the
        # declaration level -- --check works fully (F1 unchanged).
        with tempfile.TemporaryDirectory() as td:
            p = _write(td, "prog.capa", _NESTED_PROG)
            rc, out, _err = _run_cli(["--check", str(p)], cwd=td)
            self.assertEqual(rc, 0)
            self.assertIn("ok", out)


class TestForeignAggregateSbomPosture(unittest.TestCase):
    """The composed SBOM downgrade is unchanged by F2c: an
    aggregate-bearing foreign method composes TOP by default and BOUNDED
    only under the wasm-sandbox posture, exactly like a scalar one."""

    def _compose(self, td: str, posture: str):
        (Path(td) / "capa.toml").write_text(
            '[package]\nname = "fdemo"\nversion = "0.1.0"\n', encoding="utf-8",
        )
        src = (
            'extern component B from "agg_net_child.wasm"\n'
            "    fun submit(net: Net, xs: List<Int>) -> Int\n"
            "\n"
            "fun main(net: Net) -> Int\n"
            "    return B.submit(net, [1, 2])\n"
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


class TestCapaTypeToWit(unittest.TestCase):
    """The general Capa-type -> WIT-type mapping the parent import and the
    external child export agree on (feature #4 F2c)."""

    def test_scalar_and_aggregate_mappings(self):
        from capa.ir._emit_wit import capa_type_to_wit

        self.assertEqual(capa_type_to_wit("Int"), "s64")
        self.assertEqual(capa_type_to_wit("Bool"), "bool")
        self.assertEqual(capa_type_to_wit("Float"), "f64")
        self.assertEqual(capa_type_to_wit("String"), "string")
        self.assertEqual(capa_type_to_wit("List<Int>"), "list<s64>")
        self.assertEqual(
            capa_type_to_wit("List<String>"), "list<string>",
        )
        self.assertEqual(
            capa_type_to_wit("Option<Int>"), "option<s64>",
        )
        self.assertEqual(
            capa_type_to_wit("Result<Int, String>"),
            "result<s64, string>",
        )
        self.assertEqual(
            capa_type_to_wit("(Int, String)"), "tuple<s64, string>",
        )
        # A user struct name maps to its (kebab-cased) WIT record name.
        self.assertEqual(capa_type_to_wit("Point"), "point")
        self.assertEqual(capa_type_to_wit("My_Rec"), "my-rec")


if __name__ == "__main__":
    unittest.main()
