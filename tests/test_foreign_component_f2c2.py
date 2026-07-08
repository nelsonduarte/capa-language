"""Feature #4 F2c-2: runtime sandbox marshalling of NESTED,
non-self-referential AGGREGATE crossing types across a typed
foreign-component boundary.

F2c-1 crossed FLAT one-level scalar-leaf aggregates. F2c-2 generalises to
ANY finite nesting depth by general recursion: a nested struct field /
List element / variant payload carries its own sub-schema and is a 4-byte
pointer to a separately-allocated record. Supported shapes exercised here:

- ``List<Point>``   -- a list of a flat struct (stride-4 pointer elements,
  each a recursively-marshalled record).
- ``Bag { items: List<Int>, name: String, tag: Option<Int> }`` -- a struct
  with a nested List, a String field and a nested Option.
- ``List<(Int, String)>``, ``Option<Point>``, ``Result<Point, String>``,
  ``List<List<Int>>``, a multi-payload user sum ``Shape``, and a 4-level
  ``List<Option<List<Point>>>``.

The host reads the Capa heap value out of the parent's linear memory into a
plain (nested) Python value, hands it to the sandboxed child through
wasmtime's canonical ABI, and writes the child's returned value back --
reusing the byte offsets ``_layout.py`` computes (threaded as a recursive
schema) so the reader / writer cannot disagree with the backend. Each child
export echoes / reconstructs its argument, so a divergent host-side offset
corrupts the observed round trip.

The F2a/F2b/F2c-1 confinement is UNTOUCHED: the host still resolves the
caller's attenuated cap handles, instantiates the child in a bare store
under a restricted linker binding ONLY the granted caps, and a child
importing an un-granted cap still fails at instantiation. F2c-2 changes
only which value SHAPES cross the already-enforced boundary; a crossing
aggregate is F1-quarantine-clean plain data (no Fun / cap / Unsafe nested)
and carries no authority.

STOP-report boundaries (rejected up front with a specific error): a
``Map<K, V>`` and a self-referential type ``type Tree { kids: List<Tree> }``.

Fixtures (see ``tests/fixtures/foreign/``, with .wat / .wit sources):

- ``agg2_child.wasm``: no caps. One echo/reconstruct export per shape.
- ``agg2_net_child.wasm``: imports ``capa:host/net``; ``submit(net,
  List<List<Int>>) -> Int`` returns ``sum(all) + (allows("example.com")
  ? 1000 : 0)`` -- a cap coexisting with NESTED aggregate marshalling.
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

from capa.cli import _wasm_tooling_available, main

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


# ---- programs ---------------------------------------------------------

# List<Point>: a list of a flat struct. Each element is a pointer-slot
# (stride 4) to a recursively-marshalled Point record.
_LIST_POINT_PROG = (
    "type Point { x: Int, flag: Bool, ratio: Float, label: String }\n"
    "\n"
    'extern component Agg from "agg2_child.wasm"\n'
    "    fun list_point(xs: List<Point>) -> List<Point>\n"
    "\n"
    "fun main(stdio: Stdio)\n"
    '    let p0 = Point { x: 1, flag: true, ratio: 1.5, label: "a" }\n'
    '    let p1 = Point { x: 2, flag: false, ratio: 2.5, label: "" }\n'
    "    let r = Agg.list_point([p0, p1])\n"
    '    stdio.println("n=${r.length()}")\n'
    '    stdio.println("p0 x=${r[0].x} flag=${r[0].flag} ratio=${r[0].ratio} '
    'label=${r[0].label}")\n'
    '    stdio.println("p1 x=${r[1].x} flag=${r[1].flag} ratio=${r[1].ratio} '
    'label=[${r[1].label}]")\n'
    "    let empty = Agg.list_point([])\n"
    '    stdio.println("empty=${empty.length()}")\n'
)

# struct with a nested List + String + nested Option field.
_BAG_PROG = (
    "type Bag { items: List<Int>, name: String, tag: Option<Int> }\n"
    "\n"
    'extern component Agg from "agg2_child.wasm"\n'
    "    fun bag_echo(b: Bag) -> Bag\n"
    "\n"
    "fun show_tag(o: Option<Int>) -> String\n"
    "    return match o\n"
    '        Some(v) -> "Some(${v})"\n'
    '        None -> "None"\n'
    "\n"
    "fun main(stdio: Stdio)\n"
    '    let b = Bag { items: [10, 20, 30], name: "hi", tag: Some(7) }\n'
    "    let r = Agg.bag_echo(b)\n"
    '    stdio.println("items=${r.items[0]},${r.items[1]},${r.items[2]} '
    'n=${r.items.length()} name=${r.name} tag=${show_tag(r.tag)}")\n'
    '    let b2 = Bag { items: [], name: "", tag: None }\n'
    "    let r2 = Agg.bag_echo(b2)\n"
    '    stdio.println("empty items=${r2.items.length()} name=[${r2.name}] '
    'tag=${show_tag(r2.tag)}")\n'
)

# List<(Int, String)>: list of a tuple (pointer-slot elements).
_LIST_PAIR_PROG = (
    'extern component Agg from "agg2_child.wasm"\n'
    "    fun list_pair(xs: List<(Int, String)>) -> List<(Int, String)>\n"
    "\n"
    "fun main(stdio: Stdio)\n"
    '    let r = Agg.list_pair([(1, "a"), (2, "bb"), (3, "")])\n'
    "    let (a0, s0) = r[0]\n"
    "    let (a1, s1) = r[1]\n"
    "    let (a2, s2) = r[2]\n"
    '    stdio.println("p0=${a0}:${s0} p1=${a1}:${s1} p2=${a2}:[${s2}] '
    'n=${r.length()}")\n'
)

# Option<Point> + Result<Point, String>: struct nested in a variant slot,
# incl None / Err (nested-position empties).
_OPTRES_PROG = (
    "type Point { x: Int, flag: Bool, ratio: Float, label: String }\n"
    "\n"
    'extern component Agg from "agg2_child.wasm"\n'
    "    fun opt_point(o: Option<Point>) -> Option<Point>\n"
    "    fun res_point(r: Result<Point, String>) -> Result<Point, String>\n"
    "\n"
    "fun show_opt(o: Option<Point>) -> String\n"
    "    return match o\n"
    '        Some(p) -> "Some(${p.x}:${p.label})"\n'
    '        None -> "None"\n'
    "\n"
    "fun show_res(r: Result<Point, String>) -> String\n"
    "    return match r\n"
    '        Ok(p) -> "Ok(${p.x}:${p.label})"\n'
    '        Err(e) -> "Err(${e})"\n'
    "\n"
    "fun main(stdio: Stdio)\n"
    '    let p = Point { x: 5, flag: true, ratio: 2.0, label: "z" }\n'
    '    stdio.println("os=${show_opt(Agg.opt_point(Some(p)))}")\n'
    '    stdio.println("on=${show_opt(Agg.opt_point(None))}")\n'
    '    stdio.println("ro=${show_res(Agg.res_point(Ok(p)))}")\n'
    '    stdio.println("re=${show_res(Agg.res_point(Err("boom")))}")\n'
)

# List<List<Int>>: nested list, incl empty inner lists.
_LIST_LIST_PROG = (
    'extern component Agg from "agg2_child.wasm"\n'
    "    fun list_list(xs: List<List<Int>>) -> List<List<Int>>\n"
    "\n"
    "fun main(stdio: Stdio)\n"
    "    let r = Agg.list_list([[1, 2], [], [3, 4, 5]])\n"
    '    stdio.println("outer=${r.length()} i0=${r[0].length()} '
    'i1=${r[1].length()} i2=${r[2].length()}")\n'
    '    stdio.println("vals=${r[0][0]},${r[0][1]},${r[2][0]},${r[2][2]}")\n'
)

# A child RETURNS a struct that implements a multi-impl trait: the host
# write-back reserves the 8-byte trait-dispatch header and writes the
# type-id at offset 4 (the WRITE-back has_header path -- F2c-1 only tested
# the read path). The parent then dispatches ``.name()`` on the returned
# value; a missing / wrong type-id would route to the wrong impl.
_HEADER_RETURN_PROG = (
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
    'extern component Agg from "agg2_child.wasm"\n'
    "    fun mk_gadget(code: Int, active: Bool) -> Gadget\n"
    "\n"
    "fun describe(n: Named) -> String\n"
    "    return n.name()\n"
    "\n"
    "fun main(stdio: Stdio)\n"
    "    let g = Agg.mk_gadget(40, true)\n"
    '    stdio.println("code=${g.code} active=${g.active} name=${describe(g)}")\n'
)

# A multi-payload user sum (variant), incl a no-payload case.
_SHAPE_PROG = (
    "type Shape =\n"
    "    Dot\n"
    "    Circle(Int)\n"
    "    Label(String)\n"
    "    Rect(Int, Int)\n"
    "\n"
    'extern component Agg from "agg2_child.wasm"\n'
    "    fun shape_echo(s: Shape) -> Shape\n"
    "\n"
    "fun show(s: Shape) -> String\n"
    "    return match s\n"
    '        Dot -> "Dot"\n'
    '        Circle(n) -> "Circle(${n})"\n'
    '        Label(t) -> "Label(${t})"\n'
    '        Rect(a, b) -> "Rect(${a},${b})"\n'
    "\n"
    "fun main(stdio: Stdio)\n"
    '    stdio.println("s0=${show(Agg.shape_echo(Dot))}")\n'
    '    stdio.println("s1=${show(Agg.shape_echo(Circle(9)))}")\n'
    '    stdio.println("s2=${show(Agg.shape_echo(Label("hey")))}")\n'
    '    stdio.println("s3=${show(Agg.shape_echo(Rect(3, 4)))}")\n'
)

# A 4-level nested crossing: List<Option<List<Point>>>, incl a None at a
# nested position and an empty inner list.
_DEEP_PROG = (
    "type Point { x: Int, flag: Bool, ratio: Float, label: String }\n"
    "\n"
    'extern component Agg from "agg2_child.wasm"\n'
    "    fun deep(d: List<Option<List<Point>>>) -> List<Option<List<Point>>>\n"
    "\n"
    "fun main(stdio: Stdio)\n"
    '    let p = Point { x: 7, flag: true, ratio: 1.0, label: "q" }\n'
    "    let r = Agg.deep([Some([p]), None, Some([])])\n"
    '    let head = match r[0]\n'
    '        Some(xs) -> "Some(len=${xs.length()},x=${xs[0].x},lbl=${xs[0].label})"\n'
    '        None -> "None"\n'
    '    let mid = match r[1]\n'
    '        Some(xs) -> "Some(${xs.length()})"\n'
    '        None -> "None"\n'
    '    let tail = match r[2]\n'
    '        Some(xs) -> "Some(len=${xs.length()})"\n'
    '        None -> "None"\n'
    '    stdio.println("n=${r.length()} head=${head} mid=${mid} tail=${tail}")\n'
)

# A large-but-bounded nested generation forced to exceed a tight parent
# memory cap: the write-back OOM surfaces as a clean host error, never a
# scribble / crash.
_OOM_PROG = (
    'extern component Agg from "agg2_child.wasm"\n'
    "    fun gen(n: Int) -> List<Int>\n"
    "\n"
    "fun main(stdio: Stdio)\n"
    "    let r = Agg.gen(400000)\n"
    '    stdio.println("n=${r.length()}")\n'
)

# Cap + NESTED aggregate: proves the host-bound Net is the caller's
# ATTENUATED cap (example.com allowed => + 1000).
_NET_OK_PROG = (
    'extern component B from "agg2_net_child.wasm"\n'
    "    fun submit(net: Net, xs: List<List<Int>>) -> Int\n"
    "\n"
    "fun main(net: Net, stdio: Stdio)\n"
    '    let safe = net.restrict_to("example.com")\n'
    '    stdio.println("r=${B.submit(safe, [[1, 2, 3], [4], []])}")\n'
)

_NET_DENY_PROG = (
    'extern component B from "agg2_net_child.wasm"\n'
    "    fun submit(net: Net, xs: List<List<Int>>) -> Int\n"
    "\n"
    "fun main(net: Net, stdio: Stdio)\n"
    '    let narrow = net.restrict_to("other.example")\n'
    '    stdio.println("r=${B.submit(narrow, [[1, 2, 3], [4], []])}")\n'
)

_NET_UNGRANTED_PROG = (
    'extern component B from "agg2_net_child.wasm"\n'
    "    fun submit(xs: List<List<Int>>) -> Int\n"
    "\n"
    "fun main()\n"
    "    let _r = B.submit([[1, 2, 3]])\n"
)

# STOP-report: a self-referential (recursive) crossing type.
_RECURSIVE_PROG = (
    "type Tree { value: Int, kids: List<Tree> }\n"
    "\n"
    'extern component A from "agg2_child.wasm"\n'
    "    fun walk(t: Tree) -> Int\n"
    "\n"
    "fun main(stdio: Stdio)\n"
    "    let leaf = Tree { value: 1, kids: [] }\n"
    "    let r = A.walk(leaf)\n"
    '    stdio.println("r=${r}")\n'
)


@unittest.skipUnless(
    _wasm_tooling_available(), "wasm-tools / wasmtime missing",
)
class TestForeignNestedAggregateRuntime(unittest.TestCase):
    def _run(self, src: str, fixture: str = "agg2_child.wasm", extra=()):
        with tempfile.TemporaryDirectory() as td:
            shutil.copy(_FIXTURES / fixture, Path(td) / fixture)
            p = _write(td, "prog.capa", src)
            return _run_cli(
                ["--wasm", "--run", *extra, str(p)], cwd=td,
            )

    def test_list_of_struct(self):
        rc, out, err = self._run(_LIST_POINT_PROG)
        self.assertEqual(rc, 0, err)
        self.assertIn("n=2", out)
        self.assertIn("p0 x=1 flag=true ratio=1.5 label=a", out)
        self.assertIn("p1 x=2 flag=false ratio=2.5 label=[]", out)
        self.assertIn("empty=0", out)

    def test_struct_with_nested_list_string_option(self):
        rc, out, err = self._run(_BAG_PROG)
        self.assertEqual(rc, 0, err)
        self.assertIn("items=10,20,30 n=3 name=hi tag=Some(7)", out)
        self.assertIn("empty items=0 name=[] tag=None", out)

    def test_list_of_tuple(self):
        rc, out, err = self._run(_LIST_PAIR_PROG)
        self.assertEqual(rc, 0, err)
        self.assertIn("p0=1:a p1=2:bb p2=3:[] n=3", out)

    def test_option_and_result_of_struct(self):
        rc, out, err = self._run(_OPTRES_PROG)
        self.assertEqual(rc, 0, err)
        self.assertIn("os=Some(5:z)", out)
        self.assertIn("on=None", out)
        self.assertIn("ro=Ok(5:z)", out)
        self.assertIn("re=Err(boom)", out)

    def test_list_of_list(self):
        rc, out, err = self._run(_LIST_LIST_PROG)
        self.assertEqual(rc, 0, err)
        self.assertIn("outer=3 i0=2 i1=0 i2=3", out)
        self.assertIn("vals=1,2,3,5", out)

    def test_returned_multi_impl_trait_struct_header(self):
        # The child returns a Gadget (a multi-impl-trait struct); the host
        # writes back the 8-byte header + type-id so the parent's dynamic
        # dispatch on the returned value routes to Gadget's impl.
        rc, out, err = self._run(_HEADER_RETURN_PROG)
        self.assertEqual(rc, 0, err)
        self.assertIn("code=40 active=true name=gadget", out)

    def test_multi_payload_sum(self):
        rc, out, err = self._run(_SHAPE_PROG)
        self.assertEqual(rc, 0, err)
        self.assertIn("s0=Dot", out)
        self.assertIn("s1=Circle(9)", out)
        self.assertIn("s2=Label(hey)", out)
        self.assertIn("s3=Rect(3,4)", out)

    def test_deep_four_level_nesting(self):
        rc, out, err = self._run(_DEEP_PROG)
        self.assertEqual(rc, 0, err)
        self.assertIn(
            "n=3 head=Some(len=1,x=7,lbl=q) mid=None tail=Some(len=0)", out,
        )

    def test_oom_nested_return_is_clean_host_error(self):
        # SECURITY / SAFETY: a large child return that overruns a tight
        # parent memory cap surfaces as a clean host error (WasmHostError
        # -> non-zero exit), never a scribble at address 0 or a crash.
        rc, _out, err = self._run(
            _OOM_PROG, extra=("--wasm-memory-cap", "16"),
        )
        self.assertEqual(rc, 1)
        self.assertIn("out of memory", err.lower() + _out.lower())

    def test_cap_with_nested_aggregate_attenuation_allowed(self):
        rc, out, err = self._run(_NET_OK_PROG, "agg2_net_child.wasm")
        self.assertEqual(rc, 0, err)
        # sum(1,2,3,4)=10, +1000 because example.com is allowed.
        self.assertIn("r=1010", out)

    def test_cap_with_nested_aggregate_attenuation_holds(self):
        # SECURITY REGRESSION CHECK: attenuation still fires on a
        # nested-aggregate-carrying call -- the child cannot widen past the
        # caller's grant, so no + 1000.
        rc, out, err = self._run(_NET_DENY_PROG, "agg2_net_child.wasm")
        self.assertEqual(rc, 0, err)
        self.assertIn("r=10", out)

    def test_ungranted_cap_denied_on_nested_aggregate_path(self):
        # SECURITY REGRESSION CHECK: the structural cap-set deny still
        # fires on the nested-aggregate path -- byte-for-byte the same
        # enforcement as F2a/F2b/F2c-1.
        rc, _out, err = self._run(_NET_UNGRANTED_PROG, "agg2_net_child.wasm")
        self.assertEqual(rc, 1)
        self.assertIn("instantiation denied", err)
        self.assertIn("capa:host/net", err)

    def test_recursive_type_rejected(self):
        # STOP-report: a self-referential crossing type is rejected up
        # front with a clean, specific error (no infinite loop / crash).
        rc, _out, err = self._run(_RECURSIVE_PROG)
        self.assertEqual(rc, 1)
        self.assertIn("self-referential", err)
        self.assertIn("Tree", err)

    def test_recursive_type_declaration_still_checks(self):
        # NON-REGRESSION: a recursive-crossing boundary is inert at the
        # declaration level -- --check works fully (F1 unchanged).
        with tempfile.TemporaryDirectory() as td:
            p = _write(td, "prog.capa", _RECURSIVE_PROG)
            rc, out, _err = _run_cli(["--check", str(p)], cwd=td)
            self.assertEqual(rc, 0)
            self.assertIn("ok", out)


class TestNestedCapaTypeToWit(unittest.TestCase):
    """The Capa-type -> WIT-type generator maps NESTED aggregates
    structurally (record / list / option / result / tuple) so the
    parent-import and child-export agree at every level, and never loops
    on a self-referential type name (it emits a bare record-name
    reference, not the resolved fields)."""

    def test_nested_mappings(self):
        from capa.ir._emit_wit import capa_type_to_wit
        self.assertEqual(capa_type_to_wit("List<Point>"), "list<point>")
        self.assertEqual(
            capa_type_to_wit("List<List<Int>>"), "list<list<s64>>",
        )
        self.assertEqual(
            capa_type_to_wit("Option<List<Point>>"),
            "option<list<point>>",
        )
        self.assertEqual(
            capa_type_to_wit("Result<Point, String>"),
            "result<point, string>",
        )
        self.assertEqual(
            capa_type_to_wit("List<(Int, String)>"),
            "list<tuple<s64, string>>",
        )
        self.assertEqual(
            capa_type_to_wit("List<Option<List<Point>>>"),
            "list<option<list<point>>>",
        )

    def test_self_referential_name_does_not_loop(self):
        # A bare user-type name emits a name reference (fields not
        # resolved), so even ``Tree`` maps without recursing into itself.
        from capa.ir._emit_wit import capa_type_to_wit
        self.assertEqual(capa_type_to_wit("List<Tree>"), "list<tree>")


if __name__ == "__main__":
    unittest.main()
