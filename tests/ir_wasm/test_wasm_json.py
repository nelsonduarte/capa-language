"""WebAssembly backend: the injected JSON parser (JsonValue construction,
matching, and the as_* accessors).

Part of the tests/ir_wasm package; see tests/ir_wasm/__init__.py for
the growth convention. The shared _parse_lower / skip gates live in
tests/ir_wasm/_helpers.py.
"""

from __future__ import annotations

import unittest

from tests.ir_wasm._helpers import _parse_lower, _has_wasm_tools, _has_wasmtime_py
from capa.ir import compile_wasm


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestWasmJson(unittest.TestCase):
    """Phase 6G end-to-end JsonValue support: variant constructors,
    method dispatch (as_X / is_null), and the parse_json / to_json
    host bridge.

    Each test drives a small main() through the WasmHost so the
    full pipeline (CIR -> WAT -> wasm -> host imports) is
    exercised. Output is checked against the expected stdout."""

    def _run_capturing_stdout(self, src: str) -> str:
        import io
        import sys
        from capa.runtime._wasm_host import WasmHost
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types)
        host = WasmHost()
        out = io.StringIO()
        saved_out = sys.stdout
        sys.stdout = out
        try:
            host.run_main(blob)
        finally:
            sys.stdout = saved_out
        return out.getvalue()

    def test_jstr_construct_and_match(self):
        src = (
            'fun main(stdio: Stdio)\n'
            '    let j = JStr("hello")\n'
            '    match j\n'
            '        JStr(s) -> stdio.println(s)\n'
            '        _ -> stdio.println("other")\n'
        )
        self.assertEqual(self._run_capturing_stdout(src), "hello\n")

    def test_jnum_construct_and_match(self):
        src = (
            'fun main(stdio: Stdio)\n'
            '    let j = JNum(3.5)\n'
            '    match j\n'
            '        JNum(v) -> stdio.println("got ${v}")\n'
            '        _       -> stdio.println("other")\n'
        )
        self.assertEqual(
            self._run_capturing_stdout(src), "got 3.5\n",
        )

    def test_jnull_via_parse(self):
        # JNull as a bare identifier hits a gap in the IR lowerer
        # (it only registers user-declared payloadless variants);
        # exercise the same code path via parse_json("null") which
        # produces a JNull, then is_null() projects it back to Bool.
        src = (
            'fun main(stdio: Stdio)\n'
            '    match parse_json("null")\n'
            '        Ok(jv) ->\n'
            '            if jv.is_null()\n'
            '                stdio.println("null")\n'
            '            else\n'
            '                stdio.println("not null")\n'
            '        Err(_) -> stdio.println("parse err")\n'
        )
        self.assertEqual(self._run_capturing_stdout(src), "null\n")

    def test_as_string_some_on_jstr(self):
        src = (
            'fun main(stdio: Stdio)\n'
            '    let j = JStr("abc")\n'
            '    match j.as_string()\n'
            '        Some(s) -> stdio.println("got ${s}")\n'
            '        None    -> stdio.println("none")\n'
        )
        self.assertEqual(self._run_capturing_stdout(src), "got abc\n")

    def test_as_string_none_on_other_variant(self):
        src = (
            'fun main(stdio: Stdio)\n'
            '    let j = JNum(1.0)\n'
            '    match j.as_string()\n'
            '        Some(_) -> stdio.println("got string")\n'
            '        None    -> stdio.println("none")\n'
        )
        self.assertEqual(self._run_capturing_stdout(src), "none\n")

    def test_as_int_some_on_integer_valued_jnum(self):
        # Audit 2026-05-25 parity fix: integer-valued JNum (1.0,
        # -7.0) projects to Some(int). Both backends must agree.
        src = (
            'fun main(stdio: Stdio)\n'
            '    let j = JNum(7.0)\n'
            '    match j.as_int()\n'
            '        Some(n) -> stdio.println("got ${n}")\n'
            '        None    -> stdio.println("none")\n'
        )
        self.assertEqual(self._run_capturing_stdout(src), "got 7\n")

    def test_as_int_none_on_non_integer_jnum(self):
        # Audit 2026-05-25 parity fix: non-integer JNum (3.14)
        # must return None on both backends. Wasm used to truncate
        # unconditionally and return Some(3); now it checks for
        # zero fractional first.
        src = (
            'fun main(stdio: Stdio)\n'
            '    let j = JNum(3.14)\n'
            '    match j.as_int()\n'
            '        Some(n) -> stdio.println("got ${n}")\n'
            '        None    -> stdio.println("none")\n'
        )
        self.assertEqual(self._run_capturing_stdout(src), "none\n")

    def test_as_int_none_on_non_jnum_variant(self):
        # Sanity: non-JNum variants are unconditionally None on
        # both backends. This branch already worked but lock it in
        # so a future refactor of the as_int dispatch doesn't
        # regress it.
        src = (
            'fun main(stdio: Stdio)\n'
            '    let j = JStr("not a number")\n'
            '    match j.as_int()\n'
            '        Some(n) -> stdio.println("got ${n}")\n'
            '        None    -> stdio.println("none")\n'
        )
        self.assertEqual(self._run_capturing_stdout(src), "none\n")

    def test_parse_json_array(self):
        src = (
            'fun main(stdio: Stdio)\n'
            '    let txt = "[1, 2, 3]"\n'
            '    match parse_json(txt)\n'
            '        Ok(jv) ->\n'
            '            match jv.as_array()\n'
            '                Some(arr) -> stdio.println("len=${arr.length()}")\n'
            '                None      -> stdio.println("not array")\n'
            '        Err(_) -> stdio.println("parse error")\n'
        )
        self.assertEqual(self._run_capturing_stdout(src), "len=3\n")

    def test_parse_json_object_key_lookup(self):
        src = (
            'fun main(stdio: Stdio)\n'
            '    let txt = "{\\"name\\": \\"alice\\"}"\n'
            '    match parse_json(txt)\n'
            '        Ok(jv) ->\n'
            '            match jv.as_object()\n'
            '                Some(obj) ->\n'
            '                    match obj.get("name")\n'
            '                        Some(jname) ->\n'
            '                            match jname.as_string()\n'
            '                                Some(s) -> stdio.println(s)\n'
            '                                None    -> stdio.println("not string")\n'
            '                        None -> stdio.println("no key")\n'
            '                None -> stdio.println("not object")\n'
            '        Err(_) -> stdio.println("parse error")\n'
        )
        self.assertEqual(self._run_capturing_stdout(src), "alice\n")

    def test_parse_json_malformed_returns_err(self):
        src = (
            'fun main(stdio: Stdio)\n'
            '    match parse_json("not json")\n'
            '        Ok(_) -> stdio.println("unexpected ok")\n'
            '        Err(_) -> stdio.println("got err")\n'
        )
        self.assertEqual(self._run_capturing_stdout(src), "got err\n")

    def test_to_json_array_round_trip(self):
        src = (
            'fun main(stdio: Stdio)\n'
            '    let built = JArr([JStr("a"), JNum(1.5), JBool(true)])\n'
            '    stdio.println(to_json(built))\n'
        )
        self.assertEqual(
            self._run_capturing_stdout(src), '["a", 1.5, true]\n',
        )

    def test_parse_json_deeply_nested_within_limit_succeeds(self):
        # 50 nested arrays is well under the 100-level cap.
        # Builds ``[[[ ... [] ... ]]]`` at runtime and parses it.
        # The parse must succeed; the result is an array of arrays
        # ending in an empty list.
        src = (
            'fun main(stdio: Stdio)\n'
            '    var s = ""\n'
            '    var i = 0\n'
            '    while i < 50\n'
            '        s = s + "["\n'
            '        i = i + 1\n'
            '    i = 0\n'
            '    while i < 50\n'
            '        s = s + "]"\n'
            '        i = i + 1\n'
            '    match parse_json(s)\n'
            '        Ok(_)  -> stdio.println("ok")\n'
            '        Err(_) -> stdio.println("err")\n'
        )
        self.assertEqual(self._run_capturing_stdout(src), "ok\n")

    def test_parse_json_exceeds_depth_limit_returns_err(self):
        # Audit 2026-05-25 H4: pre-fix the parser recursed without
        # bound, so adversarial ``[[[ ... ]]]`` input was a DoS
        # surface (Wasm stack trap or deep recursion before failing).
        # Post-fix 150 levels exceeds the 100-level cap and the
        # parser returns Err(...) cleanly with a "max nesting depth"
        # diagnostic.
        src = (
            'fun main(stdio: Stdio)\n'
            '    var s = ""\n'
            '    var i = 0\n'
            '    while i < 150\n'
            '        s = s + "["\n'
            '        i = i + 1\n'
            '    i = 0\n'
            '    while i < 150\n'
            '        s = s + "]"\n'
            '        i = i + 1\n'
            '    match parse_json(s)\n'
            '        Ok(_)   -> stdio.println("unexpected ok")\n'
            '        Err(msg) -> stdio.println(msg)\n'
        )
        out = self._run_capturing_stdout(src)
        self.assertIn("max nesting depth", out)

    def test_parse_json_deeply_nested_objects_capped(self):
        # Same cap applies to nested objects: 150 nested ``{"k":...}``
        # exceeds the depth limit.
        src = (
            'fun main(stdio: Stdio)\n'
            '    var s = ""\n'
            '    var i = 0\n'
            '    while i < 150\n'
            '        s = s + "{\\"k\\":"\n'
            '        i = i + 1\n'
            '    s = s + "null"\n'
            '    i = 0\n'
            '    while i < 150\n'
            '        s = s + "}"\n'
            '        i = i + 1\n'
            '    match parse_json(s)\n'
            '        Ok(_)    -> stdio.println("unexpected ok")\n'
            '        Err(msg) -> stdio.println(msg)\n'
        )
        out = self._run_capturing_stdout(src)
        self.assertIn("max nesting depth", out)
