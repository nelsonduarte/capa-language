"""WebAssembly backend: WIT (component interface) generation.

Part of the tests/ir_wasm package; see tests/ir_wasm/__init__.py for
the growth convention. The shared _parse_lower / skip gates live in
tests/ir_wasm/_helpers.py.
"""

from __future__ import annotations

import unittest

from tests.ir_wasm._helpers import _parse_lower
from capa.ir import emit_wit, collect_used_capabilities, UnsupportedCapabilityMethod, MainReturnTypeUnsupported


class TestWitGeneration(unittest.TestCase):
    """Phase 6B: WIT file generation from CIR. Tests the structural
    output (interface declarations + world) for canonical programs.
    Does not shell out to wasm-tools; just checks the textual form."""

    def test_program_with_stdio_emits_stdio_interface(self):
        src = (
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"hi\")\n"
        )
        ir_mod, _, _ = _parse_lower(src)
        wit = emit_wit(ir_mod)
        self.assertIn("package capa:host;", wit)
        self.assertIn("interface stdio {", wit)
        self.assertIn("println: func(msg: string);", wit)
        self.assertIn("world program {", wit)
        self.assertIn("import stdio;", wit)

    def test_program_using_multiple_stdio_methods(self):
        src = (
            "fun main(stdio: Stdio)\n"
            "    stdio.print(\"a\")\n"
            "    stdio.println(\"b\")\n"
            "    stdio.eprintln(\"err\")\n"
        )
        ir_mod, _, _ = _parse_lower(src)
        wit = emit_wit(ir_mod)
        # All three methods must show up. Order is deterministic
        # (we sort by name) but using substring search across
        # "print:" / "println:" is brittle because "print" is a
        # prefix of "println"; check on full lines instead.
        self.assertIn("print: func(msg: string);", wit)
        self.assertIn("println: func(msg: string);", wit)
        self.assertIn("eprintln: func(msg: string);", wit)

    def test_program_without_capabilities_has_no_imports(self):
        src = (
            "fun add(a: Int, b: Int) -> Int\n"
            "    return a + b\n"
        )
        ir_mod, _, _ = _parse_lower(src)
        wit = emit_wit(ir_mod)
        # The world is still emitted (caller may want to package it
        # as a component) but with no imports.
        self.assertIn("world program {", wit)
        self.assertNotIn("interface", wit)
        self.assertNotIn("import", wit)

    def test_collect_used_capabilities_groups_by_capability(self):
        src = (
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"a\")\n"
            "    stdio.eprintln(\"b\")\n"
        )
        ir_mod, _, _ = _parse_lower(src)
        used = collect_used_capabilities(ir_mod)
        self.assertEqual(used, {"Stdio": {"println", "eprintln"}})

    def test_unsupported_cap_method_raises_at_wit_gen(self):
        # ``UnsupportedCapabilityMethod`` is the precise error the WIT
        # generator raises when a CIR ``MethodCall`` references a
        # capability method that has no signature in ``_WIT_SIGNATURES``.
        # ``Stdio.read_line`` used to be the canary here; slice 1 of
        # the Wasm-fully-functional arc closed that gap, so we drive
        # the error path via a synthetic ``MethodCall`` instead. This
        # keeps the contract (raise loudly, never silently emit a
        # half-defined interface) under test even as the supported set
        # grows toward full coverage.
        from capa.ir._nodes import (
            Module, Function, MethodCall, Value, Param,
        )
        # Hand-build a one-instr module that calls a non-existent
        # method. ``cap_used="Stdio"`` makes the WIT walker classify
        # the receiver as the built-in cap; the method name is novel
        # so the lookup misses and the exception fires.
        recv = Value(kind="param", name="stdio", ty="Stdio")
        fake = MethodCall(
            dst=None, receiver=recv,
            method="not_a_real_method", args=[],
            cap_used="Stdio",
        )
        fn = Function(
            name="main",
            params=[Param(name="stdio", ty="Stdio", is_capability=True)],
            return_type="",
            declared_caps=["Stdio"],
            body=[fake],
        )
        ir_mod = Module(types=[], functions=[fn])
        with self.assertRaises(UnsupportedCapabilityMethod):
            emit_wit(ir_mod)

    def test_main_returning_unit_has_no_result_clause(self):
        # Baseline / no-regression: a plain ``fun main`` (Unit return)
        # keeps the historical ``export main: func();`` shape with no
        # result clause, matching the core module's Unit ``main``.
        src = (
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"hi\")\n"
        )
        ir_mod, _, _ = _parse_lower(src)
        wit = emit_wit(ir_mod)
        self.assertIn("export main: func();", wit)
        self.assertNotIn("export main: func() ->", wit)

    def test_main_returning_explicit_empty_tuple_is_unit(self):
        # An EXPLICIT ``fun main -> ()`` lowers ``return_type`` to the
        # AST repr ``UnitType(pos=...)`` (not the literal ``"Unit"``).
        # The result-clause helper must treat it as Unit (no clause),
        # NOT mis-classify it as an unsupported composite and raise
        # ``MainReturnTypeUnsupported`` with an ugly AST repr in the
        # message. (The core emitter still rejects ``-> ()`` later with
        # its own pre-existing "no Wasm encoding" error; that is out of
        # scope -- here we only pin that the WIT layer emits the
        # trivial ``func();`` and never leaks the repr.)
        src = (
            "fun main(stdio: Stdio) -> ()\n"
            "    stdio.println(\"hi\")\n"
        )
        ir_mod, _, _ = _parse_lower(src)
        wit = emit_wit(ir_mod)
        self.assertIn("export main: func();", wit)
        self.assertNotIn("export main: func() ->", wit)
        self.assertNotIn("UnitType", wit)

    def test_main_returning_int_emits_s64_result(self):
        # ``main -> Int``: the core module returns ``(result i64)``,
        # so the WIT world must advertise ``-> s64`` (Capa Int is
        # signed) or ``wasm-tools component new`` rejects the artifact
        # with a core-vs-world result mismatch.
        src = (
            "fun main(stdio: Stdio) -> Int\n"
            "    stdio.println(\"hi\")\n"
            "    return 7\n"
        )
        ir_mod, _, _ = _parse_lower(src)
        wit = emit_wit(ir_mod)
        self.assertIn("export main: func() -> s64;", wit)

    def test_main_returning_float_emits_f64_result(self):
        src = (
            "fun main(stdio: Stdio) -> Float\n"
            "    stdio.println(\"hi\")\n"
            "    return 1.5\n"
        )
        ir_mod, _, _ = _parse_lower(src)
        wit = emit_wit(ir_mod)
        self.assertIn("export main: func() -> f64;", wit)

    def test_main_returning_bool_emits_bool_result(self):
        src = (
            "fun main(stdio: Stdio) -> Bool\n"
            "    stdio.println(\"hi\")\n"
            "    return true\n"
        )
        ir_mod, _, _ = _parse_lower(src)
        wit = emit_wit(ir_mod)
        self.assertIn("export main: func() -> bool;", wit)

    def test_main_result_clause_present_with_handle_params(self):
        # The result clause must sit AFTER the cap-handle param list,
        # so a ``main`` with both handle params and a scalar return
        # produces ``export main: func(cap0-fs: u32) -> s64;``. Guards
        # the ordering the shared ``main_result_clause`` helper appends.
        src = (
            "fun main(stdio: Stdio, fs: Fs) -> Int\n"
            "    let _e = fs.exists(\"/nope\")\n"
            "    stdio.println(\"hi\")\n"
            "    return 3\n"
        )
        ir_mod, _, _ = _parse_lower(src)
        wit = emit_wit(ir_mod)
        self.assertIn("export main: func(cap0-fs: u32) -> s64;", wit)

    def test_main_returning_string_rejected_with_clear_error(self):
        # ``main -> String``: the core returns a flattened (i32 i32)
        # multi-value the Component Model canonical ABI cannot lift
        # from a WIT ``string`` result (it demands an indirect return
        # area). Rather than surface the cryptic wasm-tools mismatch,
        # the WIT generator raises a clear Capa compile-time error.
        src = (
            "fun main(stdio: Stdio) -> String\n"
            "    stdio.println(\"hi\")\n"
            "    return \"x\"\n"
        )
        ir_mod, _, _ = _parse_lower(src)
        with self.assertRaises(MainReturnTypeUnsupported) as ctx:
            emit_wit(ir_mod)
        self.assertIn("String", str(ctx.exception))

    def test_main_returning_struct_rejected_with_clear_error(self):
        # A composite (Struct) return on ``main`` is likewise rejected
        # at WIT generation with the actionable Capa error, not the raw
        # component-linker mismatch.
        src = (
            "type Point { x: Int, y: Int }\n"
            "fun main(stdio: Stdio) -> Point\n"
            "    stdio.println(\"hi\")\n"
            "    return Point(x: 1, y: 2)\n"
        )
        ir_mod, _, _ = _parse_lower(src)
        with self.assertRaises(MainReturnTypeUnsupported):
            emit_wit(ir_mod)

    def test_parse_json_does_not_emit_host_json_interface(self):
        # Audit 2026-05-25 (item #3): parse_json / to_json are
        # bundled into the guest module via
        # ``capa.ir._builtin_json.inject_into``; the Wasm side never
        # imports a ``capa:host/json`` interface. The WIT emitter
        # used to keep emitting ``interface json`` and ``import
        # json``, contradicting what the component actually consumes.
        src = (
            "fun main(stdio: Stdio)\n"
            "    let s = \"abc\"\n"
            "    let r = parse_json(s)\n"
            "    stdio.println(\"parsed\")\n"
        )
        ir_mod, _, _ = _parse_lower(src)
        wit = emit_wit(ir_mod)
        self.assertNotIn("interface json", wit)
        self.assertNotIn("import json", wit)
        self.assertIn("interface stdio", wit)

    def test_to_json_does_not_emit_host_json_interface(self):
        # Same as the parse_json case, but exercising the serialise
        # direction as well so both bundled functions are covered.
        # The ``?`` operator needs a Result-returning function, so the
        # json round-trip lives in a helper; ``main`` stays Unit so the
        # world export is the trivial ``func()`` shape (a composite /
        # Result return on ``main`` itself is unsupported by the
        # component backend -- see the main-return-type tests above).
        src = (
            "fun roundtrip() -> Result<String, String>\n"
            "    let jv = parse_json(\"[1,2]\")?\n"
            "    return Ok(to_json(jv))\n"
            "fun main(stdio: Stdio)\n"
            "    match roundtrip()\n"
            "        Ok(back) -> stdio.println(back)\n"
            "        Err(_) -> stdio.eprintln(\"bug\")\n"
        )
        ir_mod, _, _ = _parse_lower(src)
        wit = emit_wit(ir_mod)
        self.assertNotIn("interface json", wit)
        self.assertNotIn("import json", wit)

    def test_wit_and_wasm_discovery_agree_on_used_caps(self):
        # Cross-side parity: the WIT and Wasm emitters must compute
        # the same used-capability set for the same module, otherwise
        # ``--component --run`` either misses a host import or
        # publishes a phantom one. Audit 2026-05-25.
        from capa.ir._emit_wasm import WasmEmitter

        src = (
            "fun main(stdio: Stdio)\n"
            "    let s = \"abc\"\n"
            "    let r = parse_json(s)\n"
            "    stdio.println(\"x\")\n"
        )
        ir_mod, _, _ = _parse_lower(src)
        wit_used = set(collect_used_capabilities(ir_mod).keys())

        emitter = WasmEmitter()
        for fn in ir_mod.functions:
            emitter._discover_instrs(fn.body)
        wasm_used = {cap for (cap, _method) in emitter._used_caps}

        self.assertEqual(wit_used, wasm_used)
