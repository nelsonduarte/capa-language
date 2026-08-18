# pyright: reportCallIssue=none
"""Gating tests for the C-F2 Wasm-codegen soundness fix.

C-F2: on the Wasm backend a ``match`` / destructure whose PATTERN
carries a String literal that appears NOWHERE ELSE in the module
read unemitted / dangling memory -- ``$str_eq`` compared against an
offset that was bumped past the frozen ``heap_start`` and never
written to a ``(data ...)`` block. Layout-dependent: usually a
silent wrong branch (fail-closed miss), occasionally a spurious
match (an authorization bypass). See ``capa/ir/_emit_wasm/
_discovery.py`` (``_pattern_str_literals`` + the ``Match`` branch in
``_discover_instrs``) for the fix.

Every fixture here heap-CONSTRUCTS the scrutinee / needle via string
interpolation of locals, so the pattern literal's bytes surface
ONLY in the pattern -- the exact condition that triggered the bug.
The parity corpus (``tests/test_ir_wasm_parity.py``) does NOT cover
this class: its match programs also print or otherwise materialise
their pattern literals, which masks the missing ``(data ...)`` block.

Each output-parity fixture is checked across ALL THREE backends
(legacy Python == CIR Python == Wasm), the same trio the CLI drives
via ``--run`` / ``--run --ir`` / ``--run --wasm``; the guarantee is
byte-identical program OUTPUT (benign WAT offset shifts are fine).
The two WAT-level tests (F2-W4 data blocks, the high-water guard)
drive ``compile_wat`` / ``compile_wasm`` directly.
"""

from __future__ import annotations

import unittest
from unittest import mock

from capa.ir import compile_wasm, compile_wat
from capa.ir._emit_wasm._layout import WasmEmissionError

from tests.test_ir_wasm_parity import (
    _capture_stdout,
    _has_wasm_tools,
    _has_wasmtime_py,
    _parse_and_analyze,
    _run_cir,
    _run_python,
    _run_wasm,
)


def _three_backend_outputs(src: str) -> tuple[str, str, str]:
    """Return (legacy-Python, CIR-Python, Wasm) stdout for ``src``."""
    py = _capture_stdout(lambda: _run_python(src))
    cir = _capture_stdout(lambda: _run_cir(src))
    wasm = _capture_stdout(lambda: _run_wasm(src))
    return py, cir, wasm


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestPatternLiteralInterning(unittest.TestCase):
    """Three-backend byte-identical OUTPUT for each of the five
    String-pattern-literal emit sites, each with a heap-built
    scrutinee so the literal appears nowhere else."""

    def _assert_three_backend(
        self, src: str, expected: str, *, include_cir: bool = True,
    ) -> None:
        py = _capture_stdout(lambda: _run_python(src))
        wasm = _capture_stdout(lambda: _run_wasm(src))
        # The CIR Python emitter (the ``--ir`` path) predates PatStruct
        # support, so a struct-pattern program cannot run under it; the
        # existing parity corpus diffs such programs legacy-Python vs
        # Wasm only. That gap is pre-existing and out of scope for the
        # C-F2 fix (which is Wasm-only), so callers opt out of the CIR
        # leg there.
        if include_cir:
            cir = _capture_stdout(lambda: _run_cir(src))
            self.assertEqual(
                py, cir,
                f"legacy-Python vs CIR-Python diverge:\n"
                f"--- py ---\n{py}\n--- cir ---\n{cir}",
            )
        self.assertEqual(py, wasm, f"Python vs Wasm diverge:\n"
                                   f"--- py ---\n{py}\n--- wasm ---\n{wasm}")
        self.assertEqual(py, expected, f"unexpected output:\n{py}")

    def test_site2_top_level_scrutinee(self):
        # Site 2: top-level String scrutinee -- the "wizard" repro.
        # ``classify(built)`` must be granted on all three backends;
        # pre-fix the Wasm run denied it (dangling $str_eq compare).
        src = (
            "fun classify(role: String) -> String\n"
            "    return match role\n"
            '        "wizard" -> "granted"\n'
            '        _ -> "denied"\n'
            "\n"
            "fun main(stdio: Stdio)\n"
            '    let a = "wiz"\n'
            '    let b = "ard"\n'
            '    stdio.println(classify("${a}${b}"))\n'
            '    let c = "no"\n'
            '    let d = "pe"\n'
            '    stdio.println(classify("${c}${d}"))\n'
        )
        self._assert_three_backend(src, "granted\ndenied\n")

    def test_site1_variant_payload(self):
        # Site 1: a String literal in a variant payload, Ok("yes"),
        # with a heap-built Ok payload.
        src = (
            "fun answer(reply: Result<String, String>) -> String\n"
            "    return match reply\n"
            '        Ok("yes") -> "agreed"\n'
            '        Ok(other) -> "other: ${other}"\n'
            '        Err(e) -> "err: ${e}"\n'
            "\n"
            "fun main(stdio: Stdio)\n"
            '    let a = "ye"\n'
            '    let b = "s"\n'
            '    let built: Result<String, String> = Ok("${a}${b}")\n'
            "    stdio.println(answer(built))\n"
            '    let c = "n"\n'
            '    let d = "o"\n'
            '    let other: Result<String, String> = Ok("${c}${d}")\n'
            "    stdio.println(answer(other))\n"
        )
        self._assert_three_backend(src, "agreed\nother: no\n")

    def test_site3_tuple_element(self):
        # Site 3: a String literal as a tuple element, ("yes", n),
        # with a heap-built first element.
        src = (
            "fun check(p: (String, Int)) -> String\n"
            "    return match p\n"
            '        ("yes", n) -> "yes ${n}"\n'
            '        (other, n) -> "${other} ${n}"\n'
            "\n"
            "fun main(stdio: Stdio)\n"
            '    let a = "ye"\n'
            '    let b = "s"\n'
            '    stdio.println(check(("${a}${b}", 7)))\n'
            '    let c = "n"\n'
            '    let d = "o"\n'
            '    stdio.println(check(("${c}${d}", 3)))\n'
        )
        self._assert_three_backend(src, "yes 7\nno 3\n")

    def test_site4_struct_field(self):
        # Site 4: a String literal as a struct field, P { name: "bob" },
        # with a heap-built field value.
        src = (
            "type P { name: String, age: Int }\n"
            "\n"
            "fun check(p: P) -> String\n"
            "    return match p\n"
            '        P { name: "bob", age: a } -> "bob ${a}"\n'
            '        P { name: u, age: a } -> "${u} ${a}"\n'
            "\n"
            "fun main(stdio: Stdio)\n"
            '    let a = "bo"\n'
            '    let b = "b"\n'
            '    stdio.println(check(P { name: "${a}${b}", age: 5 }))\n'
            '    let c = "sa"\n'
            '    let d = "m"\n'
            '    stdio.println(check(P { name: "${c}${d}", age: 9 }))\n'
        )
        # CIR-Python has no PatStruct support (pre-existing); diff
        # legacy-Python vs Wasm, as the parity corpus does for struct
        # patterns.
        self._assert_three_backend(
            src, "bob 5\nsam 9\n", include_cir=False,
        )

    def test_site5_guarded_arm(self):
        # Site 5: a String literal arm in a match that carries a guard
        # (the guard routes the whole match through the flat-block
        # guarded emission path), with the literal heap-built at every
        # call site.
        src = (
            "fun check(role: String, n: Int) -> String\n"
            "    return match role\n"
            '        "super" if n > 0 -> "super pos"\n'
            '        "super" -> "super nonpos"\n'
            '        _ -> "other"\n'
            "\n"
            "fun main(stdio: Stdio)\n"
            '    let a = "su"\n'
            '    let b = "per"\n'
            '    stdio.println(check("${a}${b}", 1))\n'
            '    stdio.println(check("${a}${b}", 0))\n'
            '    let c = "no"\n'
            '    let d = "pe"\n'
            '    stdio.println(check("${c}${d}", 1))\n'
        )
        self._assert_three_backend(
            src, "super pos\nsuper nonpos\nother\n",
        )

    def test_nested_pattern_literal(self):
        # Nesting: a String literal two levels down, Some(Ok("deep")),
        # with a heap-built payload. Exercises the recursive collector.
        src = (
            "fun classify(v: Option<Result<String, Int>>) -> String\n"
            "    return match v\n"
            '        Some(Ok("deep")) -> "found"\n'
            '        Some(Ok(other)) -> "ok: ${other}"\n'
            '        Some(Err(n)) -> "err: ${n}"\n'
            '        None -> "none"\n'
            "\n"
            "fun main(stdio: Stdio)\n"
            '    let a = "de"\n'
            '    let b = "ep"\n'
            '    let built: Option<Result<String, Int>> = Some(Ok("${a}${b}"))\n'
            "    stdio.println(classify(built))\n"
            '    let c = "sha"\n'
            '    let d = "llow"\n'
            '    let other: Option<Result<String, Int>> = Some(Ok("${c}${d}"))\n'
            "    stdio.println(classify(other))\n"
        )
        self._assert_three_backend(src, "found\nok: shallow\n")

    def test_spurious_grant_same_length(self):
        # Security shape: an admin-granting arm ``"admin"`` (5 bytes)
        # matched against a heap-built 5-byte unknown role ``"guest"``.
        # A dangling $str_eq against undefined memory can spuriously
        # match a same-length needle; on Wasm the unknown role must
        # NEVER take the admin branch. All three backends must deny.
        src = (
            "fun auth(role: String) -> String\n"
            "    return match role\n"
            '        "admin" -> "GRANT"\n'
            '        _ -> "deny"\n'
            "\n"
            "fun main(stdio: Stdio)\n"
            '    let a = "gu"\n'
            '    let b = "est"\n'
            '    stdio.println(auth("${a}${b}"))\n'
        )
        self._assert_three_backend(src, "deny\n")

    def test_dedup_noop_when_materialised_elsewhere(self):
        # Dedup path: the pattern literal is ALSO printed, so it is
        # interned during the normal value walk regardless. Interning
        # it again from the pattern branch must be a no-op returning the
        # cached offset -- output stays granted, byte-identical.
        src = (
            "fun classify(role: String) -> String\n"
            "    return match role\n"
            '        "wizard" -> "granted"\n'
            '        _ -> "denied"\n'
            "\n"
            "fun main(stdio: Stdio)\n"
            '    stdio.println("wizard")\n'
            '    let a = "wiz"\n'
            '    let b = "ard"\n'
            '    stdio.println(classify("${a}${b}"))\n'
        )
        self._assert_three_backend(src, "wizard\ngranted\n")


class TestFsFixedErrorStringsHoisted(unittest.TestCase):
    """F2-W4: the four FIXED Fs Err messages must be pre-interned for
    a DYNAMIC-preopen program too (``wasi_dynamic_fs=True``, the
    ceiling is open), not only inside the static ``closed`` branch.
    Pre-fix each message got a valid offset but no ``(data ...)``
    block; post-fix it appears in a data block."""

    _SRC = (
        "fun main(fs: Fs, env: Env, stdio: Stdio)\n"
        "    let args = env.args()\n"
        "    match args.get(0)\n"
        "        Some(p) ->\n"
        "            match fs.read(p)\n"
        "                Ok(c) -> stdio.println(c)\n"
        '                Err(e) -> stdio.println("read err")\n'
        '            match fs.write(p, "data")\n'
        '                Ok(_) -> stdio.println("wrote")\n'
        '                Err(e) -> stdio.println("write err")\n'
        "            match fs.list_dir(p)\n"
        '                Ok(items) -> stdio.println("listed")\n'
        '                Err(e) -> stdio.println("list err")\n'
        "            match fs.mkdir(p)\n"
        '                Ok(_) -> stdio.println("made")\n'
        '                Err(e) -> stdio.println("mkdir err")\n'
        '        None -> stdio.println("none")\n'
    )

    _MESSAGES = (
        "mkdir failed",
        "failed to read file",
        "failed to write file",
        "failed to list directory",
    )

    def test_fixed_error_strings_in_data_blocks(self):
        module, result = _parse_and_analyze(self._SRC)
        wat = compile_wat(
            module, types=result.types, wasi=True, wasi_dynamic_fs=True,
        )
        for msg in self._MESSAGES:
            # Each interned string is written as exactly one
            # ``(data (i32.const N) "<msg>")`` block. Pre-fix count 0,
            # post-fix count 1.
            self.assertEqual(
                wat.count(f'"{msg}"'), 1,
                msg=f"expected one (data ...) block for {msg!r}",
            )


class TestHighWaterGuardFires(unittest.TestCase):
    """The step-3 high-water guard must BITE, not merely run: with the
    step-1 pattern pre-intern suppressed, a pattern-only literal is
    first seen at match-emit time (past the frozen data segment) and
    ``_intern_string`` must raise ``WasmEmissionError`` naming it."""

    _SRC = (
        "fun classify(role: String) -> String\n"
        "    return match role\n"
        '        "wizard" -> "granted"\n'
        '        _ -> "denied"\n'
        "\n"
        "fun main(stdio: Stdio)\n"
        '    let a = "wiz"\n'
        '    let b = "ard"\n'
        '    stdio.println(classify("${a}${b}"))\n'
    )

    def test_guard_raises_on_post_freeze_new_string(self):
        module, result = _parse_and_analyze(self._SRC)
        # Suppress the step-1 pattern-literal pre-intern so "wizard" is
        # never interned during discovery; the match emitter is then
        # the first to see it, after the data segment is frozen.
        with mock.patch(
            "capa.ir._emit_wasm._discovery._pattern_str_literals",
            lambda pat: iter(()),
        ):
            with self.assertRaises(WasmEmissionError) as cm:
                compile_wasm(module, types=result.types)
        self.assertIn("wizard", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
