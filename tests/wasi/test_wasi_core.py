"""WASI mode: core capabilities (Random / Clock) and cross-capability
mechanisms.

WIT generation, emitter rejections, flag guards, the wasm-output core-module
message, WIT license headers, the Random / Clock hybrid end-to-end run, the
Env-ceiling const-propagation, and the Stdio parity / stdin-readline / path-arg
surfaces. Split out of tests/test_wasi_mode.py; see tests/wasi/__init__.py for
the growth convention. The shared primitives and the Env fixtures live in
tests/wasi/_helpers.py.
"""

from __future__ import annotations

import io
import sys
import time
import unittest

from tests.wasi._helpers import (
    _ENV_ARGS_SRC,
    _ENV_ATTEN_SRC,
    _ENV_GET_SRC,
    _ENV_HYBRID_SRC,
    _REPO_ROOT,
    _build_wasi_component,
    _has_wasm_tools,
    _has_wasmtime_wasip2,
    _parse_analyze,
    _run_python,
    _run_wasi_component,
    _wasi_run_capture,
)


def _wasi_run_capture_stderr(host, comp) -> tuple[str, str]:
    """Like ``_wasi_run_capture`` but returns ``(stdout, stderr)``, both
    read from the host's captured buffers. Used by the Stdio parity
    tests that assert eprintln lands on a stream distinct from stdout.
    Suppresses the live echo the same way ``_wasi_run_capture`` does
    (throwaway redirect), reading the assertions from the captured
    buffers."""
    so, se = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = io.StringIO(), io.StringIO()
    try:
        host.run_main(comp)
    finally:
        sys.stdout, sys.stderr = so, se
    return (
        host.captured_stdout().decode("utf-8", errors="surrogatepass"),
        host.captured_stderr().decode("utf-8", errors="surrogatepass"),
    )


_SEEDED_SRC = """
fun main(stdio: Stdio, rng: Random)
    let seeded = rng.with_seed(42)
    var i = 0
    while i < 10
        stdio.println("${seeded.int_range(0, 100)}")
        i = i + 1
"""

_CLOCK_SRC = """
fun main(stdio: Stdio, clock: Clock)
    let m1 = clock.now_monotonic()
    let m2 = clock.now_monotonic()
    if m2 >= m1
        stdio.println("MONO_OK")
    else
        stdio.println("MONO_BAD")
    let s = clock.now_secs()
    stdio.println("WALL ${s}")
"""

_SYSRAND_SRC = """
fun main(stdio: Stdio, rng: Random)
    stdio.println("${rng.int_range(0, 1000000000)}")
"""

_HYBRID_SRC = """
fun main(stdio: Stdio, clock: Clock, rng: Random)
    let seeded = rng.with_seed(7)
    stdio.println("seeded ${seeded.int_range(0, 100)}")
    let m1 = clock.now_monotonic()
    let m2 = clock.now_monotonic()
    if m2 >= m1
        stdio.println("mono ok")
    let now = clock.now_secs()
    if now > 1700000000.0
        stdio.println("wall ok")
"""


class TestWasiWitGeneration(unittest.TestCase):
    """WIT shape is pure (no wasm-tools needed)."""

    def _wit(self, src: str) -> str:
        from capa.ir import compile_wit
        module, result = _parse_analyze(src)
        return compile_wit(module, types=result.types, wasi=True)

    def test_world_imports_wasi_interfaces(self):
        wit = self._wit(_HYBRID_SRC)
        self.assertIn("import wasi:random/random@0.2.0;", wit)
        self.assertIn("import wasi:clocks/monotonic-clock@0.2.0;", wit)
        self.assertIn("import wasi:clocks/wall-clock@0.2.0;", wit)

    def test_stdio_output_migrates_to_wasi_cli(self):
        # Stdio Phase 1 (2026-06-29): print / println / eprintln migrate
        # to wasi:cli/stdout|stderr. _HYBRID_SRC uses println only, so the
        # world imports wasi:cli/stdout (+ wasi:io/streams) and carries NO
        # capa:host stdio interface. (As of Phase 2 the WHOLE Stdio surface
        # is migrated off capa:host -- read_line too, to wasi:cli/stdin --
        # so no built-in Stdio method ever pulls a capa:host stdio
        # interface; read_line is simply absent from this program.)
        wit = self._wit(_HYBRID_SRC)
        self.assertIn("import wasi:cli/stdout@0.2.0;", wit)
        self.assertIn("import wasi:io/streams@0.2.0;", wit)
        self.assertNotIn("interface stdio {", wit)
        self.assertNotIn("  import stdio;", wit)
        # println writes to stdout, not stderr, so no get-stderr import.
        self.assertNotIn("import wasi:cli/stderr@0.2.0;", wit)

    def test_no_capa_host_random_or_clock_interface(self):
        # The migrated caps must NOT also emit a capa:host interface
        # (that would force the host to provide a stub the component
        # never imports).
        wit = self._wit(_HYBRID_SRC)
        self.assertNotIn("interface random {", wit)
        self.assertNotIn("interface clock {", wit)

    def test_default_mode_unchanged(self):
        # The default (non-WASI) WIT still uses capa:host for Random /
        # Clock; the flag is genuinely opt-in.
        from capa.ir import compile_wit
        module, result = _parse_analyze(_HYBRID_SRC)
        wit = compile_wit(module, types=result.types, wasi=False)
        self.assertIn("interface clock {", wit)
        self.assertNotIn("wasi:", wit)

    def test_env_world_imports_wasi_environment(self):
        wit = self._wit(_ENV_GET_SRC)
        self.assertIn("import wasi:cli/environment@0.2.0;", wit)

    def test_env_args_world_imports_wasi_environment(self):
        wit = self._wit(_ENV_ARGS_SRC)
        self.assertIn("import wasi:cli/environment@0.2.0;", wit)

    def test_no_capa_host_env_interface(self):
        # The migrated Env reader must NOT also emit a capa:host env
        # interface (that would force the host to provide a stub the
        # component never imports).
        wit = self._wit(_ENV_GET_SRC)
        self.assertNotIn("interface env {", wit)
        self.assertNotIn("  import env;", wit)

    def test_env_default_mode_unchanged(self):
        # The default (non-WASI) Env WIT still uses capa:host.
        from capa.ir import compile_wit
        module, result = _parse_analyze(_ENV_GET_SRC)
        wit = compile_wit(module, types=result.types, wasi=False)
        self.assertIn("interface env {", wit)
        self.assertNotIn("wasi:", wit)

    def test_env_hybrid_imports_all_three_wasi(self):
        wit = self._wit(_ENV_HYBRID_SRC)
        self.assertIn("import wasi:cli/environment@0.2.0;", wit)
        self.assertIn("import wasi:random/random@0.2.0;", wit)
        self.assertIn("import wasi:clocks/wall-clock@0.2.0;", wit)
        # Stdio Phase 1: println now routes to wasi:cli/stdout too, so the
        # program imports NO capa:host interface at all (Random / Clock /
        # Env / Stdio output are all on wasi:*); it is 100 % stock WASI.
        self.assertIn("import wasi:cli/stdout@0.2.0;", wit)
        self.assertNotIn("interface stdio {", wit)


class TestWasiEmitterRejections(unittest.TestCase):
    """The excluded surface is rejected at compile time (no
    wasm-tools needed)."""

    def _compile(self, src: str):
        from capa.ir import compile_wat
        module, result = _parse_analyze(src)
        return compile_wat(module, types=result.types, wasi=True)

    def test_sleep_rejected(self):
        src = """
fun main(stdio: Stdio, clock: Clock)
    clock.sleep(0.0)
    stdio.println("x")
"""
        with self.assertRaises(Exception) as cm:
            self._compile(src)
        self.assertIn("WASI mode", str(cm.exception))

    def test_attenuation_rejected(self):
        src = """
fun main(stdio: Stdio, clock: Clock)
    let c2 = clock.restrict_to_after(0.0)
    stdio.println("${c2.now_secs()}")
"""
        with self.assertRaises(Exception) as cm:
            self._compile(src)
        self.assertIn("WASI mode", str(cm.exception))

    def test_env_restrict_to_keys_accepted_guest_side(self):
        # Env attenuation is now SUPPORTED under --wasi, implemented
        # guest-side (Level 2). It compiles cleanly and emits the
        # guest-side $Env_restrict_to_keys wrapper (no host import).
        wat = self._compile(_ENV_ATTEN_SRC)
        self.assertIn("(func $Env_restrict_to_keys", wat)
        self.assertIn("(func $Env_allows", wat)
        self.assertIn("(func $Env_key_allowed", wat)
        # No capa:host env import is pulled in (the whole interface is
        # routed off capa:host in WASI mode).
        self.assertNotIn('"capa:host/env"', wat)
        # The narrowing has no host import string at all.
        self.assertNotIn("restrict-to-keys", wat)

    def test_env_get_fail_closed_consults_handle(self):
        # The $Env_get wrapper gains the guest-side fail-closed gate:
        # it calls $Env_key_allowed before reading the environment.
        wat = self._compile(_ENV_ATTEN_SRC)
        get_body = wat.split("(func $Env_get")[1].split("(func ")[0]
        self.assertIn("call $Env_key_allowed", get_body)

    def test_env_get_args_accepted(self):
        # The readers compile cleanly under --wasi (no rejection).
        wat = self._compile(_ENV_GET_SRC)
        self.assertIn("$Env_get", wat)
        self.assertIn("wasi:cli/environment@0.2.0", wat)
        wat_args = self._compile(_ENV_ARGS_SRC)
        self.assertIn("$Env_args", wat_args)


class TestWasiFlagGuards(unittest.TestCase):
    """``--wasi`` is rejected unless paired with ``--wasm --component``;
    these guards need no Wasm toolchain (they fail before compilation)."""

    def _run_cli(self, argv):
        import tempfile
        from pathlib import Path
        from capa.cli import main
        src = (
            "fun main(stdio: Stdio, rng: Random)\n"
            "    stdio.println(\"${rng.int_range(0, 10)}\")\n"
        )
        err = io.StringIO()
        old_err = sys.stderr
        old_argv = sys.argv
        sys.stderr = err
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "p.capa"
            f.write_text(src, encoding="utf-8")
            sys.argv = ["capa", *argv, str(f)]
            try:
                code = main()
            finally:
                sys.stderr = old_err
                sys.argv = old_argv
        return code, err.getvalue()

    def test_wasi_without_wasm_rejected(self):
        # Previously silently ignored (hit the pure-Python backend).
        code, err = self._run_cli(["--wasi", "--run"])
        self.assertEqual(code, 1)
        self.assertIn("--wasi requires --wasm", err)

    def test_wasi_without_component_rejected(self):
        code, err = self._run_cli(["--wasm", "--wasi", "--run"])
        self.assertEqual(code, 1)
        self.assertIn("--wasi requires --component", err)

    def test_wasi_without_component_message_pins_core_module(self):
        # Pin the FULL rejection wording (regression guard: the
        # ``ctx`` field rename once corrupted the ``core module`` literal
        # in this message to ``core ctx.module``). The prefix check above
        # would not have caught that.
        code, err = self._run_cli(["--wasm", "--wasi", "--run"])
        self.assertEqual(code, 1)
        self.assertIn(
            "the bare core module / core host has no WASI provider", err
        )


@unittest.skipUnless(_has_wasm_tools(), "wasm-tools not installed")
class TestWasmOutputCoreModuleMessage(unittest.TestCase):
    """``--wasm --output`` without ``--component`` writes a core module and
    reports it as ``core module``. Regression guard: the ``ctx`` field
    rename once corrupted the ``core module`` literal to ``core ctx.module``
    on this everyday success path (exit 0), which no other test sampled."""

    def test_output_core_module_message(self):
        import tempfile
        from pathlib import Path
        from capa.cli import main

        hello = _REPO_ROOT / "examples" / "wasm" / "hello.capa"
        err, out = io.StringIO(), io.StringIO()
        old_err, old_out, old_argv = sys.stderr, sys.stdout, sys.argv
        sys.stderr, sys.stdout = err, out
        with tempfile.TemporaryDirectory() as d:
            out_path = Path(d) / "core.wasm"
            sys.argv = ["capa", "--wasm", "--output", str(out_path), str(hello)]
            try:
                code = main()
            finally:
                sys.stderr, sys.stdout, sys.argv = old_err, old_out, old_argv
        self.assertEqual(code, 0, err.getvalue())
        # The success message is on stderr; it must read "core module".
        self.assertIn("wrote core module (", err.getvalue())


class TestWasiWitLicenseHeaders(unittest.TestCase):
    """Each vendored WIT carries its SPDX license + provenance header."""

    def _wit(self, *parts):
        from pathlib import Path
        return (
            _REPO_ROOT
            / "capa" / "wasi_wit" / "deps" / Path(*parts)
        ).read_text(encoding="utf-8")

    def test_random_spdx_header(self):
        text = self._wit("random", "random.wit")
        self.assertIn(
            "SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception", text
        )
        self.assertIn("wasi-random", text)

    def test_clocks_spdx_header(self):
        text = self._wit("clocks", "clocks.wit")
        self.assertIn(
            "SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception", text
        )
        self.assertIn("wasi-clocks", text)

    def test_cli_environment_spdx_header(self):
        text = self._wit("cli", "environment.wit")
        self.assertIn(
            "SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception", text
        )
        self.assertIn("wasi-cli", text)
        self.assertIn("get-environment", text)
        self.assertIn("get-arguments", text)

    def test_cli_stdin_spdx_header(self):
        # Phase 2 (2026-06-29): the vendored wasi:cli/stdin interface
        # (Stdio.read_line -> get-stdin) carries the same SPDX + provenance
        # header as the other cli files, and omits the package declaration
        # (which lives only in environment.wit).
        text = self._wit("cli", "stdin.wit")
        self.assertIn(
            "SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception", text
        )
        self.assertIn("wasi-cli", text)
        self.assertIn("get-stdin", text)
        # No actual ``package`` DECLARATION line (the package lives only in
        # environment.wit; the comment text mentioning the package name is
        # fine). A declaration line is a non-comment line starting with
        # ``package``.
        decl_lines = [
            ln for ln in text.splitlines()
            if ln.strip().startswith("package ")
        ]
        self.assertEqual(decl_lines, [])


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_wasip2(),
    "wasm-tools and/or wasmtime-py with WASI P2 not installed",
)
class TestWasiMode(unittest.TestCase):
    """End-to-end pipeline + property checks under the real host."""

    def test_pipeline_instantiates_and_runs(self):
        # The hybrid Clock + Random + Stdio program builds, embeds the
        # WASI WIT, instantiates (wasi:* + capa:host in one Linker),
        # and runs without trap.
        out = _run_wasi_component(_HYBRID_SRC)
        self.assertIn("mono ok", out)
        self.assertIn("wall ok", out)
        self.assertTrue(out.startswith("seeded "))

    def test_seeded_random_byte_identical_to_python(self):
        # The seeded path is 100 % guest-side (the WASI random import
        # never fires); it must match the Python backend exactly.
        wasi_out = _run_wasi_component(_SEEDED_SRC)
        py_out = _run_python(_SEEDED_SRC)
        self.assertEqual(py_out, wasi_out)

    def test_monotonic_non_decreasing(self):
        out = _run_wasi_component(_CLOCK_SRC)
        self.assertIn("MONO_OK", out)
        self.assertNotIn("MONO_BAD", out)

    def test_wall_clock_plausible(self):
        out = _run_wasi_component(_CLOCK_SRC)
        wall_line = next(
            ln for ln in out.splitlines() if ln.startswith("WALL ")
        )
        guest_secs = float(wall_line.split(" ", 1)[1])
        host_secs = time.time()
        # The guest reads wall-clock.now (seconds + nanos/1e9) at
        # roughly the same instant; a few seconds of drift is ample
        # slack for a slow CI box.
        self.assertLess(
            abs(guest_secs - host_secs), 30.0,
            msg=f"guest wall={guest_secs} host={host_secs}",
        )

    def test_system_seed_distinct_between_runs(self):
        # Unseeded Random draws fresh OS entropy via
        # wasi:random/get-random-u64 each run.
        a = _run_wasi_component(_SYSRAND_SRC).strip()
        b = _run_wasi_component(_SYSRAND_SRC).strip()
        self.assertNotEqual(a, b)

    def test_example_program_runs(self):
        from pathlib import Path
        path = (
            _REPO_ROOT
            / "examples" / "wasm" / "wasi_random_clock.capa"
        )
        out = _run_wasi_component(path.read_text(encoding="utf-8"))
        self.assertIn("monotonic: non-decreasing", out)
        self.assertIn("wall: plausible", out)


class TestWasiCeilingConstProp(unittest.TestCase):
    """Inter-procedural const-propagation of the static authority
    ceilings (helper-routed literals). Pure-Python ceiling checks, so
    this class is not gated on wasm-tools / wasmtime."""

    def _fs(self, src: str):
        from capa.ir import compute_fs_ceiling
        module, result = _parse_analyze(src)
        return compute_fs_ceiling(module, types=result.types)

    def _net(self, src: str):
        from capa.ir import compute_net_ceiling
        module, result = _parse_analyze(src)
        return compute_net_ceiling(module, types=result.types)

    def _env(self, src: str):
        from capa.ir import compute_env_ceiling
        module, result = _parse_analyze(src)
        return compute_env_ceiling(module, types=result.types)

    def test_fs_single_helper_routing_closes(self):
        # The motivating case: a literal routed through one helper frame.
        src = (
            "fun read_one(fs: Fs, path: String, stdio: Stdio)\n"
            "    match fs.read(path)\n"
            "        Ok(c) -> stdio.println(c)\n"
            "        Err(e) -> stdio.println(\"err\")\n"
            "fun main(fs: Fs, stdio: Stdio)\n"
            "    read_one(fs, \"conf/app.json\", stdio)\n"
        )
        ceiling = self._fs(src)
        self.assertTrue(ceiling.closed)
        self.assertEqual(
            tuple(p.host_path for p in ceiling.preopens), ("conf",),
        )

    def test_fs_multi_level_chain_closes(self):
        # main -> run -> parse -> read_one -> fs.read.
        src = (
            "fun read_one(fs: Fs, path: String, stdio: Stdio)\n"
            "    match fs.read(path)\n"
            "        Ok(c) -> stdio.println(c)\n"
            "        Err(e) -> stdio.println(\"err\")\n"
            "fun parse(fs: Fs, p: String, stdio: Stdio)\n"
            "    read_one(fs, p, stdio)\n"
            "fun run(fs: Fs, q: String, stdio: Stdio)\n"
            "    parse(fs, q, stdio)\n"
            "fun main(fs: Fs, stdio: Stdio)\n"
            "    let path = \"data/sample.json\"\n"
            "    run(fs, path, stdio)\n"
        )
        ceiling = self._fs(src)
        self.assertTrue(ceiling.closed)
        self.assertEqual(
            tuple(p.host_path for p in ceiling.preopens), ("data",),
        )

    def test_fs_multi_literal_at_one_sink_stays_open(self):
        # Two call sites route TWO distinct literals through the SAME
        # helper into the SAME sink. The analysis resolves the union (no
        # dynamic value reaches the sink), but the const-substitution only
        # materialises a sink whose slot is provably ONE literal -- a
        # multi-literal slot would need a runtime preopen resolver this
        # increment does not add, so it is left dynamic and the ceiling
        # stays NOT closed (fail-closed, never an over-grant). A program
        # in this shape compiles by giving each sink its own helper /
        # literal, or by dropping --wasi.
        src = (
            "fun read_one(fs: Fs, path: String, stdio: Stdio)\n"
            "    match fs.read(path)\n"
            "        Ok(c) -> stdio.println(c)\n"
            "        Err(e) -> stdio.println(\"err\")\n"
            "fun main(fs: Fs, stdio: Stdio)\n"
            "    read_one(fs, \"one/a.json\", stdio)\n"
            "    read_one(fs, \"two/b.json\", stdio)\n"
        )
        ceiling = self._fs(src)
        self.assertFalse(ceiling.closed)
        self.assertEqual(ceiling.preopens, ())

    def test_fs_two_sinks_two_literals_close(self):
        # Two DISTINCT sinks, each with its own single literal (no shared
        # multi-literal slot): both resolve and both preopens materialise.
        src = (
            "fun read_a(fs: Fs, path: String, stdio: Stdio)\n"
            "    match fs.read(path)\n"
            "        Ok(c) -> stdio.println(c)\n"
            "        Err(e) -> stdio.println(\"err\")\n"
            "fun read_b(fs: Fs, path: String, stdio: Stdio)\n"
            "    match fs.read(path)\n"
            "        Ok(c) -> stdio.println(c)\n"
            "        Err(e) -> stdio.println(\"err\")\n"
            "fun main(fs: Fs, stdio: Stdio)\n"
            "    read_a(fs, \"one/a.json\", stdio)\n"
            "    read_b(fs, \"two/b.json\", stdio)\n"
        )
        ceiling = self._fs(src)
        self.assertTrue(ceiling.closed)
        self.assertEqual(
            tuple(p.host_path for p in ceiling.preopens), ("one", "two"),
        )

    def test_fs_mixed_literal_and_dynamic_stays_open(self):
        # A sink reached by both a literal and a genuinely dynamic value
        # stays NOT closed (fail-closed): no preopen is materialised.
        src = (
            "fun read_one(fs: Fs, path: String, stdio: Stdio)\n"
            "    match fs.read(path)\n"
            "        Ok(c) -> stdio.println(c)\n"
            "        Err(e) -> stdio.println(\"err\")\n"
            "fun main(fs: Fs, stdio: Stdio, x: String)\n"
            "    read_one(fs, \"a.json\", stdio)\n"
            "    read_one(fs, x, stdio)\n"
        )
        ceiling = self._fs(src)
        self.assertFalse(ceiling.closed)
        self.assertEqual(ceiling.preopens, ())

    def test_net_helper_routing_closes(self):
        src = (
            "fun fetch(net: Net, url: String, stdio: Stdio)\n"
            "    match net.get(url)\n"
            "        Ok(b) -> stdio.println(b)\n"
            "        Err(e) -> stdio.println(\"e\")\n"
            "fun main(net: Net, stdio: Stdio)\n"
            "    fetch(net, \"https://api.example.com/v1\", stdio)\n"
        )
        ceiling = self._net(src)
        self.assertTrue(ceiling.closed)
        self.assertEqual(ceiling.hosts, frozenset({"api.example.com"}))

    def test_net_dynamic_helper_routing_stays_open(self):
        src = (
            "fun fetch(net: Net, url: String, stdio: Stdio)\n"
            "    match net.get(url)\n"
            "        Ok(b) -> stdio.println(b)\n"
            "        Err(e) -> stdio.println(\"e\")\n"
            "fun main(net: Net, stdio: Stdio, host: String)\n"
            "    fetch(net, \"https://${host}/v1\", stdio)\n"
        )
        ceiling = self._net(src)
        self.assertFalse(ceiling.closed)

    def test_env_helper_routing_closes(self):
        src = (
            "fun lookup(env: Env, key: String) -> String\n"
            "    return match env.get(key) { None -> \"\", Some(v) -> v }\n"
            "fun main(env: Env, stdio: Stdio)\n"
            "    let v = lookup(env, \"HOME\")\n"
            "    stdio.println(v)\n"
        )
        ceiling = self._env(src)
        self.assertTrue(ceiling.closed)
        self.assertEqual(ceiling.keys, frozenset({"HOME"}))

    def test_env_dynamic_helper_routing_degrades(self):
        src = (
            "fun lookup(env: Env, key: String) -> String\n"
            "    return match env.get(key) { None -> \"\", Some(v) -> v }\n"
            "fun main(env: Env, stdio: Stdio, k: String)\n"
            "    let v = lookup(env, k)\n"
            "    stdio.println(v)\n"
        )
        ceiling = self._env(src)
        self.assertFalse(ceiling.closed)

    def test_method_routed_path_stays_open(self):
        # A path routed through a method is conservatively dynamic.
        src = (
            "type Reader { tag: Int }\n"
            "impl Reader\n"
            "    fun load(self, fs: Fs, path: String, stdio: Stdio)\n"
            "        match fs.read(path)\n"
            "            Ok(c) -> stdio.println(c)\n"
            "            Err(e) -> stdio.println(\"err\")\n"
            "fun main(fs: Fs, stdio: Stdio)\n"
            "    let r = Reader { tag: 0 }\n"
            "    r.load(fs, \"via_method.json\", stdio)\n"
        )
        ceiling = self._fs(src)
        self.assertFalse(ceiling.closed)


def _run_python_out_err(src: str) -> tuple[str, str]:
    """Python oracle run capturing BOTH stdout and stderr (the eprintln
    parity check needs the two streams distinct)."""
    from capa import transpile
    module, result = _parse_analyze(src)
    code = transpile(module, types=result.types, bindings=result.bindings)
    out, err = io.StringIO(), io.StringIO()
    so, se = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = out, err
    try:
        ns: dict = {"__name__": "__main__"}
        exec(compile(code, "<wasi-stdio-parity>", "exec"), ns)
    finally:
        sys.stdout, sys.stderr = so, se
    return out.getvalue(), err.getvalue()


def _run_capa_host_out_err(src: str) -> tuple[str, str]:
    """capa:host component run capturing BOTH stdout and stderr."""
    from capa.ir import compile_wasm, compile_wit
    from capa.cli import _wrap_as_component
    from capa.runtime._wasm_component_host import WasmComponentHost
    module, result = _parse_analyze(src)
    core = compile_wasm(module, types=result.types, wasi=False)
    wit = compile_wit(module, types=result.types, wasi=False)
    comp = _wrap_as_component(core, wit, wasi=False)
    out, err = io.StringIO(), io.StringIO()
    so, se = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = out, err
    try:
        WasmComponentHost(wasi=False).run_main(comp)
    finally:
        sys.stdout, sys.stderr = so, se
    return out.getvalue(), err.getvalue()


def _run_wasi_out_err(src: str) -> tuple[str, str]:
    """WASI component run capturing BOTH stdout and stderr from the host's
    captured buffers (wasi:cli/stdout + wasi:cli/stderr)."""
    from capa.runtime._wasm_component_host import WasmComponentHost
    comp = _build_wasi_component(src)
    return _wasi_run_capture_stderr(WasmComponentHost(wasi=True), comp)


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_wasip2(),
    "wasm-tools and/or wasmtime-py with WASI P2 not installed",
)
class TestWasiStdioParity(unittest.TestCase):
    """Stdio Phase 1 (2026-06-29): print / println / eprintln route to
    wasi:cli/stdout (print / println) and wasi:cli/stderr (eprintln) over
    wasi:io/streams (output-stream.blocking-write-and-flush in <= 4096-byte
    chunks). The captured output is BYTE-IDENTICAL across the three
    backends (Python oracle, capa:host component, WASI component) for valid
    UTF-8 Capa strings, with stdout and stderr kept on distinct streams.

    UTF-8 note: the Python oracle's ``_write_safe`` uses
    ``errors='replace'`` only for terminal codecs that cannot encode a
    character; for valid UTF-8 (which every Capa String literal is) the
    WASI path's raw UTF-8 bytes and the oracle's text are identical. They
    differ ONLY on genuinely invalid bytes, a case Capa strings do not
    produce (so it is not exercised here)."""

    def _assert_three_way(self, src: str):
        py_out, py_err = _run_python_out_err(src)
        host_out, host_err = _run_capa_host_out_err(src)
        wasi_out, wasi_err = _run_wasi_out_err(src)
        self.assertEqual(py_out, host_out, "py/host stdout diverge")
        self.assertEqual(py_out, wasi_out, "py/wasi stdout diverge")
        self.assertEqual(py_err, host_err, "py/host stderr diverge")
        self.assertEqual(py_err, wasi_err, "py/wasi stderr diverge")
        return wasi_out, wasi_err

    def test_print_no_newline(self):
        # print writes the text with NO trailing newline.
        src = (
            "fun main(stdio: Stdio)\n"
            "    stdio.print(\"a\")\n"
            "    stdio.print(\"b\")\n"
            "    stdio.print(\"c\")\n"
        )
        out, err = self._assert_three_way(src)
        self.assertEqual(out, "abc")
        self.assertEqual(err, "")

    def test_println_appends_newline(self):
        src = (
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"line one\")\n"
            "    stdio.println(\"line two\")\n"
        )
        out, err = self._assert_three_way(src)
        self.assertEqual(out, "line one\nline two\n")
        self.assertEqual(err, "")

    def test_print_then_println(self):
        # A print (no newline) followed by a println on the same stream:
        # the bytes concatenate in order, then the newline lands.
        src = (
            "fun main(stdio: Stdio)\n"
            "    stdio.print(\"x=\")\n"
            "    stdio.println(\"42\")\n"
        )
        out, _err = self._assert_three_way(src)
        self.assertEqual(out, "x=42\n")

    def test_eprintln_separate_stream(self):
        # eprintln lands on STDERR, not stdout; the two are distinct.
        src = (
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"to stdout\")\n"
            "    stdio.eprintln(\"to stderr\")\n"
            "    stdio.println(\"stdout again\")\n"
        )
        out, err = self._assert_three_way(src)
        self.assertEqual(out, "to stdout\nstdout again\n")
        self.assertEqual(err, "to stderr\n")

    def test_large_output_multichunk(self):
        # A single println longer than one 4096-byte page forces the
        # write loop to iterate (the WASI 0.2 single-write page bound; a
        # one-shot write past it traps). The output must be COMPLETE, not
        # truncated or duplicated. 10000 'z' + the newline = 10001 bytes,
        # spanning three chunks (4096 + 4096 + 1808 + the \n in the last).
        n = 10000
        src = (
            "fun main(stdio: Stdio)\n"
            "    var s = \"\"\n"
            "    var i = 0\n"
            f"    while i < {n}\n"
            "        s = s + \"z\"\n"
            "        i = i + 1\n"
            "    stdio.println(s)\n"
        )
        out, _err = self._assert_three_way(src)
        self.assertEqual(out, ("z" * n) + "\n")
        self.assertEqual(len(out), n + 1)

    def test_utf8_multibyte(self):
        # Multibyte UTF-8 (2-, 3- and 4-byte code points) round-trips
        # byte-identically: the guest writes raw UTF-8, the oracle writes
        # the same text, so for valid UTF-8 they match exactly.
        src = (
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"caf\\u{00e9} \\u{4e2d}\\u{6587} \\u{1f680}\")\n"
        )
        out, _err = self._assert_three_way(src)
        self.assertEqual(out, "café 中文 \U0001f680\n")

    def test_utf8_multibyte_spanning_chunk_boundary(self):
        # A multibyte sequence that straddles the 4096-byte chunk boundary
        # must not be split incorrectly: the write loop slices by BYTE
        # offset, and the host reassembles the full byte stream before
        # decoding, so the code point survives intact. Build a string of
        # 3-byte chars long enough to cross 4096 bytes (1500 * 3 = 4500).
        src = (
            "fun main(stdio: Stdio)\n"
            "    var s = \"\"\n"
            "    var i = 0\n"
            "    while i < 1500\n"
            "        s = s + \"\\u{4e2d}\"\n"
            "        i = i + 1\n"
            "    stdio.println(s)\n"
        )
        out, _err = self._assert_three_way(src)
        self.assertEqual(out, ("中" * 1500) + "\n")

    def test_stdio_only_program_is_stock_wasi(self):
        # A print-only program (no panic, no read_line) imports NO
        # capa:host interface: it is 100 % stock WASI for its output. The
        # host's captured_stdout exposes exactly the guest's bytes.
        from capa.ir import compile_wit
        module, result = _parse_analyze(
            "fun main(stdio: Stdio)\n    stdio.println(\"stock\")\n"
        )
        wit = compile_wit(module, types=result.types, wasi=True)
        self.assertNotIn("capa:host", wit.split("world", 1)[1])
        self.assertNotIn("import stdio;", wit)
        self.assertNotIn("import panic;", wit)
        out, err = _run_wasi_out_err(
            "fun main(stdio: Stdio)\n    stdio.println(\"stock\")\n"
        )
        self.assertEqual(out, "stock\n")
        self.assertEqual(err, "")

    def test_coexists_with_env_and_random(self):
        # Stdio output (wasi:cli) coexists with other wasi caps (Env +
        # Random) in one component, all served by add_wasip2 alongside the
        # capa:host panic (unused here). The seeded RNG keeps it
        # deterministic for byte-parity; the env.get of an absent key is a
        # deterministic None on every backend.
        src = (
            "fun main(stdio: Stdio, env: Env, rng: Random)\n"
            "    let seeded = rng.with_seed(7)\n"
            "    match env.get(\"CAPA_WASI_ABSENT_COEXIST_KEY_XYZ\")\n"
            "        Some(_) -> stdio.println(\"env=set\")\n"
            "        None -> stdio.println(\"env=none\")\n"
            "    stdio.println(\"r=${seeded.int_range(0, 100)}\")\n"
            "    stdio.eprintln(\"err line\")\n"
        )
        out, err = self._assert_three_way(src)
        self.assertIn("env=none", out)
        self.assertIn("r=", out)
        self.assertEqual(err, "err line\n")


def _run_python_stdin(src: str, stdin_bytes: bytes) -> str:
    """Python oracle run with ``stdin_bytes`` fed as standard input,
    capturing stdout. ``sys.stdin`` is replaced by a TextIOWrapper over
    the bytes in TEXT MODE with universal newlines (``newline=None``) so
    it behaves exactly like the real interpreter's ``sys.stdin`` -- the
    same text-mode that translates ``\\r\\n`` -> ``\\n`` before the
    runtime's ``readline().rstrip("\\n")``. This is the parity reference
    the WASI byte reader's trailing-``\\r`` strip is calibrated against."""
    from capa import transpile
    module, result = _parse_analyze(src)
    code = transpile(module, types=result.types, bindings=result.bindings)
    out = io.StringIO()
    so, si = sys.stdout, sys.stdin
    sys.stdout = out
    sys.stdin = io.TextIOWrapper(
        io.BytesIO(stdin_bytes), encoding="utf-8", newline=None,
    )
    try:
        ns: dict = {"__name__": "__main__"}
        exec(compile(code, "<wasi-stdin-parity>", "exec"), ns)
    finally:
        sys.stdout, sys.stdin = so, si
    return out.getvalue()


def _run_capa_host_stdin(src: str, stdin_bytes: bytes) -> str:
    """capa:host (default, non-wasi) component run with ``stdin_bytes`` fed
    as standard input, capturing stdout. The capa:host read-line bridge
    reads ``sys.stdin.readline()``, so the bytes are wrapped in a
    text-mode ``sys.stdin`` (universal newlines) for the duration of the
    run, identical to the Python oracle's stdin."""
    from capa.ir import compile_wasm, compile_wit
    from capa.cli import _wrap_as_component
    from capa.runtime._wasm_component_host import WasmComponentHost
    module, result = _parse_analyze(src)
    core = compile_wasm(module, types=result.types, wasi=False)
    wit = compile_wit(module, types=result.types, wasi=False)
    comp = _wrap_as_component(core, wit, wasi=False)
    out = io.StringIO()
    so, si = sys.stdout, sys.stdin
    sys.stdout = out
    sys.stdin = io.TextIOWrapper(
        io.BytesIO(stdin_bytes), encoding="utf-8", newline=None,
    )
    try:
        WasmComponentHost(wasi=False).run_main(comp)
    finally:
        sys.stdout, sys.stdin = so, si
    return out.getvalue()


def _run_wasi_stdin(src: str, stdin_bytes: bytes) -> str:
    """WASI component run with ``stdin_bytes`` fed through the host's
    WasiConfig stdin source (Stdio.read_line -> wasi:cli/stdin), capturing
    stdout from the host's captured buffer (wasi:cli/stdout)."""
    from capa.runtime._wasm_component_host import WasmComponentHost
    comp = _build_wasi_component(src)
    host = WasmComponentHost(wasi=True, stdin=stdin_bytes)
    return _wasi_run_capture(host, comp)


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_wasip2(),
    "wasm-tools and/or wasmtime-py with WASI P2 not installed",
)
class TestWasiStdinReadLine(unittest.TestCase):
    """Stdio.read_line Phase 2 (2026-06-29): read_line routes to
    wasi:cli/stdin (get-stdin -> input-stream) + wasi:io/streams
    (input-stream.blocking-read, byte-at-a-time until "\\n" or EOF). The
    Result<String, IoError> is BYTE-IDENTICAL across the three backends
    (Python oracle, capa:host component, WASI component) for input whose
    line terminators are "\\n" or "\\r\\n": a line yields Ok(text) without
    the trailing "\\n"; EOF yields Err(IoError("end of input")). The WASI
    byte reader strips a single trailing "\\r" so "\\r\\n" lines reach
    parity with the oracle's universal-newline text mode.

    DELIBERATE DIVERGENCE (lone CR). The --wasi reader recognises only
    "\\n" / "\\r\\n" as line terminators, NOT full universal-newlines, so
    an isolated "\\r" (CR not followed by "\\n") is kept as an ordinary
    byte while the oracle's text mode breaks the line on it. The
    three-way parity asserts therefore use only "\\n" / "\\r\\n" input;
    the lone-CR case is pinned separately as the documented --wasi
    behaviour (test_lone_cr_is_not_a_line_break_wasi_divergence), NOT as
    parity. See docs/design/wasi_mode.md "read_line lone-CR divergence".

    panic stays on capa:host/panic; this phase leaves ONLY panic on
    capa:host for a --wasi program."""

    # A read-all loop: read lines until Err, emit each as ``[line]\n``,
    # then a terminator. Reconstructs the input (minus the "\n"s) and lets
    # us compare the full transcript across backends.
    _READ_ALL = (
        "fun main(stdio: Stdio)\n"
        "    var go = true\n"
        "    while go\n"
        "        match stdio.read_line()\n"
        "            Ok(line) -> stdio.println(\"[${line}]\")\n"
        "            Err(e) -> go = false\n"
        "    stdio.println(\"<END>\")\n"
    )

    # A single read_line that reports Ok / Err distinctly. The Err arm
    # prints a fixed marker (the builtin IoError exposes no source-level
    # field; the "end of input" message parity is proven at the wrapper /
    # pre-interning level and host-side, and the Err DISCRIMINANT parity
    # is what the three-way equality below asserts).
    _ONE = (
        "fun main(stdio: Stdio)\n"
        "    match stdio.read_line()\n"
        "        Ok(line) -> stdio.println(\"ok:${line}\")\n"
        "        Err(e) -> stdio.println(\"err:eof\")\n"
    )

    def _assert_three_way(self, src: str, stdin_bytes: bytes) -> str:
        py = _run_python_stdin(src, stdin_bytes)
        host = _run_capa_host_stdin(src, stdin_bytes)
        wasi = _run_wasi_stdin(src, stdin_bytes)
        self.assertEqual(py, host, "py/host read_line diverge")
        self.assertEqual(py, wasi, "py/wasi read_line diverge")
        return wasi

    def test_single_line(self):
        out = self._assert_three_way(self._ONE, b"abc\n")
        self.assertEqual(out, "ok:abc\n")

    def test_multiple_lines_in_order(self):
        # Three successive read_line over three lines return line1, line2,
        # line3 in order, no byte lost or repeated (the stdin position
        # persists across the per-call get-stdin + drop).
        out = self._assert_three_way(self._READ_ALL, b"one\ntwo\nthree\n")
        self.assertEqual(out, "[one]\n[two]\n[three]\n<END>\n")

    def test_empty_line(self):
        # A bare "\n" yields Ok("") (an empty line), distinct from EOF.
        out = self._assert_three_way(self._READ_ALL, b"a\n\nb\n")
        self.assertEqual(out, "[a]\n[]\n[b]\n<END>\n")

    def test_crlf_parity(self):
        # "\r\n" line endings reach parity with "\n": the trailing "\r" is
        # stripped, so the line content matches the oracle's text mode.
        out = self._assert_three_way(self._READ_ALL, b"x\r\ny\r\n")
        self.assertEqual(out, "[x]\n[y]\n<END>\n")

    def test_lf_and_crlf_same_result(self):
        # The SAME logical input with "\n" vs "\r\n" endings produces the
        # identical transcript on the WASI backend (the \r-strip is what
        # makes them converge).
        lf = _run_wasi_stdin(self._READ_ALL, b"alpha\nbeta\n")
        crlf = _run_wasi_stdin(self._READ_ALL, b"alpha\r\nbeta\r\n")
        self.assertEqual(lf, crlf)
        self.assertEqual(lf, "[alpha]\n[beta]\n<END>\n")

    def test_lone_cr_is_not_a_line_break_wasi_divergence(self):
        # DOCUMENTED, DELIBERATE divergence (NOT three-backend parity): the
        # --wasi reader breaks lines only on "\n" / "\r\n", so a lone "\r"
        # (a CR not followed by "\n") is kept as an ordinary byte, EVEN with
        # a trailing "\n". The Python oracle's text mode, by contrast,
        # treats any isolated "\r" as a line break. We assert the EXPECTED
        # --wasi behaviour directly (no oracle comparison), pinning the
        # accepted divergence. See docs/design/wasi_mode.md "read_line
        # lone-CR divergence" and the $Stdio_read_line docstring.
        #
        # "a\rb\n": the whole "a\rb" is one line on --wasi (the embedded
        # "\r" is not a terminator); the oracle would yield ["a", "b"].
        wasi = _run_wasi_stdin(self._READ_ALL, b"a\rb\n")
        self.assertEqual(wasi, "[a\rb]\n<END>\n")
        # Classic pre-2001 Mac line endings "x\ry\rz\r": one --wasi line
        # "x\ry\rz" (the final lone "\r" is stripped as a trailing CR, the
        # embedded ones are kept); the oracle would yield ["x", "y", "z"].
        wasi_mac = _run_wasi_stdin(self._READ_ALL, b"x\ry\rz\r")
        self.assertEqual(wasi_mac, "[x\ry\rz]\n<END>\n")
        # Sanity: the oracle genuinely DOES split on the lone "\r" here, so
        # this case is a real divergence and rightly excluded from the
        # three-backend parity asserts above.
        oracle = _run_python_stdin(self._READ_ALL, b"a\rb\n")
        self.assertEqual(oracle, "[a]\n[b]\n<END>\n")
        self.assertNotEqual(wasi, oracle)

    def test_last_line_without_newline(self):
        # A final line with no trailing "\n" is still returned; the NEXT
        # read_line then hits EOF.
        out = self._assert_three_way(self._READ_ALL, b"abc\ndef")
        self.assertEqual(out, "[abc]\n[def]\n<END>\n")

    def test_empty_input_is_eof(self):
        # Empty stdin -> the first read_line is Err (the EOF marker), the
        # SAME discriminant on every backend.
        out = self._assert_three_way(self._ONE, b"")
        self.assertEqual(out, "err:eof\n")

    def test_eof_message_pre_interned(self):
        # The WASI wrapper writes the oracle's "end of input" message into
        # the Err arm; it must be pre-interned (present in the data segment
        # with a backing ``(data ...)`` block), else its bytes would be
        # undefined memory. Assert the literal appears in the emitted WAT
        # data segment for a read_line program.
        from capa.ir import compile_wasm
        module, result = _parse_analyze(self._ONE)
        core = compile_wasm(module, types=result.types, wasi=True)
        self.assertIn(b"end of input", core)

    def test_utf8_multibyte_line(self):
        # A line with 2-, 3- and 4-byte UTF-8 code points round-trips
        # byte-identically through the byte reader.
        data = "café 中文 🚀\n".encode("utf-8")
        out = self._assert_three_way(self._ONE, data)
        self.assertEqual(out, "ok:café 中文 🚀\n")

    def test_read_all_reconstructs_input(self):
        # The read-all loop reconstructs the exact input (minus the "\n"s)
        # identically on all three backends, including a long run of lines.
        lines = [f"line-{i}" for i in range(50)]
        data = ("\n".join(lines) + "\n").encode("utf-8")
        out = self._assert_three_way(self._READ_ALL, data)
        expected = "".join(f"[{ln}]\n" for ln in lines) + "<END>\n"
        self.assertEqual(out, expected)

    def test_long_line_multibyte_accumulation(self):
        # A single line longer than the initial buffer capacity forces the
        # geometric realloc + copy path; the full line must survive intact.
        long_line = "z" * 5000
        out = self._assert_three_way(
            self._ONE, (long_line + "\n").encode("utf-8"),
        )
        self.assertEqual(out, f"ok:{long_line}\n")

    def test_read_line_only_program_is_stock_wasi(self):
        # A read_line-only program (no panic) imports NO capa:host
        # interface: only wasi:cli/stdin + wasi:cli/stdout + wasi:io/* .
        from capa.ir import compile_wit
        module, result = _parse_analyze(self._ONE)
        wit = compile_wit(module, types=result.types, wasi=True)
        self.assertIn("import wasi:cli/stdin@0.2.0;", wit)
        self.assertNotIn("interface stdio {", wit)
        self.assertNotIn("  import stdio;", wit)
        self.assertNotIn("import panic;", wit)

    def test_coexists_with_fs_read_dedups_imports(self):
        # read_line + Fs.read in one program share the wasi:io/streams
        # input-stream blocking-read + resource-drop and the wasi:io/error
        # resource-drop. Each shared import must appear EXACTLY once in the
        # emitted core module (a core module re-declaring the same import is
        # rejected by wasm-tools). The combined component must also build.
        from capa.ir import compile_wasm, compile_wit
        from capa.cli import _wrap_as_component
        src = (
            "fun main(stdio: Stdio, fs: Fs)\n"
            "    match fs.read(\"/tmp/capa-coexist.txt\")\n"
            "        Ok(c) -> stdio.println(\"fsok\")\n"
            "        Err(e) -> stdio.println(\"fserr\")\n"
            "    match stdio.read_line()\n"
            "        Ok(line) -> stdio.println(\"rl:${line}\")\n"
            "        Err(e) -> stdio.println(\"rlerr\")\n"
        )
        module, result = _parse_analyze(src)
        core = compile_wasm(module, types=result.types, wasi=True)
        for sym in (
            b"[method]input-stream.blocking-read",
            b"[resource-drop]input-stream",
            b"[resource-drop]error",
            b"get-stdin",
        ):
            self.assertEqual(
                core.count(sym), 1, f"{sym!r} not imported exactly once",
            )
        wit = compile_wit(module, types=result.types, wasi=True)
        # The component links (the shared imports resolve, the world
        # imports both wasi:cli/stdin and wasi:filesystem).
        _wrap_as_component(core, wit, wasi=True)


class TestWasiPathArgSurface(unittest.TestCase):
    """WASI Layer 1 path-arg surface: the ``--wasi-surface`` inspection
    command, the compiler-derived SBOM block, and the actionable
    fail-closed message. None of these need the Wasm toolchain except the
    message test, which exercises the emitter's validation directly."""

    _ARGV_PROG = (
        "fun main(fs: Fs, env: Env)\n"
        "    let path = match env.args().get(0) "
        "{ None -> \"\", Some(p) -> p }\n"
        "    let out  = match env.args().get(1) "
        "{ None -> \"o\", Some(p) -> p }\n"
        "    let _ = match fs.read(path) { Err(_) -> \"\", Ok(s) -> s }\n"
        "    let _ = fs.write(out, \"x\")\n"
    )

    _NO_ARGV = (
        "fun main(fs: Fs)\n"
        "    let _ = match fs.read(\"static.json\") "
        "{ Err(_) -> \"\", Ok(s) -> s }\n"
    )

    def _run_cli(self, argv, src):
        import tempfile
        from pathlib import Path
        from capa.cli import main
        out, err = io.StringIO(), io.StringIO()
        old_out, old_err, old_argv = sys.stdout, sys.stderr, sys.argv
        sys.stdout, sys.stderr = out, err
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "p.capa"
            f.write_text(src, encoding="utf-8")
            sys.argv = ["capa", *argv, str(f)]
            try:
                code = main()
            finally:
                sys.stdout, sys.stderr, sys.argv = old_out, old_err, old_argv
        return code, out.getvalue(), err.getvalue()

    def test_wasi_surface_command_reports_facts(self):
        code, out, _err = self._run_cli(["--wasi-surface"], self._ARGV_PROG)
        self.assertEqual(code, 0)
        self.assertIn("compiler-derived", out)
        self.assertIn("argv[0] -> Fs.read (read-only)", out)
        self.assertIn("argv[1] -> Fs.write (writes)", out)

    def test_wasi_surface_command_empty_when_no_argv(self):
        code, out, _err = self._run_cli(["--wasi-surface"], self._NO_ARGV)
        self.assertEqual(code, 0)
        self.assertIn("no argv", out)

    def test_manifest_surface_block_is_compiler_derived(self):
        import json
        code, out, _err = self._run_cli(["--manifest"], self._ARGV_PROG)
        self.assertEqual(code, 0)
        m = json.loads(out)
        block = m["compiler_derived_path_arg_surface"]
        self.assertEqual(block["trust_level"], "compiler-derived")
        # Distinct from the operator-declared grants block.
        self.assertEqual(
            m["operator_declared_grants"]["trust_level"], "operator-declared",
        )
        facts = {
            (a["arg_index"], a["capability"], a["method"], a["access"])
            for a in block["arguments"]
        }
        self.assertIn((0, "Fs", "read", "read"), facts)
        self.assertIn((1, "Fs", "write", "write"), facts)

    def test_cyclonedx_surface_property_present(self):
        import json
        code, out, _err = self._run_cli(["--cyclonedx"], self._ARGV_PROG)
        self.assertEqual(code, 0)
        sbom = json.loads(out)
        props = {
            p["name"]: p["value"]
            for p in sbom["metadata"]["properties"]
        }
        self.assertEqual(
            props.get("capa:compiler_derived_path_arg_surface:trust_level"),
            "compiler-derived",
        )

    def test_actionable_failclosed_message_names_arg_to_sink(self):
        from capa import Lexer, analyze
        from capa.ir import compile_wat
        from capa.loader import ModuleLoader
        src = self._ARGV_PROG
        linked = ModuleLoader().load_root(src, "p.capa")
        module = linked.module
        result = analyze(module, source=src, filename="p.capa")
        with self.assertRaises(Exception) as cm:
            compile_wat(module, types=result.types, wasi=True)
        msg = str(cm.exception)
        # Names the proven argv -> sink and suggests --preopen.
        self.assertIn("argv[0] -> Fs.read", msg)
        self.assertIn("--preopen", msg)


if __name__ == "__main__":
    unittest.main()
