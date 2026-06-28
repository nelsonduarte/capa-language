"""Experimental WASI Preview 2 mode (opt-in ``--wasi``).

Validates the proof-of-concept that migrates the Random and Clock
capabilities off the custom ``capa:host`` interfaces and onto
canonical WASI Preview 2 interfaces (``wasi:random`` /
``wasi:clocks``), satisfied by wasmtime's ``add_wasip2()`` host, while
the rest of the program's capabilities (Stdio here) stay on
``capa:host`` in the SAME component Linker (hybrid coexistence).

The migrated touch-points are non-deterministic (system_seed entropy,
wall + monotonic clocks), so the validation is by PROPERTY, not by
byte-equality:

- PIPELINE: a Clock + Random + Stdio program compiles in WASI mode,
  embeds the WASI WIT, instantiates, and runs without trap.
- SEEDED PARITY: ``with_seed(fixed) + int_range`` runs 100 % guest-side
  and stays byte-identical to the Python backend (the WASI random
  import never fires on the seeded path).
- CLOCK PROPERTIES: ``now_monotonic`` does not decrease across
  successive reads; ``now_secs`` is a plausible Unix timestamp.
- SYSTEM_SEED: an unseeded ``Random()`` draws fresh entropy each run,
  so two runs of the same program produce distinct values.
- ENV ATTENUATION: ``Env.restrict_to_keys`` / ``Env.allows`` / the
  ``Env.get`` fail-closed gate are implemented GUEST-SIDE under
  ``--wasi`` (Level 2 of ``docs/design/wasi-attenuation.md``), with
  intersection + fail-closed semantics byte-identical to the Python
  backend (the oracle) and the capa:host backend.
- EXCLUSIONS: ``Clock.sleep`` and Clock attenuation
  (``restrict_to_after``) are rejected with a clear error in WASI mode.

The default ``capa:host`` path is exercised by the rest of the suite;
this file only covers the new flag.
"""

from __future__ import annotations

import io
import os
import shutil
import sys
import time
import unittest

from capa import Lexer, Parser, analyze


def _has_wasm_tools() -> bool:
    return shutil.which("wasm-tools") is not None


def _has_wasmtime_wasip2() -> bool:
    try:
        import wasmtime
        import wasmtime.component as wc  # noqa: F401
    except ImportError:
        return False
    # add_wasip2 + WasiConfig are the host surface the WASI mode needs.
    return hasattr(wasmtime, "WasiConfig") and hasattr(
        wc.Linker(wasmtime.Engine()), "add_wasip2",
    )


def _parse_analyze(src: str):
    module = Parser(Lexer(src).lex(), source=src).parse_module()
    result = analyze(module, source=src)
    if not result.ok:
        raise AssertionError(f"analyzer errors: {result.errors}")
    return module, result


def _build_wasi_component(src: str) -> bytes:
    from capa.ir import compile_wasm, compile_wit
    from capa.cli import _wrap_as_component
    module, result = _parse_analyze(src)
    core = compile_wasm(module, types=result.types, wasi=True)
    wit = compile_wit(module, types=result.types, wasi=True)
    return _wrap_as_component(core, wit, wasi=True)


def _run_wasi_component(src: str, args: tuple = ()) -> str:
    """Build + run a program in WASI mode; capture stdout.

    ``args`` is the program argument vector handed to the host (the
    ``env.args()`` source in WASI mode comes through the WasiConfig
    argv this host sets, not the ``capa:host/env`` bridge)."""
    from capa.runtime._wasm_component_host import WasmComponentHost
    comp = _build_wasi_component(src)
    buf = io.StringIO()
    saved = sys.stdout
    sys.stdout = buf
    try:
        WasmComponentHost(args=args, wasi=True).run_main(comp)
    finally:
        sys.stdout = saved
    return buf.getvalue()


def _run_wasi_component_with_ceiling(src: str, args: tuple = ()):
    """Build + run a program in WASI mode with the static Env ceiling
    computed and handed to the host (Level 1).

    Returns ``(stdout, env_applied)`` where ``env_applied`` is the
    env-set the host actually installed on the WASI component (a dict
    of the ceiling keys projected onto the host environment for a
    CLOSED ceiling, or the sentinel ``"inherit"`` when the host fell
    back to ``inherit_env`` for a non-closed ceiling). The env-set is
    the inspection point that proves the leak-closed guarantee: a host
    env var the program never reads must not appear in it."""
    from capa.ir import compile_wasm, compile_wit, compute_env_ceiling
    from capa.cli import _wrap_as_component
    from capa.runtime._wasm_component_host import WasmComponentHost
    module, result = _parse_analyze(src)
    core = compile_wasm(module, types=result.types, wasi=True)
    wit = compile_wit(module, types=result.types, wasi=True)
    comp = _wrap_as_component(core, wit, wasi=True)
    ceiling = compute_env_ceiling(module, types=result.types)
    host = WasmComponentHost(args=args, wasi=True, env_ceiling=ceiling)
    buf = io.StringIO()
    saved = sys.stdout
    sys.stdout = buf
    try:
        host.run_main(comp)
    finally:
        sys.stdout = saved
    return buf.getvalue(), host._wasi_env_applied


def _run_capa_host_component(src: str, args: tuple = ()) -> str:
    """Build + run a program on the DEFAULT capa:host Component
    backend (``--wasm --component``, no ``--wasi``); capture stdout.

    Used for three-way byte-parity checks of the Env attenuation: the
    capa:host backend enforces the narrowing host-side via the cap
    handle table, the WASI backend enforces it guest-side, and both
    must match the Python oracle. ``Env.get`` / ``allows`` here read
    ``os.environ`` through the capa:host bridge, so the controlled keys
    set in the test environment are visible to this backend too."""
    from capa.ir import compile_wasm, compile_wit
    from capa.cli import _wrap_as_component
    from capa.runtime._wasm_component_host import WasmComponentHost
    module, result = _parse_analyze(src)
    core = compile_wasm(module, types=result.types, wasi=False)
    wit = compile_wit(module, types=result.types, wasi=False)
    comp = _wrap_as_component(core, wit, wasi=False)
    buf = io.StringIO()
    saved = sys.stdout
    sys.stdout = buf
    try:
        WasmComponentHost(args=args, wasi=False).run_main(comp)
    finally:
        sys.stdout = saved
    return buf.getvalue()


def _run_python(src: str) -> str:
    from capa import transpile
    module, result = _parse_analyze(src)
    code = transpile(module, types=result.types, bindings=result.bindings)
    buf = io.StringIO()
    saved = sys.stdout
    sys.stdout = buf
    try:
        ns: dict = {"__name__": "__main__"}
        exec(compile(code, "<wasi-parity>", "exec"), ns)
    finally:
        sys.stdout = saved
    return buf.getvalue()


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

# Env reader migration: get(KEY) -> wasi:cli/environment.get-environment
# searched guest-side; args() -> get-arguments. The test sets the key in
# os.environ before building so the result is determinable.
_ENV_KEY = "CAPA_WASI_ENV_TEST_KEY"
_ENV_VAL = "wasi-env-test-value-123"

_ENV_GET_SRC = f"""
fun main(stdio: Stdio, env: Env)
    let present = env.get("{_ENV_KEY}")
    match present
        Some(v) -> stdio.println("present=${{v}}")
        None -> stdio.println("present=<unset>")
    let absent = env.get("CAPA_WASI_ABSENT_KEY_DEFINITELY_NOT_SET_999")
    match absent
        Some(_) -> stdio.println("absent=SET")
        None -> stdio.println("absent=none")
"""

_ENV_ARGS_SRC = """
fun main(stdio: Stdio, env: Env)
    let args = env.args()
    stdio.println("argc=${args.length()}")
    for a in args
        stdio.println("arg=${a}")
"""

# Guest-side Env attenuation (Level 2). The three controlled keys are
# set in os.environ for the duration of the attenuation tests so the
# result is determinable and parity-comparable to the Python backend.
_ATT_A = "CAPA_WASI_ATT_A"
_ATT_B = "CAPA_WASI_ATT_B"
_ATT_C = "CAPA_WASI_ATT_C"
_ATT_VALS = {_ATT_A: "att-a-val", _ATT_B: "att-b-val", _ATT_C: "att-c-val"}

# restrict_to_keys([A, B]) then restrict_to_keys([B, C]) -> the
# intersection {B} is the effective allow-list. allows + get reflect it,
# get is fail-closed against it, and the wider parent still admits A.
_ENV_ATTEN_SRC = f"""
fun main(stdio: Stdio, env: Env)
    let ab = env.restrict_to_keys(["{_ATT_A}", "{_ATT_B}"])
    let only_b = ab.restrict_to_keys(["{_ATT_B}", "{_ATT_C}"])
    if only_b.allows("{_ATT_B}")
        stdio.println("allows_B=yes")
    else
        stdio.println("allows_B=no")
    if only_b.allows("{_ATT_A}")
        stdio.println("allows_A=yes")
    else
        stdio.println("allows_A=no")
    if only_b.allows("{_ATT_C}")
        stdio.println("allows_C=yes")
    else
        stdio.println("allows_C=no")
    match only_b.get("{_ATT_B}")
        Some(v) -> stdio.println("get_B=${{v}}")
        None -> stdio.println("get_B=none")
    match only_b.get("{_ATT_A}")
        Some(v) -> stdio.println("get_A=${{v}}")
        None -> stdio.println("get_A=none")
    match ab.get("{_ATT_A}")
        Some(v) -> stdio.println("parent_get_A=${{v}}")
        None -> stdio.println("parent_get_A=none")
"""

# Edge cases: the unrestricted root allows + reads everything, and an
# empty restriction (restrict_to_keys([])) admits nothing (fail-closed
# on every key), distinct from the unrestricted root.
_ENV_ATTEN_EDGE_SRC = f"""
fun main(stdio: Stdio, env: Env)
    if env.allows("{_ATT_A}")
        stdio.println("root_allows=yes")
    match env.get("{_ATT_A}")
        Some(v) -> stdio.println("root_get=${{v}}")
        None -> stdio.println("root_get=none")
    let empty = env.restrict_to_keys([])
    if empty.allows("{_ATT_A}")
        stdio.println("empty_allows=yes")
    else
        stdio.println("empty_allows=no")
    match empty.get("{_ATT_A}")
        Some(v) -> stdio.println("empty_get=${{v}}")
        None -> stdio.println("empty_get=none")
"""

# Env + Random + Clock all in WASI mode at once: proves the three
# wasi:* interfaces coexist with capa:host/stdio in one Linker.
_ENV_HYBRID_SRC = f"""
fun main(stdio: Stdio, env: Env, clock: Clock, rng: Random)
    let v = env.get("{_ENV_KEY}")
    match v
        Some(s) -> stdio.println("env=${{s}}")
        None -> stdio.println("env=<unset>")
    let seeded = rng.with_seed(7)
    stdio.println("rng=${{seeded.int_range(0, 100)}}")
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

    def test_stdio_stays_capa_host(self):
        # Hybrid: Stdio keeps its capa:host interface + world import.
        wit = self._wit(_HYBRID_SRC)
        self.assertIn("interface stdio {", wit)
        self.assertIn("  import stdio;", wit)

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
        # Stdio is the only capa:host interface left.
        self.assertIn("interface stdio {", wit)


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


class TestWasiEnvCeilingAnalysis(unittest.TestCase):
    """Static Env authority-ceiling analysis (Level 1 pre-requisite).

    Pure analysis over the CIR -- no Wasm toolchain needed. The ceiling
    is the set of keys a program can read via ``env.get``; it is CLOSED
    iff every ``env.get`` key is a string literal."""

    def _ceiling(self, src: str):
        from capa.ir import compute_env_ceiling
        module, result = _parse_analyze(src)
        return compute_env_ceiling(module, types=result.types)

    def test_literal_keys_close_the_ceiling(self):
        src = (
            "fun main(stdio: Stdio, env: Env)\n"
            "    let a = env.get(\"CAPA_PUBLIC\")\n"
            "    let b = env.get(\"OTHER\")\n"
            "    match a\n"
            "        Some(v) -> stdio.println(v)\n"
            "        None -> stdio.println(\"none\")\n"
        )
        ceiling = self._ceiling(src)
        self.assertTrue(ceiling.closed)
        self.assertEqual(ceiling.keys, frozenset({"CAPA_PUBLIC", "OTHER"}))

    def test_dynamic_key_opens_the_ceiling(self):
        # A key built at runtime (a local) cannot be materialised, so
        # the ceiling is NOT closed and the host must fall back to
        # inherit_env (Level 2).
        src = (
            "fun main(stdio: Stdio, env: Env)\n"
            "    let p = env.get(\"CAPA_PUBLIC\")\n"
            "    let prefix = \"CAPA_\"\n"
            "    let key = \"${prefix}X\"\n"
            "    let d = env.get(key)\n"
            "    stdio.println(\"done\")\n"
        )
        ceiling = self._ceiling(src)
        self.assertFalse(ceiling.closed)

    def test_let_bound_literal_is_conservatively_dynamic(self):
        # A literal routed through an intermediate `let` appears as a
        # local at the call site; the simple literal scan treats it as
        # dynamic (conservative: falls back to inherit_env, never
        # under-delivers a key the program reads).
        src = (
            "fun main(stdio: Stdio, env: Env)\n"
            "    let key = \"CAPA_PUBLIC\"\n"
            "    let v = env.get(key)\n"
            "    stdio.println(\"done\")\n"
        )
        ceiling = self._ceiling(src)
        self.assertFalse(ceiling.closed)

    def test_args_and_attenuators_do_not_widen_ceiling(self):
        # env.args reads argv (no key); restrict_to_keys / allows only
        # narrow / query. None of them widens the read ceiling, which is
        # defined solely by the env.get literals.
        src = (
            "fun main(stdio: Stdio, env: Env)\n"
            "    let r = env.restrict_to_keys([\"A\", \"B\"])\n"
            "    let ok = r.allows(\"A\")\n"
            "    let args = env.args()\n"
            "    let v = env.get(\"CAPA_PUBLIC\")\n"
            "    stdio.println(\"argc=${args.length()}\")\n"
        )
        ceiling = self._ceiling(src)
        self.assertTrue(ceiling.closed)
        self.assertEqual(ceiling.keys, frozenset({"CAPA_PUBLIC"}))

    def test_no_env_get_yields_empty_closed_ceiling(self):
        # A program that never reads a key has an empty, closed ceiling:
        # the component gets a completely empty environment.
        src = (
            "fun main(stdio: Stdio, env: Env)\n"
            "    let args = env.args()\n"
            "    stdio.println(\"argc=${args.length()}\")\n"
        )
        ceiling = self._ceiling(src)
        self.assertTrue(ceiling.closed)
        self.assertEqual(ceiling.keys, frozenset())

    def test_host_env_set_projects_onto_ceiling(self):
        # host_env_set drops every host var outside the ceiling and
        # omits a ceiling key absent from the host environment.
        src = (
            "fun main(stdio: Stdio, env: Env)\n"
            "    let v = env.get(\"CAPA_PUBLIC\")\n"
            "    let w = env.get(\"CAPA_MISSING\")\n"
            "    stdio.println(\"done\")\n"
        )
        ceiling = self._ceiling(src)
        environ = {
            "CAPA_PUBLIC": "pub",
            "CAPA_SECRET": "sec",   # not read -> dropped
        }
        env_set = ceiling.host_env_set(environ)
        self.assertEqual(env_set, {"CAPA_PUBLIC": "pub"})
        self.assertNotIn("CAPA_SECRET", env_set)
        self.assertNotIn("CAPA_MISSING", env_set)  # absent from host env


class TestWasiWitLicenseHeaders(unittest.TestCase):
    """Each vendored WIT carries its SPDX license + provenance header."""

    def _wit(self, *parts):
        from pathlib import Path
        return (
            Path(__file__).resolve().parent.parent
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
            Path(__file__).resolve().parent.parent
            / "examples" / "wasm" / "wasi_random_clock.capa"
        )
        out = _run_wasi_component(path.read_text(encoding="utf-8"))
        self.assertIn("monotonic: non-decreasing", out)
        self.assertIn("wall: plausible", out)


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_wasip2(),
    "wasm-tools and/or wasmtime-py with WASI P2 not installed",
)
class TestWasiEnvMode(unittest.TestCase):
    """End-to-end Env reader migration under the real WASI P2 host.

    ``env.get`` reads wasi:cli/environment.get-environment (inherited
    host env via the WasiConfig), searched guest-side for the key;
    ``env.args`` reads get-arguments (the WasiConfig argv this host
    sets). The controlled key is set in ``os.environ`` for the duration
    of the test so the result is determinable and parity-comparable to
    the Python backend (which reads ``os.environ`` directly). The full
    environment is non-deterministic, so only the controlled key + the
    fail-closed semantics are asserted."""

    def setUp(self):
        import os
        self._saved = os.environ.get(_ENV_KEY)
        os.environ[_ENV_KEY] = _ENV_VAL

    def tearDown(self):
        import os
        if self._saved is None:
            os.environ.pop(_ENV_KEY, None)
        else:
            os.environ[_ENV_KEY] = self._saved

    def test_env_get_present_and_absent(self):
        out = _run_wasi_component(_ENV_GET_SRC)
        self.assertIn(f"present={_ENV_VAL}", out)
        # Fail-closed: a key not set in the environment reads as None.
        self.assertIn("absent=none", out)
        self.assertNotIn("absent=SET", out)

    def test_env_get_controlled_key_parity_with_python(self):
        # The controlled key is in os.environ for both backends, so the
        # WASI guest's get-environment search and the Python runtime's
        # os.environ.get must agree on it (and on the absent key being
        # None). The two outputs match line-for-line for this program.
        wasi_out = _run_wasi_component(_ENV_GET_SRC)
        py_out = _run_python(_ENV_GET_SRC)
        self.assertEqual(py_out, wasi_out)

    def test_env_args_empty(self):
        out = _run_wasi_component(_ENV_ARGS_SRC, args=())
        self.assertIn("argc=0", out)

    def test_env_args_passed_through(self):
        out = _run_wasi_component(_ENV_ARGS_SRC, args=("alpha", "beta"))
        self.assertIn("argc=2", out)
        self.assertIn("arg=alpha", out)
        self.assertIn("arg=beta", out)

    def test_env_random_clock_coexist(self):
        # Env + Random + Clock all on wasi:* in one component; Stdio on
        # capa:host. Hybrid coexistence with three wasi interfaces.
        out = _run_wasi_component(_ENV_HYBRID_SRC)
        self.assertIn(f"env={_ENV_VAL}", out)
        self.assertIn("wall ok", out)
        # Seeded draw is byte-stable; with_seed(7).int_range(0,100)
        # matches the Python backend.
        py_out = _run_python(_ENV_HYBRID_SRC)
        wasi_rng = next(
            ln for ln in out.splitlines() if ln.startswith("rng=")
        )
        py_rng = next(
            ln for ln in py_out.splitlines() if ln.startswith("rng=")
        )
        self.assertEqual(wasi_rng, py_rng)

    def test_example_env_program_runs(self):
        import os
        from pathlib import Path
        os.environ["CAPA_WASI_ENV_DEMO"] = "demo-value"
        try:
            path = (
                Path(__file__).resolve().parent.parent
                / "examples" / "wasm" / "wasi_env.capa"
            )
            out = _run_wasi_component(path.read_text(encoding="utf-8"))
        finally:
            os.environ.pop("CAPA_WASI_ENV_DEMO", None)
        self.assertIn("CAPA_WASI_ENV_DEMO=demo-value", out)
        self.assertIn("absent: none", out)
        self.assertIn("argc=0", out)


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_wasip2(),
    "wasm-tools and/or wasmtime-py with WASI P2 not installed",
)
class TestWasiEnvAttenuation(unittest.TestCase):
    """End-to-end GUEST-SIDE Env attenuation under the real WASI P2
    host, with three-way byte-parity (Python oracle == capa:host
    backend == WASI backend).

    The three controlled keys are set in ``os.environ`` for the
    duration of each test so every backend observes the same surface
    (the Python runtime reads ``os.environ`` directly; the capa:host
    bridge reads it host-side; the WASI host ``inherit_env``s it to the
    component). The narrowing then happens guest-side on the WASI path
    and host-side on the capa:host path; both must equal the oracle."""

    def setUp(self):
        import os
        self._saved = {k: os.environ.get(k) for k in _ATT_VALS}
        for k, v in _ATT_VALS.items():
            os.environ[k] = v

    def tearDown(self):
        import os
        for k, old in self._saved.items():
            if old is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = old

    def test_intersection_and_fail_closed(self):
        # restrict_to_keys([A,B]).restrict_to_keys([B,C]) -> {B}.
        out = _run_wasi_component(_ENV_ATTEN_SRC)
        self.assertIn("allows_B=yes", out)
        self.assertIn("allows_A=no", out)   # narrowed out by the chain
        self.assertIn("allows_C=no", out)   # never in the first list
        self.assertIn(f"get_B={_ATT_VALS[_ATT_B]}", out)
        # Fail-closed: A is set in the environment but denied by the
        # allow-list, so get reads None without consulting it.
        self.assertIn("get_A=none", out)
        # The wider parent still admits A (each Env carries its own
        # restriction).
        self.assertIn(f"parent_get_A={_ATT_VALS[_ATT_A]}", out)

    def test_intersection_parity_three_backends(self):
        # The load-bearing parity claim: guest-side (WASI) == host-side
        # (capa:host) == Python oracle, byte-for-byte, for the
        # controlled keys.
        wasi_out = _run_wasi_component(_ENV_ATTEN_SRC)
        host_out = _run_capa_host_component(_ENV_ATTEN_SRC)
        py_out = _run_python(_ENV_ATTEN_SRC)
        self.assertEqual(py_out, host_out)
        self.assertEqual(py_out, wasi_out)

    def test_unrestricted_root_and_empty_restriction(self):
        out = _run_wasi_component(_ENV_ATTEN_EDGE_SRC)
        # Unrestricted root: allows + reads everything.
        self.assertIn("root_allows=yes", out)
        self.assertIn(f"root_get={_ATT_VALS[_ATT_A]}", out)
        # restrict_to_keys([]) admits nothing (distinct from the
        # unrestricted root): allows is false and get fail-closes.
        self.assertIn("empty_allows=no", out)
        self.assertIn("empty_get=none", out)

    def test_edge_parity_three_backends(self):
        wasi_out = _run_wasi_component(_ENV_ATTEN_EDGE_SRC)
        host_out = _run_capa_host_component(_ENV_ATTEN_EDGE_SRC)
        py_out = _run_python(_ENV_ATTEN_EDGE_SRC)
        self.assertEqual(py_out, host_out)
        self.assertEqual(py_out, wasi_out)

    def test_example_attenuation_program_runs(self):
        import os
        from pathlib import Path
        keys = {
            "CAPA_WASI_A": "alpha",
            "CAPA_WASI_B": "bravo",
            "CAPA_WASI_C": "charlie",
        }
        saved = {k: os.environ.get(k) for k in keys}
        for k, v in keys.items():
            os.environ[k] = v
        try:
            path = (
                Path(__file__).resolve().parent.parent
                / "examples" / "wasm" / "wasi_env_attenuation.capa"
            )
            out = _run_wasi_component(path.read_text(encoding="utf-8"))
        finally:
            for k, old in saved.items():
                if old is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = old
        self.assertIn("allows B: yes", out)
        self.assertIn("allows A: no", out)
        self.assertIn("get B: bravo", out)
        self.assertIn("get A: none", out)
        self.assertIn("parent get A: alpha", out)


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_wasip2(),
    "wasm-tools and/or wasmtime-py with WASI P2 not installed",
)
class TestWasiEnvCeilingLevel1(unittest.TestCase):
    """End-to-end Env Level 1 (the authority ceiling mapped to the WASI
    env-set) under the real WASI P2 host.

    Two host env vars are set: ``CAPA_PUBLIC`` (read by the program via
    a literal ``env.get``) and ``CAPA_SECRET`` (never read). With a
    CLOSED ceiling the host instantiates the component with an env-set
    of ONLY the ceiling keys, so ``CAPA_SECRET`` is never delivered (the
    leak-by-default fix). The program's observable output is unchanged
    from the inherit_env path, because it only ever reads ceiling keys.
    """

    _PUB = "CAPA_CEILING_PUBLIC"
    _SECRET = "CAPA_CEILING_SECRET"

    # Reads CAPA_PUBLIC by literal; never names CAPA_SECRET. Also reads a
    # literal key absent from the host env to show fail-closed parity.
    _CLOSED_SRC = (
        "fun main(stdio: Stdio, env: Env)\n"
        f"    let p = env.get(\"{_PUB}\")\n"
        "    match p\n"
        "        Some(v) -> stdio.println(\"pub=${v}\")\n"
        "        None -> stdio.println(\"pub=<unset>\")\n"
        "    let m = env.get(\"CAPA_CEILING_ABSENT_KEY_999\")\n"
        "    match m\n"
        "        Some(_) -> stdio.println(\"absent=SET\")\n"
        "        None -> stdio.println(\"absent=none\")\n"
    )

    # A dynamic key forces the inherit_env fallback (Level 2).
    _DYNAMIC_SRC = (
        "fun main(stdio: Stdio, env: Env)\n"
        "    let prefix = \"CAPA_CEILING_\"\n"
        "    let key = \"${prefix}PUBLIC\"\n"
        "    let p = env.get(key)\n"
        "    match p\n"
        "        Some(v) -> stdio.println(\"pub=${v}\")\n"
        "        None -> stdio.println(\"pub=<unset>\")\n"
    )

    def setUp(self):
        import os
        self._saved = {
            k: os.environ.get(k) for k in (self._PUB, self._SECRET)
        }
        os.environ[self._PUB] = "public-value"
        os.environ[self._SECRET] = "secret-value"

    def tearDown(self):
        import os
        for k, old in self._saved.items():
            if old is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = old

    def test_closed_ceiling_delivers_only_read_keys(self):
        out, env_applied = _run_wasi_component_with_ceiling(self._CLOSED_SRC)
        # Functional output: reads the public key, fail-closes on the
        # absent literal key (in the ceiling but absent from host env).
        self.assertIn("pub=public-value", out)
        self.assertIn("absent=none", out)
        # The leak-closed proof: the env-set actually installed on the
        # component is exactly the ceiling-key projection. CAPA_SECRET
        # is NOT delivered to the component.
        self.assertIsInstance(env_applied, dict)
        self.assertEqual(env_applied, {self._PUB: "public-value"})
        self.assertNotIn(self._SECRET, env_applied)

    def test_closed_ceiling_output_parity_three_backends(self):
        # The observable output is identical across Python, capa:host
        # (inherit-all host-side), and WASI Level 1 (restricted env-set),
        # because the program only ever reads ceiling keys.
        wasi_out, _ = _run_wasi_component_with_ceiling(self._CLOSED_SRC)
        host_out = _run_capa_host_component(self._CLOSED_SRC)
        py_out = _run_python(self._CLOSED_SRC)
        self.assertEqual(py_out, host_out)
        self.assertEqual(py_out, wasi_out)

    def test_dynamic_key_falls_back_to_inherit_env(self):
        out, env_applied = _run_wasi_component_with_ceiling(self._DYNAMIC_SRC)
        # Not closed -> inherit_env (Level 2); the program still reads
        # the (dynamically named) key correctly.
        self.assertEqual(env_applied, "inherit")
        self.assertIn("pub=public-value", out)


# ===================================================================
# WASI Fs metadata via wasi:filesystem (Phase 0 + metadata).
# exists / is_dir / mkdir migrate to wasi:filesystem stat-at /
# create-directory-at against host preopen descriptors; read / write /
# list_dir / restrict_to / allows are rejected at compile time.
# ===================================================================


def _fs_ceiling(src: str):
    from capa.ir import compute_fs_ceiling
    module, result = _parse_analyze(src)
    return compute_fs_ceiling(module, types=result.types)


class TestWasiFsCeilingAnalysis(unittest.TestCase):
    """The static Fs preopen ceiling (no wasm-tools needed)."""

    def test_literal_paths_close_the_ceiling(self):
        src = (
            "fun main(fs: Fs, stdio: Stdio)\n"
            "    stdio.println(\"${fs.exists(\\\"/a/b/file.txt\\\")}\")\n"
            "    let r = fs.mkdir(\"/a/b/sub\")\n"
        )
        c = _fs_ceiling(src)
        self.assertTrue(c.closed)
        # Both literals share parent /a/b; one preopen, READ_WRITE
        # (mkdir mutates it).
        self.assertEqual(len(c.preopens), 1)
        self.assertEqual(c.preopens[0].host_path, "/a/b")
        self.assertTrue(c.preopens[0].read_write)

    def test_read_only_when_no_mutating_op(self):
        src = (
            "fun main(fs: Fs, stdio: Stdio)\n"
            "    stdio.println(\"${fs.exists(\\\"/ro/x\\\")}\")\n"
            "    stdio.println(\"${fs.is_dir(\\\"/ro/y\\\")}\")\n"
        )
        c = _fs_ceiling(src)
        self.assertTrue(c.closed)
        self.assertEqual(len(c.preopens), 1)
        self.assertEqual(c.preopens[0].host_path, "/ro")
        self.assertFalse(c.preopens[0].read_write)

    def test_dynamic_path_opens_the_ceiling(self):
        # A path read through env is not a literal -> not closed
        # (fail-closed). The host materialises no preopens.
        src = (
            "fun main(fs: Fs, env: Env, stdio: Stdio)\n"
            "    let p = env.get(\"P\")\n"
            "    match p\n"
            "        Some(path) -> stdio.println("
            "\"${fs.exists(path)}\")\n"
            "        None -> stdio.println(\"none\")\n"
        )
        c = _fs_ceiling(src)
        self.assertFalse(c.closed)
        self.assertEqual(c.preopens, ())

    def test_resolve_maps_literal_to_index_and_basename(self):
        from capa.ir import resolve_fs_call
        src = (
            "fun main(fs: Fs, stdio: Stdio)\n"
            "    stdio.println(\"${fs.exists(\\\"/p/q/file.txt\\\")}\")\n"
            "    stdio.println(\"${fs.is_dir(\\\"/other/dir\\\")}\")\n"
        )
        c = _fs_ceiling(src)
        self.assertTrue(c.closed)
        # Sorted parents: /other, /p/q.
        self.assertEqual(
            [p.host_path for p in c.preopens], ["/other", "/p/q"],
        )
        self.assertEqual(resolve_fs_call(c, "/p/q/file.txt"), (1, "file.txt"))
        self.assertEqual(resolve_fs_call(c, "/other/dir"), (0, "dir"))

    def test_nested_parents_coalesce_to_outermost(self):
        # A parent nested under another collected parent is folded into
        # the outer preopen (wasmtime collapses overlapping preopens and
        # would trap on the inner descriptor index). The inner path
        # resolves to the outer preopen with a multi-segment relative
        # path, and READ_WRITE propagates up from the mutating member.
        from capa.ir import resolve_fs_call
        src = (
            "fun main(fs: Fs, stdio: Stdio)\n"
            "    stdio.println(\"${fs.exists(\\\"/root/x\\\")}\")\n"
            "    let r = fs.mkdir(\"/root/sub/dir\")\n"
        )
        c = _fs_ceiling(src)
        self.assertTrue(c.closed)
        # Only the outermost /root survives, READ_WRITE (mkdir under it).
        self.assertEqual(len(c.preopens), 1)
        self.assertEqual(c.preopens[0].host_path, "/root")
        self.assertTrue(c.preopens[0].read_write)
        # The nested path resolves to /root with a multi-segment rel.
        self.assertEqual(resolve_fs_call(c, "/root/x"), (0, "x"))
        self.assertEqual(
            resolve_fs_call(c, "/root/sub/dir"), (0, "sub/dir"),
        )

    def test_directory_itself_resolves_to_dot(self):
        # A path that IS a preopen directory (e.g. is_dir of the dir
        # whose own parent is the preopen) resolves to a "." relative.
        from capa.ir import resolve_fs_call
        src = (
            "fun main(fs: Fs, stdio: Stdio)\n"
            "    stdio.println(\"${fs.is_dir(\\\"/a/b\\\")}\")\n"
            "    stdio.println(\"${fs.exists(\\\"/a/b/c\\\")}\")\n"
        )
        c = _fs_ceiling(src)
        # Parents: /a (for /a/b) and /a/b (for /a/b/c) -> coalesce to /a.
        self.assertEqual([p.host_path for p in c.preopens], ["/a"])
        self.assertEqual(resolve_fs_call(c, "/a/b"), (0, "b"))
        self.assertEqual(resolve_fs_call(c, "/a/b/c"), (0, "b/c"))

    def test_mkdir_prefixes_cumulative_segments(self):
        # Recursive mkdir splits a relative target into its cumulative
        # prefixes (os.makedirs order), the sequence the call site emits
        # one create-directory-at per. Single-segment and "." (the
        # preopen itself) stay one call, the prior behaviour.
        from capa.ir import mkdir_prefixes
        self.assertEqual(mkdir_prefixes("a/b/c"), ("a", "a/b", "a/b/c"))
        self.assertEqual(mkdir_prefixes("sub"), ("sub",))
        self.assertEqual(mkdir_prefixes("."), (".",))
        # Defensive normalisation: stray leading / trailing / doubled
        # separators collapse to clean cumulative segments.
        self.assertEqual(mkdir_prefixes("x/y/"), ("x", "x/y"))
        self.assertEqual(mkdir_prefixes("/p/q"), ("p", "p/q"))


class TestWasiFsWitGeneration(unittest.TestCase):
    """WIT shape for Fs metadata (no wasm-tools needed)."""

    def _wit(self, src: str) -> str:
        from capa.ir import compile_wit
        module, result = _parse_analyze(src)
        return compile_wit(module, types=result.types, wasi=True)

    _FS_SRC = (
        "fun main(fs: Fs, stdio: Stdio)\n"
        "    stdio.println(\"${fs.exists(\\\"/d/f\\\")}\")\n"
        "    let r = fs.mkdir(\"/d/sub\")\n"
    )

    def test_world_imports_wasi_filesystem(self):
        wit = self._wit(self._FS_SRC)
        self.assertIn("import wasi:filesystem/types@0.2.0;", wit)
        self.assertIn("import wasi:filesystem/preopens@0.2.0;", wit)
        # Metadata-only program does NOT pull in the io stream imports.
        self.assertNotIn("import wasi:io/streams@0.2.0;", wit)
        self.assertNotIn("import wasi:io/error@0.2.0;", wit)

    def test_read_world_imports_io_streams(self):
        # A program reaching fs.read additionally imports
        # wasi:io/streams (blocking-read) and wasi:io/error (the
        # resource-drop of the error a failed read carries).
        src = (
            "fun main(fs: Fs, stdio: Stdio)\n"
            "    let r = fs.read(\"/d/f.txt\")\n"
            "    match r\n"
            "        Ok(c) -> stdio.println(c)\n"
            "        Err(e) -> stdio.println(\"err\")\n"
        )
        wit = self._wit(src)
        self.assertIn("import wasi:filesystem/types@0.2.0;", wit)
        self.assertIn("import wasi:io/streams@0.2.0;", wit)
        self.assertIn("import wasi:io/error@0.2.0;", wit)

    def test_write_world_imports_io_streams(self):
        # A program reaching fs.write additionally imports
        # wasi:io/streams (blocking-write-and-flush / blocking-flush)
        # and wasi:io/error (the resource-drop of the error a failed
        # stream op carries), same as read.
        src = (
            "fun main(fs: Fs, stdio: Stdio)\n"
            "    let r = fs.write(\"/d/f.txt\", \"x\")\n"
            "    match r\n"
            "        Ok(_) -> stdio.println(\"ok\")\n"
            "        Err(e) -> stdio.println(\"err\")\n"
        )
        wit = self._wit(src)
        self.assertIn("import wasi:filesystem/types@0.2.0;", wit)
        self.assertIn("import wasi:io/streams@0.2.0;", wit)
        self.assertIn("import wasi:io/error@0.2.0;", wit)

    def test_no_capa_host_fs_interface(self):
        # Fs metadata routes off capa:host entirely in WASI mode.
        wit = self._wit(self._FS_SRC)
        self.assertNotIn("interface fs {", wit)
        self.assertNotIn("  import fs;", wit)

    def test_default_mode_unchanged(self):
        from capa.ir import compile_wit
        module, result = _parse_analyze(self._FS_SRC)
        wit = compile_wit(module, types=result.types, wasi=False)
        self.assertIn("interface fs {", wit)
        self.assertNotIn("wasi:filesystem", wit)


class TestWasiFsRejections(unittest.TestCase):
    """The non-migrated Fs surface is rejected at compile time."""

    def _compile(self, src: str):
        from capa.ir import compile_wat
        module, result = _parse_analyze(src)
        return compile_wat(module, types=result.types, wasi=True)

    def test_write_accepted(self):
        # write compiles cleanly and emits the wasi:filesystem +
        # wasi:io/streams write wrappers (no capa:host/fs import).
        src = (
            "fun main(fs: Fs, stdio: Stdio)\n"
            "    let r = fs.write(\"/d/f\", \"x\")\n"
            "    match r\n"
            "        Ok(_) -> stdio.println(\"ok\")\n"
            "        Err(e) -> stdio.println(\"err\")\n"
        )
        wat = self._compile(src)
        self.assertIn("(func $Fs_write", wat)
        self.assertIn("(func $__wasi_fs_preopen_desc", wat)
        self.assertIn("[method]descriptor.open-at", wat)
        self.assertIn("[method]descriptor.write-via-stream", wat)
        self.assertIn(
            "[method]output-stream.blocking-write-and-flush", wat,
        )
        self.assertIn("[method]output-stream.blocking-flush", wat)
        self.assertIn("[resource-drop]output-stream", wat)
        self.assertIn("[resource-drop]descriptor", wat)
        self.assertIn("[resource-drop]error", wat)
        # No capa:host/fs interface is imported in WASI mode.
        self.assertNotIn('"capa:host/fs"', wat)

    def test_list_dir_rejected(self):
        src = (
            "fun main(fs: Fs, stdio: Stdio)\n"
            "    let r = fs.list_dir(\"/d\")\n"
            "    match r\n"
            "        Ok(xs) -> stdio.println(\"ok\")\n"
            "        Err(e) -> stdio.println(\"err\")\n"
        )
        with self.assertRaises(Exception) as cm:
            self._compile(src)
        self.assertIn("Fs.list_dir", str(cm.exception))

    def test_allows_rejected(self):
        src = (
            "fun main(fs: Fs, stdio: Stdio)\n"
            "    stdio.println(\"${fs.allows(\\\"/d/f\\\")}\")\n"
        )
        with self.assertRaises(Exception) as cm:
            self._compile(src)
        self.assertIn("Fs.allows", str(cm.exception))

    def test_dynamic_path_fail_closed_rejected(self):
        # A migrated metadata op with a dynamic path is rejected
        # (fail-closed: no preopen can be derived).
        src = (
            "fun main(fs: Fs, env: Env, stdio: Stdio)\n"
            "    let p = env.get(\"P\")\n"
            "    match p\n"
            "        Some(path) -> stdio.println("
            "\"${fs.exists(path)}\")\n"
            "        None -> stdio.println(\"none\")\n"
        )
        with self.assertRaises(Exception) as cm:
            self._compile(src)
        self.assertIn("WASI mode", str(cm.exception))
        self.assertIn("literal", str(cm.exception))

    def test_metadata_accepted(self):
        # exists / is_dir / mkdir compile cleanly and emit the
        # wasi:filesystem wrappers (no capa:host/fs import).
        src = (
            "fun main(fs: Fs, stdio: Stdio)\n"
            "    stdio.println(\"${fs.exists(\\\"/d/f\\\")}\")\n"
            "    stdio.println(\"${fs.is_dir(\\\"/d/g\\\")}\")\n"
            "    let r = fs.mkdir(\"/d/sub\")\n"
        )
        wat = self._compile(src)
        self.assertIn("(func $Fs_exists", wat)
        self.assertIn("(func $Fs_is_dir", wat)
        self.assertIn("(func $Fs_mkdir", wat)
        self.assertIn("(func $__wasi_fs_preopen_desc", wat)
        self.assertIn("wasi:filesystem/preopens@0.2.0", wat)
        self.assertIn("[method]descriptor.stat-at", wat)
        self.assertIn("[method]descriptor.create-directory-at", wat)
        self.assertNotIn('"capa:host/fs"', wat)

    def test_read_accepted(self):
        # read compiles cleanly and emits the wasi:filesystem +
        # wasi:io/streams wrappers (open-at -> read-via-stream ->
        # blocking-read), with all three resource drops and no
        # capa:host/fs import.
        src = (
            "fun main(fs: Fs, stdio: Stdio)\n"
            "    let r = fs.read(\"/d/file.txt\")\n"
            "    match r\n"
            "        Ok(c) -> stdio.println(c)\n"
            "        Err(e) -> stdio.println(\"err\")\n"
        )
        wat = self._compile(src)
        self.assertIn("(func $Fs_read", wat)
        self.assertIn("(func $__wasi_fs_preopen_desc", wat)
        self.assertIn("[method]descriptor.open-at", wat)
        self.assertIn("[method]descriptor.read-via-stream", wat)
        self.assertIn("[method]input-stream.blocking-read", wat)
        # All three OWN resource drops are imported.
        self.assertIn(
            '"wasi:filesystem/types@0.2.0" "[resource-drop]descriptor"',
            wat,
        )
        self.assertIn(
            '"wasi:io/streams@0.2.0" "[resource-drop]input-stream"', wat,
        )
        self.assertIn(
            '"wasi:io/error@0.2.0" "[resource-drop]error"', wat,
        )
        self.assertNotIn('"capa:host/fs"', wat)

    def test_read_dynamic_path_fail_closed_rejected(self):
        # A read with a dynamic path is rejected (fail-closed: no
        # preopen can be derived), exactly like the metadata ops.
        src = (
            "fun main(fs: Fs, env: Env, stdio: Stdio)\n"
            "    let p = env.get(\"P\")\n"
            "    match p\n"
            "        Some(path) ->\n"
            "            let r = fs.read(path)\n"
            "            match r\n"
            "                Ok(c) -> stdio.println(c)\n"
            "                Err(e) -> stdio.println(\"err\")\n"
            "        None -> stdio.println(\"none\")\n"
        )
        with self.assertRaises(Exception) as cm:
            self._compile(src)
        self.assertIn("WASI mode", str(cm.exception))
        self.assertIn("literal", str(cm.exception))


class TestWasiFsWitLicenseHeaders(unittest.TestCase):
    """The vendored wasi:filesystem / wasi:io WIT carry SPDX +
    provenance headers (no wasm-tools needed)."""

    def _wit(self, *parts):
        from pathlib import Path
        return (
            Path(__file__).resolve().parent.parent
            / "capa" / "wasi_wit" / "deps" / Path(*parts)
        ).read_text(encoding="utf-8")

    def test_filesystem_spdx_header(self):
        text = self._wit("filesystem", "filesystem.wit")
        self.assertIn(
            "SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception", text
        )
        self.assertIn("wasi-filesystem", text)
        self.assertIn("get-directories", text)
        self.assertIn("stat-at", text)
        self.assertIn("create-directory-at", text)

    def test_io_spdx_header(self):
        text = self._wit("io", "io.wit")
        self.assertIn(
            "SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception", text
        )
        self.assertIn("wasi-io", text)


def _run_fs_program_three_ways(src: str):
    """Build + run a Fs metadata program on the Python backend, the
    capa:host component backend, and the WASI component backend.
    Returns ``(py, host, wasi)`` stdout strings. The program's paths
    must be literals under a controlled directory the caller created."""
    from capa.ir import compile_wasm, compile_wit, compute_fs_ceiling
    from capa.cli import _wrap_as_component
    from capa.runtime._wasm_component_host import WasmComponentHost
    module, result = _parse_analyze(src)

    def _cap(buf_fn):
        buf = io.StringIO()
        saved = sys.stdout
        sys.stdout = buf
        try:
            buf_fn()
        finally:
            sys.stdout = saved
        return buf.getvalue()

    py = _run_python(src)
    # capa:host component
    core_h = compile_wasm(module, types=result.types, wasi=False)
    wit_h = compile_wit(module, types=result.types, wasi=False)
    comp_h = _wrap_as_component(core_h, wit_h, wasi=False)
    host = _cap(
        lambda: WasmComponentHost(wasi=False).run_main(comp_h)
    )
    # WASI component (with the Fs preopen ceiling)
    core_w = compile_wasm(module, types=result.types, wasi=True)
    wit_w = compile_wit(module, types=result.types, wasi=True)
    comp_w = _wrap_as_component(core_w, wit_w, wasi=True)
    ceiling = compute_fs_ceiling(module, types=result.types)
    wasi = _cap(
        lambda: WasmComponentHost(
            wasi=True, fs_ceiling=ceiling,
        ).run_main(comp_w)
    )
    return py, host, wasi


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_wasip2(),
    "wasm-tools and/or wasmtime-py with WASI P2 not installed",
)
class TestWasiFsMode(unittest.TestCase):
    """End-to-end: the component imports wasi:filesystem, runs, and
    its exists / is_dir / mkdir agree with the Python oracle and the
    capa:host backend over a controlled temp directory."""

    def setUp(self):
        import tempfile
        self._td = tempfile.mkdtemp(prefix="capa-wasi-fs-test-")
        # Controlled fixtures under <td>/data.
        self._data = os.path.join(self._td, "data")
        os.makedirs(os.path.join(self._data, "existing"))
        with open(os.path.join(self._data, "file.txt"), "w") as f:
            f.write("hello")

    def tearDown(self):
        import shutil
        shutil.rmtree(self._td, ignore_errors=True)

    def _src(self) -> str:
        # Forward-slash paths so the same literals work on every OS the
        # WASI host normalises. The data dir is the single preopen
        # (READ_WRITE because mkdir mutates it).
        d = self._data.replace("\\", "/")
        return (
            "fun main(fs: Fs, stdio: Stdio)\n"
            f"    stdio.println(\"ef=${{fs.exists(\\\"{d}/file.txt\\\")}}\")\n"
            f"    stdio.println(\"em=${{fs.exists(\\\"{d}/nope\\\")}}\")\n"
            f"    stdio.println(\"id=${{fs.is_dir(\\\"{d}/existing\\\")}}\")\n"
            f"    stdio.println(\"if=${{fs.is_dir(\\\"{d}/file.txt\\\")}}\")\n"
            f"    let r = fs.mkdir(\"{d}/created\")\n"
            "    match r\n"
            "        Ok(_) -> stdio.println(\"mk=ok\")\n"
            "        Err(e) -> stdio.println(\"mk=err\")\n"
            f"    let r2 = fs.mkdir(\"{d}/created\")\n"
            "    match r2\n"
            "        Ok(_) -> stdio.println(\"mk2=ok\")\n"
            "        Err(e) -> stdio.println(\"mk2=err\")\n"
            f"    stdio.println(\"ec=${{fs.exists(\\\"{d}/created\\\")}}\")\n"
        )

    def test_metadata_correct_and_idempotent(self):
        out = _run_wasi_fs(self._src(), self._data)
        self.assertIn("ef=true", out)        # existing file
        self.assertIn("em=false", out)       # missing
        self.assertIn("id=true", out)        # existing dir
        self.assertIn("if=false", out)       # file is not a dir
        self.assertIn("mk=ok", out)          # created
        self.assertIn("mk2=ok", out)         # idempotent
        self.assertIn("ec=true", out)        # created now exists

    def test_three_backend_parity(self):
        py, host, wasi = _run_fs_program_three_ways(self._src())
        self.assertEqual(py, host)
        self.assertEqual(py, wasi)

    def test_component_imports_wasi_filesystem(self):
        comp = _build_wasi_component(self._src())
        import subprocess
        import tempfile
        with tempfile.NamedTemporaryFile(
            suffix=".wasm", delete=False,
        ) as t:
            t.write(comp)
            path = t.name
        try:
            wit = subprocess.run(
                ["wasm-tools", "component", "wit", path],
                capture_output=True, check=True,
            ).stdout.decode("utf-8", errors="replace")
        finally:
            os.unlink(path)
        self.assertIn("import wasi:filesystem/types@0.2.0;", wit)
        self.assertIn("import wasi:filesystem/preopens@0.2.0;", wit)

    def test_preopen_ceiling_is_minimal(self):
        # The host materialises EXACTLY one preopen (the data dir,
        # READ_WRITE), nothing else: the program can reach no directory
        # outside its literal ceiling.
        from capa.ir import compute_fs_ceiling
        from capa.runtime._wasm_component_host import WasmComponentHost
        module, result = _parse_analyze(self._src())
        ceiling = compute_fs_ceiling(module, types=result.types)
        host = WasmComponentHost(wasi=True, fs_ceiling=ceiling)
        self.assertEqual(
            host._wasi_fs_applied,
            [(self._data.replace("\\", "/"), "rw")],
        )

    def test_dynamic_path_fail_closed_no_preopens(self):
        # A non-closed ceiling registers no preopens (fail-closed).
        from capa.ir import FsCeiling
        from capa.runtime._wasm_component_host import WasmComponentHost
        host = WasmComponentHost(
            wasi=True, fs_ceiling=FsCeiling(closed=False, preopens=()),
        )
        # Trigger the wasi config build (it runs in __init__).
        self.assertEqual(host._wasi_fs_applied, [])

    def test_recursive_mkdir_multi_segment_three_backend_parity(self):
        # REGRESSION (recursive mkdir): mkdir("data/sub/new") when the
        # intermediate "sub" does NOT exist must create the whole tree
        # (os.makedirs(exist_ok=True) semantics) and bite byte-identical
        # across all three backends. The single-segment
        # create-directory-at would return no-entry on the missing
        # parent in --wasi; the call-site emits one create per cumulative
        # prefix (sub, then sub/new) to match the oracle / capa:host.
        d = self._data.replace("\\", "/")
        src = (
            "fun main(fs: Fs, stdio: Stdio)\n"
            f"    let r = fs.mkdir(\"{d}/sub/new\")\n"
            "    match r\n"
            "        Ok(_) -> stdio.println(\"mk=ok\")\n"
            "        Err(e) -> stdio.println(\"mk=err\")\n"
            f"    stdio.println(\"es=${{fs.is_dir(\\\"{d}/sub\\\")}}\")\n"
            f"    stdio.println(\"en=${{fs.is_dir(\\\"{d}/sub/new\\\")}}\")\n"
            # Idempotent re-run of the same deep mkdir is still Ok.
            f"    let r2 = fs.mkdir(\"{d}/sub/new\")\n"
            "    match r2\n"
            "        Ok(_) -> stdio.println(\"mk2=ok\")\n"
            "        Err(e) -> stdio.println(\"mk2=err\")\n"
        )
        py, host, wasi = _run_fs_program_three_ways(src)
        self.assertEqual(py, host)
        self.assertEqual(py, wasi)
        # And the tree was actually built (sanity over the parity).
        self.assertIn("mk=ok", wasi)
        self.assertIn("es=true", wasi)
        self.assertIn("en=true", wasi)
        self.assertIn("mk2=ok", wasi)

    def test_stat_after_mkdir_does_not_corrupt_preopen(self):
        # REGRESSION (scratch sizing): the shared Fs indirect-return
        # scratch must fit the FULL result<descriptor-stat, error-code>
        # that stat-at writes (104 bytes), not just 16. With a 16-byte
        # slot, a stat-at after a create-directory-at overflowed into
        # the cached get-directories list buffer and the NEXT is_dir
        # trapped with "unknown handle index" reading a corrupted
        # preopen descriptor. A program doing mkdir then two is_dir on
        # the same preopen must run clean and match every backend.
        d = self._data.replace("\\", "/")
        src = (
            "fun main(fs: Fs, stdio: Stdio)\n"
            f"    let r = fs.mkdir(\"{d}/made\")\n"
            "    match r\n"
            "        Ok(_) -> stdio.println(\"mk=ok\")\n"
            "        Err(e) -> stdio.println(\"mk=err\")\n"
            f"    stdio.println(\"a=${{fs.is_dir(\\\"{d}/existing\\\")}}\")\n"
            f"    stdio.println(\"b=${{fs.is_dir(\\\"{d}/made\\\")}}\")\n"
        )
        py, host, wasi = _run_fs_program_three_ways(src)
        self.assertEqual(py, host)
        self.assertEqual(py, wasi)
        self.assertIn("mk=ok", wasi)
        self.assertIn("a=true", wasi)
        self.assertIn("b=true", wasi)

    def test_nested_preopens_coalesce_and_run(self):
        # A program that touches both a directory and a path nested
        # below it must coalesce to ONE preopen (overlapping preopens
        # trap in wasmtime), and still produce results matching Python.
        os.makedirs(os.path.join(self._data, "deep", "inner"))
        with open(
            os.path.join(self._data, "deep", "inner", "z.txt"), "w",
        ) as f:
            f.write("z")
        d = self._data.replace("\\", "/")
        src = (
            "fun main(fs: Fs, stdio: Stdio)\n"
            f"    stdio.println(\"a=${{fs.is_dir(\\\"{d}/deep\\\")}}\")\n"
            f"    stdio.println(\"b=${{fs.exists("
            f"\\\"{d}/deep/inner/z.txt\\\")}}\")\n"
        )
        py = _run_python(src)
        wasi = _run_wasi_fs(src, self._data)
        self.assertEqual(py, wasi)
        self.assertIn("a=true", wasi)
        self.assertIn("b=true", wasi)


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_wasip2(),
    "wasm-tools and/or wasmtime-py with WASI P2 not installed",
)
class TestWasiFsRead(unittest.TestCase):
    """End-to-end: fs.read in --wasi mode goes open-at ->
    read-via-stream -> blocking-read loop over wasi:io/streams against
    the host preopens, and its Ok(String) is BYTE-IDENTICAL to the
    Python oracle and the capa:host backend across small / empty /
    large-multichunk / UTF-8 files; a missing file is a coherent Err on
    all three backends. Resource OWN handles (descriptor, input-stream,
    error) are dropped on every path with no leak / double-drop (a
    double-drop or a dropped preopen root would trap a later op).
    """

    def setUp(self):
        import tempfile
        self._td = tempfile.mkdtemp(prefix="capa-wasi-read-test-")
        self._data = os.path.join(self._td, "data")
        os.makedirs(os.path.join(self._data, "sub"))
        # small file.
        with open(os.path.join(self._data, "small.txt"), "wb") as f:
            f.write(b"hello world")
        # empty file (0 bytes): the first blocking-read is closed (EOF).
        with open(os.path.join(self._data, "empty.txt"), "wb") as f:
            f.write(b"")
        # large file > the blocking-read chunk: forces the loop to run
        # multiple iterations and the accumulation buffer to grow.
        with open(os.path.join(self._data, "big.txt"), "wb") as f:
            f.write(b"A" * 10000)
        # UTF-8 multi-byte (accents + emoji + CJK): the bytes must round-
        # trip unchanged so the Capa String is byte-identical.
        with open(
            os.path.join(self._data, "utf8.txt"), "w", encoding="utf-8",
        ) as f:
            f.write("café-\U0001F98A multi: éè你好")
        # nested file under a subdirectory (multi-segment relative path).
        with open(
            os.path.join(self._data, "sub", "c.txt"), "wb",
        ) as f:
            f.write(b"gamma")

    def tearDown(self):
        import shutil
        shutil.rmtree(self._td, ignore_errors=True)

    def _read_src(self, rel: str) -> str:
        d = self._data.replace("\\", "/")
        return (
            "fun main(fs: Fs, stdio: Stdio)\n"
            f"    let r = fs.read(\"{d}/{rel}\")\n"
            "    match r\n"
            "        Ok(c) -> stdio.println(\"OK:${c}\")\n"
            "        Err(e) -> stdio.println(\"ERR\")\n"
        )

    def _assert_three_backend_parity(self, rel: str):
        src = self._read_src(rel)
        py, host, wasi = _run_fs_program_three_ways(src)
        self.assertEqual(py, host, f"py/host diverge for {rel}")
        self.assertEqual(py, wasi, f"py/wasi diverge for {rel}")
        return wasi

    def test_small_file_parity(self):
        out = self._assert_three_backend_parity("small.txt")
        self.assertIn("OK:hello world", out)

    def test_empty_file_parity(self):
        # 0 bytes: Ok("") on every backend (the first blocking-read is
        # stream-error::closed and the loop accumulates nothing).
        out = self._assert_three_backend_parity("empty.txt")
        self.assertEqual(out, "OK:\n")

    def test_large_multichunk_file_parity(self):
        # > one blocking-read chunk: the loop runs multiple iterations
        # and the heap accumulation buffer grows. Byte-identical to the
        # single-shot Python read.
        out = self._assert_three_backend_parity("big.txt")
        self.assertEqual(out, "OK:" + ("A" * 10000) + "\n")

    def test_utf8_multibyte_file_parity(self):
        # Accents + emoji + CJK: the raw bytes round-trip unchanged.
        out = self._assert_three_backend_parity("utf8.txt")
        self.assertIn(
            "café-\U0001F98A multi: éè你好", out,
        )

    def test_nested_relative_path_parity(self):
        # A file under a subdirectory: the resolved relative path is
        # multi-segment (sub/c.txt), addressed against the one preopen.
        out = self._assert_three_backend_parity("sub/c.txt")
        self.assertIn("OK:gamma", out)

    def test_missing_file_is_coherent_err(self):
        # A file that does not exist inside the preopen: open-at fails,
        # the wrapper writes Err(IoError) and drops nothing (nothing
        # opened). Every backend takes the Err arm. The Err MESSAGE
        # differs (the oracle carries the OS errno; the WASI wrapper
        # writes a fixed message), so parity is on the discriminant.
        src = self._read_src("does-not-exist.txt")
        py, host, wasi = _run_fs_program_three_ways(src)
        self.assertIn("ERR", py)
        self.assertIn("ERR", host)
        self.assertIn("ERR", wasi)

    def test_interleaved_reads_and_metadata_no_resource_leak(self):
        # Reads interleaved with metadata ops on the SAME preopen must
        # all succeed: a leaked / double-dropped OWN handle, or a
        # dropped preopen ROOT, would trap the next op. The sequence
        # ends with an exists / is_dir on the same preopen to prove the
        # root descriptor is still live after several open/read/drop
        # cycles.
        d = self._data.replace("\\", "/")
        src = (
            "fun main(fs: Fs, stdio: Stdio)\n"
            f"    let r1 = fs.read(\"{d}/small.txt\")\n"
            "    match r1\n"
            "        Ok(c) -> stdio.println(\"r1=${c}\")\n"
            "        Err(e) -> stdio.println(\"r1=ERR\")\n"
            f"    stdio.println(\"d=${{fs.is_dir(\\\"{d}/sub\\\")}}\")\n"
            f"    let r2 = fs.read(\"{d}/big.txt\")\n"
            "    match r2\n"
            "        Ok(c) -> stdio.println(\"r2ok\")\n"
            "        Err(e) -> stdio.println(\"r2=ERR\")\n"
            f"    let r3 = fs.read(\"{d}/sub/c.txt\")\n"
            "    match r3\n"
            "        Ok(c) -> stdio.println(\"r3=${c}\")\n"
            "        Err(e) -> stdio.println(\"r3=ERR\")\n"
            f"    stdio.println(\"e=${{fs.exists(\\\"{d}/small.txt\\\")}}\")\n"
        )
        py, host, wasi = _run_fs_program_three_ways(src)
        self.assertEqual(py, host)
        self.assertEqual(py, wasi)
        self.assertIn("r1=hello world", wasi)
        self.assertIn("d=true", wasi)
        self.assertIn("r2ok", wasi)
        self.assertIn("r3=gamma", wasi)
        self.assertIn("e=true", wasi)


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_wasip2(),
    "wasm-tools and/or wasmtime-py with WASI P2 not installed",
)
class TestWasiFsWrite(unittest.TestCase):
    """End-to-end: fs.write in --wasi mode goes open-at (create|
    truncate, write) -> write-via-stream -> blocking-write-and-flush
    loop -> blocking-flush over wasi:io/streams against the host
    preopens. Its Ok(Unit) result AND the bytes that land on disk are
    BYTE-IDENTICAL to the Python oracle and the capa:host backend across
    small / empty / large-multichunk / UTF-8 content and an overwrite
    (truncate). The proof is write-then-read-back: each program writes a
    file then reads it back (read is also --wasi), and the test also
    inspects the file on the host disk directly. A write through a
    READ_ONLY preopen is a coherent Err on every backend with no file
    left behind. Resource OWN handles (descriptor, output-stream, error)
    are dropped on every path with no leak / double-drop.
    """

    def setUp(self):
        import tempfile
        self._td = tempfile.mkdtemp(prefix="capa-wasi-write-test-")
        self._data = os.path.join(self._td, "data")
        os.makedirs(os.path.join(self._data, "sub"))

    def tearDown(self):
        import shutil
        shutil.rmtree(self._td, ignore_errors=True)

    def _write_read_src(self, rel: str, content_literal: str) -> str:
        """A program that writes ``content_literal`` to ``rel`` then
        reads it back, printing the write result and the read-back."""
        d = self._data.replace("\\", "/")
        return (
            "fun main(fs: Fs, stdio: Stdio)\n"
            f"    let w = fs.write(\"{d}/{rel}\", \"{content_literal}\")\n"
            "    match w\n"
            "        Ok(_) -> stdio.println(\"W=ok\")\n"
            "        Err(e) -> stdio.println(\"W=err\")\n"
            f"    let r = fs.read(\"{d}/{rel}\")\n"
            "    match r\n"
            "        Ok(c) -> stdio.println(\"R=${c}\")\n"
            "        Err(e) -> stdio.println(\"R=ERR\")\n"
        )

    def _assert_parity_and_disk(self, rel, content_literal, expected_bytes):
        """Run the write-then-read-back program on all three backends
        (each mutating the SAME file in sequence) and assert: identical
        stdout across backends, and the on-disk bytes equal
        ``expected_bytes`` after EACH backend ran (so a backend that
        wrote wrong bytes is caught even if its stdout happened to
        match)."""
        src = self._write_read_src(rel, content_literal)
        target = os.path.join(self._data, rel.replace("/", os.sep))
        outs = {}
        for backend, runner in self._runners(src):
            # Remove any file a prior backend left so each starts clean
            # (create path), except we WANT the overwrite case to test
            # truncate; that is handled by its own test pre-seeding.
            outs[backend] = runner()
            with open(target, "rb") as f:
                disk = f.read()
            self.assertEqual(
                disk, expected_bytes,
                f"{backend} wrote wrong bytes for {rel}",
            )
        self.assertEqual(outs["py"], outs["host"], f"py/host diverge {rel}")
        self.assertEqual(outs["py"], outs["wasi"], f"py/wasi diverge {rel}")
        return outs["wasi"]

    def _runners(self, src):
        """Yield (backend_name, zero-arg runner) for the three backends,
        each capturing stdout. Built lazily so the same source mutates
        disk in a deterministic py -> host -> wasi order."""
        from capa.ir import compile_wasm, compile_wit, compute_fs_ceiling
        from capa.cli import _wrap_as_component
        from capa.runtime._wasm_component_host import WasmComponentHost
        module, result = _parse_analyze(src)

        def _cap(fn):
            buf = io.StringIO()
            saved = sys.stdout
            sys.stdout = buf
            try:
                fn()
            finally:
                sys.stdout = saved
            return buf.getvalue()

        def py():
            return _run_python(src)

        def host():
            core = compile_wasm(module, types=result.types, wasi=False)
            wit = compile_wit(module, types=result.types, wasi=False)
            comp = _wrap_as_component(core, wit, wasi=False)
            return _cap(lambda: WasmComponentHost(wasi=False).run_main(comp))

        def wasi():
            core = compile_wasm(module, types=result.types, wasi=True)
            wit = compile_wit(module, types=result.types, wasi=True)
            comp = _wrap_as_component(core, wit, wasi=True)
            ceiling = compute_fs_ceiling(module, types=result.types)
            return _cap(
                lambda: WasmComponentHost(
                    wasi=True, fs_ceiling=ceiling,
                ).run_main(comp)
            )

        return [("py", py), ("host", host), ("wasi", wasi)]

    def test_small_content_parity(self):
        out = self._assert_parity_and_disk(
            "small.txt", "hello world", b"hello world",
        )
        self.assertIn("W=ok", out)
        self.assertIn("R=hello world", out)

    def test_empty_content_parity(self):
        # Empty content: a 0-byte file (open create|truncate, the write
        # loop runs zero times). Ok(Unit) on every backend.
        out = self._assert_parity_and_disk("empty.txt", "", b"")
        self.assertIn("W=ok", out)
        self.assertEqual(out, "W=ok\nR=\n")

    def test_large_multichunk_content_parity(self):
        # > one blocking-write-and-flush chunk (4096): the write loop
        # runs multiple iterations. Byte-identical on disk.
        big = "A" * 10000
        out = self._assert_parity_and_disk(
            "big.txt", big, b"A" * 10000,
        )
        self.assertIn("W=ok", out)
        self.assertIn("R=" + big, out)

    def test_utf8_multibyte_content_parity(self):
        # Accents + emoji + CJK: the UTF-8 bytes land unchanged.
        content = "café-\U0001F98A multi: éè你好"
        out = self._assert_parity_and_disk(
            "utf8.txt", content, content.encode("utf-8"),
        )
        self.assertIn("W=ok", out)
        self.assertIn("R=" + content, out)

    def test_nested_relative_path_parity(self):
        # A write into a subdirectory: the resolved relative path is
        # multi-segment (sub/n.txt), addressed against the one preopen.
        out = self._assert_parity_and_disk(
            "sub/n.txt", "nested", b"nested",
        )
        self.assertIn("W=ok", out)
        self.assertIn("R=nested", out)

    def test_overwrite_truncates_parity(self):
        # Pre-seed an EXISTING longer file; the write must TRUNCATE it so
        # the final content is exactly the new (shorter) bytes, not a mix.
        rel = "ov.txt"
        target = os.path.join(self._data, rel)
        src = self._write_read_src(rel, "short")
        outs = {}
        for backend, runner in self._runners(src):
            with open(target, "wb") as f:
                f.write(b"PREEXISTING LONGER CONTENT 1234567890")
            outs[backend] = runner()
            with open(target, "rb") as f:
                disk = f.read()
            self.assertEqual(
                disk, b"short", f"{backend} did not truncate on overwrite",
            )
        self.assertEqual(outs["py"], outs["host"])
        self.assertEqual(outs["py"], outs["wasi"])
        self.assertIn("R=short", outs["wasi"])

    def test_write_denied_through_read_only_preopen(self):
        # A write into a READ_ONLY preopen is denied by wasmtime at
        # open-at; the wrapper writes Err(IoError) and drops nothing
        # (nothing opened). No file is left on disk. Construct a forced
        # READ_ONLY ceiling so the same literal write hits a RO preopen.
        from capa.ir import FsCeiling, FsPreopen
        from capa.runtime._wasm_component_host import WasmComponentHost
        from capa.ir import compile_wasm, compile_wit
        from capa.cli import _wrap_as_component
        d = self._data.replace("\\", "/")
        src = (
            "fun main(fs: Fs, stdio: Stdio)\n"
            f"    let w = fs.write(\"{d}/ro.txt\", \"nope\")\n"
            "    match w\n"
            "        Ok(_) -> stdio.println(\"W=ok\")\n"
            "        Err(e) -> stdio.println(\"W=err\")\n"
        )
        module, result = _parse_analyze(src)
        core = compile_wasm(module, types=result.types, wasi=True)
        wit = compile_wit(module, types=result.types, wasi=True)
        comp = _wrap_as_component(core, wit, wasi=True)
        ro_ceiling = FsCeiling(
            closed=True,
            preopens=(FsPreopen(host_path=self._data, read_write=False),),
        )
        buf = io.StringIO()
        saved = sys.stdout
        sys.stdout = buf
        try:
            WasmComponentHost(
                wasi=True, fs_ceiling=ro_ceiling,
            ).run_main(comp)
        finally:
            sys.stdout = saved
        out = buf.getvalue()
        self.assertIn("W=err", out)
        self.assertFalse(
            os.path.exists(os.path.join(self._data, "ro.txt")),
            "a denied write must not leave a file behind",
        )


def _run_wasi_fs(src: str, data_dir: str) -> str:
    """Build + run a Fs program in WASI mode with its preopen ceiling
    computed and handed to the host; capture stdout."""
    from capa.ir import compute_fs_ceiling
    from capa.runtime._wasm_component_host import WasmComponentHost
    comp = _build_wasi_component(src)
    module, result = _parse_analyze(src)
    ceiling = compute_fs_ceiling(module, types=result.types)
    buf = io.StringIO()
    saved = sys.stdout
    sys.stdout = buf
    try:
        WasmComponentHost(wasi=True, fs_ceiling=ceiling).run_main(comp)
    finally:
        sys.stdout = saved
    return buf.getvalue()


if __name__ == "__main__":
    unittest.main()
