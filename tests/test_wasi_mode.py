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


if __name__ == "__main__":
    unittest.main()
