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


def _wasi_run_capture(host, comp) -> str:
    """Run a built WASI component on ``host`` and return its STDOUT as a
    str, read from ``host.captured_stdout()``.

    Stdio Phase 1 (2026-06-29) centralisation: in --wasi the guest writes
    print / println to wasi:cli/stdout (output-stream.blocking-write-and-
    flush), captured by the host's WasiConfig stdout_custom callback --
    NOT through ``sys.stdout``. Reading ``captured_stdout()`` is the
    canonical capture point (the bytes are exactly what the guest wrote);
    every WASI-mode test run funnels through here so the capture lives in
    one place. The bytes are decoded as UTF-8 with surrogatepass (Capa
    strings are WTF-8) so a valid string round-trips byte-for-byte.

    The default (capa:host) and Python oracle runs keep their own
    ``sys.stdout`` redirect: their Stdio output genuinely flows through
    ``sys.stdout``, so they do not use this helper.

    sys.stdout / sys.stderr are redirected to throwaway buffers for the
    duration of the run only to SUPPRESS the host's live echo (the host
    echoes captured bytes onward to the live streams for the CLI's
    benefit and to preserve panic ordering); the test reads the captured
    buffer, not the echo, so the redirect just keeps the test console
    quiet without affecting what is asserted."""
    so, se = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = io.StringIO(), io.StringIO()
    try:
        host.run_main(comp)
    finally:
        sys.stdout, sys.stderr = so, se
    return host.captured_stdout().decode("utf-8", errors="surrogatepass")


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


def _run_wasi_component(src: str, args: tuple = ()) -> str:
    """Build + run a program in WASI mode; capture stdout.

    ``args`` is the program argument vector handed to the host (the
    ``env.args()`` source in WASI mode comes through the WasiConfig
    argv this host sets, not the ``capa:host/env`` bridge)."""
    from capa.runtime._wasm_component_host import WasmComponentHost
    comp = _build_wasi_component(src)
    return _wasi_run_capture(
        WasmComponentHost(args=args, wasi=True), comp,
    )


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
    return _wasi_run_capture(host, comp), host._wasi_env_applied


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


class TestWasiPreopenFlagGuards(unittest.TestCase):
    """``--preopen`` (layer b1) guards: it requires --wasi (or an SBOM
    command) and b1 supports a single preopen for dynamic paths. These
    fail before any Wasm toolchain is needed."""

    def _run_cli(self, argv, src):
        import tempfile
        from pathlib import Path
        from capa.cli import main
        err = io.StringIO()
        old_err, old_out, old_argv = sys.stderr, sys.stdout, sys.argv
        sys.stderr = err
        sys.stdout = io.StringIO()
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "p.capa"
            f.write_text(src, encoding="utf-8")
            sys.argv = ["capa", *argv, str(f)]
            try:
                code = main()
            finally:
                sys.stderr, sys.stdout, sys.argv = old_err, old_out, old_argv
        return code, err.getvalue()

    _DYN = (
        "fun main(fs: Fs, env: Env, stdio: Stdio)\n"
        "    let args = env.args()\n"
        "    match args.get(0)\n"
        "        Some(p) ->\n"
        "            match fs.read(p)\n"
        "                Ok(c) -> stdio.println(c)\n"
        "                Err(e) -> stdio.println(\"err\")\n"
        "        None -> stdio.println(\"none\")\n"
    )

    def test_preopen_without_wasi_rejected(self):
        code, err = self._run_cli(
            ["--wasm", "--component", "--run", "--preopen", "/tmp/x"],
            self._DYN,
        )
        self.assertEqual(code, 1)
        self.assertIn("--preopen requires --wasi", err)

    def test_multiple_preopen_rejected(self):
        code, err = self._run_cli(
            ["--wasm", "--component", "--wasi", "--run",
             "--preopen", "/tmp/a", "--preopen", "/tmp/b"],
            self._DYN,
        )
        self.assertEqual(code, 1)
        self.assertIn("single --preopen", err)

    def test_preopen_allowed_with_manifest(self):
        # --preopen is accepted alongside an SBOM/--manifest command (it
        # records the operator grant). No --wasi needed there.
        code, err = self._run_cli(
            ["--manifest", "--preopen", "/data:ro"], self._DYN,
        )
        self.assertEqual(code, 0, err)


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

    def test_let_bound_literal_folds_and_closes(self):
        # A literal routed through an intermediate `let` is now FOLDED by
        # the inter-procedural const-prop (the (a) local-fold case): the
        # ceiling closes on the resolved key, materialising it via env-set
        # instead of degrading to inherit_env. Sound: the key genuinely
        # reaches env.get, so folding is exact, never an over-grant.
        src = (
            "fun main(stdio: Stdio, env: Env)\n"
            "    let key = \"CAPA_PUBLIC\"\n"
            "    let v = env.get(key)\n"
            "    stdio.println(\"done\")\n"
        )
        ceiling = self._ceiling(src)
        self.assertTrue(ceiling.closed)
        self.assertEqual(ceiling.keys, frozenset({"CAPA_PUBLIC"}))

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

    # Fs metadata only, NO Stdio: keeps the "metadata does not pull in
    # io streams" assertion clean now that Stdio output (Phase 1) imports
    # wasi:io/streams itself. The exists result is bound (not printed) so
    # the program needs no Stdio capability at all.
    _FS_SRC = (
        "fun main(fs: Fs)\n"
        "    let e = fs.exists(\"/d/f\")\n"
        "    let r = fs.mkdir(\"/d/sub\")\n"
    )

    def test_world_imports_wasi_filesystem(self):
        wit = self._wit(self._FS_SRC)
        self.assertIn("import wasi:filesystem/types@0.2.0;", wit)
        self.assertIn("import wasi:filesystem/preopens@0.2.0;", wit)
        # Metadata-only program (no Stdio output) does NOT pull in the io
        # stream imports. With Stdio Phase 1, print / println / eprintln
        # would import wasi:io/streams themselves, so this src omits Stdio
        # to keep the assertion testing the Fs metadata path in isolation.
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

    def test_list_dir_accepted(self):
        # list_dir compiles cleanly and emits the wasi:filesystem
        # directory-enumeration wrappers (open-at with the directory
        # open-flag -> read-directory -> directory-entry-stream.
        # read-directory-entry loop), the guest-side sort helper
        # ($str_cmp), the directory-entry-stream drop, and the shared
        # descriptor drop -- with no capa:host/fs import and no
        # wasi:io/streams (list_dir uses no streams).
        # No Stdio: Stdio output (Phase 1) imports wasi:io/streams itself,
        # so this src binds the list_dir result without printing to keep
        # the "list_dir uses no streams" assertion below isolated to the
        # Fs path. The match arms bind the payload (consumed, not printed).
        src = (
            "fun main(fs: Fs)\n"
            "    let r = fs.list_dir(\"/d\")\n"
            "    match r\n"
            "        Ok(xs) -> xs.length()\n"
            "        Err(e) -> 0\n"
        )
        wat = self._compile(src)
        self.assertIn("(func $Fs_list_dir", wat)
        self.assertIn("(func $__wasi_fs_preopen_desc", wat)
        self.assertIn("[method]descriptor.open-at", wat)
        self.assertIn("[method]descriptor.read-directory", wat)
        self.assertIn(
            "[method]directory-entry-stream.read-directory-entry", wat,
        )
        self.assertIn("[resource-drop]directory-entry-stream", wat)
        self.assertIn(
            '"wasi:filesystem/types@0.2.0" "[resource-drop]descriptor"',
            wat,
        )
        # The guest-side sort comparator (sorted(os.listdir) parity).
        self.assertIn("(func $str_cmp", wat)
        self.assertIn("call $str_cmp", wat)
        # list_dir uses no streams: no wasi:io/streams / wasi:io/error
        # imports are pulled in by a list_dir-only program.
        self.assertNotIn("wasi:io/streams@0.2.0", wat)
        self.assertNotIn("wasi:io/error@0.2.0", wat)
        self.assertNotIn('"capa:host/fs"', wat)

    def test_allows_accepted_guest_side(self):
        # Fs.allows is now SUPPORTED under --wasi, implemented entirely
        # guest-side (Level 2): the receiver Fs handle (0 = unrestricted
        # root, else a List<String> prefix allow-list) is consulted by
        # the guest ``$Fs_allows`` -> ``$Fs_path_allowed`` ->
        # ``$Fs_path_contained`` helpers (no host import).
        src = (
            "fun main(fs: Fs, stdio: Stdio)\n"
            "    stdio.println(\"${fs.allows(\\\"/d/f\\\")}\")\n"
        )
        wat = self._compile(src)
        self.assertIn("(func $Fs_allows", wat)
        self.assertIn("(func $Fs_path_allowed", wat)
        self.assertIn("(func $Fs_path_contained", wat)
        # No capa:host/fs import: the whole attenuation surface is
        # routed off capa:host in WASI mode.
        self.assertNotIn('"capa:host/fs"', wat)

    def test_restrict_to_accepted_guest_side(self):
        # Fs.restrict_to is now SUPPORTED under --wasi, implemented
        # guest-side: it builds a fresh List<String> prefix allow-list
        # (parent's prefixes UNION the new one) via ``$Fs_restrict_to``,
        # the Fs analogue of ``$Env_restrict_to_keys``.
        src = (
            "fun main(fs: Fs, stdio: Stdio)\n"
            "    let s = fs.restrict_to(\"/d/a\")\n"
            "    stdio.println(\"${s.allows(\\\"/d/a/f\\\")}\")\n"
        )
        wat = self._compile(src)
        self.assertIn("(func $Fs_restrict_to", wat)
        self.assertIn("(func $Fs_path_allowed", wat)
        self.assertNotIn('"capa:host/fs"', wat)

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


class TestWasiFsDynamicPreopenCompile(unittest.TestCase):
    """WASI Fs layer b1: the operator ``--preopen`` flag UNBLOCKS a
    DYNAMIC Fs path at compile time (suppressing the dynamic-path
    rejection) and records the grant in the SBOM. Pure-Python checks (no
    wasm-tools / wasmtime), so this class is not gated."""

    _DYN_SRC = (
        "fun main(fs: Fs, env: Env, stdio: Stdio)\n"
        "    let args = env.args()\n"
        "    match args.get(0)\n"
        "        Some(p) ->\n"
        "            match fs.read(p)\n"
        "                Ok(c) -> stdio.println(c)\n"
        "                Err(e) -> stdio.println(\"err\")\n"
        "        None -> stdio.println(\"none\")\n"
    )

    def _compile(self, src: str, *, dynamic_fs: bool):
        from capa.ir import compile_wat
        module, result = _parse_analyze(src)
        return compile_wat(
            module, types=result.types, wasi=True,
            wasi_dynamic_fs=dynamic_fs,
        )

    def test_without_preopen_still_rejected(self):
        # NO regression: without the operator preopen the dynamic path is
        # still rejected at compile time exactly as before.
        with self.assertRaises(Exception) as cm:
            self._compile(self._DYN_SRC, dynamic_fs=False)
        self.assertIn("WASI mode", str(cm.exception))
        self.assertIn("literal", str(cm.exception))

    def test_with_preopen_compiles(self):
        # With the operator preopen the dynamic path compiles: the Fs.read
        # wrapper + the preopen resolver are emitted, no capa:host/fs.
        wat = self._compile(self._DYN_SRC, dynamic_fs=True)
        self.assertIn("(func $Fs_read", wat)
        self.assertIn("(func $__wasi_fs_preopen_desc", wat)
        self.assertNotIn('"capa:host/fs"', wat)

    def test_dynamic_metadata_and_streams_compile(self):
        # exists / is_dir / mkdir / write / list_dir all admit a dynamic
        # path under the operator preopen.
        src = (
            "fun main(fs: Fs, env: Env, stdio: Stdio)\n"
            "    let args = env.args()\n"
            "    match args.get(0)\n"
            "        Some(p) ->\n"
            "            stdio.println(\"${fs.exists(p)}\")\n"
            "            stdio.println(\"${fs.is_dir(p)}\")\n"
            "            let m = fs.mkdir(p)\n"
            "            let w = fs.write(p, \"x\")\n"
            "            let l = fs.list_dir(p)\n"
            "        None -> stdio.println(\"none\")\n"
        )
        wat = self._compile(src, dynamic_fs=True)
        self.assertIn("(func $Fs_exists", wat)
        self.assertIn("(func $Fs_is_dir", wat)
        self.assertIn("(func $Fs_mkdir", wat)
        self.assertIn("(func $Fs_write", wat)
        self.assertIn("(func $Fs_list_dir", wat)

    def test_mixed_literal_and_dynamic_path_clear_message(self):
        # A program that mixes a LITERAL Fs path and a DYNAMIC one under
        # --preopen fails closed (no index misalignment), but with a CLEAR
        # message naming the b1 limitation and the flag, not the internal
        # "no closed preopen ceiling" wording.
        src = (
            "fun main(fs: Fs, env: Env, stdio: Stdio)\n"
            "    let args = env.args()\n"
            "    match fs.read(\"fixed.txt\")\n"
            "        Ok(c) -> stdio.println(c)\n"
            "        Err(e) -> stdio.println(\"err\")\n"
            "    match args.get(0)\n"
            "        Some(p) ->\n"
            "            match fs.read(p)\n"
            "                Ok(c) -> stdio.println(c)\n"
            "                Err(e) -> stdio.println(\"err\")\n"
            "        None -> stdio.println(\"none\")\n"
        )
        with self.assertRaises(Exception) as cm:
            self._compile(src, dynamic_fs=True)
        msg = str(cm.exception)
        self.assertIn("--preopen", msg)
        self.assertIn("MIXING", msg)
        self.assertNotIn("has no closed preopen ceiling", msg)

    def test_operator_preopen_index_is_zero_when_ceiling_open(self):
        # b1 index rule: with no derived preopens (dynamic ceiling) the
        # operator preopen is index 0, the constant the dynamic call site
        # addresses.
        from capa.ir import compile_wat  # noqa: F401
        from capa.ir._emit_wasm import WasmEmitter
        from capa.ir._lower import Lowerer
        module, result = _parse_analyze(self._DYN_SRC)
        cir = Lowerer(types=result.types or {}).lower_module(module)
        em = WasmEmitter(wasi=True, wasi_dynamic_fs=True)
        em.emit(cir)
        self.assertEqual(em._wasi_operator_preopen_index(), 0)

    def test_grant_recorded_in_manifest(self):
        # The operator grant is surfaced in the manifest as a Level-2
        # operator-DECLARED block, distinct from the derived surface.
        from capa.manifest import (
            build_manifest, build_operator_declared_grants,
        )
        module, result = _parse_analyze(self._DYN_SRC)
        grants = build_operator_declared_grants([
            {"kind": "fs", "host_dir": "/data", "permission": "rw"},
        ])
        man = build_manifest(
            module, operator_declared_grants=grants,
        )
        block = man["operator_declared_grants"]
        self.assertEqual(block["trust_level"], "operator-declared")
        self.assertEqual(block["preopens"][0]["host_dir"], "/data")
        self.assertEqual(block["preopens"][0]["permission"], "rw")

    def test_grant_recorded_in_cyclonedx_and_spdx(self):
        from capa.manifest import (
            build_cyclonedx, build_spdx, build_operator_declared_grants,
        )
        module, result = _parse_analyze(self._DYN_SRC)
        grants = build_operator_declared_grants([
            {"kind": "fs", "host_dir": "/data", "permission": "ro"},
        ])
        cdx = build_cyclonedx(
            module, timestamp="2026-06-30T00:00:00Z",
            operator_declared_grants=grants,
        )
        props = {p["name"]: p["value"] for p in cdx["metadata"]["properties"]}
        self.assertEqual(
            props["capa:operator_declared_grants:trust_level"],
            "operator-declared",
        )
        self.assertIn(
            "capa:operator_declared_grant:preopen", props,
        )
        self.assertIn("/data", props["capa:operator_declared_grant:preopen"])
        spdx = build_spdx(
            module, timestamp="2026-06-30T00:00:00Z",
            operator_declared_grants=grants,
        )
        comments = [
            a["comment"] for a in spdx["packages"][0]["annotations"]
        ]
        self.assertTrue(any(
            "operator_declared_grant:preopen" in c for c in comments
        ))

    def test_empty_grant_block_present_by_default(self):
        # The block is always present (empty preopens) so consumers can
        # rely on the shape even when no operator grant is declared.
        from capa.manifest import build_manifest
        module, result = _parse_analyze(
            "fun main(stdio: Stdio)\n    stdio.println(\"hi\")\n"
        )
        man = build_manifest(module)
        self.assertEqual(man["operator_declared_grants"]["preopens"], [])


class TestWasiPreopenSpecParse(unittest.TestCase):
    """The CLI ``--preopen <dir>[:ro|:rw]`` spec parser (pure Python)."""

    def test_default_is_read_write(self):
        from capa.cli import _parse_preopen_spec
        self.assertEqual(_parse_preopen_spec("/data"), ("/data", True))

    def test_ro_suffix(self):
        from capa.cli import _parse_preopen_spec
        self.assertEqual(_parse_preopen_spec("/data:ro"), ("/data", False))

    def test_rw_suffix(self):
        from capa.cli import _parse_preopen_spec
        self.assertEqual(_parse_preopen_spec("/data:rw"), ("/data", True))

    def test_colon_in_path_preserved(self):
        from capa.cli import _parse_preopen_spec
        # Only a trailing :ro / :rw is a permission suffix; a Windows
        # drive colon (or any other colon) is preserved.
        self.assertEqual(
            _parse_preopen_spec("C:/data"), ("C:/data", True),
        )
        self.assertEqual(
            _parse_preopen_spec("C:/data:ro"), ("C:/data", False),
        )


class TestWasiNetDynamicUrlRejections(unittest.TestCase):
    """A DYNAMIC Net url (not a string literal) reaching get / post is
    rejected at COMPILE time in --wasi (2026-06-29), SYMMETRIC with the Fs
    dynamic-path rejection above. Before this, a dynamic url compiled to a
    runtime fail-closed (Err without touching the network) that an
    ``Err(_) -> ()`` arm could swallow silently; now the program does not
    compile under --wasi, making the problem visible to the programmer.
    The rejection is a pure-Python compile-time check (no wasm-tools /
    wasmtime needed), so this class is not gated like the end-to-end ones.
    A LITERAL url still compiles (covered by TestWasiNetRejections)."""

    def _compile(self, src: str):
        from capa.ir import compile_wat
        module, result = _parse_analyze(src)
        return compile_wat(module, types=result.types, wasi=True)

    def _assert_rejected(self, src: str):
        with self.assertRaises(Exception) as cm:
            self._compile(src)
        msg = str(cm.exception)
        self.assertIn("WASI mode", msg)
        self.assertIn("literal", msg)
        # The message names get/post and points at the host ceiling, so the
        # programmer knows precisely what to fix (make the url a literal).
        self.assertIn("get/post", msg)
        return msg

    def test_get_interpolated_url_rejected(self):
        # An interpolated url (the capa_governance_pack shape) is dynamic:
        # rejected at compile (was: silent runtime fail-closed).
        src = (
            "fun main(net: Net, stdio: Stdio, name: String)\n"
            "    match net.get(\"http://api.example/?q=${name}\")\n"
            "        Ok(b) -> stdio.println(b)\n"
            "        Err(e) -> stdio.println(\"e\")\n"
        )
        self._assert_rejected(src)

    def test_get_param_url_rejected(self):
        # A url taken straight from a parameter is dynamic: rejected.
        src = (
            "fun main(net: Net, stdio: Stdio, u: String)\n"
            "    match net.get(u)\n"
            "        Ok(b) -> stdio.println(b)\n"
            "        Err(e) -> stdio.println(\"e\")\n"
        )
        self._assert_rejected(src)

    def test_get_let_bound_literal_folds_and_compiles(self):
        # A literal bound through a let is now FOLDED by the const-prop
        # (the (a) local-fold case): the host ceiling closes on the
        # resolved host, so the program COMPILES (previously rejected as
        # conservatively dynamic). Sound: the url genuinely reaches
        # net.get, so the derived host is exact.
        from capa.ir import compute_net_ceiling
        src = (
            "fun main(net: Net, stdio: Stdio)\n"
            "    let u = \"http://api.example/x\"\n"
            "    match net.get(u)\n"
            "        Ok(b) -> stdio.println(b)\n"
            "        Err(e) -> stdio.println(\"e\")\n"
        )
        module, result = _parse_analyze(src)
        ceiling = compute_net_ceiling(module, types=result.types)
        self.assertTrue(ceiling.closed)
        self.assertEqual(ceiling.hosts, frozenset({"api.example"}))

    def test_post_param_url_rejected(self):
        # post is symmetric with get: a dynamic url is rejected.
        src = (
            "fun main(net: Net, stdio: Stdio, u: String)\n"
            "    match net.post(u, \"body\")\n"
            "        Ok(b) -> stdio.println(b)\n"
            "        Err(e) -> stdio.println(\"e\")\n"
        )
        self._assert_rejected(src)

    def test_literal_get_still_compiles(self):
        # The positive control alongside the rejections: a literal url
        # compiles to the $Net_get wrapper (the host-literal Net tests stay
        # green).
        src = (
            "fun main(net: Net, stdio: Stdio)\n"
            "    match net.get(\"http://api.example/x\")\n"
            "        Ok(b) -> stdio.println(b)\n"
            "        Err(e) -> stdio.println(\"e\")\n"
        )
        wat = self._compile(src)
        self.assertIn("(func $Net_get", wat)

    def test_mixed_literal_and_dynamic_rejected(self):
        # Even ONE dynamic url among otherwise-literal calls opens the
        # ceiling and rejects the whole program (the ceiling is closed only
        # when EVERY get/post url is literal).
        src = (
            "fun main(net: Net, stdio: Stdio, u: String)\n"
            "    match net.get(\"http://api.example/x\")\n"
            "        Ok(b) -> stdio.println(b)\n"
            "        Err(e) -> stdio.println(\"e\")\n"
            "    match net.get(u)\n"
            "        Ok(b) -> stdio.println(b)\n"
            "        Err(e) -> stdio.println(\"e\")\n"
        )
        self._assert_rejected(src)


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
    # WASI component (with the Fs preopen ceiling). Stdio output goes to
    # wasi:cli/stdout now, so read it from the host's captured buffer
    # (the centralised capture point) rather than sys.stdout.
    core_w = compile_wasm(module, types=result.types, wasi=True)
    wit_w = compile_wit(module, types=result.types, wasi=True)
    comp_w = _wrap_as_component(core_w, wit_w, wasi=True)
    ceiling = compute_fs_ceiling(module, types=result.types)
    wasi = _wasi_run_capture(
        WasmComponentHost(wasi=True, fs_ceiling=ceiling), comp_w,
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
            return _wasi_run_capture(
                WasmComponentHost(wasi=True, fs_ceiling=ceiling), comp,
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
        out = _wasi_run_capture(
            WasmComponentHost(wasi=True, fs_ceiling=ro_ceiling), comp,
        )
        self.assertIn("W=err", out)
        self.assertFalse(
            os.path.exists(os.path.join(self._data, "ro.txt")),
            "a denied write must not leave a file behind",
        )


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_wasip2(),
    "wasm-tools and/or wasmtime-py with WASI P2 not installed",
)
class TestWasiFsWriteOnly(unittest.TestCase):
    """Regression for the WRITE-ONLY parity bug (2026-06-28).

    A program whose ONLY Fs operation is ``write`` (no read / exists /
    is_dir / mkdir sharing the literal path) used to FAIL in ``--wasi``
    mode: the resolved relative basename (and the ``failed to write
    file`` Err message) were interned only at ``$Fs_write`` emission
    time, AFTER the static data segment had already been written, so
    they got a valid offset but NO ``(data ...)`` block. The relative
    path the guest handed to ``open-at`` was therefore undefined memory;
    the open failed and the wrapper returned ``Err(IoError)`` with NO
    file written -- diverging from the Python and ``capa:host`` backends,
    which both wrote ``Ok(Unit)`` and the file. A co-present ``read`` of
    the same path masked the bug (it pre-interned the shared basename
    early), which is why ``TestWasiFsWrite`` (every case write-then-read-
    back) never caught it.

    These tests use NO read at all: each asserts the write result AND
    reads the file back from the HOST disk directly in Python. They fail
    before the pre-intern fix (W=err, no file) and pass after.
    """

    def setUp(self):
        import tempfile
        self._td = tempfile.mkdtemp(prefix="capa-wasi-writeonly-test-")
        self._data = os.path.join(self._td, "data")
        os.makedirs(self._data)

    def tearDown(self):
        import shutil
        shutil.rmtree(self._td, ignore_errors=True)

    def _write_only_src(self, rel: str, content_literal: str) -> str:
        """A program whose sole Fs op is a single ``write`` (no read)."""
        d = self._data.replace("\\", "/")
        return (
            "fun main(fs: Fs, stdio: Stdio)\n"
            f'    let w = fs.write("{d}/{rel}", "{content_literal}")\n'
            "    match w\n"
            '        Ok(_) -> stdio.println("W=ok")\n'
            '        Err(e) -> stdio.println("W=err")\n'
        )

    def _runners(self, src):
        """Yield (backend, zero-arg runner) for the three backends, each
        capturing stdout, mutating disk in a deterministic py -> host ->
        wasi order. Mirrors TestWasiFsWrite._runners but for a write-only
        program (no read in the source)."""
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
            return _wasi_run_capture(
                WasmComponentHost(wasi=True, fs_ceiling=ceiling), comp,
            )

        return [("py", py), ("host", host), ("wasi", wasi)]

    def _assert_parity_and_disk(self, rel, content_literal, expected_bytes):
        """Run the write-only program on all three backends (each
        overwriting the SAME file) and assert identical stdout across
        backends AND that the on-disk bytes equal ``expected_bytes``
        after EACH backend ran. The on-disk read is in Python (the
        program has no fs.read), so a wrong-bytes write is caught even if
        stdout matched."""
        src = self._write_only_src(rel, content_literal)
        target = os.path.join(self._data, rel.replace("/", os.sep))
        outs = {}
        for backend, runner in self._runners(src):
            outs[backend] = runner()
            with open(target, "rb") as f:
                disk = f.read()
            self.assertEqual(
                disk, expected_bytes,
                f"{backend} wrote wrong bytes for write-only {rel}",
            )
        self.assertEqual(outs["py"], outs["host"], f"py/host diverge {rel}")
        self.assertEqual(outs["py"], outs["wasi"], f"py/wasi diverge {rel}")
        for backend, out in outs.items():
            self.assertEqual(out, "W=ok\n", f"{backend} not Ok for {rel}")
        return outs["wasi"]

    def test_write_only_creates_new_file(self):
        # (a) A single write that CREATES a new file; no read in the
        # program. Three-backend Ok(Unit) parity + on-disk bytes.
        self._assert_parity_and_disk(
            "new.txt", "hello world", b"hello world",
        )

    def test_write_only_overwrites_existing_file_truncates(self):
        # (b) A single write that OVERWRITES (truncates) a pre-existing
        # longer file; final on-disk content must be exactly the new
        # bytes, not a mix.
        rel = "ov.txt"
        target = os.path.join(self._data, rel)
        src = self._write_only_src(rel, "short")
        outs = {}
        for backend, runner in self._runners(src):
            with open(target, "wb") as f:
                f.write(b"PREEXISTING LONGER CONTENT 1234567890")
            outs[backend] = runner()
            with open(target, "rb") as f:
                disk = f.read()
            self.assertEqual(
                disk, b"short",
                f"{backend} did not truncate on write-only overwrite",
            )
        self.assertEqual(outs["py"], outs["host"])
        self.assertEqual(outs["py"], outs["wasi"])
        self.assertEqual(outs["wasi"], "W=ok\n")

    def test_write_only_several_writes_in_sequence(self):
        # (c) Several distinct write-only calls in one program (different
        # files, no read anywhere). Each must land its own bytes.
        d = self._data.replace("\\", "/")
        src = (
            "fun main(fs: Fs, stdio: Stdio)\n"
            f'    let a = fs.write("{d}/one.txt", "alpha")\n'
            f'    let b = fs.write("{d}/two.txt", "beta")\n'
            f'    let c = fs.write("{d}/three.txt", "gamma")\n'
            "    match a\n"
            '        Ok(_) -> stdio.println("A=ok")\n'
            '        Err(e) -> stdio.println("A=err")\n'
            "    match b\n"
            '        Ok(_) -> stdio.println("B=ok")\n'
            '        Err(e) -> stdio.println("B=err")\n'
            "    match c\n"
            '        Ok(_) -> stdio.println("C=ok")\n'
            '        Err(e) -> stdio.println("C=err")\n'
        )
        outs = {}
        for backend, runner in self._runners(src):
            outs[backend] = runner()
            for name, payload in (
                ("one.txt", b"alpha"),
                ("two.txt", b"beta"),
                ("three.txt", b"gamma"),
            ):
                with open(os.path.join(self._data, name), "rb") as f:
                    self.assertEqual(
                        f.read(), payload,
                        f"{backend} wrong bytes for {name}",
                    )
        self.assertEqual(outs["py"], outs["host"])
        self.assertEqual(outs["py"], outs["wasi"])
        self.assertEqual(outs["wasi"], "A=ok\nB=ok\nC=ok\n")

    def test_write_only_denied_through_read_only_preopen(self):
        # (d) A write-only program whose target preopen is forced
        # READ_ONLY: wasmtime denies the open-at, the wrapper returns
        # Err(IoError) with NO file left behind. Coherent Err, no file.
        from capa.ir import FsCeiling, FsPreopen
        from capa.runtime._wasm_component_host import WasmComponentHost
        from capa.ir import compile_wasm, compile_wit
        from capa.cli import _wrap_as_component
        src = self._write_only_src("ro.txt", "nope")
        module, result = _parse_analyze(src)
        core = compile_wasm(module, types=result.types, wasi=True)
        wit = compile_wit(module, types=result.types, wasi=True)
        comp = _wrap_as_component(core, wit, wasi=True)
        ro_ceiling = FsCeiling(
            closed=True,
            preopens=(FsPreopen(host_path=self._data, read_write=False),),
        )
        out = _wasi_run_capture(
            WasmComponentHost(wasi=True, fs_ceiling=ro_ceiling), comp,
        )
        self.assertEqual(out, "W=err\n")
        self.assertFalse(
            os.path.exists(os.path.join(self._data, "ro.txt")),
            "a denied write-only must not leave a file behind",
        )


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_wasip2(),
    "wasm-tools and/or wasmtime-py with WASI P2 not installed",
)
class TestWasiFsListDir(unittest.TestCase):
    """End-to-end: fs.list_dir in --wasi mode goes open-at (directory
    open-flag) -> read-directory -> directory-entry-stream.
    read-directory-entry loop over the host preopens, accumulates the
    entry names, and SORTS them guest-side ($str_cmp, unsigned byte ==
    Python code-point order) so the returned List<String> is
    BYTE-IDENTICAL -- including the ORDER -- to the Python oracle's
    sorted(os.listdir(path)) and the capa:host backend across a
    multi-entry directory (mixed case + a subdirectory), an empty
    directory (-> empty list), and UTF-8 multi-byte names; a missing
    path and a path that is a FILE (not a directory) are coherent Errs on
    all three backends. The directory-entry-stream and the opened
    descriptor are dropped on every path (the preopen ROOT never).
    """

    def setUp(self):
        import tempfile
        self._td = tempfile.mkdtemp(prefix="capa-wasi-listdir-test-")
        self._data = os.path.join(self._td, "data")
        # A multi-entry directory whose names exercise the lexicographic
        # ordering: an UPPERCASE name (Z, 0x5A) sorts BEFORE the lowercase
        # ones (a/b, 0x61/0x62) by code point, exactly as Python's
        # sorted() does; a subdirectory entry sorts among the files by
        # name with no special treatment. (Names are chosen NOT to collide
        # under a case-insensitive filesystem -- Windows -- so all entries
        # survive.)
        os.makedirs(os.path.join(self._data, "many", "c_dir"))
        for n in ("b.txt", "a.txt", "Z.txt"):
            with open(os.path.join(self._data, "many", n), "wb") as f:
                f.write(b"x")
        # An empty directory: read-directory's first read-directory-entry
        # is none (end of stream), so the list is empty.
        os.makedirs(os.path.join(self._data, "empty"))
        # A plain file (to list_dir as a non-directory -> Err).
        with open(os.path.join(self._data, "afile.txt"), "wb") as f:
            f.write(b"x")
        # A directory with UTF-8 multi-byte names: the byte-wise sort must
        # equal Python's code-point sort over these names.
        self._utf8_dir = os.path.join(self._data, "utf8names")
        os.makedirs(self._utf8_dir)
        for n in ("zebra", "Apple", "banana", "Zulu", "你好"):
            with open(
                os.path.join(self._utf8_dir, n), "w", encoding="utf-8",
            ) as f:
                f.write("x")

    def tearDown(self):
        import shutil
        shutil.rmtree(self._td, ignore_errors=True)

    def _list_src(self, rel: str) -> str:
        d = self._data.replace("\\", "/")
        return (
            "fun main(fs: Fs, stdio: Stdio)\n"
            f"    let r = fs.list_dir(\"{d}/{rel}\")\n"
            "    match r\n"
            "        Ok(xs) ->\n"
            "            for x in xs\n"
            "                stdio.println(x)\n"
            "        Err(e) -> stdio.println(\"ERR\")\n"
        )

    def test_multi_entry_sorted_order_parity(self):
        # The crux: wasi returns entries in FILESYSTEM order; the oracle
        # returns sorted(os.listdir). The guest-side sort makes the ORDER
        # byte-identical. Z.txt (uppercase) sorts before a.txt / b.txt.
        src = self._list_src("many")
        py, host, wasi = _run_fs_program_three_ways(src)
        self.assertEqual(py, host, "py/host diverge")
        self.assertEqual(py, wasi, "py/wasi diverge (order!)")
        self.assertEqual(wasi, "Z.txt\na.txt\nb.txt\nc_dir\n")

    def test_empty_directory_parity(self):
        # An empty directory -> empty List<String> -> no lines printed.
        src = self._list_src("empty")
        py, host, wasi = _run_fs_program_three_ways(src)
        self.assertEqual(py, host)
        self.assertEqual(py, wasi)
        self.assertEqual(wasi, "")

    def test_utf8_names_sorted_parity(self):
        # UTF-8 multi-byte names: the byte-wise $str_cmp must equal
        # Python's code-point sorted(). 你好 (high code points) sorts last.
        expected = sorted(os.listdir(self._utf8_dir))
        src = self._list_src("utf8names")
        py, host, wasi = _run_fs_program_three_ways(src)
        self.assertEqual(py, host)
        self.assertEqual(py, wasi)
        self.assertEqual(
            wasi, "".join(name + "\n" for name in expected),
        )

    def test_missing_directory_is_coherent_err(self):
        # A path that does not exist inside the preopen: open-at fails,
        # the wrapper writes Err(IoError) and drops nothing. Every backend
        # takes the Err arm. The Err MESSAGE differs (the oracle carries
        # the OS errno; the WASI wrapper writes a fixed message), so parity
        # is on the discriminant.
        src = self._list_src("does-not-exist")
        py, host, wasi = _run_fs_program_three_ways(src)
        self.assertIn("ERR", py)
        self.assertIn("ERR", host)
        self.assertIn("ERR", wasi)

    def test_path_is_a_file_is_coherent_err(self):
        # list_dir of a path that is a FILE (not a directory): the
        # directory open-flag makes open-at fail (confirmed by oracle), so
        # the wrapper returns Err on every backend.
        src = self._list_src("afile.txt")
        py, host, wasi = _run_fs_program_three_ways(src)
        self.assertIn("ERR", py)
        self.assertIn("ERR", host)
        self.assertIn("ERR", wasi)

    def test_list_dir_interleaved_with_metadata_no_resource_leak(self):
        # list_dir interleaved with metadata + read on the SAME preopen
        # must all succeed: a leaked / double-dropped OWN handle, or a
        # dropped preopen ROOT, would trap the next op. The sequence ends
        # with an is_dir on the same preopen to prove the root descriptor
        # is still live after the open/read-directory/drop cycle.
        d = self._data.replace("\\", "/")
        src = (
            "fun main(fs: Fs, stdio: Stdio)\n"
            f"    let r = fs.list_dir(\"{d}/many\")\n"
            "    match r\n"
            "        Ok(xs) -> stdio.println(\"n=${xs.length()}\")\n"
            "        Err(e) -> stdio.println(\"ERR\")\n"
            f"    stdio.println(\"d=${{fs.is_dir(\\\"{d}/empty\\\")}}\")\n"
            f"    let r2 = fs.list_dir(\"{d}/utf8names\")\n"
            "    match r2\n"
            "        Ok(xs) -> stdio.println(\"n2=${xs.length()}\")\n"
            "        Err(e) -> stdio.println(\"ERR\")\n"
            f"    stdio.println(\"e=${{fs.exists(\\\"{d}/afile.txt\\\")}}\")\n"
        )
        py, host, wasi = _run_fs_program_three_ways(src)
        self.assertEqual(py, host)
        self.assertEqual(py, wasi)
        self.assertIn("n=4", wasi)
        self.assertIn("d=true", wasi)
        self.assertIn("n2=5", wasi)
        self.assertIn("e=true", wasi)


def _run_wasi_fs(src: str, data_dir: str) -> str:
    """Build + run a Fs program in WASI mode with its preopen ceiling
    computed and handed to the host; capture stdout."""
    from capa.ir import compute_fs_ceiling
    from capa.runtime._wasm_component_host import WasmComponentHost
    comp = _build_wasi_component(src)
    module, result = _parse_analyze(src)
    ceiling = compute_fs_ceiling(module, types=result.types)
    return _wasi_run_capture(
        WasmComponentHost(wasi=True, fs_ceiling=ceiling), comp,
    )


def _build_wasi_dynamic_fs_component(src: str) -> bytes:
    """Build a --wasi component with the operator-preopen flag set, so a
    DYNAMIC Fs path is admitted (layer b1). The compiler suppresses its
    dynamic-path rejection because an operator preopen is declared."""
    from capa.ir import compile_wasm, compile_wit
    from capa.cli import _wrap_as_component
    module, result = _parse_analyze(src)
    core = compile_wasm(
        module, types=result.types, wasi=True, wasi_dynamic_fs=True,
    )
    wit = compile_wit(module, types=result.types, wasi=True)
    return _wrap_as_component(core, wit, wasi=True)


def _run_wasi_dynamic_fs(
    src: str, preopen_dir: str, *, read_write: bool = True,
    args: tuple = (),
) -> str:
    """Build + run a DYNAMIC-path Fs program in WASI mode under a single
    operator ``--preopen`` directory; capture stdout. The dynamic path is
    resolved at runtime relative to ``preopen_dir`` (the operator grant)."""
    from capa.runtime._wasm_component_host import WasmComponentHost
    comp = _build_wasi_dynamic_fs_component(src)
    host = WasmComponentHost(
        args=args, wasi=True,
        fs_operator_preopen=(preopen_dir, read_write),
    )
    return _wasi_run_capture(host, comp)


def _run_python_in_cwd(src: str, cwd: str, args: tuple = ()) -> str:
    """Run a program on the Python oracle with ``cwd`` as the working
    directory and ``args`` as ``sys.argv[1:]`` (so ``env.args()`` and a
    relative Fs path resolve the same way the WASI operator preopen makes
    them resolve: relative to the granted directory)."""
    from capa import transpile
    module, result = _parse_analyze(src)
    code = transpile(module, types=result.types, bindings=result.bindings)
    buf = io.StringIO()
    saved_out, saved_argv, saved_cwd = sys.stdout, list(sys.argv), os.getcwd()
    sys.stdout = buf
    sys.argv = ["prog"] + list(args)
    os.chdir(cwd)
    try:
        ns: dict = {"__name__": "__main__"}
        exec(compile(code, "<wasi-dyn-parity>", "exec"), ns)
    finally:
        sys.stdout = saved_out
        sys.argv = saved_argv
        os.chdir(saved_cwd)
    return buf.getvalue()


def _run_capa_host_in_cwd(src: str, cwd: str, args: tuple = ()) -> str:
    """Run a program on the default capa:host component backend with
    ``cwd`` as the working directory and ``args`` as the program argv, so
    a relative dynamic Fs path resolves identically to the WASI operator
    preopen and the Python oracle."""
    from capa.ir import compile_wasm, compile_wit
    from capa.cli import _wrap_as_component
    from capa.runtime._wasm_component_host import WasmComponentHost
    module, result = _parse_analyze(src)
    core = compile_wasm(module, types=result.types, wasi=False)
    wit = compile_wit(module, types=result.types, wasi=False)
    comp = _wrap_as_component(core, wit, wasi=False)
    buf = io.StringIO()
    saved_out, saved_cwd = sys.stdout, os.getcwd()
    sys.stdout = buf
    os.chdir(cwd)
    try:
        WasmComponentHost(args=args, wasi=False).run_main(comp)
    finally:
        sys.stdout = saved_out
        os.chdir(saved_cwd)
    return buf.getvalue()


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_wasip2(),
    "wasm-tools and/or wasmtime-py with WASI P2 not installed",
)
class TestWasiFsDynamicPreopen(unittest.TestCase):
    """End-to-end WASI Fs layer b1: a genuine DYNAMIC Fs path (sourced
    from ``env.args()``) compiles + runs under a single operator
    ``--preopen`` directory, resolving at runtime relative to it, with
    three-way byte-parity (Python oracle == capa:host backend == WASI
    backend) on both output and filesystem effect. The dynamic path makes
    the static ceiling NOT closed, so the operator preopen is the sole
    preopen (index 0)."""

    def setUp(self):
        import tempfile
        self._td = tempfile.mkdtemp(prefix="capa-wasi-dynfs-")

    def tearDown(self):
        import shutil
        shutil.rmtree(self._td, ignore_errors=True)

    def _fresh_dir(self, name):
        import tempfile
        d = tempfile.mkdtemp(prefix=f"capa-{name}-", dir=self._td)
        return d

    def test_read_dynamic_three_backend_parity(self):
        src = (
            "fun main(fs: Fs, env: Env, stdio: Stdio)\n"
            "    let args = env.args()\n"
            "    match args.get(0)\n"
            "        Some(p) ->\n"
            "            match fs.read(p)\n"
            "                Ok(c) -> stdio.println(c)\n"
            "                Err(e) -> stdio.println(\"ERR\")\n"
            "        None -> stdio.println(\"NOARG\")\n"
        )
        # One controlled directory PER backend so each reads its own copy.
        outs = []
        for be in ("wasi", "py", "host"):
            d = self._fresh_dir(be)
            with open(os.path.join(d, "hello.txt"), "w") as f:
                f.write("DYNAMIC-READ-OK")
            if be == "wasi":
                outs.append(_run_wasi_dynamic_fs(
                    src, d, args=("hello.txt",),
                ))
            elif be == "py":
                outs.append(_run_python_in_cwd(src, d, args=("hello.txt",)))
            else:
                outs.append(_run_capa_host_in_cwd(
                    src, d, args=("hello.txt",),
                ))
        self.assertEqual(outs[0], "DYNAMIC-READ-OK\n")
        self.assertEqual(outs[0], outs[1])
        self.assertEqual(outs[0], outs[2])

    def test_write_dynamic_three_backend_parity_and_effect(self):
        src = (
            "fun main(fs: Fs, env: Env, stdio: Stdio)\n"
            "    let args = env.args()\n"
            "    match args.get(0)\n"
            "        Some(p) ->\n"
            "            match fs.write(p, \"CONTENT-XYZ\")\n"
            "                Ok(u) -> stdio.println(\"WROTE\")\n"
            "                Err(e) -> stdio.println(\"ERR\")\n"
            "        None -> stdio.println(\"NOARG\")\n"
        )
        results = {}
        effects = {}
        for be in ("wasi", "py", "host"):
            d = self._fresh_dir(be)
            if be == "wasi":
                results[be] = _run_wasi_dynamic_fs(src, d, args=("o.txt",))
            elif be == "py":
                results[be] = _run_python_in_cwd(src, d, args=("o.txt",))
            else:
                results[be] = _run_capa_host_in_cwd(src, d, args=("o.txt",))
            with open(os.path.join(d, "o.txt")) as f:
                effects[be] = f.read()
        self.assertEqual(results["wasi"], "WROTE\n")
        self.assertEqual(results["wasi"], results["py"])
        self.assertEqual(results["wasi"], results["host"])
        self.assertEqual(effects["wasi"], "CONTENT-XYZ")
        self.assertEqual(effects["wasi"], effects["py"])
        self.assertEqual(effects["wasi"], effects["host"])

    def test_exists_is_dir_dynamic_parity(self):
        src = (
            "fun main(fs: Fs, env: Env, stdio: Stdio)\n"
            "    let args = env.args()\n"
            "    match args.get(0)\n"
            "        Some(p) ->\n"
            "            stdio.println(\"e=${fs.exists(p)}\")\n"
            "            stdio.println(\"d=${fs.is_dir(p)}\")\n"
            "        None -> stdio.println(\"NOARG\")\n"
        )
        for arg, mk in (("there.txt", "file"), ("adir", "dir"),
                        ("nope", None)):
            results = {}
            for be in ("wasi", "py", "host"):
                d = self._fresh_dir(f"{be}-{arg}")
                with open(os.path.join(d, "there.txt"), "w") as f:
                    f.write("x")
                os.makedirs(os.path.join(d, "adir"))
                if be == "wasi":
                    results[be] = _run_wasi_dynamic_fs(src, d, args=(arg,))
                elif be == "py":
                    results[be] = _run_python_in_cwd(src, d, args=(arg,))
                else:
                    results[be] = _run_capa_host_in_cwd(src, d, args=(arg,))
            self.assertEqual(results["wasi"], results["py"], arg)
            self.assertEqual(results["wasi"], results["host"], arg)

    def test_mkdir_dynamic_parity_and_effect(self):
        src = (
            "fun main(fs: Fs, env: Env, stdio: Stdio)\n"
            "    let args = env.args()\n"
            "    match args.get(0)\n"
            "        Some(p) ->\n"
            "            match fs.mkdir(p)\n"
            "                Ok(u) -> stdio.println(\"MK=ok\")\n"
            "                Err(e) -> stdio.println(\"MK=err\")\n"
            "            stdio.println(\"d=${fs.is_dir(p)}\")\n"
            "        None -> stdio.println(\"NOARG\")\n"
        )
        results = {}
        for be in ("wasi", "py", "host"):
            d = self._fresh_dir(be)
            if be == "wasi":
                results[be] = _run_wasi_dynamic_fs(src, d, args=("newdir",))
            elif be == "py":
                results[be] = _run_python_in_cwd(src, d, args=("newdir",))
            else:
                results[be] = _run_capa_host_in_cwd(src, d, args=("newdir",))
            self.assertTrue(os.path.isdir(os.path.join(d, "newdir")), be)
        self.assertEqual(results["wasi"], results["py"])
        self.assertEqual(results["wasi"], results["host"])

    def test_mkdir_dynamic_multi_segment_parity_and_effect(self):
        # A MULTI-segment dynamic mkdir replicates os.makedirs(exist_ok)
        # at runtime ($Fs_mkdir_recursive over $Fs_mkdir per prefix), so a
        # missing-parent tree is created and the Result matches the oracle.
        src = (
            "fun main(fs: Fs, env: Env, stdio: Stdio)\n"
            "    let args = env.args()\n"
            "    match args.get(0)\n"
            "        Some(p) ->\n"
            "            match fs.mkdir(p)\n"
            "                Ok(u) -> stdio.println(\"MK=ok\")\n"
            "                Err(e) -> stdio.println(\"MK=err\")\n"
            "            stdio.println(\"d=${fs.is_dir(p)}\")\n"
            "        None -> stdio.println(\"NOARG\")\n"
        )
        results = {}
        for be in ("wasi", "py", "host"):
            d = self._fresh_dir(be)
            if be == "wasi":
                results[be] = _run_wasi_dynamic_fs(src, d, args=("a/b/c",))
            elif be == "py":
                results[be] = _run_python_in_cwd(src, d, args=("a/b/c",))
            else:
                results[be] = _run_capa_host_in_cwd(src, d, args=("a/b/c",))
            self.assertTrue(os.path.isdir(os.path.join(d, "a", "b", "c")), be)
        self.assertEqual(results["wasi"], "MK=ok\nd=true\n")
        self.assertEqual(results["wasi"], results["py"])
        self.assertEqual(results["wasi"], results["host"])

    def test_list_dir_dynamic_parity(self):
        src = (
            "fun main(fs: Fs, env: Env, stdio: Stdio)\n"
            "    let args = env.args()\n"
            "    match args.get(0)\n"
            "        Some(p) ->\n"
            "            match fs.list_dir(p)\n"
            "                Ok(names) ->\n"
            "                    for n in names\n"
            "                        stdio.println(n)\n"
            "                Err(e) -> stdio.println(\"ERR\")\n"
            "        None -> stdio.println(\"NOARG\")\n"
        )
        results = {}
        for be in ("wasi", "py", "host"):
            d = self._fresh_dir(be)
            sub = os.path.join(d, "ld")
            os.makedirs(sub)
            for nm in ("b.txt", "a.txt", "c.txt"):
                with open(os.path.join(sub, nm), "w") as f:
                    f.write("")
            if be == "wasi":
                results[be] = _run_wasi_dynamic_fs(src, d, args=("ld",))
            elif be == "py":
                results[be] = _run_python_in_cwd(src, d, args=("ld",))
            else:
                results[be] = _run_capa_host_in_cwd(src, d, args=("ld",))
        self.assertEqual(results["wasi"], "a.txt\nb.txt\nc.txt\n")
        self.assertEqual(results["wasi"], results["py"])
        self.assertEqual(results["wasi"], results["host"])

    def test_restricted_fs_plus_dynamic_path_mitigation(self):
        # The fine attenuation gate ($Fs_path_allowed) still works with a
        # DYNAMIC path: a restrict_to'd Fs denies a runtime path outside
        # the prefix and admits one inside, byte-parity with the oracle.
        src = (
            "fun main(fs: Fs, env: Env, stdio: Stdio)\n"
            "    let r = fs.restrict_to(\"allowed\")\n"
            "    let args = env.args()\n"
            "    match args.get(0)\n"
            "        Some(p) -> stdio.println(\"${r.exists(p)}\")\n"
            "        None -> stdio.println(\"NOARG\")\n"
        )
        for arg, expect in (("allowed/ok.txt", "true\n"),
                            ("secret.txt", "false\n")):
            results = {}
            for be in ("wasi", "py", "host"):
                d = self._fresh_dir(f"{be}-r")
                os.makedirs(os.path.join(d, "allowed"))
                with open(os.path.join(d, "allowed", "ok.txt"), "w") as f:
                    f.write("INSIDE")
                with open(os.path.join(d, "secret.txt"), "w") as f:
                    f.write("SECRET")
                if be == "wasi":
                    results[be] = _run_wasi_dynamic_fs(src, d, args=(arg,))
                elif be == "py":
                    results[be] = _run_python_in_cwd(src, d, args=(arg,))
                else:
                    results[be] = _run_capa_host_in_cwd(src, d, args=(arg,))
            self.assertEqual(results["wasi"], expect, arg)
            self.assertEqual(results["wasi"], results["py"], arg)
            self.assertEqual(results["wasi"], results["host"], arg)

    def test_restricted_fs_dynamic_path_dotdot_normalized(self):
        # CRITICAL parity: a DYNAMIC path with '.' / '..' must be LEXICALLY
        # normalised before the fine-attenuation containment check, so a
        # path that escapes the restrict_to subtree via '..' is DENIED
        # (matching the realpath oracle), and one that stays inside after
        # normalisation is ADMITTED. Without normalisation the lexical
        # prefix "sub/" would match "sub/../secret.txt" and LEAK a sibling.
        src = (
            "fun main(fs: Fs, env: Env, stdio: Stdio)\n"
            "    let r = fs.restrict_to(\"sub\")\n"
            "    let args = env.args()\n"
            "    match args.get(0)\n"
            "        Some(p) ->\n"
            "            match r.read(p)\n"
            "                Ok(c) -> stdio.println(\"READ:${c}\")\n"
            "                Err(e) -> stdio.println(\"DENIED\")\n"
            "        None -> stdio.println(\"NOARG\")\n"
        )
        # (arg, expected). The oracle (os.path.realpath + is_relative_to)
        # produces exactly this table; the WASI guest must match it.
        table = [
            ("sub/ok.txt", "READ:SUB-OK\n"),       # inside -> read
            ("sub/../secret.txt", "DENIED\n"),     # escapes -> denied
            ("sub/../sub2/x.txt", "DENIED\n"),     # escapes -> denied
            ("secret.txt", "DENIED\n"),            # outside -> denied
            ("sub/../sub/ok.txt", "READ:SUB-OK\n"),  # normalises inside
            ("sub/./ok.txt", "READ:SUB-OK\n"),     # '.' inside
        ]
        for arg, expect in table:
            results = {}
            for be in ("wasi", "py", "host"):
                d = self._fresh_dir(f"{be}-dd")
                os.makedirs(os.path.join(d, "sub"))
                os.makedirs(os.path.join(d, "sub2"))
                with open(os.path.join(d, "sub", "ok.txt"), "w") as f:
                    f.write("SUB-OK")
                with open(os.path.join(d, "secret.txt"), "w") as f:
                    f.write("TOP-SECRET")
                with open(os.path.join(d, "sub2", "x.txt"), "w") as f:
                    f.write("SIBLING")
                if be == "wasi":
                    results[be] = _run_wasi_dynamic_fs(src, d, args=(arg,))
                elif be == "py":
                    results[be] = _run_python_in_cwd(src, d, args=(arg,))
                else:
                    results[be] = _run_capa_host_in_cwd(src, d, args=(arg,))
            self.assertEqual(results["wasi"], expect, arg)
            self.assertEqual(results["wasi"], results["py"], arg)
            self.assertEqual(results["wasi"], results["host"], arg)

    def test_dynamic_dotdot_confined_to_preopen_when_unrestricted(self):
        # LEVEL-1 confinement is NOT regressed: an UNRESTRICTED Fs (handle
        # 0, no restrict_to) with a dynamic '..' path that tries to escape
        # the operator preopen is denied by WASMTIME (the preopen ceiling),
        # not by the guest gate. A decoy file sits OUTSIDE the preopen.
        src = (
            "fun main(fs: Fs, env: Env, stdio: Stdio)\n"
            "    let args = env.args()\n"
            "    match args.get(0)\n"
            "        Some(p) ->\n"
            "            match fs.read(p)\n"
            "                Ok(c) -> stdio.println(\"READ:${c}\")\n"
            "                Err(e) -> stdio.println(\"DENIED\")\n"
            "        None -> stdio.println(\"NOARG\")\n"
        )
        outer = self._fresh_dir("confine")
        preopen = os.path.join(outer, "preopen")
        os.makedirs(preopen)
        with open(os.path.join(outer, "decoy.txt"), "w") as f:
            f.write("OUTSIDE-DECOY")
        with open(os.path.join(preopen, "in.txt"), "w") as f:
            f.write("INSIDE-OK")
        # An escape attempt -> wasmtime denies (Err), not the decoy leaked.
        esc = _run_wasi_dynamic_fs(src, preopen, args=("../decoy.txt",))
        self.assertEqual(esc, "DENIED\n")
        # The in-preopen read still works.
        ok = _run_wasi_dynamic_fs(src, preopen, args=("in.txt",))
        self.assertEqual(ok, "READ:INSIDE-OK\n")

    def test_operator_preopen_registered_at_index_zero(self):
        # The host installs exactly the operator preopen (index 0) for a
        # dynamic-path program (no derived ceiling).
        from capa.runtime._wasm_component_host import WasmComponentHost
        d = self._fresh_dir("idx")
        host = WasmComponentHost(
            wasi=True, fs_operator_preopen=(d, True),
        )
        self.assertEqual(host._wasi_fs_applied, [(d, "operator-rw")])


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_wasip2(),
    "wasm-tools and/or wasmtime-py with WASI P2 not installed",
)
class TestWasiFsAttenuation(unittest.TestCase):
    """End-to-end GUEST-SIDE Fs fine attenuation (Level 2 of
    ``docs/design/wasi-attenuation.md``) under the real WASI P2 host,
    with three-way byte-parity (Python oracle == capa:host backend ==
    WASI backend) over a controlled temp directory.

    ``Fs.restrict_to`` accumulates canonical path prefixes; ``allows``
    requires LEXICAL segment-containment in EVERY prefix (the
    intersection of the containments the oracle's realpath +
    is_relative_to computes for CANONICAL paths). Every privileged op
    (read / write / exists / is_dir / mkdir / list_dir) consults the
    same gate and FAILS CLOSED on a denied path, exactly as the Python
    runtime does. All paths here are CANONICAL absolute literals, so the
    lexical guest-side check is byte-identical to the realpath oracle.
    """

    def setUp(self):
        import tempfile
        self._td = tempfile.mkdtemp(prefix="capa-wasi-fs-att-test-")
        self._data = os.path.join(self._td, "data")
        os.makedirs(os.path.join(self._data, "a"))
        os.makedirs(os.path.join(self._data, "b"))
        with open(os.path.join(self._data, "a", "f.txt"), "w") as f:
            f.write("ALPHA")
        with open(os.path.join(self._data, "b", "g.txt"), "w") as f:
            f.write("BRAVO")

    def tearDown(self):
        import shutil
        shutil.rmtree(self._td, ignore_errors=True)

    def _d(self) -> str:
        # Forward-slash absolute paths (the convention the WASI host
        # normalises and the lexical guest-side containment compares).
        return self._data.replace("\\", "/")

    def test_restrict_read_exists_isdir_per_op_three_backend_parity(self):
        # Each op (allows / read / exists / is_dir) admits a path inside
        # the restricted prefix and DENIES one outside, fail-closed,
        # byte-identical across all three backends.
        d = self._d()
        src = (
            "fun main(fs: Fs, stdio: Stdio)\n"
            f"    let s = fs.restrict_to(\"{d}/a\")\n"
            f"    stdio.println(\"ai=${{s.allows(\\\"{d}/a/f.txt\\\")}}\")\n"
            f"    stdio.println(\"ao=${{s.allows(\\\"{d}/b/g.txt\\\")}}\")\n"
            f"    let r1 = s.read(\"{d}/a/f.txt\")\n"
            "    match r1\n"
            "        Ok(c) -> stdio.println(\"r1=${c}\")\n"
            "        Err(e) -> stdio.println(\"r1=err\")\n"
            f"    let r2 = s.read(\"{d}/b/g.txt\")\n"
            "    match r2\n"
            "        Ok(c) -> stdio.println(\"r2=${c}\")\n"
            "        Err(e) -> stdio.println(\"r2=err\")\n"
            f"    stdio.println(\"ef=${{s.exists(\\\"{d}/a/f.txt\\\")}}\")\n"
            f"    stdio.println(\"eo=${{s.exists(\\\"{d}/b/g.txt\\\")}}\")\n"
            f"    stdio.println(\"di=${{s.is_dir(\\\"{d}/a\\\")}}\")\n"
            f"    stdio.println(\"do=${{s.is_dir(\\\"{d}/b\\\")}}\")\n"
        )
        py, host, wasi = _run_fs_program_three_ways(src)
        self.assertEqual(py, host)
        self.assertEqual(py, wasi)
        self.assertIn("ai=true", wasi)
        self.assertIn("ao=false", wasi)
        self.assertIn("r1=ALPHA", wasi)
        self.assertIn("r2=err", wasi)        # denied read, fail-closed
        self.assertIn("ef=true", wasi)
        self.assertIn("eo=false", wasi)      # denied exists -> absent
        self.assertIn("di=true", wasi)
        self.assertIn("do=false", wasi)      # denied is_dir -> false

    def test_denied_write_and_mkdir_leave_no_trace(self):
        # A denied write / mkdir is an Err and creates NOTHING on disk
        # (the gate fires before open-at / create-directory-at), matching
        # the Python oracle. Three-backend parity on the Result, plus a
        # disk check that the out-of-prefix targets were never created.
        d = self._d()
        src = (
            "fun main(fs: Fs, stdio: Stdio)\n"
            f"    let s = fs.restrict_to(\"{d}/a\")\n"
            f"    let w1 = s.write(\"{d}/a/new.txt\", \"X\")\n"
            "    match w1\n"
            "        Ok(_) -> stdio.println(\"w1=ok\")\n"
            "        Err(e) -> stdio.println(\"w1=err\")\n"
            f"    let w2 = s.write(\"{d}/b/new.txt\", \"Y\")\n"
            "    match w2\n"
            "        Ok(_) -> stdio.println(\"w2=ok\")\n"
            "        Err(e) -> stdio.println(\"w2=err\")\n"
            f"    let m1 = s.mkdir(\"{d}/a/sub\")\n"
            "    match m1\n"
            "        Ok(_) -> stdio.println(\"m1=ok\")\n"
            "        Err(e) -> stdio.println(\"m1=err\")\n"
            f"    let m2 = s.mkdir(\"{d}/b/sub\")\n"
            "    match m2\n"
            "        Ok(_) -> stdio.println(\"m2=ok\")\n"
            "        Err(e) -> stdio.println(\"m2=err\")\n"
        )
        py, host, wasi = _run_fs_program_three_ways(src)
        self.assertEqual(py, host)
        self.assertEqual(py, wasi)
        self.assertIn("w1=ok", wasi)
        self.assertIn("w2=err", wasi)
        self.assertIn("m1=ok", wasi)
        self.assertIn("m2=err", wasi)
        # The out-of-prefix targets were never created on disk.
        self.assertFalse(
            os.path.exists(os.path.join(self._data, "b", "new.txt"))
        )
        self.assertFalse(
            os.path.exists(os.path.join(self._data, "b", "sub"))
        )

    def test_chaining_intersection_three_backend_parity(self):
        # restrict_to(a).restrict_to(b): a path must be contained in
        # BOTH prefixes (the intersection of the containments), so
        # neither an a-path nor a b-path is admitted; the wider single
        # restriction still admits its own subtree.
        d = self._d()
        src = (
            "fun main(fs: Fs, stdio: Stdio)\n"
            f"    let sa = fs.restrict_to(\"{d}/a\")\n"
            f"    let sab = sa.restrict_to(\"{d}/b\")\n"
            f"    stdio.println(\"both_a=${{sab.allows(\\\"{d}/a/f.txt\\\")}}\")\n"
            f"    stdio.println(\"both_b=${{sab.allows(\\\"{d}/b/g.txt\\\")}}\")\n"
            f"    stdio.println(\"single_a=${{sa.allows(\\\"{d}/a/f.txt\\\")}}\")\n"
        )
        py, host, wasi = _run_fs_program_three_ways(src)
        self.assertEqual(py, host)
        self.assertEqual(py, wasi)
        self.assertIn("both_a=false", wasi)
        self.assertIn("both_b=false", wasi)
        self.assertIn("single_a=true", wasi)

    def test_isolation_child_does_not_affect_parent(self):
        # Deriving a more restricted child Fs leaves the parent's
        # authority untouched (each value carries its own restriction).
        d = self._d()
        src = (
            "fun main(fs: Fs, stdio: Stdio)\n"
            f"    let parent = fs.restrict_to(\"{d}\")\n"
            f"    let child = parent.restrict_to(\"{d}/a\")\n"
            f"    stdio.println(\"parent_b=${{parent.allows(\\\"{d}/b/g.txt\\\")}}\")\n"
            f"    stdio.println(\"child_b=${{child.allows(\\\"{d}/b/g.txt\\\")}}\")\n"
            f"    stdio.println(\"child_a=${{child.allows(\\\"{d}/a/f.txt\\\")}}\")\n"
        )
        py, host, wasi = _run_fs_program_three_ways(src)
        self.assertEqual(py, host)
        self.assertEqual(py, wasi)
        self.assertIn("parent_b=true", wasi)   # parent still admits b
        self.assertIn("child_b=false", wasi)   # child narrowed b out
        self.assertIn("child_a=true", wasi)

    def test_unrestricted_root_admits_everything(self):
        # The Fs root main receives is unrestricted: allows is true for
        # any path and every op runs (here list_dir + read).
        d = self._d()
        src = (
            "fun main(fs: Fs, stdio: Stdio)\n"
            f"    stdio.println(\"ra=${{fs.allows(\\\"{d}/b/g.txt\\\")}}\")\n"
            f"    let r = fs.read(\"{d}/b/g.txt\")\n"
            "    match r\n"
            "        Ok(c) -> stdio.println(\"r=${c}\")\n"
            "        Err(e) -> stdio.println(\"r=err\")\n"
        )
        py, host, wasi = _run_fs_program_three_ways(src)
        self.assertEqual(py, host)
        self.assertEqual(py, wasi)
        self.assertIn("ra=true", wasi)
        self.assertIn("r=BRAVO", wasi)

    def test_list_dir_attenuated_three_backend_parity(self):
        # list_dir on a denied directory is a fail-closed Err; on an
        # allowed one it returns the sorted entries, byte-identical
        # across all three backends.
        d = self._d()
        src = (
            "fun main(fs: Fs, stdio: Stdio)\n"
            f"    let s = fs.restrict_to(\"{d}/a\")\n"
            f"    let denied = s.list_dir(\"{d}/b\")\n"
            "    match denied\n"
            "        Ok(xs) -> stdio.println(\"ld=ok\")\n"
            "        Err(e) -> stdio.println(\"ld=err\")\n"
            f"    let ok = s.list_dir(\"{d}/a\")\n"
            "    match ok\n"
            "        Ok(xs) ->\n"
            "            for x in xs\n"
            "                stdio.println(\"e=${x}\")\n"
            "        Err(e) -> stdio.println(\"ld2=err\")\n"
        )
        py, host, wasi = _run_fs_program_three_ways(src)
        self.assertEqual(py, host)
        self.assertEqual(py, wasi)
        self.assertIn("ld=err", wasi)    # denied dir, fail-closed
        self.assertIn("e=f.txt", wasi)   # allowed dir lists its entry

    def test_cross_function_boundary_keeps_restriction(self):
        # The load-bearing guarantee: a restricted Fs passed to a helper
        # KEEPS its restriction (the allow-list travels with the Fs
        # value, an i32 pointer, across the function boundary), so the
        # helper's read of an out-of-prefix path fails closed -- the same
        # result on all three backends.
        d = self._d()
        src = (
            "fun probe(fs: Fs, stdio: Stdio)\n"
            f"    stdio.println(\"hi=${{fs.allows(\\\"{d}/a/f.txt\\\")}}\")\n"
            f"    stdio.println(\"ho=${{fs.allows(\\\"{d}/b/g.txt\\\")}}\")\n"
            f"    let r = fs.read(\"{d}/b/g.txt\")\n"
            "    match r\n"
            "        Ok(c) -> stdio.println(\"hr=ok\")\n"
            "        Err(e) -> stdio.println(\"hr=err\")\n"
            "\n"
            "fun main(fs: Fs, stdio: Stdio)\n"
            f"    let s = fs.restrict_to(\"{d}/a\")\n"
            "    probe(s, stdio)\n"
        )
        py, host, wasi = _run_fs_program_three_ways(src)
        self.assertEqual(py, host)
        self.assertEqual(py, wasi)
        self.assertIn("hi=true", wasi)
        self.assertIn("ho=false", wasi)
        self.assertIn("hr=err", wasi)   # restriction survived the call


# ----- Net.get via wasi:http (Phase 1) ---------------------------


def _has_wasmtime_wasi_http() -> bool:
    """True when the installed wasmtime exposes the wasi:http C-ABI the
    Net.get host recipe reaches through ``wasmtime._bindings``
    (``add_wasi_http`` on the component linker + ``set_wasi_http`` on the
    store context). The high-level component API does not surface these,
    so we probe the bindings module directly."""
    if not _has_wasmtime_wasip2():
        return False
    try:
        import wasmtime._bindings as b
    except ImportError:
        return False
    return hasattr(
        b, "wasmtime_component_linker_add_wasi_http",
    ) and hasattr(b, "wasmtime_context_set_wasi_http")


class _LocalHttpServer:
    """A 127.0.0.1 HTTP server returning a fixed body + status on GET.

    Context-manager: yields the ``host:port`` authority. Bound to an
    ephemeral port so concurrent tests do not collide, and to the
    loopback interface ONLY so no external network is touched."""

    def __init__(self, body: bytes, status: int = 200):
        self._body = body
        self._status = status
        self._srv = None
        self._thread = None
        self.port = None

    def __enter__(self):
        import threading
        from http.server import BaseHTTPRequestHandler, HTTPServer
        body = self._body
        status = self._status

        class _H(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(status)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        self._srv = HTTPServer(("127.0.0.1", 0), _H)
        self.port = self._srv.server_address[1]
        self._thread = threading.Thread(
            target=self._srv.serve_forever, daemon=True,
        )
        self._thread.start()
        return f"127.0.0.1:{self.port}"

    def __exit__(self, *exc):
        if self._srv is not None:
            self._srv.shutdown()
            self._srv.server_close()
        return False


def _dead_port() -> int:
    """Return a 127.0.0.1 port number that is closed (no listener), so a
    GET to it is a connection-refused transport error."""
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _run_net_program_three_ways(src: str):
    """Build + run a Net program on the Python backend, the capa:host
    component backend, and the WASI component backend (with the Net host
    ceiling). Returns ``(py, host, wasi)`` stdout strings. The program's
    urls must be literals pointing at a local server the caller started.
    """
    from capa.ir import compile_wasm, compile_wit, compute_net_ceiling
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

    py = _run_python(src)
    core_h = compile_wasm(module, types=result.types, wasi=False)
    wit_h = compile_wit(module, types=result.types, wasi=False)
    comp_h = _wrap_as_component(core_h, wit_h, wasi=False)
    host = _cap(lambda: WasmComponentHost(wasi=False).run_main(comp_h))
    core_w = compile_wasm(module, types=result.types, wasi=True)
    wit_w = compile_wit(module, types=result.types, wasi=True)
    comp_w = _wrap_as_component(core_w, wit_w, wasi=True)
    ceiling = compute_net_ceiling(module, types=result.types)
    # Stdio output goes to wasi:cli/stdout; read it from the host's
    # captured buffer (the centralised capture point), not sys.stdout.
    wasi = _wasi_run_capture(
        WasmComponentHost(wasi=True, net_ceiling=ceiling), comp_w,
    )
    return py, host, wasi


def _net_get_src(authority: str, path: str = "/p") -> str:
    """A program that GETs ``http://<authority><path>`` and prints the
    body wrapped in brackets on Ok, ``ERR`` on Err."""
    return (
        "fun main(net: Net, stdio: Stdio)\n"
        f"    match net.get(\"http://{authority}{path}\")\n"
        "        Ok(b) -> stdio.println(\"[${b}]\")\n"
        "        Err(e) -> stdio.println(\"ERR\")\n"
    )


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_wasi_http(),
    "wasm-tools and/or wasmtime-py with wasi:http not installed",
)
class TestWasiNetGet(unittest.TestCase):
    """End-to-end: net.get in --wasi mode builds an outgoing request over
    wasi:http (outgoing-handler.handle + the outgoing-request /
    future-incoming-response / incoming-response / incoming-body chain),
    reads the body via wasi:io/streams.input-stream.blocking-read, and its
    Ok(String) is BYTE-IDENTICAL to the Python oracle and the capa:host
    backend across small / empty / large-multichunk / UTF-8 bodies. A
    status >= 400 and a connection-refused transport error are coherent
    Err on all three backends. The body is fetched from a LOCAL 127.0.0.1
    server (no external network), and all three backends GET the same
    url."""

    def _assert_parity(self, authority, **kw):
        src = _net_get_src(authority, kw.get("path", "/p"))
        py, host, wasi = _run_net_program_three_ways(src)
        self.assertEqual(py, host, "py/capa:host diverge")
        self.assertEqual(py, wasi, "py/wasi diverge")
        return wasi

    def test_small_body_parity(self):
        with _LocalHttpServer(b"hello world") as auth:
            out = self._assert_parity(auth)
        self.assertEqual(out, "[hello world]\n")

    def test_empty_body_parity(self):
        # 0 bytes: Ok("") on every backend (the first blocking-read is
        # stream-error::closed and the loop accumulates nothing).
        with _LocalHttpServer(b"") as auth:
            out = self._assert_parity(auth)
        self.assertEqual(out, "[]\n")

    def test_large_multichunk_body_parity(self):
        # > the 4096-byte blocking-read chunk: forces the read loop to run
        # multiple iterations and the accumulation buffer to grow.
        body = b"x" * 20000 + b"END"
        with _LocalHttpServer(body) as auth:
            out = self._assert_parity(auth)
        self.assertEqual(len(out), len(body) + 3)  # [ ... ] + newline
        self.assertIn("END]", out)

    def test_utf8_multibyte_body_parity(self):
        body = "café-\U0001F98A multi: éè你好".encode("utf-8")
        with _LocalHttpServer(body) as auth:
            out = self._assert_parity(auth)
        self.assertIn("café", out)
        self.assertIn("你好", out)

    def test_status_404_is_err_on_all_backends(self):
        # urllib raises HTTPError on status >= 400, so the oracle returns
        # Err; the wasi wrapper fails closed on any non-2xx (404 included),
        # so all three backends agree on Err here. (3xx redirects diverge
        # by design and are covered separately by
        # TestWasiNetRedirectFailClosed, NOT as parity.)
        with _LocalHttpServer(b"not found", status=404) as auth:
            out = self._assert_parity(auth)
        self.assertEqual(out, "ERR\n")

    def test_status_500_is_err_on_all_backends(self):
        with _LocalHttpServer(b"boom", status=500) as auth:
            out = self._assert_parity(auth)
        self.assertEqual(out, "ERR\n")

    def test_transport_error_is_err_on_all_backends(self):
        # Connection refused (no listener on the port): Err everywhere.
        auth = f"127.0.0.1:{_dead_port()}"
        out = self._assert_parity(auth)
        self.assertEqual(out, "ERR\n")

    def test_host_ceiling_links_wasi_http(self):
        # The host links wasi:http ONLY when the program uses Net.get
        # (signalled by a non-None net_ceiling); inspect the recorded flag.
        from capa.ir import (
            compile_wasm, compile_wit, compute_net_ceiling,
        )
        from capa.cli import _wrap_as_component
        from capa.runtime._wasm_component_host import WasmComponentHost
        with _LocalHttpServer(b"ok") as auth:
            src = _net_get_src(auth)
            module, result = _parse_analyze(src)
            core = compile_wasm(module, types=result.types, wasi=True)
            wit = compile_wit(module, types=result.types, wasi=True)
            comp = _wrap_as_component(core, wit, wasi=True)
            ceiling = compute_net_ceiling(module, types=result.types)
            host = WasmComponentHost(wasi=True, net_ceiling=ceiling)
            _wasi_run_capture(host, comp)
        self.assertTrue(host._wasi_http_linked)

    def test_no_net_program_does_not_link_wasi_http(self):
        # A program with no Net.get keeps net_ceiling None, so the host
        # never links wasi:http (clean total deny + avoids the C-API
        # context panic). A Stdio-only program proves it.
        from capa.runtime._wasm_component_host import WasmComponentHost
        host = WasmComponentHost(wasi=True)  # no net_ceiling
        self.assertFalse(host._wasi_http_linked)

    def test_leak_many_gets_no_handle_exhaustion(self):
        # Many GETs against the local server in one component instance
        # exercise the resource-drop discipline (8 OWN handles per call);
        # a leak or double-drop would trap. Distinct from heap growth,
        # which is inherent. 300 keeps the test fast while still proving
        # the drops (the oracle spike ran 1500).
        from capa.ir import (
            compile_wasm, compile_wit, compute_net_ceiling,
        )
        from capa.cli import _wrap_as_component
        from capa.runtime._wasm_component_host import WasmComponentHost
        with _LocalHttpServer(b"leakcheck") as auth:
            src = (
                "fun main(net: Net, stdio: Stdio)\n"
                "    var i = 0\n"
                "    while i < 300\n"
                f"        match net.get(\"http://{auth}/p\")\n"
                "            Ok(b) -> stdio.print(\"\")\n"
                "            Err(e) -> stdio.println(\"ERR\")\n"
                "        i = i + 1\n"
                "    stdio.println(\"done\")\n"
            )
            module, result = _parse_analyze(src)
            core = compile_wasm(module, types=result.types, wasi=True)
            wit = compile_wit(module, types=result.types, wasi=True)
            comp = _wrap_as_component(core, wit, wasi=True)
            ceiling = compute_net_ceiling(module, types=result.types)
            host = WasmComponentHost(wasi=True, net_ceiling=ceiling)
            out = _wasi_run_capture(host, comp)
        # No ERR (every GET succeeded) and the program reached the end.
        self.assertNotIn("ERR", out)
        self.assertEqual(out, "done\n")


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_wasi_http(),
    "wasm-tools and/or wasmtime-py with wasi:http not installed",
)
class TestWasiNetCeiling(unittest.TestCase):
    """The Net host ceiling is GUEST-SIDE (codegen-enforced): a host the
    program does not name as a literal net.get url is denied, and a
    DYNAMIC url (built at runtime) is fail-closed. These are the
    restriction guarantees, not an oracle-parity property (the deny is a
    coarser ceiling than the Python oracle's unrestricted Net), so they
    are asserted on the WASI backend alone."""

    def test_dynamic_url_is_rejected_at_compile(self):
        # A GENUINELY dynamic url (interpolated from a runtime value)
        # cannot be resolved to a wasi:http request, so the allowed-host
        # ceiling cannot be materialised. SYMMETRIC with Fs (2026-06-29):
        # the program is REJECTED at compile time with a clear message
        # rather than emitting a call site that fail-closes silently at
        # runtime (which a ``Err(_) -> ()`` would swallow). The ceiling is
        # NOT closed. (A let-bound LITERAL, by contrast, is now folded by
        # the inter-procedural const-prop and compiles -- see
        # ``TestWasiNetDynamicUrlRejections.test_get_let_bound_literal_folds_and_compiles``.)
        from capa.ir import compile_wasm, compute_net_ceiling
        src = (
            "fun main(net: Net, stdio: Stdio, host: String)\n"
            "    let u = \"http://${host}/p\"\n"
            "    match net.get(u)\n"
            "        Ok(b) -> stdio.println(\"[${b}]\")\n"
            "        Err(e) -> stdio.println(\"ERR\")\n"
        )
        module, result = _parse_analyze(src)
        # The ceiling is NOT closed (a genuinely computed url).
        ceiling = compute_net_ceiling(module, types=result.types)
        self.assertFalse(ceiling.closed)
        with self.assertRaises(Exception) as cm:
            compile_wasm(module, types=result.types, wasi=True)
        self.assertIn("WASI mode", str(cm.exception))
        self.assertIn("literal", str(cm.exception))

    def test_ceiling_collects_literal_hosts(self):
        from capa.ir import compute_net_ceiling
        src = (
            "fun main(net: Net, stdio: Stdio)\n"
            "    match net.get(\"http://a.example:80/x\")\n"
            "        Ok(b) -> stdio.println(b)\n"
            "        Err(e) -> stdio.println(\"e\")\n"
            "    match net.get(\"https://B.Example/y\")\n"
            "        Ok(b) -> stdio.println(b)\n"
            "        Err(e) -> stdio.println(\"e\")\n"
        )
        module, result = _parse_analyze(src)
        ceiling = compute_net_ceiling(module, types=result.types)
        self.assertTrue(ceiling.closed)
        # Hosts are lowercased and port-stripped.
        self.assertEqual(ceiling.hosts, frozenset({"a.example", "b.example"}))

    def test_host_outside_ceiling_denied_guest_side(self):
        # Compile a program whose only literal host is the live server,
        # then run it (it should succeed). Separately, a program naming a
        # DIFFERENT host than the one it reaches cannot occur with a single
        # literal -- the gate's denial is proven structurally by the
        # dynamic-url fail-closed above (no literal host => empty ceiling
        # match) and by the ceiling-collection test. Here we assert the
        # gate admits the named host (positive control).
        with _LocalHttpServer(b"ok") as auth:
            src = _net_get_src(auth)
            _py, _host, wasi = _run_net_program_three_ways(src)
        self.assertEqual(wasi, "[ok]\n")


# ----- Net.post via wasi:http (Phase 2) --------------------------


class _LocalPostServer:
    """A 127.0.0.1 HTTP server that READS the POST request body and
    returns a body-dependent response (echo or fixed / big), recording the
    received request body so a test can assert the SERVER saw the exact
    bytes the client sent.

    Reads the body whether the client sends it with a Content-Length or
    CHUNKED (Transfer-Encoding: chunked) -- wasi:http sends the outgoing
    request body chunked by default, so the handler must accept both to
    verify the body across all three backends. Context-manager: yields the
    ``host:port`` authority. ``received['body']`` holds the last body."""

    def __init__(self, mode: str = "echo", fixed: bytes = b"RESP-OK",
                 status: int = 200):
        # mode: "echo" (respond with the received body), "fixed" (respond
        # with ``fixed``), "big" (respond with a > one-chunk fixed body).
        self._mode = mode
        self._fixed = fixed
        self._status = status
        self._srv = None
        self._thread = None
        self.port = None
        self.received = {}

    def __enter__(self):
        import threading
        from http.server import BaseHTTPRequestHandler, HTTPServer
        mode = self._mode
        fixed = self._fixed
        status = self._status
        received = self.received

        class _H(BaseHTTPRequestHandler):
            def do_POST(self):
                te = self.headers.get("Transfer-Encoding", "")
                if "chunked" in te.lower():
                    body = b""
                    while True:
                        line = self.rfile.readline().strip()
                        if not line:
                            continue
                        size = int(line, 16)
                        if size == 0:
                            self.rfile.readline()
                            break
                        body += self.rfile.read(size)
                        self.rfile.readline()
                else:
                    n = int(self.headers.get("Content-Length", 0))
                    body = self.rfile.read(n)
                received["body"] = body
                received["len"] = len(body)
                if mode == "echo":
                    out = body
                elif mode == "big":
                    out = b"R" * 25000 + b"-END"
                else:
                    out = fixed
                self.send_response(status)
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

            def log_message(self, *a):
                pass

        self._srv = HTTPServer(("127.0.0.1", 0), _H)
        self.port = self._srv.server_address[1]
        self._thread = threading.Thread(
            target=self._srv.serve_forever, daemon=True,
        )
        self._thread.start()
        return f"127.0.0.1:{self.port}"

    def __exit__(self, *exc):
        if self._srv is not None:
            self._srv.shutdown()
            self._srv.server_close()
        return False


def _net_post_src(authority: str, body: str, path: str = "/p") -> str:
    """A program that POSTs ``body`` to ``http://<authority><path>`` and
    prints the RESPONSE body wrapped in brackets on Ok, ``ERR`` on Err."""
    return (
        "fun main(net: Net, stdio: Stdio)\n"
        f"    match net.post(\"http://{authority}{path}\", \"{body}\")\n"
        "        Ok(b) -> stdio.println(\"[${b}]\")\n"
        "        Err(e) -> stdio.println(\"ERR\")\n"
    )


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_wasi_http(),
    "wasm-tools and/or wasmtime-py with wasi:http not installed",
)
class TestWasiNetPost(unittest.TestCase):
    """End-to-end: net.post in --wasi mode REUSES the Net.get wasi:http
    chain and ADDS a flow-controlled outgoing-body write of the REQUEST
    body before the handle. The Ok(String) RESPONSE is BYTE-IDENTICAL to
    the Python oracle and the capa:host backend across small / empty /
    large-multichunk request bodies and large-multichunk responses, with
    UTF-8 round-tripping in both directions; a status >= 400 and a
    connection-refused transport error are coherent Err on all three
    backends. The SERVER additionally asserts it received the exact bytes
    the client sent (the request body is verified, not only the response).
    """

    def _assert_response_parity(self, server, body):
        with server as auth:
            src = _net_post_src(auth, body)
            py, host, wasi = _run_net_program_three_ways(src)
        self.assertEqual(py, host, "py/capa:host diverge")
        self.assertEqual(py, wasi, "py/wasi diverge")
        return wasi, server.received

    def test_small_request_body_echoed_parity(self):
        # The server echoes the request body; the response (== request) is
        # byte-identical on all three backends, and the server saw the body.
        wasi, recv = self._assert_response_parity(
            _LocalPostServer("echo"), "hello-body",
        )
        self.assertEqual(wasi, "[hello-body]\n")
        self.assertEqual(recv["body"], b"hello-body")

    def test_empty_request_body_parity(self):
        # 0-byte request body: the write loop runs zero times, the server
        # receives an empty body, the echo is "".
        wasi, recv = self._assert_response_parity(
            _LocalPostServer("echo"), "",
        )
        self.assertEqual(wasi, "[]\n")
        self.assertEqual(recv["len"], 0)

    def test_large_multichunk_request_body_complete(self):
        # > the per-iteration check-write budget: the request body is
        # written across multiple non-blocking writes. The SERVER must
        # receive the COMPLETE body (no truncation / duplication), proven by
        # comparing the received bytes to the sent bytes.
        body = "A" * 20005 + "-Z"
        wasi, recv = self._assert_response_parity(
            _LocalPostServer("echo"), body,
        )
        self.assertEqual(recv["len"], len(body.encode("utf-8")))
        self.assertEqual(recv["body"], body.encode("utf-8"))
        self.assertTrue(wasi.endswith("-Z]\n"))

    def test_utf8_request_and_response_roundtrip(self):
        body = "café-你好"
        wasi, recv = self._assert_response_parity(
            _LocalPostServer("echo"), body,
        )
        self.assertEqual(recv["body"], body.encode("utf-8"))
        self.assertIn("café", wasi)
        self.assertIn("你好", wasi)

    def test_large_multichunk_response_parity(self):
        # The response is > the 4096-byte blocking-read chunk, forcing the
        # RESPONSE read loop to grow its accumulation buffer (the reused get
        # path). Parity across all three backends.
        wasi, _recv = self._assert_response_parity(
            _LocalPostServer("big"), "small-req",
        )
        self.assertEqual(len(wasi), len(b"R" * 25000 + b"-END") + 3)
        self.assertTrue(wasi.endswith("-END]\n"))

    def test_status_404_is_err_on_all_backends(self):
        wasi, _recv = self._assert_response_parity(
            _LocalPostServer("fixed", status=404), "x",
        )
        self.assertEqual(wasi, "ERR\n")

    def test_status_500_is_err_on_all_backends(self):
        wasi, _recv = self._assert_response_parity(
            _LocalPostServer("fixed", status=500), "x",
        )
        self.assertEqual(wasi, "ERR\n")

    def test_transport_error_is_err_on_all_backends(self):
        auth = f"127.0.0.1:{_dead_port()}"
        src = _net_post_src(auth, "x")
        py, host, wasi = _run_net_program_three_ways(src)
        self.assertEqual(py, host)
        self.assertEqual(py, wasi)
        self.assertEqual(wasi, "ERR\n")

    def test_leak_many_posts_no_handle_exhaustion(self):
        # Many POSTs in one component instance exercise the resource-drop
        # discipline (the get chain's eight OWN handles PLUS the request
        # output-stream per call); a leak or double-drop would trap.
        from capa.ir import (
            compile_wasm, compile_wit, compute_net_ceiling,
        )
        from capa.cli import _wrap_as_component
        from capa.runtime._wasm_component_host import WasmComponentHost
        with _LocalPostServer("fixed", fixed=b"ok") as auth:
            src = (
                "fun main(net: Net, stdio: Stdio)\n"
                "    var i = 0\n"
                "    while i < 300\n"
                f"        match net.post(\"http://{auth}/p\", \"payload\")\n"
                "            Ok(b) -> stdio.print(\"\")\n"
                "            Err(e) -> stdio.println(\"ERR\")\n"
                "        i = i + 1\n"
                "    stdio.println(\"done\")\n"
            )
            module, result = _parse_analyze(src)
            core = compile_wasm(module, types=result.types, wasi=True)
            wit = compile_wit(module, types=result.types, wasi=True)
            comp = _wrap_as_component(core, wit, wasi=True)
            ceiling = compute_net_ceiling(module, types=result.types)
            host = WasmComponentHost(wasi=True, net_ceiling=ceiling)
            out = _wasi_run_capture(host, comp)
        self.assertNotIn("ERR", out)
        self.assertEqual(out, "done\n")


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_wasi_http(),
    "wasm-tools and/or wasmtime-py with wasi:http not installed",
)
class TestWasiNetPostCeiling(unittest.TestCase):
    """The Net host ceiling covers Net.post too: a host the program does
    not name as a literal net.post url is denied, and a DYNAMIC url (built
    at runtime) is fail-closed WITHOUT reaching the network."""

    def test_post_dynamic_url_is_rejected_at_compile(self):
        # SYMMETRIC with Fs and with Net.get (2026-06-29): a GENUINELY
        # dynamic post url (interpolated from a runtime value) cannot
        # materialise the allowed-host ceiling, so the program is REJECTED
        # at compile time rather than fail-closing silently at runtime. (A
        # let-bound LITERAL is now folded by the const-prop and compiles.)
        from capa.ir import compile_wasm, compute_net_ceiling
        src = (
            "fun main(net: Net, stdio: Stdio, host: String)\n"
            "    let u = \"http://${host}/p\"\n"
            "    match net.post(u, \"body\")\n"
            "        Ok(b) -> stdio.println(\"[${b}]\")\n"
            "        Err(e) -> stdio.println(\"ERR\")\n"
        )
        module, result = _parse_analyze(src)
        ceiling = compute_net_ceiling(module, types=result.types)
        self.assertFalse(ceiling.closed)
        with self.assertRaises(Exception) as cm:
            compile_wasm(module, types=result.types, wasi=True)
        self.assertIn("WASI mode", str(cm.exception))
        self.assertIn("literal", str(cm.exception))

    def test_post_ceiling_collects_literal_hosts(self):
        from capa.ir import compute_net_ceiling
        src = (
            "fun main(net: Net, stdio: Stdio)\n"
            "    match net.post(\"http://a.example:80/x\", \"b1\")\n"
            "        Ok(b) -> stdio.println(b)\n"
            "        Err(e) -> stdio.println(\"e\")\n"
            "    match net.get(\"https://B.Example/y\")\n"
            "        Ok(b) -> stdio.println(b)\n"
            "        Err(e) -> stdio.println(\"e\")\n"
        )
        module, result = _parse_analyze(src)
        ceiling = compute_net_ceiling(module, types=result.types)
        self.assertTrue(ceiling.closed)
        # post AND get hosts both contribute (lowercased, port-stripped).
        self.assertEqual(
            ceiling.hosts, frozenset({"a.example", "b.example"}),
        )


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_wasip2(),
    "wasm-tools and/or wasmtime-py with WASI P2 not installed",
)
class TestWasiNetWitGeneration(unittest.TestCase):
    """The WASI-mode WIT world for a Net.get program imports wasi:http
    (types + outgoing-handler) plus the wasi:io interfaces the body read
    needs, and emits NO capa:host/net interface (Net.get is fully
    migrated). Net.post / restrict_to / allows are rejected before WIT
    generation, so a valid WASI Net program uses only get."""

    def _wit(self, src: str) -> str:
        from capa.ir import compile_wit
        module, result = _parse_analyze(src)
        return compile_wit(module, types=result.types, wasi=True)

    def test_net_world_imports_wasi_http(self):
        src = _net_get_src("example.com")
        wit = self._wit(src)
        self.assertIn("import wasi:http/types@0.2.0;", wit)
        self.assertIn("import wasi:http/outgoing-handler@0.2.0;", wit)
        self.assertIn("import wasi:io/streams@0.2.0;", wit)
        self.assertIn("import wasi:io/poll@0.2.0;", wit)

    def test_post_world_imports_wasi_http(self):
        # A post-only program imports the same wasi:http world as get (post
        # reuses the get chain plus the output-stream write, all under the
        # already-imported interfaces) and emits NO capa:host/net interface.
        src = (
            "fun main(net: Net, stdio: Stdio)\n"
            "    match net.post(\"http://example.com/p\", \"b\")\n"
            "        Ok(b) -> stdio.println(b)\n"
            "        Err(e) -> stdio.println(\"e\")\n"
        )
        wit = self._wit(src)
        self.assertIn("import wasi:http/types@0.2.0;", wit)
        self.assertIn("import wasi:http/outgoing-handler@0.2.0;", wit)
        self.assertIn("import wasi:io/streams@0.2.0;", wit)
        self.assertNotIn("interface net", wit)

    def test_no_capa_host_net_interface(self):
        src = _net_get_src("example.com")
        wit = self._wit(src)
        self.assertNotIn("interface net", wit)
        self.assertNotIn("import net;", wit)

    def test_io_imports_not_duplicated_with_fs(self):
        # A program using BOTH Fs.read (wasi:io/streams + error) and
        # Net.get (also wasi:io/streams + error) must not import the same
        # interface twice (a world that does fails to type-check).
        src = (
            "fun main(fs: Fs, net: Net, stdio: Stdio)\n"
            "    let r = fs.read(\"data/x.txt\")\n"
            "    match net.get(\"http://example.com/p\")\n"
            "        Ok(b) -> stdio.println(b)\n"
            "        Err(e) -> stdio.println(\"e\")\n"
        )
        wit = self._wit(src)
        self.assertEqual(wit.count("import wasi:io/streams@0.2.0;"), 1)
        self.assertEqual(wit.count("import wasi:io/error@0.2.0;"), 1)


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_wasip2(),
    "wasm-tools and/or wasmtime-py with WASI P2 not installed",
)
class TestWasiNetRejections(unittest.TestCase):
    """The Net surface is COMPLETE in --wasi (Phase 3, 2026-06-29):
    get / post (wasi:http) AND restrict_to / allows (guest-side Level 2
    fine attenuation). Every Net method now compiles under --wasi; this
    class is the positive control that none is rejected. The guest-side
    wrappers (no capa:host/net import) back restrict_to / allows."""

    def _compile_wasi(self, src: str):
        from capa.ir import compile_wasm
        module, result = _parse_analyze(src)
        return compile_wasm(module, types=result.types, wasi=True)

    def _compile_wat(self, src: str):
        from capa.ir import compile_wat
        module, result = _parse_analyze(src)
        return compile_wat(module, types=result.types, wasi=True)

    def test_net_post_accepted(self):
        src = (
            "fun main(net: Net, stdio: Stdio)\n"
            "    match net.post(\"http://example.com/p\", \"body\")\n"
            "        Ok(b) -> stdio.println(b)\n"
            "        Err(e) -> stdio.println(\"e\")\n"
        )
        blob = self._compile_wasi(src)
        self.assertIsInstance(blob, (bytes, bytearray))

    def test_net_restrict_to_accepted_guest_side(self):
        # Phase 3: Net.restrict_to compiles to a guest-side $Net_restrict_to
        # wrapper (no capa:host/net import). The WAT carries the wrapper
        # and the shared $Net_handle_allows membership helper.
        src = (
            "fun main(net: Net, stdio: Stdio)\n"
            "    let n2 = net.restrict_to(\"example.com\")\n"
            "    match n2.get(\"http://example.com/p\")\n"
            "        Ok(b) -> stdio.println(b)\n"
            "        Err(e) -> stdio.println(\"e\")\n"
        )
        wat = self._compile_wat(src)
        self.assertIn("(func $Net_restrict_to", wat)
        self.assertIn("(func $Net_handle_allows", wat)
        # No capa:host/net import for the attenuators (guest-side).
        self.assertNotIn('"capa:host/net" "restrict-to"', wat)

    def test_net_allows_accepted_guest_side(self):
        src = (
            "fun main(net: Net, stdio: Stdio)\n"
            "    let n2 = net.restrict_to(\"example.com\")\n"
            "    if n2.allows(\"example.com\")\n"
            "        stdio.println(\"y\")\n"
            "    else\n"
            "        stdio.println(\"n\")\n"
        )
        wat = self._compile_wat(src)
        self.assertIn("(func $Net_allows", wat)
        self.assertIn("(func $Net_handle_allows", wat)
        self.assertNotIn('"capa:host/net" "allows"', wat)

    def test_net_get_accepted(self):
        # The positive control: Net.get alone compiles (no rejection).
        src = _net_get_src("example.com")
        blob = self._compile_wasi(src)
        self.assertIsInstance(blob, (bytes, bytearray))


# Net fine attenuation (Phase 3): restrict_to(host) / allows(host) with
# EXACT-HOSTNAME equality, intersection-monotonic narrowing, fail-closed
# request gating layered on top of the static ceiling. The host permitted
# in each scenario is the local server's 127.0.0.1; a different host is the
# deny control. Parity is asserted byte-for-byte across the Python oracle,
# the capa:host component backend, and the WASI component backend.
@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_wasi_http(),
    "wasm-tools and/or wasmtime-py with wasi:http not installed",
)
class TestWasiNetAttenuation(unittest.TestCase):
    """End-to-end: Net.restrict_to / Net.allows guest-side Level 2 fine
    attenuation in --wasi, byte-identical to the Python oracle and the
    capa:host backend.

    Confirms the oracle semantics replicated guest-side:
    - restrict_to is INTERSECTION (``{host} & parent``): a chain to two
      distinct hosts collapses to the empty allow-list (admits nothing).
    - allows is EXACT-HOSTNAME equality, NOT substring / prefix
      containment: a host that is a substring or super-domain of an
      allowed host is denied (the security point).
    - get / post FAIL CLOSED before touching the network on a host outside
      the allow-list, layered on top of the static ceiling.
    - the unrestricted root (handle 0) admits everything.
    - deriving a narrower child never mutates the parent (isolation).
    """

    def test_allows_true_false_three_backends(self):
        src = (
            "fun show(stdio: Stdio, label: String, flag: Bool)\n"
            "    if flag\n"
            "        stdio.println(\"${label}=yes\")\n"
            "    else\n"
            "        stdio.println(\"${label}=no\")\n"
            "fun main(net: Net, stdio: Stdio)\n"
            "    let scoped = net.restrict_to(\"127.0.0.1\")\n"
            "    show(stdio, \"allowed\", scoped.allows(\"127.0.0.1\"))\n"
            "    show(stdio, \"denied\", scoped.allows(\"evil.example\"))\n"
        )
        py, host, wasi = _run_net_program_three_ways(src)
        self.assertEqual(py, host, "py/capa:host diverge")
        self.assertEqual(py, wasi, "py/wasi diverge")
        self.assertIn("allowed=yes", wasi)
        self.assertIn("denied=no", wasi)

    def test_exact_equality_not_substring_three_backends(self):
        # The security point: a host that is a SUBSTRING or a SUPER-DOMAIN
        # of an allowed host is NOT admitted (equality, not containment).
        src = (
            "fun show(stdio: Stdio, label: String, flag: Bool)\n"
            "    if flag\n"
            "        stdio.println(\"${label}=yes\")\n"
            "    else\n"
            "        stdio.println(\"${label}=no\")\n"
            "fun main(net: Net, stdio: Stdio)\n"
            "    let scoped = net.restrict_to(\"example.com\")\n"
            "    show(stdio, \"exact\", scoped.allows(\"example.com\"))\n"
            "    show(stdio, \"prefixed\", scoped.allows(\"evil-example.com\"))\n"
            "    show(stdio, \"suffixed\", scoped.allows(\"example.com.evil.com\"))\n"
            "    show(stdio, \"substr\", scoped.allows(\"example.co\"))\n"
        )
        py, host, wasi = _run_net_program_three_ways(src)
        self.assertEqual(py, host, "py/capa:host diverge")
        self.assertEqual(py, wasi, "py/wasi diverge")
        self.assertIn("exact=yes", wasi)
        self.assertIn("prefixed=no", wasi)
        self.assertIn("suffixed=no", wasi)
        self.assertIn("substr=no", wasi)

    def test_chaining_intersection_collapses_three_backends(self):
        # restrict_to(A).restrict_to(B), A != B -> the intersection is the
        # empty set, so even the originally-allowed host is denied.
        src = (
            "fun show(stdio: Stdio, label: String, flag: Bool)\n"
            "    if flag\n"
            "        stdio.println(\"${label}=yes\")\n"
            "    else\n"
            "        stdio.println(\"${label}=no\")\n"
            "fun main(net: Net, stdio: Stdio)\n"
            "    let a = net.restrict_to(\"127.0.0.1\")\n"
            "    let ab = a.restrict_to(\"other.example\")\n"
            "    show(stdio, \"first_in_chain\", ab.allows(\"127.0.0.1\"))\n"
            "    show(stdio, \"second_in_chain\", ab.allows(\"other.example\"))\n"
            "    show(stdio, \"parent_unaffected\", a.allows(\"127.0.0.1\"))\n"
            "    let same = a.restrict_to(\"127.0.0.1\")\n"
            "    show(stdio, \"same_host_chain\", same.allows(\"127.0.0.1\"))\n"
        )
        py, host, wasi = _run_net_program_three_ways(src)
        self.assertEqual(py, host, "py/capa:host diverge")
        self.assertEqual(py, wasi, "py/wasi diverge")
        self.assertIn("first_in_chain=no", wasi)    # narrowed out
        self.assertIn("second_in_chain=no", wasi)   # never in parent {A}
        self.assertIn("parent_unaffected=yes", wasi)  # isolation
        self.assertIn("same_host_chain=yes", wasi)    # {A} & {A} = {A}

    def test_unrestricted_root_allows_everything_three_backends(self):
        src = (
            "fun show(stdio: Stdio, label: String, flag: Bool)\n"
            "    if flag\n"
            "        stdio.println(\"${label}=yes\")\n"
            "    else\n"
            "        stdio.println(\"${label}=no\")\n"
            "fun main(net: Net, stdio: Stdio)\n"
            "    show(stdio, \"root_a\", net.allows(\"127.0.0.1\"))\n"
            "    show(stdio, \"root_b\", net.allows(\"anything.example\"))\n"
        )
        py, host, wasi = _run_net_program_three_ways(src)
        self.assertEqual(py, host, "py/capa:host diverge")
        self.assertEqual(py, wasi, "py/wasi diverge")
        self.assertIn("root_a=yes", wasi)
        self.assertIn("root_b=yes", wasi)

    def test_restrict_get_allowed_host_ok_three_backends(self):
        # The allowed host (the local server) passes the fine gate AND the
        # ceiling, so the GET reaches the server and returns its body.
        with _LocalHttpServer(b"PONG") as authority:
            host_only = authority.split(":")[0]  # "127.0.0.1"
            src = (
                "fun main(net: Net, stdio: Stdio)\n"
                f"    let scoped = net.restrict_to(\"{host_only}\")\n"
                f"    match scoped.get(\"http://{authority}/p\")\n"
                "        Ok(b) -> stdio.println(\"[${b}]\")\n"
                "        Err(e) -> stdio.println(\"ERR\")\n"
            )
            py, host, wasi = _run_net_program_three_ways(src)
        self.assertEqual(py, host, "py/capa:host diverge")
        self.assertEqual(py, wasi, "py/wasi diverge")
        self.assertIn("[PONG]", wasi)

    def test_restrict_get_denied_host_fail_closed_three_backends(self):
        # The receiver Net is restricted to a host the GET url does NOT
        # name, so the fine gate denies BEFORE touching the network. The
        # url's own host is in the ceiling (it is a literal), so the deny is
        # the fine attenuation, not the ceiling. Identical Err on all three.
        with _LocalHttpServer(b"PONG") as authority:
            src = (
                "fun main(net: Net, stdio: Stdio)\n"
                "    let scoped = net.restrict_to(\"only.allowed.example\")\n"
                f"    match scoped.get(\"http://{authority}/p\")\n"
                "        Ok(b) -> stdio.println(\"[${b}]\")\n"
                "        Err(e) -> stdio.println(\"DENIED\")\n"
            )
            py, host, wasi = _run_net_program_three_ways(src)
        self.assertEqual(py, host, "py/capa:host diverge")
        self.assertEqual(py, wasi, "py/wasi diverge")
        self.assertIn("DENIED", wasi)

    def test_example_attenuation_program_runs(self):
        # The shipped slice example, run against a live local server with
        # its hardcoded 127.0.0.1:8080 authority rewritten to the ephemeral
        # port. Asserts the allows / narrowing / isolation answers and the
        # allowed-host get, byte-identical across the three backends.
        from pathlib import Path
        path = (
            Path(__file__).resolve().parent.parent
            / "examples" / "wasm" / "wasi_net_attenuation.capa"
        )
        src = path.read_text(encoding="utf-8")
        with _LocalHttpServer(b"HELLO") as authority:
            live = src.replace("127.0.0.1:8080", authority)
            py, host, wasi = _run_net_program_three_ways(live)
        self.assertEqual(py, host, "py/capa:host diverge")
        self.assertEqual(py, wasi, "py/wasi diverge")
        self.assertIn("allowed exact: yes", wasi)
        self.assertIn("denied other: no", wasi)
        self.assertIn("denied super-domain: no", wasi)
        self.assertIn("root admits any: yes", wasi)
        self.assertIn("narrowed first: no", wasi)
        self.assertIn("parent unaffected: yes", wasi)
        self.assertIn("get allowed-host ok: HELLO", wasi)
        self.assertIn("get narrowed denied", wasi)

    def test_restrict_post_allowed_and_denied_three_backends(self):
        with _LocalPostServer(mode="fixed", fixed=b"ACK") as authority:
            host_only = authority.split(":")[0]
            src = (
                "fun main(net: Net, stdio: Stdio)\n"
                f"    let ok = net.restrict_to(\"{host_only}\")\n"
                f"    match ok.post(\"http://{authority}/p\", \"payload\")\n"
                "        Ok(b) -> stdio.println(\"post_ok=[${b}]\")\n"
                "        Err(e) -> stdio.println(\"post_ok=ERR\")\n"
                "    let no = net.restrict_to(\"only.allowed.example\")\n"
                f"    match no.post(\"http://{authority}/p\", \"payload\")\n"
                "        Ok(b) -> stdio.println(\"post_deny=[${b}]\")\n"
                "        Err(e) -> stdio.println(\"post_deny=DENIED\")\n"
            )
            py, host, wasi = _run_net_program_three_ways(src)
        self.assertEqual(py, host, "py/capa:host diverge")
        self.assertEqual(py, wasi, "py/wasi diverge")
        self.assertIn("post_ok=[ACK]", wasi)
        self.assertIn("post_deny=DENIED", wasi)


# ----- Net redirect fail-closed (anti-SSRF security decision) ----
#
# In --wasi mode the guest does NOT follow HTTP redirects and treats ANY
# non-2xx response (3xx included) as a fail-closed Err WITHOUT reading the
# body, DELIBERATELY diverging (in the more-restrictive direction) from the
# urllib oracle / capa:host, which FOLLOW redirects. Reason: an implicit
# redirect from an allowed host to a non-allowed host would bypass the Net
# host ceiling + fine allow-list (an SSRF / host-authority bypass). See
# docs/design/wasi_mode.md "Redirects are fail-closed (anti-SSRF)".
#
# These are FAIL-CLOSED BEHAVIOUR tests, NOT three-backend parity tests:
# the Python oracle / capa:host follow the redirect (or raise on a 3xx
# without a Location), so they DIVERGE from --wasi by design. They are
# therefore asserted on the WASI backend ALONE and are deliberately kept
# OUT of any Net parity harness (_run_net_program_three_ways).


class _LocalRedirectServer:
    """A 127.0.0.1 HTTP server that answers BOTH GET and POST with a 3xx
    redirect. With ``location`` set it sends that ``Location`` header (the
    common 301 / 302 / 303 / 307 / 308 case); with ``location=None`` it sends a
    bodyless 3xx WITHOUT a Location (e.g. a 304 Not Modified). It never
    serves a 2xx, so a client that FOLLOWS the redirect would loop or fail,
    and a fail-closed client (--wasi) returns Err on the first response.

    Context-manager: yields the ``host:port`` authority. Loopback-only, so
    no external network is touched."""

    def __init__(self, status: int, location: str | None):
        self._status = status
        self._location = location
        self._srv = None
        self._thread = None
        self.port = None

    def __enter__(self):
        import threading
        from http.server import BaseHTTPRequestHandler, HTTPServer
        status = self._status
        location = self._location

        class _H(BaseHTTPRequestHandler):
            def _respond(self):
                self.send_response(status)
                if location is not None:
                    self.send_header("Location", location)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def do_GET(self):
                self._respond()

            def do_POST(self):
                # Drain the request body so the connection closes cleanly.
                te = self.headers.get("Transfer-Encoding", "")
                if "chunked" in te.lower():
                    while True:
                        line = self.rfile.readline().strip()
                        if not line:
                            continue
                        size = int(line, 16)
                        if size == 0:
                            self.rfile.readline()
                            break
                        self.rfile.read(size)
                        self.rfile.readline()
                else:
                    n = int(self.headers.get("Content-Length", 0))
                    if n:
                        self.rfile.read(n)
                self._respond()

            def log_message(self, *a):
                pass

        self._srv = HTTPServer(("127.0.0.1", 0), _H)
        self.port = self._srv.server_address[1]
        self._thread = threading.Thread(
            target=self._srv.serve_forever, daemon=True,
        )
        self._thread.start()
        return f"127.0.0.1:{self.port}"

    def __exit__(self, *exc):
        if self._srv is not None:
            self._srv.shutdown()
            self._srv.server_close()
        return False


def _run_net_wasi_only(src: str) -> str:
    """Build + run a Net program on the WASI component backend ALONE (with
    the static Net host ceiling) and return its stdout.

    Used for the redirect fail-closed tests, which are NOT parity tests:
    the Python oracle / capa:host follow redirects and so diverge from
    --wasi by design, so only the WASI backend's behaviour is asserted."""
    from capa.ir import compile_wasm, compile_wit, compute_net_ceiling
    from capa.cli import _wrap_as_component
    from capa.runtime._wasm_component_host import WasmComponentHost
    module, result = _parse_analyze(src)
    core = compile_wasm(module, types=result.types, wasi=True)
    wit = compile_wit(module, types=result.types, wasi=True)
    comp = _wrap_as_component(core, wit, wasi=True)
    ceiling = compute_net_ceiling(module, types=result.types)
    return _wasi_run_capture(
        WasmComponentHost(wasi=True, net_ceiling=ceiling), comp,
    )


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_wasi_http(),
    "wasm-tools and/or wasmtime-py with wasi:http not installed",
)
class TestWasiNetRedirectFailClosed(unittest.TestCase):
    """Security decision (anti-SSRF, "option B"): in --wasi mode the guest
    does NOT follow HTTP redirects and fails closed on ANY non-2xx response.
    A 3xx (301 / 302 / 303 / 307 / 308 with a Location, and a 304 without one) is
    a coherent Err on the WASI backend for BOTH net.get and net.post -- the
    response is dropped without reading the body and no Location is fetched.

    This DELIBERATELY diverges from the urllib oracle / capa:host (which
    follow redirects), so these are fail-closed BEHAVIOUR tests asserted on
    the WASI backend ALONE, NOT three-backend parity tests, and are kept out
    of the Net parity harness (the divergence is intentional, see
    docs/design/wasi_mode.md)."""

    # 3xx with a Location (the redirect-following vector) + a 304 without a
    # Location (a bodyless 3xx). The Location points at a host the program
    # never named, which is exactly the SSRF vector fail-closed defeats.
    _REDIRECTS = (
        (301, "http://evil.example/elsewhere"),
        (302, "http://evil.example/elsewhere"),
        (303, "http://evil.example/elsewhere"),
        (307, "http://evil.example/elsewhere"),
        (308, "http://evil.example/elsewhere"),
        (304, None),
    )

    def test_get_fails_closed_on_3xx(self):
        for status, location in self._REDIRECTS:
            with self.subTest(status=status):
                with _LocalRedirectServer(status, location) as auth:
                    out = _run_net_wasi_only(_net_get_src(auth))
                self.assertEqual(
                    out, "ERR\n",
                    f"GET {status} should fail closed (no redirect follow)",
                )

    def test_post_fails_closed_on_3xx(self):
        for status, location in self._REDIRECTS:
            with self.subTest(status=status):
                with _LocalRedirectServer(status, location) as auth:
                    out = _run_net_wasi_only(_net_post_src(auth, "payload"))
                self.assertEqual(
                    out, "ERR\n",
                    f"POST {status} should fail closed (no redirect follow)",
                )


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
