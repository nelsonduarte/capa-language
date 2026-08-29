"""Shared helpers for the tests/wasi/ package.

The single source of the WASI test primitives every capability module reuses:
the wasm-tools / wasip2 skip gates (``_has_wasm_tools`` /
``_has_wasmtime_wasip2``), the parse+analyze front end, the WASI component
build / run primitives, and the Env program-source fixtures shared by the core
and env modules.

This is NOT a test module: its name does not match the test*.py discovery
pattern, so unittest discovery and pytest never collect it as tests. Facet-local
helpers (the stdio / stdin runners, the fs preopen runners, the net loopback
servers) live with their capability module, not here.
"""

from __future__ import annotations

import io
import shutil
import sys

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
