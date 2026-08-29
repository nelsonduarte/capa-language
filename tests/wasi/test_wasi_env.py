"""WASI mode: the Env capability (wasi:cli/environment).

Static env-ceiling analysis, the guest-side Env reader + args migration, the
Level 2 guest-side attenuation (restrict_to_keys / allows / fail-closed get),
and the Level 1 static-ceiling leak-closed guarantee. Split out of
tests/test_wasi_mode.py; see tests/wasi/__init__.py for the growth convention.
The shared primitives and the Env fixtures live in tests/wasi/_helpers.py.
"""

from __future__ import annotations

import io
import os
import sys
import unittest

from tests.wasi._helpers import (
    _ATT_A,
    _ATT_B,
    _ATT_VALS,
    _ENV_ARGS_SRC,
    _ENV_ATTEN_EDGE_SRC,
    _ENV_ATTEN_SRC,
    _ENV_GET_SRC,
    _ENV_HYBRID_SRC,
    _ENV_KEY,
    _ENV_VAL,
    _REPO_ROOT,
    _has_wasm_tools,
    _has_wasmtime_wasip2,
    _parse_analyze,
    _run_python,
    _run_wasi_component,
    _wasi_run_capture,
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
                _REPO_ROOT
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
                _REPO_ROOT
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


if __name__ == "__main__":
    unittest.main()
