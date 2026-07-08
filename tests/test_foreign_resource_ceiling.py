"""Feature #4 hardening: a RESOURCE CEILING on the untrusted
foreign-component sandbox.

The confinement (which capabilities a child can reach) is proven sound in
F2a/F2b/F2c. This module covers the remaining AVAILABILITY bound: the
child store is fuel-metered (CPU) and memory-limited so a malicious or
buggy foreign component cannot hang or memory-exhaust the host. It only
adds a store ceiling; the restricted linker / granted caps / host-bound
closures are UNCHANGED.

Fixtures (hand-assembled, see ``tests/fixtures/foreign/``):

- ``spin_child.wasm`` -- exports ``run(x)`` whose body is ``(loop br 0)``,
  an infinite CPU spin. Under the fuel budget it TRAPS on fuel exhaustion
  instead of hanging the host.
- ``bigmem_child.wasm`` -- declares a 5000-page (320 MiB) minimum linear
  memory, over the 256 MiB default child memory ceiling, so it is refused
  at instantiation (a runaway self-allocation, bounded).
"""

from __future__ import annotations

import io
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import unittest.mock as mock
from pathlib import Path

from capa.cli import _wasm_tooling_available, main

_FIXTURES = Path(__file__).parent / "fixtures" / "foreign"
_REPO_ROOT = Path(__file__).resolve().parent.parent


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


# Grants no caps: run(x) -> x, but the body is an infinite loop.
_SPIN_PROG = (
    'extern component Spin from "spin_child.wasm"\n'
    "    fun run(x: Int) -> Int\n"
    "\n"
    "fun main(stdio: Stdio)\n"
    "    let r = Spin.run(41)\n"
    '    stdio.println("r=${r}")\n'
)

# Grants no caps: the child declares 320 MiB minimum memory, over the cap.
_BIGMEM_PROG = (
    'extern component Big from "bigmem_child.wasm"\n'
    "    fun run(x: Int) -> Int\n"
    "\n"
    "fun main(stdio: Stdio)\n"
    "    let r = Big.run(41)\n"
    '    stdio.println("r=${r}")\n'
)

# A legitimate scalar foreign call: Net attenuated to example.com; the
# child returns 41 + 1 (example.com allowed) + 0 (evil.com denied) = 42.
_NET_PROG = (
    'extern component Bureau from "net_child.wasm"\n'
    "    fun submit(net: Net, x: Int) -> Int\n"
    "\n"
    "fun main(net: Net, stdio: Stdio)\n"
    '    let safe = net.restrict_to("example.com")\n'
    "    let r = Bureau.submit(safe, 41)\n"
    '    stdio.println("result=${r}")\n'
)

# The child imports capa:host/fs but the method grants only Net -> the
# structural cap-set deny must still fire with the ceiling in place.
_FS_DENY_PROG = (
    'extern component Bad from "fs_child.wasm"\n'
    "    fun submit(net: Net, x: Int) -> Int\n"
    "\n"
    "fun main(net: Net)\n"
    "    let r = Bad.submit(net, 41)\n"
)

# Grants no caps: grow(n) returns the result of a huge table.grow (old
# size, or -1 if the table ceiling refused it).
_TABLEGROW_PROG = (
    'extern component TG from "tablegrow_child.wasm"\n'
    "    fun grow(n: Int) -> Int\n"
    "\n"
    "fun main(stdio: Stdio)\n"
    "    let r = TG.grow(10000000)\n"
    '    stdio.println("grow=${r}")\n'
)

# Grants Clock: nap(secs) asks the host to sleep for a huge duration; the
# blocking-closure bound must clamp it so the host does not hang.
_NAP_PROG = (
    'extern component Nap from "nap_child.wasm"\n'
    "    fun nap(clock: Clock, secs: Float) -> Int\n"
    "\n"
    "fun main(clock: Clock, stdio: Stdio)\n"
    "    let r = Nap.nap(clock, 100000000.0)\n"
    '    stdio.println("napped=${r}")\n'
)


@unittest.skipUnless(
    _wasm_tooling_available(), "wasm-tools / wasmtime missing",
)
class TestForeignResourceCeiling(unittest.TestCase):
    def _copy(self, td, *names):
        for n in names:
            shutil.copy(_FIXTURES / n, Path(td) / n)

    # ---- CPU / fuel bound ------------------------------------------

    def test_infinite_loop_traps_on_fuel_budget(self):
        # The credibility row: an infinite-loop child TRAPS on fuel
        # exhaustion under the default budget, with the clean CPU/fuel
        # message and exit 1 -- NOT a host hang or a raw traceback.
        with tempfile.TemporaryDirectory() as td:
            self._copy(td, "spin_child.wasm")
            p = _write(td, "prog.capa", _SPIN_PROG)
            rc, out, err = _run_cli(["--wasm", "--run", str(p)], cwd=td)
            self.assertEqual(rc, 1)
            self.assertIn("CPU/fuel budget", err)
            self.assertNotIn("r=", out)
            # No raw Python traceback leaked.
            self.assertNotIn("Traceback (most recent call last)", err)

    def test_infinite_loop_process_exits_within_timeout(self):
        # Non-hang proof: run the CLI in a SUBPROCESS with a hard wall
        # timeout. Fuel bounds the spin, so the host process must EXIT
        # (return) well within the timeout instead of hanging forever.
        with tempfile.TemporaryDirectory() as td:
            self._copy(td, "spin_child.wasm")
            p = _write(td, "prog.capa", _SPIN_PROG)
            start = time.monotonic()
            proc = None
            try:
                proc = subprocess.run(
                    [sys.executable, "-m", "capa", "--wasm", "--run", str(p)],
                    cwd=td,
                    capture_output=True,
                    text=True,
                    timeout=90,
                    env={**os.environ, "PYTHONPATH": str(_REPO_ROOT)},
                )
            except subprocess.TimeoutExpired:
                self.fail(
                    "foreign infinite-loop child HUNG the host: the process "
                    "did not exit within the timeout (fuel bound not enforced)"
                )
            elapsed = time.monotonic() - start
            self.assertEqual(proc.returncode, 1, proc.stderr)
            self.assertIn("CPU/fuel budget", proc.stderr)
            # Sanity: it terminated promptly, not just under the ceiling.
            self.assertLess(elapsed, 90)

    def test_foreign_fuel_flag_traps_legit_call(self):
        # The flag is wired: a deliberately tiny --foreign-fuel budget
        # traps even the legitimate net fixture on fuel exhaustion.
        with tempfile.TemporaryDirectory() as td:
            self._copy(td, "net_child.wasm")
            p = _write(td, "prog.capa", _NET_PROG)
            rc, _out, err = _run_cli(
                ["--wasm", "--run", "--foreign-fuel", "1", str(p)], cwd=td,
            )
            self.assertEqual(rc, 1)
            self.assertIn("CPU/fuel budget", err)

    def test_foreign_fuel_zero_opts_out(self):
        # --foreign-fuel 0 skips the CPU bound: the legit call runs
        # unaffected (the flag's opt-out path is honoured).
        with tempfile.TemporaryDirectory() as td:
            self._copy(td, "net_child.wasm")
            p = _write(td, "prog.capa", _NET_PROG)
            rc, out, err = _run_cli(
                ["--wasm", "--run", "--foreign-fuel", "0", str(p)], cwd=td,
            )
            self.assertEqual(rc, 0, err)
            self.assertIn("result=42", out)

    # ---- memory bound ----------------------------------------------

    def test_oversized_memory_traps_on_limit(self):
        # A child whose minimum linear memory (320 MiB) exceeds the
        # default 256 MiB ceiling is refused, with the clean resource-limit
        # message and exit 1 -- no host OOM, no traceback.
        with tempfile.TemporaryDirectory() as td:
            self._copy(td, "bigmem_child.wasm")
            p = _write(td, "prog.capa", _BIGMEM_PROG)
            rc, out, err = _run_cli(["--wasm", "--run", str(p)], cwd=td)
            self.assertEqual(rc, 1)
            self.assertIn("exceeded its memory", err)
            self.assertIn("resource limit", err)
            self.assertNotIn("r=", out)
            self.assertNotIn("Traceback (most recent call last)", err)

    def test_foreign_memory_cap_flag_changes_outcome(self):
        # The flag is wired: raising --foreign-memory-cap above the
        # child's footprint lets the same oversized fixture instantiate
        # and run (proving the flag tunes the ceiling, not a constant).
        with tempfile.TemporaryDirectory() as td:
            self._copy(td, "bigmem_child.wasm")
            p = _write(td, "prog.capa", _BIGMEM_PROG)
            rc, out, err = _run_cli(
                ["--wasm", "--run", "--foreign-memory-cap", "512", str(p)],
                cwd=td,
            )
            self.assertEqual(rc, 0, err)
            self.assertIn("r=41", out)

    # ---- table / other growable resources (review C2) --------------

    def test_table_grow_capped_under_default(self):
        # A runaway table.grow (10M funcref elements, ~80 MB) is capped:
        # grow returns -1 under the default table_elements ceiling, so the
        # host never OOMs and the child observes the refusal.
        with tempfile.TemporaryDirectory() as td:
            self._copy(td, "tablegrow_child.wasm")
            p = _write(td, "prog.capa", _TABLEGROW_PROG)
            rc, out, err = _run_cli(["--wasm", "--run", str(p)], cwd=td)
            self.assertEqual(rc, 0, err)
            self.assertIn("grow=-1", out)

    def test_table_grow_capped_under_configured_cap(self):
        # The table ceiling holds under an explicitly configured memory
        # cap too (the growable-resource bounds travel with the memory
        # bound, not only the default).
        with tempfile.TemporaryDirectory() as td:
            self._copy(td, "tablegrow_child.wasm")
            p = _write(td, "prog.capa", _TABLEGROW_PROG)
            rc, out, err = _run_cli(
                ["--wasm", "--run", "--foreign-memory-cap", "512", str(p)],
                cwd=td,
            )
            self.assertEqual(rc, 0, err)
            self.assertIn("grow=-1", out)

    def test_table_grow_unbounded_when_opted_out(self):
        # Opting out of the store limits (--foreign-memory-cap 0) lets the
        # same grow SUCCEED (returns the old size, not -1), proving the
        # ceiling -- not something else -- is what caps the table.
        with tempfile.TemporaryDirectory() as td:
            self._copy(td, "tablegrow_child.wasm")
            p = _write(td, "prog.capa", _TABLEGROW_PROG)
            rc, out, err = _run_cli(
                ["--wasm", "--run", "--foreign-memory-cap", "0", str(p)],
                cwd=td,
            )
            self.assertEqual(rc, 0, err)
            self.assertNotIn("grow=-1", out)
            self.assertIn("grow=", out)

    def test_memory_cap_zero_opts_out(self):
        # --foreign-memory-cap 0 skips the store limits: the oversized
        # child now instantiates and runs (opt-out honoured; it really
        # allocates its 320 MiB, so no store ceiling).
        with tempfile.TemporaryDirectory() as td:
            self._copy(td, "bigmem_child.wasm")
            p = _write(td, "prog.capa", _BIGMEM_PROG)
            rc, out, err = _run_cli(
                ["--wasm", "--run", "--foreign-memory-cap", "0", str(p)],
                cwd=td,
            )
            self.assertEqual(rc, 0, err)
            self.assertIn("r=41", out)

    # ---- blocking host closures (review C1) ------------------------

    def test_blocking_sleep_does_not_hang_host(self):
        # A granted clock.sleep with a huge guest-controlled duration must
        # NOT hang the host (fuel does not meter host wall-time). Run in a
        # SUBPROCESS with a hard timeout: the sleep is clamped to a bounded
        # maximum, so the process exits promptly instead of sleeping ~1e8s.
        with tempfile.TemporaryDirectory() as td:
            self._copy(td, "nap_child.wasm")
            p = _write(td, "prog.capa", _NAP_PROG)
            start = time.monotonic()
            proc = None
            try:
                proc = subprocess.run(
                    [sys.executable, "-m", "capa", "--wasm", "--run", str(p)],
                    cwd=td,
                    capture_output=True,
                    text=True,
                    timeout=90,
                    env={**os.environ, "PYTHONPATH": str(_REPO_ROOT)},
                )
            except subprocess.TimeoutExpired:
                self.fail(
                    "a granted blocking clock.sleep HUNG the host: the "
                    "process did not exit within the timeout (the closure "
                    "wall-time bound is not enforced)"
                )
            elapsed = time.monotonic() - start
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("napped=0", proc.stdout)
            # Clamped well under the huge requested duration and the timeout.
            self.assertLess(elapsed, 60)

    def test_net_closures_have_a_socket_timeout(self):
        # The net closures reach an external server; assert a socket
        # timeout is configured so a slow/hanging allowlisted host cannot
        # block the host thread indefinitely.
        import inspect
        from capa.runtime import _capabilities
        self.assertIn("timeout=", inspect.getsource(_capabilities.Net.get))
        self.assertIn("timeout=", inspect.getsource(_capabilities.Net.post))

    def test_db_query_deadline_aborts_runaway_sql(self):
        # A granted db.query running a non-terminating recursive CTE must
        # be aborted at a bounded wall-clock deadline (fuel cannot meter
        # time spent inside sqlite). Patch the bound small so the test is
        # fast, drive the real _bind_db closure, and assert it returns a
        # clean IoError instead of hanging.
        from capa.runtime import _foreign
        from capa.runtime._capabilities import Db
        from capa.runtime._wasm_component_host import IoErrorRecord

        captured: dict = {}

        class _Ifc:
            def add_func(self, name, fn):
                captured[name] = fn

            def close(self):
                pass

        class _Root:
            def add_instance(self, _name):
                return _Ifc()

        with tempfile.TemporaryDirectory() as td:
            db_path = str(Path(td) / "d.sqlite")
            with mock.patch.object(
                _foreign, "MAX_FOREIGN_BLOCKING_SECS", 0.5,
            ):
                _foreign._bind_db(_Root(), Db())
                query = captured["query"]
                runaway = (
                    "WITH RECURSIVE r(n) AS ("
                    "SELECT 1 UNION ALL SELECT n+1 FROM r) "
                    "SELECT n FROM r"
                )
                start = time.monotonic()
                result = query(None, 0, db_path, runaway)
                elapsed = time.monotonic() - start
            self.assertIsInstance(result, IoErrorRecord)
            # Aborted near the 0.5s deadline, nowhere near an infinite run.
            self.assertLess(elapsed, 20)

    # ---- confinement + legitimate-path regressions -----------------

    def test_legit_fixture_runs_unaffected_under_default_budget(self):
        # A legitimate scalar foreign call runs unaffected under the
        # default ceiling and the attenuated Net still returns 42 (the
        # ceiling did not perturb the confinement / marshalling).
        with tempfile.TemporaryDirectory() as td:
            self._copy(td, "net_child.wasm")
            p = _write(td, "prog.capa", _NET_PROG)
            rc, out, err = _run_cli(["--wasm", "--run", str(p)], cwd=td)
            self.assertEqual(rc, 0, err)
            self.assertIn("result=42", out)

    def test_ungranted_cap_still_denied_with_ceiling(self):
        # Confinement regression: the structural cap-set deny still fires
        # (the resource ceiling did not perturb the restricted linker),
        # and it is reported as an instantiation deny -- NOT mislabelled
        # as a fuel / memory ceiling breach.
        with tempfile.TemporaryDirectory() as td:
            self._copy(td, "fs_child.wasm")
            p = _write(td, "prog.capa", _FS_DENY_PROG)
            rc, _out, err = _run_cli(["--wasm", "--run", str(p)], cwd=td)
            self.assertEqual(rc, 1)
            self.assertIn("instantiation denied", err)
            self.assertIn("capa:host/fs", err)
            self.assertNotIn("CPU/fuel budget", err)
            self.assertNotIn("resource limit", err)


class TestForeignCeilingFlagValidation(unittest.TestCase):
    """The --foreign-* flags reject a NEGATIVE budget (a typo must not
    silently disable a bound); 0 remains the explicit opt-out. These do
    not need the Wasm toolchain (rejected before any run)."""

    def _rc(self, argv):
        with tempfile.TemporaryDirectory() as td:
            p = _write(td, "prog.capa", "fun main()\n    return\n")
            rc, _out, err = _run_cli(argv + [str(p)], cwd=td)
            return rc, err

    def test_negative_fuel_rejected(self):
        rc, err = self._rc(["--wasm", "--run", "--foreign-fuel", "-5"])
        self.assertEqual(rc, 2)
        self.assertIn("--foreign-fuel must be >= 0", err)

    def test_negative_memory_cap_rejected(self):
        rc, err = self._rc(["--wasm", "--run", "--foreign-memory-cap", "-1"])
        self.assertEqual(rc, 2)
        self.assertIn("--foreign-memory-cap must be >= 0", err)


@unittest.skipUnless(
    _wasm_tooling_available(), "wasm-tools / wasmtime missing",
)
class TestForeignCeilingUnit(unittest.TestCase):
    """Unit-level checks of the ceiling helpers. These reference
    ``capa.runtime._foreign`` (which imports ``wasmtime`` at module load)
    and ``wasmtime`` directly, so they carry the SAME wasm-tooling skip
    guard as the run-based classes above: on a host without wasmtime they
    SKIP cleanly rather than erroring on the import."""

    def test_defaults_are_generous_but_bounded(self):
        from capa.runtime._foreign import (
            DEFAULT_FOREIGN_FUEL,
            DEFAULT_FOREIGN_MEMORY_CAP_BYTES,
            DEFAULT_FOREIGN_TABLE_ELEMENTS,
            MAX_FOREIGN_BLOCKING_SECS,
        )
        self.assertEqual(DEFAULT_FOREIGN_FUEL, 1_000_000_000)
        self.assertEqual(DEFAULT_FOREIGN_MEMORY_CAP_BYTES, 256 * 1024 * 1024)
        self.assertEqual(DEFAULT_FOREIGN_TABLE_ELEMENTS, 1_000_000)
        # A bounded, non-trivial blocking budget (seconds).
        self.assertGreater(MAX_FOREIGN_BLOCKING_SECS, 0)
        self.assertLessEqual(MAX_FOREIGN_BLOCKING_SECS, 30)

    def test_resource_exceeded_is_a_foreign_denied(self):
        # Subclassing keeps the CLI's clean exit-1 surfacing unchanged.
        from capa.runtime._foreign import (
            ForeignDenied,
            ForeignResourceExceeded,
        )
        self.assertTrue(issubclass(ForeignResourceExceeded, ForeignDenied))

    def test_configure_foreign_limits_opt_out_and_override(self):
        from capa.runtime._foreign import (
            DEFAULT_FOREIGN_FUEL,
            DEFAULT_FOREIGN_MEMORY_CAP_BYTES,
        )
        from capa.runtime._wasm_host import WasmHost
        host = WasmHost()
        self.assertEqual(host._foreign_fuel, DEFAULT_FOREIGN_FUEL)
        self.assertEqual(
            host._foreign_memory_cap_bytes, DEFAULT_FOREIGN_MEMORY_CAP_BYTES,
        )
        # A None argument keeps the current value.
        host.configure_foreign_limits(fuel=None, memory_cap_bytes=None)
        self.assertEqual(host._foreign_fuel, DEFAULT_FOREIGN_FUEL)
        # A positive value overrides; 0 opts out (becomes None).
        host.configure_foreign_limits(fuel=5000, memory_cap_bytes=0)
        self.assertEqual(host._foreign_fuel, 5000)
        self.assertIsNone(host._foreign_memory_cap_bytes)

    def test_store_limit_error_classifier(self):
        from capa.runtime._foreign import _is_store_limit_error
        # A store-limit breach (memory / table / ...) is recognised ...
        self.assertTrue(
            _is_store_limit_error(
                Exception("memory minimum size of 5000 pages exceeds "
                          "memory limits")
            )
        )
        # ... while the structural capability-import deny is NOT (so it is
        # not mislabelled as a resource breach).
        self.assertFalse(
            _is_store_limit_error(
                Exception("component imports instance `capa:host/fs`, but a "
                          "matching implementation was not found")
            )
        )

    def test_store_limit_error_message_shape(self):
        # Pin the CURRENT wasmtime phrasing the classifier couples to, so a
        # future wasmtime message change breaks THIS test (a loud, local
        # signal) rather than silently misclassifying a real error. Builds
        # a real over-limit store and captures the actual message.
        import wasmtime
        from capa.runtime._foreign import _is_store_limit_error
        eng = wasmtime.Engine()
        mod = wasmtime.Module(
            eng,
            '(module (memory (export "m") 5000) '
            '(func (export "f")))',
        )
        store = wasmtime.Store(eng)
        store.set_limits(memory_size=4 * 1024 * 1024)
        with self.assertRaises(wasmtime.WasmtimeError) as ctx:
            wasmtime.Instance(store, mod, [])
        msg = str(ctx.exception).lower()
        self.assertIn("exceed", msg)
        self.assertIn("limit", msg)
        self.assertTrue(_is_store_limit_error(ctx.exception))


if __name__ == "__main__":
    unittest.main()
