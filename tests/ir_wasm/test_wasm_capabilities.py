"""WebAssembly backend: capability lowering and host bridges (Env, Fs,
the slice-1 host bridges, inline allows emission, attenuation
enforcement, and Random / Net execution).

Part of the tests/ir_wasm package; see tests/ir_wasm/__init__.py for
the growth convention (the Random / Net runtime-execution facet is the
named seam toward a future test_wasm_capability_exec.py). The shared
_parse_lower / skip gates live in tests/ir_wasm/_helpers.py.
"""

from __future__ import annotations

import unittest

from tests.ir_wasm._helpers import _parse_lower, _has_wasm_tools, _has_wasmtime_py
from capa.ir import emit_wat, compile_wasm


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestWasmEnv(unittest.TestCase):
    """Phase 7B: Env.get returns Option<String>, with the host
    bridge allocating both the Option container and the string
    payload bytes via the module's exported \\$alloc. String
    payloads are packed into the 8-byte Option slot as
    (ptr low, len high); the match emitter unpacks at the
    Some-binding site."""

    def test_env_get_hit_and_miss(self):
        import os
        from capa.runtime._wasm_host import WasmHost
        src = (
            "fun lookup(stdio: Stdio, env: Env, key: String)\n"
            "    match env.get(key)\n"
            "        Some(v) -> stdio.println(\"hit: ${v}\")\n"
            "        None -> stdio.println(\"miss\")\n"
            "fun main(stdio: Stdio, env: Env)\n"
            "    lookup(stdio, env, \"CAPA_WASM_TEST_HIT\")\n"
            "    lookup(stdio, env, \"DEFINITELY_NOT_SET_XYZ\")\n"
        )
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types)
        os.environ["CAPA_WASM_TEST_HIT"] = "found-value"
        os.environ.pop("DEFINITELY_NOT_SET_XYZ", None)
        try:
            import io
            import sys
            host = WasmHost()
            out = io.StringIO()
            saved = sys.stdout
            sys.stdout = out
            try:
                host.run_main(blob)
            finally:
                sys.stdout = saved
            lines = out.getvalue().strip().split("\n")
            self.assertEqual(lines, ["hit: found-value", "miss"])
        finally:
            os.environ.pop("CAPA_WASM_TEST_HIT", None)


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestWasmFs(unittest.TestCase):
    """Phase 7C: Fs.read / Fs.write return Result<T, IoError>. The
    host bridge constructs Result + IoError records in wasm
    memory via the module's exported \\$alloc. Pattern matching
    on Ok / Err works through the existing match emitter, with
    String payloads unpacked from the i64 slot and IoError
    pointer payloads i32-wrapped at the bind site."""

    def test_fs_round_trip(self):
        import os
        import tempfile
        from capa.runtime._wasm_host import WasmHost
        with tempfile.TemporaryDirectory() as td:
            target = os.path.join(td, "out.txt").replace("\\", "/")
            src = (
                "fun main(stdio: Stdio, fs: Fs)\n"
                "    match fs.write(\"" + target + "\", \"hello-fs\")\n"
                "        Ok(_) -> stdio.println(\"wrote\")\n"
                "        Err(_) -> stdio.eprintln(\"write failed\")\n"
                "    match fs.read(\"" + target + "\")\n"
                "        Ok(text) -> stdio.println(\"read: ${text}\")\n"
                "        Err(_) -> stdio.eprintln(\"read failed\")\n"
            )
            _, types, ast_mod = _parse_lower(src)
            blob = compile_wasm(ast_mod, types=types)
            import io
            import sys
            host = WasmHost()
            out = io.StringIO()
            saved = sys.stdout
            sys.stdout = out
            try:
                host.run_main(blob)
            finally:
                sys.stdout = saved
            self.assertEqual(out.getvalue(), "wrote\nread: hello-fs\n")

    def test_fs_read_missing_returns_err(self):
        from capa.runtime._wasm_host import WasmHost
        src = (
            "fun main(stdio: Stdio, fs: Fs)\n"
            "    match fs.read(\"/does/not/exist/xyz\")\n"
            "        Ok(_) -> stdio.println(\"BUG\")\n"
            "        Err(_) -> stdio.println(\"missing\")\n"
        )
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types)
        import io
        import sys
        host = WasmHost()
        out = io.StringIO()
        saved = sys.stdout
        sys.stdout = out
        try:
            host.run_main(blob)
        finally:
            sys.stdout = saved
        self.assertEqual(out.getvalue(), "missing\n")


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestWasmSlice1HostBridges(unittest.TestCase):
    """Slice 1 of the Wasm-fully-functional arc (2026-05): close
    the host-bridge pile (Fs.exists / is_dir / mkdir / list_dir,
    Stdio.read_line, Clock.sleep, Clock.allows). Each method gets
    a runtime test with a deterministic fixture so the Wasm side
    matches the Python runtime byte-for-byte (or behaviourally
    equivalent for time-dependent calls like Clock.sleep).
    """

    def _run(self, src: str, stdin_text: str | None = None) -> str:
        from capa.runtime._wasm_host import WasmHost
        import io
        import sys
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types)
        host = WasmHost()
        out = io.StringIO()
        saved_out = sys.stdout
        sys.stdout = out
        saved_in = None
        if stdin_text is not None:
            saved_in = sys.stdin
            sys.stdin = io.StringIO(stdin_text)
        try:
            host.run_main(blob)
        finally:
            sys.stdout = saved_out
            if saved_in is not None:
                sys.stdin = saved_in
        return out.getvalue()

    def test_fs_exists_true_and_false(self):
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            real = os.path.join(td, "real.txt").replace("\\", "/")
            with open(real, "w", encoding="utf-8") as f:
                f.write("x")
            missing = os.path.join(td, "missing.txt").replace("\\", "/")
            src = (
                "fun main(stdio: Stdio, fs: Fs)\n"
                f"    if fs.exists(\"{real}\")\n"
                "        stdio.println(\"real: yes\")\n"
                "    else\n"
                "        stdio.println(\"real: no\")\n"
                f"    if fs.exists(\"{missing}\")\n"
                "        stdio.println(\"missing: yes\")\n"
                "    else\n"
                "        stdio.println(\"missing: no\")\n"
            )
            self.assertEqual(
                self._run(src), "real: yes\nmissing: no\n",
            )

    def test_fs_is_dir_dir_and_file(self):
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            target = td.replace("\\", "/")
            f_path = os.path.join(td, "f.txt").replace("\\", "/")
            with open(f_path, "w", encoding="utf-8") as f:
                f.write("x")
            src = (
                "fun main(stdio: Stdio, fs: Fs)\n"
                f"    if fs.is_dir(\"{target}\")\n"
                "        stdio.println(\"dir: yes\")\n"
                "    else\n"
                "        stdio.println(\"dir: no\")\n"
                f"    if fs.is_dir(\"{f_path}\")\n"
                "        stdio.println(\"file: yes\")\n"
                "    else\n"
                "        stdio.println(\"file: no\")\n"
            )
            self.assertEqual(
                self._run(src), "dir: yes\nfile: no\n",
            )

    def test_fs_mkdir_creates_and_is_idempotent(self):
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            target = os.path.join(td, "nested", "sub").replace("\\", "/")
            src = (
                "fun main(stdio: Stdio, fs: Fs)\n"
                f"    match fs.mkdir(\"{target}\")\n"
                "        Ok(_) -> stdio.println(\"first ok\")\n"
                "        Err(_) -> stdio.println(\"first err\")\n"
                # Second call must succeed (exist_ok=True mirrors
                # the Python runtime).
                f"    match fs.mkdir(\"{target}\")\n"
                "        Ok(_) -> stdio.println(\"second ok\")\n"
                "        Err(_) -> stdio.println(\"second err\")\n"
            )
            self.assertEqual(
                self._run(src), "first ok\nsecond ok\n",
            )
            self.assertTrue(os.path.isdir(target))

    def test_fs_mkdir_err_on_file_collision(self):
        # mkdir on a path that exists as a regular file is an OS
        # error even with ``exist_ok=True``; surfaced as Err.
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            target = os.path.join(td, "f.txt").replace("\\", "/")
            with open(target, "w", encoding="utf-8") as f:
                f.write("x")
            src = (
                "fun main(stdio: Stdio, fs: Fs)\n"
                f"    match fs.mkdir(\"{target}\")\n"
                "        Ok(_) -> stdio.println(\"unexpected ok\")\n"
                "        Err(_) -> stdio.println(\"expected err\")\n"
            )
            self.assertEqual(self._run(src), "expected err\n")

    def test_fs_list_dir_sorted_entries(self):
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            for name in ("z.txt", "a.txt", "m.txt"):
                with open(os.path.join(td, name), "w") as f:
                    f.write("")
            target = td.replace("\\", "/")
            src = (
                "fun main(stdio: Stdio, fs: Fs)\n"
                f"    match fs.list_dir(\"{target}\")\n"
                "        Ok(items) -> \n"
                "            for item in items\n"
                "                stdio.println(item)\n"
                "        Err(_) -> stdio.println(\"err\")\n"
            )
            self.assertEqual(
                self._run(src), "a.txt\nm.txt\nz.txt\n",
            )

    def test_fs_list_dir_err_on_missing(self):
        src = (
            "fun main(stdio: Stdio, fs: Fs)\n"
            "    match fs.list_dir(\"/no/such/path/zzz_capa_test_98765\")\n"
            "        Ok(_) -> stdio.println(\"unexpected ok\")\n"
            "        Err(_) -> stdio.println(\"expected err\")\n"
        )
        self.assertEqual(self._run(src), "expected err\n")

    def test_fs_list_dir_empty_dir(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            target = td.replace("\\", "/")
            src = (
                "fun main(stdio: Stdio, fs: Fs)\n"
                f"    match fs.list_dir(\"{target}\")\n"
                "        Ok(items) -> stdio.println(\"len: ${items.length()}\")\n"
                "        Err(_) -> stdio.println(\"err\")\n"
            )
            self.assertEqual(self._run(src), "len: 0\n")

    def test_stdio_read_line_returns_input(self):
        src = (
            "fun main(stdio: Stdio)\n"
            "    match stdio.read_line()\n"
            "        Ok(line) -> stdio.println(\"got: ${line}\")\n"
            "        Err(_) -> stdio.println(\"err\")\n"
        )
        self.assertEqual(
            self._run(src, stdin_text="hello\n"), "got: hello\n",
        )

    def test_stdio_read_line_eof_returns_err(self):
        src = (
            "fun main(stdio: Stdio)\n"
            "    match stdio.read_line()\n"
            "        Ok(_) -> stdio.println(\"unexpected ok\")\n"
            "        Err(_) -> stdio.println(\"eof\")\n"
        )
        self.assertEqual(self._run(src, stdin_text=""), "eof\n")

    def test_clock_sleep_does_not_error(self):
        # Don't assert on timing (would be flaky); just confirm a
        # short sleep returns to the caller cleanly.
        src = (
            "fun main(stdio: Stdio, clock: Clock)\n"
            "    clock.sleep(0.001)\n"
            "    stdio.println(\"after sleep\")\n"
        )
        self.assertEqual(self._run(src), "after sleep\n")

    def test_clock_sleep_negative_is_noop(self):
        # Negative sleeps should not crash the host (the bridge
        # guards against ``time.sleep(negative)`` which would
        # otherwise raise ValueError).
        src = (
            "fun main(stdio: Stdio, clock: Clock)\n"
            "    clock.sleep(-1.0)\n"
            "    stdio.println(\"survived\")\n"
        )
        self.assertEqual(self._run(src), "survived\n")

    def test_clock_allows_unrestricted_returns_true(self):
        # Unrestricted Clock at the host returns true; matches the
        # Python runtime's ``self._not_before is None`` branch.
        src = (
            "fun main(stdio: Stdio, clock: Clock)\n"
            "    if clock.allows()\n"
            "        stdio.println(\"allowed\")\n"
            "    else\n"
            "        stdio.println(\"denied\")\n"
        )
        self.assertEqual(self._run(src), "allowed\n")


class TestWasmAllowsInlineEmit(unittest.TestCase):
    """GAP-2b (2026-06-21): ``Fs.allows`` / ``Env.allows`` /
    ``Db.allows`` / ``Net.allows`` / ``Proc.allows`` route through
    the authoritative ``$<Cap>_allows(handle, arg) -> bool`` host
    function (the same host-route ``Clock.allows`` already used), so
    a host import IS emitted and no guest-side ``$_atten_*`` check is
    left behind. Pre-route these queries were inlined at emit time
    and the dynamic-prefix case failed/diverged. These tests pin the
    emit-time contract independent of the runtime so the routing is
    visible even on machines without the Wasm toolchain.
    """

    def test_fs_allows_literal_emits_host_import(self):
        src = (
            "fun main(stdio: Stdio, fs: Fs)\n"
            "    if fs.allows(\"/x\")\n"
            "        stdio.println(\"y\")\n"
            "    else\n"
            "        stdio.println(\"n\")\n"
        )
        ir_mod, _, _ = _parse_lower(src)
        wat = emit_wat(ir_mod)
        # GAP-2b: Fs.allows now routes through the host. The
        # Stdio.println import is still present too.
        self.assertIn("\"capa:host/fs\" \"allows\"", wat)
        self.assertIn("call $Fs_allows", wat)
        self.assertIn("\"capa:host/stdio\" \"println\"", wat)

    def test_env_allows_literal_emits_host_import(self):
        src = (
            "fun main(stdio: Stdio, env: Env)\n"
            "    if env.allows(\"HOME\")\n"
            "        stdio.println(\"y\")\n"
            "    else\n"
            "        stdio.println(\"n\")\n"
        )
        ir_mod, _, _ = _parse_lower(src)
        wat = emit_wat(ir_mod)
        self.assertIn("\"capa:host/env\" \"allows\"", wat)
        self.assertIn("call $Env_allows", wat)

    def test_fs_allows_dynamic_arg_routes_through_host(self):
        # GAP-2b (2026-06-21): the dynamic-arg case (the gap) now
        # travels guest->host as a normal (ptr, len) string, so the
        # WAT carries no ``$_atten_*`` scratch and calls the host
        # import. Pre-route the unrestricted case collapsed to a
        # const and the attenuated case emitted an inline check.
        src = (
            "fun main(stdio: Stdio, fs: Fs)\n"
            "    let p = \"/x\"\n"
            "    if fs.allows(p)\n"
            "        stdio.println(\"y\")\n"
            "    else\n"
            "        stdio.println(\"n\")\n"
        )
        ir_mod, _, _ = _parse_lower(src)
        wat = emit_wat(ir_mod)
        self.assertIn("\"capa:host/fs\" \"allows\"", wat)
        self.assertIn("call $Fs_allows", wat)
        self.assertNotIn("$_atten_ok", wat)

    def test_fs_allows_dynamic_arg_attenuated_routes_through_host(self):
        # GAP-2b (2026-06-21): the dynamic-arg + attenuated case is
        # exactly what diverged before (the guest-side lexical prefix
        # check could not realpath). It now pushes the receiver
        # handle + the (ptr, len) string and calls the host import,
        # which consults the authoritative ``fs.allows(path)``; no
        # ``$_atten_*`` machinery remains.
        src = (
            "fun main(stdio: Stdio, fs: Fs)\n"
            "    let scoped = fs.restrict_to(\"/tmp/\")\n"
            "    let p = \"/tmp/work\"\n"
            "    if scoped.allows(p)\n"
            "        stdio.println(\"y\")\n"
            "    else\n"
            "        stdio.println(\"n\")\n"
        )
        ir_mod, _, _ = _parse_lower(src)
        wat = emit_wat(ir_mod)
        self.assertNotIn("$_atten_path_ptr", wat)
        self.assertNotIn("$_atten_ok", wat)
        self.assertIn("call $Fs_allows", wat)
        self.assertIn("call $Fs_restrict_to", wat)

    def test_env_allows_dynamic_arg_routes_through_host(self):
        # GAP-2b: same host-route for Env.allows. The dynamic
        # restrict_to_keys list was the silent-divergence case
        # (the lexical key-list reconstruction returned []); routing
        # it host-side restores parity.
        src = (
            "fun main(stdio: Stdio, env: Env)\n"
            "    let n = \"HOME\"\n"
            "    if env.allows(n)\n"
            "        stdio.println(\"y\")\n"
            "    else\n"
            "        stdio.println(\"n\")\n"
        )
        ir_mod, _, _ = _parse_lower(src)
        wat = emit_wat(ir_mod)
        self.assertIn("\"capa:host/env\" \"allows\"", wat)
        self.assertIn("call $Env_allows", wat)

    def test_net_proc_db_allows_emit_host_import(self):
        # GAP-2b: Net / Proc / Db .allows also route host-side.
        src = (
            "fun main(stdio: Stdio, net: Net, proc: Proc, db: Db)\n"
            "    let n = \"example.com\"\n"
            "    let c = \"git\"\n"
            "    let p = \"/var/data/x.db\"\n"
            "    if net.allows(n)\n"
            "        stdio.println(\"a\")\n"
            "    if proc.allows(c)\n"
            "        stdio.println(\"b\")\n"
            "    if db.allows(p)\n"
            "        stdio.println(\"c\")\n"
        )
        ir_mod, _, _ = _parse_lower(src)
        wat = emit_wat(ir_mod)
        self.assertIn("\"capa:host/net\" \"allows\"", wat)
        self.assertIn("\"capa:host/proc\" \"allows\"", wat)
        self.assertIn("\"capa:host/db\" \"allows\"", wat)
        self.assertIn("call $Net_allows", wat)
        self.assertIn("call $Proc_allows", wat)
        self.assertIn("call $Db_allows", wat)
        self.assertNotIn("$_atten_ok", wat)

    def test_clock_allows_stays_on_host_bridge(self):
        # Clock.allows depends on the live wall clock; per D4 we
        # keep it as a host import rather than inlining.
        src = (
            "fun main(stdio: Stdio, clock: Clock)\n"
            "    if clock.allows()\n"
            "        stdio.println(\"y\")\n"
            "    else\n"
            "        stdio.println(\"n\")\n"
        )
        ir_mod, _, _ = _parse_lower(src)
        wat = emit_wat(ir_mod)
        self.assertIn("\"capa:host/clock\" \"allows\"", wat)


class TestWasmAttenuationEnforcement(unittest.TestCase):
    """Audit C2 + slice 25 (2026-05-30): privileged capability ops
    (Fs.read / Net.get / Db.exec / ...) on a receiver bound via a
    ``restrict_to`` / ``restrict_to_keys`` chain are enforced by
    the host handle table -- the receiver is an i32 handle the
    host looks up to consult the recorded restriction before each
    syscall. Pre-slice-25 the Wasm backend emitted an inline
    check before the host import; slice 25.9 removed that dead
    machinery once every cap had been routed through the handle
    table.

    These tests cover two layers:
    - WAT shape: the emit-time inline check is no longer present
      for privileged ops; the receiver handle flows as the first
      arg of the host import instead.
    - Runtime execution: the host returns Err for denied paths,
      Ok for allowed paths -- matching the Python runtime byte-
      for-byte. Cross-function attenuation (the previous gap that
      the inline check could not catch) is now sound on both
      backends.
    """

    def test_no_restrict_no_inline_check(self):
        # Unrestricted ``fs.read`` produces no inline-check
        # machinery. Pin via grep so a regression that re-
        # introduces an emit-time check is caught.
        src = (
            "fun main(stdio: Stdio, fs: Fs)\n"
            "    match fs.read(\"/etc/passwd\")\n"
            "        Ok(_) -> stdio.println(\"X\")\n"
            "        Err(_) -> stdio.println(\"Y\")\n"
        )
        ir_mod, _, _ = _parse_lower(src)
        wat = emit_wat(ir_mod)
        self.assertNotIn("$str_starts_with", wat)
        self.assertNotIn("$_atten_ok", wat)

    def test_fs_read_restricted_uses_handle_not_inline_check(self):
        # After slice 25.2, Fs.read carries the receiver handle as
        # its first arg and the host enforces the restriction via
        # the handle table. No inline ``$str_starts_with`` /
        # ``$_atten_*`` machinery is emitted for the privileged
        # op; the WAT just passes the handle and calls $Fs_read.
        src = (
            "fun main(stdio: Stdio, fs: Fs)\n"
            "    let tmp = fs.restrict_to(\"/tmp/\")\n"
            "    match tmp.read(\"/tmp/x\")\n"
            "        Ok(_) -> stdio.println(\"X\")\n"
            "        Err(_) -> stdio.println(\"Y\")\n"
        )
        ir_mod, _, _ = _parse_lower(src)
        wat = emit_wat(ir_mod)
        self.assertNotIn("$str_starts_with", wat)
        self.assertNotIn("$_atten_ok", wat)
        self.assertNotIn("$_atten_path_ptr", wat)
        self.assertIn("call $Fs_read", wat)
        self.assertIn("call $Fs_restrict_to", wat)

    @unittest.skipUnless(
        _has_wasm_tools() and _has_wasmtime_py(),
        "wasm-tools and/or wasmtime-py not installed",
    )
    def test_fs_read_inside_prefix_allowed(self):
        import io
        import os
        import sys
        import tempfile
        from capa.runtime._wasm_host import WasmHost
        with tempfile.TemporaryDirectory() as td:
            target = os.path.join(td, "ok.txt").replace("\\", "/")
            with open(target, "w", encoding="utf-8") as f:
                f.write("inside-prefix")
            # The Wasm attenuation check is a byte-level prefix
            # check (matches the str_starts_with Python contract).
            # Use the temp directory itself as the prefix so the
            # absolute path of ``target`` starts with it on both
            # platforms.
            prefix = td.replace("\\", "/") + "/"
            src = (
                "fun main(stdio: Stdio, fs: Fs)\n"
                f"    let scoped = fs.restrict_to(\"{prefix}\")\n"
                f"    match scoped.read(\"{target}\")\n"
                "        Ok(text) -> stdio.println(\"got: ${text}\")\n"
                "        Err(_) -> stdio.println(\"DENIED\")\n"
            )
            _, types, ast_mod = _parse_lower(src)
            blob = compile_wasm(ast_mod, types=types)
            host = WasmHost()
            out = io.StringIO()
            saved = sys.stdout
            sys.stdout = out
            try:
                host.run_main(blob)
            finally:
                sys.stdout = saved
            self.assertEqual(out.getvalue(), "got: inside-prefix\n")

    @unittest.skipUnless(
        _has_wasm_tools() and _has_wasmtime_py(),
        "wasm-tools and/or wasmtime-py not installed",
    )
    def test_fs_read_outside_prefix_denied(self):
        import io
        import sys
        from capa.runtime._wasm_host import WasmHost
        src = (
            "fun main(stdio: Stdio, fs: Fs)\n"
            "    let tmp = fs.restrict_to(\"/tmp/\")\n"
            "    match tmp.read(\"/etc/passwd\")\n"
            "        Ok(_) -> stdio.println(\"BUG: read succeeded\")\n"
            "        Err(_) -> stdio.println(\"denied\")\n"
        )
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types)
        host = WasmHost()
        out = io.StringIO()
        saved = sys.stdout
        sys.stdout = out
        try:
            host.run_main(blob)
        finally:
            sys.stdout = saved
        # The inline check fires; the host import is never invoked,
        # so the failure is hermetic (would still pass on a system
        # where /etc/passwd is present and readable).
        self.assertEqual(out.getvalue(), "denied\n")

    @unittest.skipUnless(
        _has_wasm_tools() and _has_wasmtime_py(),
        "wasm-tools and/or wasmtime-py not installed",
    )
    def test_fs_write_outside_prefix_denied(self):
        import io
        import sys
        import tempfile
        from capa.runtime._wasm_host import WasmHost
        with tempfile.TemporaryDirectory() as td:
            # Write target lies outside the restrict_to prefix.
            target = "/should/not/exist.txt"
            src = (
                "fun main(stdio: Stdio, fs: Fs)\n"
                f"    let scoped = fs.restrict_to(\"{td}/\".replace(\"\\\\\", \"/\"))\n"
                f"    match scoped.write(\"{target}\", \"x\")\n"
                "        Ok(_) -> stdio.println(\"BUG: wrote\")\n"
                "        Err(_) -> stdio.println(\"denied\")\n"
            )
            # Simpler shape: use a literal /usr/ prefix so /tmp/x
            # is denied. Avoids the f-string escaping nightmare.
            src = (
                "fun main(stdio: Stdio, fs: Fs)\n"
                "    let scoped = fs.restrict_to(\"/usr/\")\n"
                "    match scoped.write(\"/tmp/should-be-denied.txt\", \"x\")\n"
                "        Ok(_) -> stdio.println(\"BUG\")\n"
                "        Err(_) -> stdio.println(\"denied\")\n"
            )
            _, types, ast_mod = _parse_lower(src)
            blob = compile_wasm(ast_mod, types=types)
            host = WasmHost()
            out = io.StringIO()
            saved = sys.stdout
            sys.stdout = out
            try:
                host.run_main(blob)
            finally:
                sys.stdout = saved
            self.assertEqual(out.getvalue(), "denied\n")

    @unittest.skipUnless(
        _has_wasm_tools() and _has_wasmtime_py(),
        "wasm-tools and/or wasmtime-py not installed",
    )
    def test_fs_two_attenuations_both_apply(self):
        # ``fs.restrict_to("/tmp/").restrict_to("/tmp/myapp/")``:
        # the second restriction must AND with the first. A read on
        # ``/tmp/foo`` matches the first but NOT the second, so the
        # combined check denies.
        import io
        import sys
        from capa.runtime._wasm_host import WasmHost
        src = (
            "fun main(stdio: Stdio, fs: Fs)\n"
            "    let one = fs.restrict_to(\"/tmp/\")\n"
            "    let two = one.restrict_to(\"/tmp/myapp/\")\n"
            "    match two.read(\"/tmp/foo\")\n"
            "        Ok(_) -> stdio.println(\"BUG\")\n"
            "        Err(_) -> stdio.println(\"denied\")\n"
        )
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types)
        host = WasmHost()
        out = io.StringIO()
        saved = sys.stdout
        sys.stdout = out
        try:
            host.run_main(blob)
        finally:
            sys.stdout = saved
        self.assertEqual(out.getvalue(), "denied\n")

    def test_net_get_restricted_uses_handle_not_inline_check(self):
        # Slice 25.3 (2026-05-30): Net.get carries the receiver
        # handle as its first arg and the host enforces the
        # restriction via the handle table (using
        # ``urlparse(url).hostname`` rather than a substring
        # check, which closes the audit slice 25 F2 lookalike-URL
        # hazard). Verify no inline ``$str_contains`` machinery
        # is emitted.
        src = (
            "fun main(stdio: Stdio, net: Net)\n"
            "    let api = net.restrict_to(\"api.example.com\")\n"
            "    match api.get(\"https://api.example.com/health\")\n"
            "        Ok(_) -> stdio.println(\"ok\")\n"
            "        Err(_) -> stdio.println(\"err\")\n"
        )
        ir_mod, _, _ = _parse_lower(src)
        wat = emit_wat(ir_mod)
        self.assertNotIn("$str_contains", wat)
        self.assertNotIn("$_atten_ok", wat)
        self.assertIn("call $Net_get", wat)
        self.assertIn("call $Net_restrict_to", wat)

    @unittest.skipUnless(
        _has_wasm_tools() and _has_wasmtime_py(),
        "wasm-tools and/or wasmtime-py not installed",
    )
    def test_env_restrict_to_keys_outside_set_denied(self):
        import os
        import io
        import sys
        from capa.runtime._wasm_host import WasmHost
        src = (
            "fun main(stdio: Stdio, env: Env)\n"
            "    let limited = env.restrict_to_keys([\"HOME\"])\n"
            "    match limited.get(\"PATH\")\n"
            "        Some(_) -> stdio.println(\"BUG: leaked PATH\")\n"
            "        None -> stdio.println(\"hidden\")\n"
        )
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types)
        # Set PATH so the host would normally return Some; the
        # check must short-circuit to None on the Wasm side.
        os.environ.setdefault("PATH", "/usr/bin:/bin")
        host = WasmHost()
        out = io.StringIO()
        saved = sys.stdout
        sys.stdout = out
        try:
            host.run_main(blob)
        finally:
            sys.stdout = saved
        self.assertEqual(out.getvalue(), "hidden\n")

    @unittest.skipUnless(
        _has_wasm_tools() and _has_wasmtime_py(),
        "wasm-tools and/or wasmtime-py not installed",
    )
    def test_env_restrict_to_keys_allowed_passes(self):
        import os
        import io
        import sys
        from capa.runtime._wasm_host import WasmHost
        os.environ["CAPA_ATTEN_ALLOW_X"] = "allowed-value"
        try:
            src = (
                "fun main(stdio: Stdio, env: Env)\n"
                "    let limited = env.restrict_to_keys([\"CAPA_ATTEN_ALLOW_X\"])\n"
                "    match limited.get(\"CAPA_ATTEN_ALLOW_X\")\n"
                "        Some(v) -> stdio.println(\"got: ${v}\")\n"
                "        None -> stdio.println(\"BUG: missed\")\n"
            )
            _, types, ast_mod = _parse_lower(src)
            blob = compile_wasm(ast_mod, types=types)
            host = WasmHost()
            out = io.StringIO()
            saved = sys.stdout
            sys.stdout = out
            try:
                host.run_main(blob)
            finally:
                sys.stdout = saved
            self.assertEqual(out.getvalue(), "got: allowed-value\n")
        finally:
            os.environ.pop("CAPA_ATTEN_ALLOW_X", None)


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestWasmRandomExecutes(unittest.TestCase):
    """Slice 2 of the "Wasm backend fully functional" arc: Random
    capability lowering through the SplitMix64 helpers in
    ``capa.ir._emit_wasm._random``. Seeded sequences must be
    byte-identical with the Python ``Random`` runtime; unseeded
    sequences must at minimum stay inside the requested range.
    """

    def _run_capturing_stdout(self, src: str) -> str:
        import io
        import sys
        from capa.runtime._wasm_host import WasmHost
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types)
        host = WasmHost()
        out = io.StringIO()
        saved = sys.stdout
        sys.stdout = out
        try:
            host.run_main(blob)
        finally:
            sys.stdout = saved
        return out.getvalue()

    def test_seeded_int_range_matches_python_oracle(self):
        # SplitMix64 starting from state=42, drawing int_range(0, 100)
        # ten times in sequence. The Python runtime's
        # ``Random(42).int_range(0, 100)`` produces this exact
        # sequence (Lemire rejection sampling never rejects for any
        # of these draws within the first 10 calls, so the body of
        # the loop runs straight-through).
        src = (
            "fun main(stdio: Stdio, rng: Random)\n"
            "    let r = rng.with_seed(42)\n"
            "    var i = 0\n"
            "    while i < 10\n"
            "        stdio.println(\"${r.int_range(0, 100)}\")\n"
            "        i = i + 1\n"
        )
        out = self._run_capturing_stdout(src)
        expected = "\n".join(
            ["13", "91", "58", "64", "50", "62", "25", "8", "5", "74"]
        ) + "\n"
        self.assertEqual(out, expected)

    def test_seeded_int_range_signed_low(self):
        # Negative ``low`` is parsed as ``0 - 50`` in Capa source
        # (no unary-negative-literal support at the moment); pin that
        # the i64 subtraction passes through unchanged so the
        # signed-add path lands the correct values.
        src = (
            "fun main(stdio: Stdio, rng: Random)\n"
            "    let r = rng.with_seed(42)\n"
            "    stdio.println(\"${r.int_range(0 - 50, 50)}\")\n"
            "    stdio.println(\"${r.int_range(0 - 50, 50)}\")\n"
            "    stdio.println(\"${r.int_range(0 - 50, 50)}\")\n"
        )
        out = self._run_capturing_stdout(src)
        # Bound 100, same draws as the (0, 100) test: 13 - 50, 91 - 50,
        # 58 - 50. Equivalent to ``low + (rng % bound)`` where the rng
        # bytes match.
        self.assertEqual(out, "-37\n41\n8\n")

    def test_with_seed_overrides_unseeded(self):
        # An incoming Random (which lazy-inits state on first draw)
        # plus a subsequent ``with_seed(42)`` must land
        # deterministically on the seed=42 sequence. The init guard
        # the helpers flip after with_seed should prevent the
        # entropy path from clobbering the state. We trigger lazy
        # init by drawing a throwaway value before reseeding so the
        # init-then-reseed order is exercised, not just the
        # reseed-only order other tests cover.
        src = (
            "fun main(stdio: Stdio, rng: Random)\n"
            "    let _throwaway = rng.int_range(0, 100)\n"
            "    let s = rng.with_seed(42)\n"
            "    stdio.println(\"${s.int_range(0, 100)}\")\n"
        )
        out = self._run_capturing_stdout(src)
        self.assertEqual(out, "13\n")

    def test_unseeded_in_range(self):
        # Unseeded Random pulls entropy from the host
        # (``capa:host/random/system-seed``). We can't pin the
        # value, but we can assert the draw lands in the requested
        # half-open range.
        src = (
            "fun main(stdio: Stdio, rng: Random)\n"
            "    let n = rng.int_range(0, 100)\n"
            "    if n >= 0\n"
            "        if n < 100\n"
            "            stdio.println(\"ok\")\n"
        )
        out = self._run_capturing_stdout(src)
        self.assertEqual(out, "ok\n")

    def test_chained_with_seed_last_wins(self):
        # Per the Python runtime semantic
        # (``Random.with_seed(1).with_seed(2)`` is two fresh
        # instances; the second seed wins), the Wasm-side last-write
        # to ``$rand_state`` must produce the same draw as a single
        # ``with_seed(2)``.
        src = (
            "fun main(stdio: Stdio, rng: Random)\n"
            "    let s = rng.with_seed(1).with_seed(2)\n"
            "    stdio.println(\"${s.int_range(0, 100)}\")\n"
        )
        out = self._run_capturing_stdout(src)
        # Recompute via the Python oracle so any future PRNG tweak
        # surfaces here too.
        from capa.runtime._capabilities import Random as _PyRandom
        expected = f"{_PyRandom(2).int_range(0, 100)}\n"
        self.assertEqual(out, expected)


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestWasmNetExecutes(unittest.TestCase):
    """Slice 3 of the "Wasm backend fully functional" arc: ``Net.get``
    end-to-end through the ``capa:host/net`` interface. The host
    bridge mirrors ``capa.runtime._capabilities.Net.get`` exactly
    (``urllib.request.urlopen`` + ``decode("utf-8", errors="replace")``);
    these tests pin the round-trip on hermetic ``file://`` URLs so
    the suite never hits a network.
    """

    def _run_capturing_stdout(self, src: str) -> str:
        import io
        import sys
        from capa.runtime._wasm_host import WasmHost
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types)
        host = WasmHost()
        out = io.StringIO()
        saved = sys.stdout
        sys.stdout = out
        try:
            host.run_main(blob)
        finally:
            sys.stdout = saved
        return out.getvalue()

    def test_net_get_round_trip(self):
        # Hermetic round-trip over a 127.0.0.1 server (no external
        # network). Both backends call ``Net.get`` against the same
        # bytes; the Wasm host's ``errors="replace"`` UTF-8 decode
        # path agrees with the Python runtime's. The fixture is
        # served rather than written to disk so the assertion
        # isolates the Net path from the Fs path.
        #
        # This used to fetch a ``file://`` URL, which was hermetic but
        # asked ``Net`` to reach urllib's FileHandler: a capability whose
        # API is HTTP GET / POST reading the local filesystem. ``Net``
        # now bounds the scheme to http / https.
        import http.server
        import threading
        payload = b"body bytes from a fixture"

        class BodyHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args, **kwargs):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), BodyHandler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            src = (
                "fun main(stdio: Stdio, net: Net)\n"
                f"    match net.get(\"http://127.0.0.1:{port}/body\")\n"
                "        Ok(text) -> stdio.println(\"got: ${text}\")\n"
                "        Err(_) -> stdio.eprintln(\"BUG: read failed\")\n"
            )
            out = self._run_capturing_stdout(src)
            self.assertEqual(out, "got: body bytes from a fixture\n")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_net_get_restrict_denies_outside_host(self):
        # Inline attenuation check (audit C2): a Net cap scoped to a
        # host string that the URL does not contain must short-
        # circuit to Err without ever calling the host bridge. The
        # restriction host (``unreachable.invalid``) names a URL no
        # real DNS resolves, so even if the check accidentally fell
        # through, a 10-second timeout would surface here as a test
        # hang -- the assertion below catches the silent-pass case.
        src = (
            "fun main(stdio: Stdio, net: Net)\n"
            "    let scoped = net.restrict_to(\"only.allowed.invalid\")\n"
            "    match scoped.get(\"https://api.example.com/path\")\n"
            "        Ok(_) -> stdio.println(\"BUG: leaked\")\n"
            "        Err(_) -> stdio.println(\"denied\")\n"
        )
        out = self._run_capturing_stdout(src)
        self.assertEqual(out, "denied\n")

    def test_net_post_round_trip_against_loopback(self):
        # Hermetic POST round-trip: spin up an in-process http.server
        # whose handler echoes the request body verbatim, then have
        # the Capa program POST a known body and assert the response
        # equals it. Validates the body-bytes path end-to-end (Wasm
        # bridge reads the body bytes from linear memory, builds the
        # urllib Request, the loopback server echoes them back, the
        # Ok arm carries the response into the program). Bound to
        # 127.0.0.1 on an ephemeral port so it never collides with
        # CI workers.
        import http.server
        import threading

        body_text = "hello-post-body"

        class EchoHandler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                payload = self.rfile.read(length)
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args, **kwargs):
                # Silence the default access log so the test output
                # stays scoped to the assertion.
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), EchoHandler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{port}/echo"
            src = (
                "fun main(stdio: Stdio, net: Net)\n"
                f"    match net.post(\"{url}\", \"{body_text}\")\n"
                "        Ok(text) -> stdio.println(\"echo: ${text}\")\n"
                "        Err(_) -> stdio.eprintln(\"BUG: post failed\")\n"
            )
            out = self._run_capturing_stdout(src)
            self.assertEqual(out, f"echo: {body_text}\n")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
