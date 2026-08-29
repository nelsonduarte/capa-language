"""WebAssembly backend: the component host and the capa manifest custom
section.

Part of the tests/ir_wasm package; see tests/ir_wasm/__init__.py for
the growth convention. The shared _parse_lower / skip gates live in
tests/ir_wasm/_helpers.py.
"""

from __future__ import annotations

import unittest

from tests.ir_wasm._helpers import _parse_lower, _has_wasm_tools, _has_wasmtime_py
from capa.ir import compile_wasm, compile_wit


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestWasmComponentHost(unittest.TestCase):
    """End-to-end coverage for the Component Model runtime host
    (``capa.runtime._wasm_component_host``). The CLI's
    ``--wasm --component --run`` path wraps a core module in a
    CM component via ``wasm-tools component embed/new`` and
    dispatches through ``WasmComponentHost`` (which speaks lifted
    WIT values instead of raw pointers). These tests exercise
    that runtime directly.

    Coverage motivation: before this class landed,
    ``_wasm_component_host.py`` had 0% test coverage; the only
    real user was the CLI path, never invoked from the test
    suite. Adding even one end-to-end run lifts the file to ~70%
    and catches any future regression that breaks the CM
    runtime."""

    def _wrap_as_component(self, core_blob: bytes, wit_text: str) -> bytes:
        """Re-export of capa.cli._wrap_as_component. Couples this
        test file to the CLI's private helper; acceptable because
        the shape (core wasm + WIT text -> CM component bytes) is
        the only contract that matters and is stable across
        wasm-tools versions."""
        from capa.cli import _wrap_as_component
        return _wrap_as_component(core_blob, wit_text)

    def _run_capturing_stdout(self, src: str, args=()) -> str:
        import io
        import sys
        from capa.runtime._wasm_component_host import WasmComponentHost
        _, types, ast_mod = _parse_lower(src)
        core_blob = compile_wasm(ast_mod, types=types)
        wit = compile_wit(ast_mod, types=types)
        component_blob = self._wrap_as_component(core_blob, wit)
        host = WasmComponentHost(args=list(args))
        out = io.StringIO()
        saved_out = sys.stdout
        sys.stdout = out
        try:
            host.run_main(component_blob)
        finally:
            sys.stdout = saved_out
        return out.getvalue()

    def test_hello_under_component_host(self):
        src = (
            'fun main(stdio: Stdio)\n'
            '    stdio.println("hello from component")\n'
        )
        self.assertEqual(
            self._run_capturing_stdout(src),
            "hello from component\n",
        )

    def test_stdio_with_string_interpolation(self):
        src = (
            'fun main(stdio: Stdio)\n'
            '    let name = "capa"\n'
            '    stdio.println("hi ${name}")\n'
        )
        self.assertEqual(
            self._run_capturing_stdout(src), "hi capa\n",
        )

    def test_env_args_round_trip(self):
        # Component-host argv lifting: Env.args() should return
        # the list passed at construction time, length-and-order
        # preserved. The print-each-arg pattern catches both
        # truncation and reordering bugs.
        src = (
            'fun main(stdio: Stdio, env: Env)\n'
            '    for a in env.args()\n'
            '        stdio.println(a)\n'
        )
        out = self._run_capturing_stdout(src, args=["alpha", "beta", "gamma"])
        self.assertEqual(out, "alpha\nbeta\ngamma\n")

    def test_clock_now_secs_returns_positive_float(self):
        # Component-host Clock bridge. Exact value depends on
        # wall-clock so we only assert shape + sign.
        src = (
            'fun main(stdio: Stdio, clock: Clock)\n'
            '    let t = clock.now_secs()\n'
            '    if t > 0.0\n'
            '        stdio.println("positive")\n'
            '    else\n'
            '        stdio.println("non-positive")\n'
        )
        self.assertEqual(
            self._run_capturing_stdout(src), "positive\n",
        )

    def test_net_get_under_component_host(self):
        # Slice 3: ``Net.get`` through the Component Model bridge.
        # Same hermetic loopback round-trip as the core-host test;
        # the component host lifts result<string, io-error> via
        # Python type dispatch (str -> Ok, IoErrorRecord -> Err)
        # and must agree on the Ok-arm bytes.
        #
        # This used to fetch a ``file://`` URL, which was hermetic but
        # asked ``Net`` to reach urllib's FileHandler: a capability whose
        # API is HTTP GET / POST reading the local filesystem. ``Net``
        # now bounds the scheme to http / https, so the fixture is served
        # over 127.0.0.1 instead -- equally hermetic, no external
        # network.
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
            self.assertEqual(
                self._run_capturing_stdout(src),
                "got: body bytes from a fixture\n",
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_net_post_under_component_host(self):
        # Slice 8 (2026-05): ``Net.post`` parallels ``Net.get`` on
        # the Component Model side. Same hermetic loopback fixture
        # as the core-host happy-path test in TestWasmNetExecutes;
        # the component host's ``post`` callback lifts
        # ``Result<String, IoError>`` via the same Python type
        # dispatch (``str`` -> Ok, ``IoErrorRecord`` -> Err).
        import http.server
        import threading
        body_text = "post-body-cm"

        class EchoHandler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                payload = self.rfile.read(length)
                self.send_response(200)
                self.send_header(
                    "Content-Type", "application/octet-stream",
                )
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args, **kwargs):
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
            self.assertEqual(
                self._run_capturing_stdout(src),
                f"echo: {body_text}\n",
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_fs_round_trip_under_component_host(self):
        # Slice 1 (2026-05): ``Fs.read`` / ``Fs.write`` /
        # ``Fs.exists`` through the Component Model bridge. Writes
        # a fixture, reads it back, then asks ``exists`` to confirm.
        # The two result<...> arms exercise both Ok and Err code
        # paths on a single program.
        import os
        import tempfile
        fd, path = tempfile.mkstemp(suffix=".txt")
        os.close(fd)
        os.unlink(path)
        # Escape backslashes in the path for the source-level
        # double-quoted string literal (Windows tempdir).
        escaped = path.replace("\\", "\\\\")
        try:
            src = (
                "fun main(stdio: Stdio, fs: Fs)\n"
                f"    match fs.write(\"{escaped}\", \"hello-cm\")\n"
                "        Ok(_) -> stdio.println(\"wrote\")\n"
                "        Err(_) -> stdio.eprintln(\"BUG: write failed\")\n"
                f"    match fs.read(\"{escaped}\")\n"
                "        Ok(text) -> stdio.println(\"read: ${text}\")\n"
                "        Err(_) -> stdio.eprintln(\"BUG: read failed\")\n"
                f"    if fs.exists(\"{escaped}\")\n"
                "        stdio.println(\"exists: yes\")\n"
                "    else\n"
                "        stdio.println(\"exists: no\")\n"
            )
            self.assertEqual(
                self._run_capturing_stdout(src),
                "wrote\nread: hello-cm\nexists: yes\n",
            )
        finally:
            if os.path.exists(path):
                os.unlink(path)

    def test_env_get_under_component_host(self):
        # Slice 1 surface continued: ``Env.get`` returns
        # ``Option<String>``. The component host lifts the Python
        # ``str | None`` directly to ``Some(...)`` / ``None``. We
        # set an env var explicitly so the value is deterministic
        # across CI runs.
        import os
        os.environ["CAPA_CM_FIXTURE"] = "hello"
        try:
            src = (
                "fun main(stdio: Stdio, env: Env)\n"
                "    match env.get(\"CAPA_CM_FIXTURE\")\n"
                "        Some(v) -> stdio.println(\"got: ${v}\")\n"
                "        None -> stdio.println(\"missing\")\n"
                "    match env.get(\"CAPA_CM_DEFINITELY_UNSET_XYZ\")\n"
                "        Some(_) -> stdio.eprintln(\"BUG: leaked\")\n"
                "        None -> stdio.println(\"missing: ok\")\n"
            )
            self.assertEqual(
                self._run_capturing_stdout(src),
                "got: hello\nmissing: ok\n",
            )
        finally:
            os.environ.pop("CAPA_CM_FIXTURE", None)

    def test_fs_mkdir_and_list_dir_under_component_host(self):
        # Slice 1 host bridges: ``Fs.mkdir`` returns
        # ``Result<Unit, IoError>`` (a result with an empty Ok
        # arm); ``Fs.list_dir`` returns ``Result<List<String>,
        # IoError>``. Both exercise canonical-ABI return shapes
        # with custom-record + list-of-string lift paths that
        # nothing else in the CM test suite hits.
        import os
        import tempfile
        base = tempfile.mkdtemp(prefix="capa_cm_listdir_")
        with open(os.path.join(base, "a.txt"), "w") as f:
            f.write("a")
        with open(os.path.join(base, "b.txt"), "w") as f:
            f.write("b")
        target = os.path.join(base, "newdir")
        base_lit = base.replace("\\", "\\\\")
        target_lit = target.replace("\\", "\\\\")
        try:
            src = (
                "fun main(stdio: Stdio, fs: Fs)\n"
                f"    match fs.mkdir(\"{target_lit}\")\n"
                "        Ok(_) -> stdio.println(\"made dir\")\n"
                "        Err(_) -> stdio.eprintln(\"BUG: mkdir failed\")\n"
                f"    match fs.list_dir(\"{base_lit}\")\n"
                "        Ok(names) -> stdio.println(\"count: ${names.length()}\")\n"
                "        Err(_) -> stdio.eprintln(\"BUG: list_dir failed\")\n"
            )
            # Three entries: a.txt, b.txt, newdir. Order is OS-
            # dependent so we only assert the count; that's
            # enough to validate the list<string> lift path
            # produced a length-3 list rather than 0 or trash.
            self.assertEqual(
                self._run_capturing_stdout(src),
                "made dir\ncount: 3\n",
            )
        finally:
            import shutil
            shutil.rmtree(base, ignore_errors=True)

    def test_stdio_read_line_eof_under_component_host(self):
        # Slice 1 host bridge: ``Stdio.read_line`` returns
        # ``Result<String, IoError>``; on EOF the bridge produces
        # Err with a known message. Validates both that the
        # bridge is wired into the CM linker and that the Err
        # arm's IoError record lifts through correctly.
        import io
        import sys
        saved_in = sys.stdin
        sys.stdin = io.StringIO("")
        try:
            src = (
                "fun main(stdio: Stdio)\n"
                "    match stdio.read_line()\n"
                "        Ok(line) -> stdio.println(\"got: ${line}\")\n"
                "        Err(_) -> stdio.println(\"eof\")\n"
            )
            self.assertEqual(
                self._run_capturing_stdout(src),
                "eof\n",
            )
        finally:
            sys.stdin = saved_in

    def test_random_seeded_sequence_under_component_host(self):
        # Slice 2: the ``Random`` capability uses a pure-WAT
        # SplitMix64 PRNG that runs entirely guest-side; the only
        # host call is ``random.system-seed`` for entropy when
        # the program constructs a fresh ``Random()`` without a
        # seed. With ``Random.with_seed(seed)`` the host bridge
        # never fires, so the sequence is byte-identical across
        # backends. This test pins that property under the CM
        # path to catch any future regression in either the
        # PRNG lowering or the CM wiring.
        src = (
            "fun main(stdio: Stdio, r: Random)\n"
            "    let rng = r.with_seed(42)\n"
            "    let a = rng.int_range(0, 1000)\n"
            "    let b = rng.int_range(0, 1000)\n"
            "    let c = rng.int_range(0, 1000)\n"
            "    stdio.println(\"a=${a} b=${b} c=${c}\")\n"
        )
        out_cm = self._run_capturing_stdout(src)
        # Cross-check: the core host produces the same line. Any
        # divergence means either the PRNG lowering or the CM
        # wiring of ``random.system-seed`` diverged from the
        # core path; the body lives in linear memory in either
        # case and shouldn't care which host wraps it.
        from capa.runtime._wasm_host import WasmHost
        import io
        import sys
        _, types, ast_mod = _parse_lower(src)
        core_blob = compile_wasm(ast_mod, types=types)
        host = WasmHost()
        core_out = io.StringIO()
        saved = sys.stdout
        sys.stdout = core_out
        try:
            host.run_main(core_blob)
        finally:
            sys.stdout = saved
        self.assertEqual(out_cm, core_out.getvalue())

    def _core_stdout(self, src: str, args=()) -> str:
        # Run the same program under the NON-component core host so a
        # test can assert 3-backend parity (Python is covered by the
        # transpiler tests; here we pin core-wasm == component). The
        # component host discards ``main``'s return value exactly like
        # the core host, so a successful run (no exception) IS the
        # exit-0 assertion for both.
        from capa.runtime._wasm_host import WasmHost
        import io
        import sys
        _, types, ast_mod = _parse_lower(src)
        core_blob = compile_wasm(ast_mod, types=types)
        host = WasmHost(args=list(args))
        buf = io.StringIO()
        saved = sys.stdout
        sys.stdout = buf
        try:
            host.run_main(core_blob)
        finally:
            sys.stdout = saved
        return buf.getvalue()

    def test_main_returning_int_runs_and_discards_value(self):
        # Regression for the component-backend ``main -> Int`` bug:
        # the WIT world now advertises ``-> s64`` so ``component new``
        # accepts the core module's ``(result i64)`` main. The return
        # value is discarded (exit 0), same stdout as the core host.
        src = (
            "fun main(stdio: Stdio) -> Int\n"
            "    stdio.println(\"int-ret\")\n"
            "    return 42\n"
        )
        self.assertEqual(self._run_capturing_stdout(src), "int-ret\n")
        self.assertEqual(
            self._run_capturing_stdout(src), self._core_stdout(src),
        )

    def test_main_returning_float_runs_and_discards_value(self):
        src = (
            "fun main(stdio: Stdio) -> Float\n"
            "    stdio.println(\"float-ret\")\n"
            "    return 3.5\n"
        )
        self.assertEqual(self._run_capturing_stdout(src), "float-ret\n")
        self.assertEqual(
            self._run_capturing_stdout(src), self._core_stdout(src),
        )

    def test_main_returning_bool_runs_and_discards_value(self):
        src = (
            "fun main(stdio: Stdio) -> Bool\n"
            "    stdio.println(\"bool-ret\")\n"
            "    return true\n"
        )
        self.assertEqual(self._run_capturing_stdout(src), "bool-ret\n")
        self.assertEqual(
            self._run_capturing_stdout(src), self._core_stdout(src),
        )

    def test_main_returning_int_with_handle_param_runs(self):
        # A ``main`` that BOTH takes a cap-handle param (Fs) AND
        # returns a scalar: the world export is
        # ``func(fs: u32) -> s64``. Exercises the result clause sitting
        # after the handle param list end-to-end through the CM host.
        src = (
            "fun main(stdio: Stdio, fs: Fs) -> Int\n"
            "    let _e = fs.exists(\"/nope\")\n"
            "    stdio.println(\"handle-int-ret\")\n"
            "    return 9\n"
        )
        self.assertEqual(
            self._run_capturing_stdout(src), "handle-int-ret\n",
        )


@unittest.skipUnless(
    _has_wasm_tools(),
    "wasm-tools not installed",
)
class TestWasmCapaManifestCustomSection(unittest.TestCase):
    """Audit fix M4 (2026-05): per-function capability manifest
    embedded in a Wasm custom section named ``capa-manifest`` so the
    discipline travels with the artefact. Runtimes ignore custom
    sections by definition; ``wasm-tools dump`` and the helper
    ``capa.ir.read_wasm_manifest`` surface them."""

    def test_manifest_section_present_and_parses(self):
        from capa.ir import compile_wasm, read_wasm_manifest
        src = (
            'fun helper() -> Int\n'
            '    return 42\n'
            'fun main(stdio: Stdio)\n'
            '    stdio.println("${helper()}")\n'
        )
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types, filename='m4_test.capa')
        manifest = read_wasm_manifest(blob)
        self.assertIsNotNone(manifest)
        self.assertEqual(manifest["capa_manifest_version"], 1)
        self.assertIn("capa_version", manifest)
        names = {f["name"]: f["declared_capabilities"]
                 for f in manifest["functions"]}
        # ``main`` declares ``Stdio`` via its capability param;
        # ``helper`` declares nothing.
        self.assertIn("main", names)
        self.assertEqual(names["main"], ["Stdio"])
        self.assertIn("helper", names)
        self.assertEqual(names["helper"], [])

    def test_manifest_off_via_embed_manifest_false(self):
        # Tests / regression scenarios where the extra custom section
        # would noisily change byte-level snapshots can pass
        # ``embed_manifest=False`` to suppress it.
        from capa.ir import compile_wasm, read_wasm_manifest
        src = (
            'fun main(stdio: Stdio)\n'
            '    stdio.println("hi")\n'
        )
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types, embed_manifest=False)
        self.assertIsNone(read_wasm_manifest(blob))

    @unittest.skipUnless(
        _has_wasmtime_py(),
        "wasmtime-py not installed",
    )
    def test_manifest_does_not_break_wasmtime_load(self):
        # Custom sections are by definition ignored by runtimes; verify
        # the resulting binary still loads + runs cleanly. The check
        # would catch a future regression where the emitter put the
        # ``(@custom ...)`` in a position wasm-tools accepts but a
        # runtime rejects.
        import io
        import sys
        from capa.ir import compile_wasm
        from capa.runtime._wasm_host import WasmHost
        src = (
            'fun main(stdio: Stdio)\n'
            '    stdio.println("manifest-ok")\n'
        )
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types)
        host = WasmHost()
        buf = io.StringIO()
        saved = sys.stdout
        sys.stdout = buf
        try:
            host.run_main(blob)
        finally:
            sys.stdout = saved
        self.assertEqual(buf.getvalue(), "manifest-ok\n")
