"""WASI mode: the Net capability (wasi:http).

Dynamic-url rejections, the end-to-end get / post over wasi:http with the Net
host ceiling, get / post ceilings, WIT generation + rejections, attenuation, and
the redirect fail-closed (anti-SSRF) behaviour. The loopback HTTP servers
(_LocalHttpServer / _LocalPostServer / _LocalRedirectServer) are net-local test
fixtures. Split out of tests/test_wasi_mode.py; see tests/wasi/__init__.py for
the growth convention. The shared primitives live in tests/wasi/_helpers.py.
"""

from __future__ import annotations

import io
import sys
import unittest

from tests.wasi._helpers import (
    _REPO_ROOT,
    _has_wasm_tools,
    _has_wasmtime_wasip2,
    _parse_analyze,
    _run_python,
    _wasi_run_capture,
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
            _REPO_ROOT
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


if __name__ == "__main__":
    unittest.main()
