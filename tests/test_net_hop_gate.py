"""Tests for the per-hop gate and the two bounds on ``Net.get`` /
``Net.post`` (2026-07).

Three defects lived in those two functions, all measured before the fix:

- REDIRECT BYPASS. ``urllib`` follows redirects transparently and the
  host gate only ever saw the URL the program wrote, so a permitted host
  answering ``302 Location: http://forbidden/`` reached the forbidden
  host with no check at all. A program restricted to ``127.0.0.1``
  printed ``allows(localhost)=false`` and served the body of a
  ``localhost`` server on the next line, while ``--manifest`` recorded
  only ``restrict_to("127.0.0.1")``. That made ``restrict_to`` -- the
  attenuation primitive documented as only ever narrowing -- false.
- SCHEME ESCALATION. urllib's redirect handler admits ``ftp:`` targets
  and its default opener carries ``FTPHandler`` / ``FileHandler`` /
  ``DataHandler``. Measured: a ``302 Location: ftp://127.0.0.1:<port>/x``
  DID open a control connection to a raw TCP listener, i.e. a ``Net``
  capability reached a protocol its API does not offer.
- UNBOUNDED TIME AND SIZE. ``urlopen(..., timeout=10)`` is a
  per-socket-operation timeout, so a server emitting one byte every few
  seconds keeps the call alive forever; and the response body had no
  default ceiling, so the remote endpoint dictated host allocation.

Every assertion here is on what the SERVER observed (which requests
actually arrived, whether a socket was accepted) and not only on what
the program returned: the point of the fix is that the forbidden peer is
never contacted, which a return value alone cannot show.

Every server started here is stopped by the test itself, including on
failure (the ``_Server`` / ``_RawListener`` context managers close in
``__exit__``), so no listener outlives the run. Nothing binds anything
but 127.0.0.1 and no external network is touched.

The capa:host parity class imports wasm tooling INSIDE its methods and is
gated with ``skipUnless``, so this module always collects under
``python -m unittest discover`` on a runner without the ``wasm`` extra.
"""

import io
import shutil
import socket
import sys
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

from capa import Lexer, Parser, analyze, transpile
from capa.runtime import _capabilities
from capa.runtime._capabilities import IoError, Net, ResultCapExceeded


def _has_component_tooling() -> bool:
    if shutil.which("wasm-tools") is None:
        return False
    try:
        import wasmtime
        import wasmtime.component as wc  # noqa: F401
    except ImportError:
        return False
    return hasattr(wc.Linker(wasmtime.Engine()), "add_wasip2")


class _Server:
    """A loopback HTTP server built from a per-request callback.

    ``handle(request)`` receives the ``BaseHTTPRequestHandler`` and writes
    the response. Every path that arrives is appended to ``self.seen``, so
    a test can assert on the SERVER's own observation of who contacted it.
    """

    def __init__(self, handle):
        self.seen: list[str] = []
        seen = self.seen

        class _H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def do_GET(self):
                seen.append(self.path)
                handle(self)

            def do_POST(self):
                seen.append(self.path)
                length = int(self.headers.get("Content-Length", 0))
                if length:
                    self.rfile.read(length)
                handle(self)

            def log_message(self, *a):
                pass

        self._srv = ThreadingHTTPServer(("127.0.0.1", 0), _H)
        self.port = self._srv.server_address[1]
        self.authority = f"127.0.0.1:{self.port}"

    def __enter__(self):
        self._thread = threading.Thread(
            target=self._srv.serve_forever, daemon=True,
        )
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._srv.shutdown()
        self._srv.server_close()
        self._thread.join(timeout=5.0)


class _RawListener:
    """A raw loopback TCP listener standing in for a non-HTTP service.

    Records whether ANY connection was accepted (``self.accepted``), which
    is how the cross-scheme test proves the ftp:// redirect target was
    never spoken to rather than merely that the call returned an error."""

    def __init__(self):
        self.accepted = False
        self._sock = socket.socket()
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(1)
        self._sock.settimeout(5.0)
        self.port = self._sock.getsockname()[1]

    def __enter__(self):
        def _accept():
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            self.accepted = True
            try:
                conn.sendall(b"220 service ready\r\n")
            except OSError:
                pass
            conn.close()

        self._thread = threading.Thread(target=_accept, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._sock.close()
        self._thread.join(timeout=5.0)


def _redirect_to(target: str, status: int = 302):
    def handle(h):
        h.send_response(status)
        h.send_header("Location", target)
        h.send_header("Content-Length", "0")
        h.end_headers()
    return handle


def _body(text: str):
    payload = text.encode("utf-8")

    def handle(h):
        h.send_response(200)
        h.send_header("Content-Length", str(len(payload)))
        h.end_headers()
        h.wfile.write(payload)
    return handle


# ---- the redirect host gate ------------------------------------------


class TestRedirectHostGate(unittest.TestCase):
    """A redirect hop is followed only when the SAME capability permits
    its host; otherwise the hop is refused and the forbidden host is
    never contacted."""

    def _assert_never_contacted(self, victim, result):
        self.assertEqual(
            victim.seen, [],
            "the forbidden host was contacted despite the restriction",
        )
        self.assertIsInstance(result.error, IoError)
        self.assertIn("does not permit access to host", result.error.message)

    def test_get_redirect_to_forbidden_host_is_refused(self):
        with _Server(_body("BODY-FROM-FORBIDDEN-HOST")) as victim:
            target = f"http://localhost:{victim.port}/PWNED"
            with _Server(_redirect_to(target)) as hop:
                net = Net().restrict_to("127.0.0.1")
                self.assertFalse(net.allows("localhost"))
                result = net.get(f"http://{hop.authority}/start")
                self.assertEqual(hop.seen, ["/start"])
            self._assert_never_contacted(victim, result)
        self.assertIn("localhost", result.error.message)

    def test_post_redirect_to_forbidden_host_is_refused(self):
        with _Server(_body("BODY-FROM-FORBIDDEN-HOST")) as victim:
            # 303 turns a POST into a GET on the target, which is the
            # shape urllib will actually follow for a POST.
            target = f"http://localhost:{victim.port}/PWNED"
            with _Server(_redirect_to(target, status=303)) as hop:
                net = Net().restrict_to("127.0.0.1")
                result = net.post(f"http://{hop.authority}/start", "payload")
            self._assert_never_contacted(victim, result)

    def test_redirect_chain_is_gated_on_every_hop(self):
        # The FIRST hop is permitted, the SECOND is not: the gate must run
        # per hop, not only once.
        with _Server(_body("BODY-FROM-FORBIDDEN-HOST")) as victim:
            with _Server(_redirect_to(
                    f"http://localhost:{victim.port}/PWNED")) as second:
                with _Server(_redirect_to(
                        f"http://127.0.0.1:{second.port}/two")) as first:
                    net = Net().restrict_to("127.0.0.1")
                    result = net.get(f"http://{first.authority}/one")
                    self.assertEqual(first.seen, ["/one"])
                    self.assertEqual(second.seen, ["/two"])
            self._assert_never_contacted(victim, result)

    def test_redirect_to_permitted_host_still_works(self):
        # The fix must NOT be "never follow redirects": a permitted host
        # is permitted, and ordinary redirects have to keep working.
        with _Server(_body("FINAL-BODY")) as final:
            with _Server(_redirect_to(
                    f"http://127.0.0.1:{final.port}/final")) as hop:
                net = Net().restrict_to("127.0.0.1")
                result = net.get(f"http://{hop.authority}/start")
            self.assertEqual(final.seen, ["/final"])
        self.assertEqual(result.value, "FINAL-BODY")

    def test_unrestricted_net_follows_any_host(self):
        # An unrestricted cap permits every host, so every hop is
        # permitted: the gate narrows nothing it was not asked to narrow.
        with _Server(_body("FINAL-BODY")) as final:
            with _Server(_redirect_to(
                    f"http://localhost:{final.port}/final")) as hop:
                result = Net().get(f"http://{hop.authority}/start")
            self.assertEqual(final.seen, ["/final"])
        self.assertEqual(result.value, "FINAL-BODY")

    def test_post_redirect_to_permitted_host_still_works(self):
        with _Server(_body("FINAL-BODY")) as final:
            with _Server(_redirect_to(
                    f"http://127.0.0.1:{final.port}/final",
                    status=303)) as hop:
                net = Net().restrict_to("127.0.0.1")
                result = net.post(f"http://{hop.authority}/start", "payload")
            self.assertEqual(final.seen, ["/final"])
        self.assertEqual(result.value, "FINAL-BODY")


# ---- the scheme bound -------------------------------------------------


class TestSchemeBound(unittest.TestCase):
    """A ``Net`` capability speaks http / https and nothing else, on the
    first request and on every hop."""

    def test_cross_scheme_redirect_is_refused(self):
        # MEASURED before the fix: urllib's redirect handler admits ftp:
        # targets and its default opener carries an FTPHandler, so this
        # listener DID accept a connection.
        with _RawListener() as ftp:
            with _Server(_redirect_to(
                    f"ftp://127.0.0.1:{ftp.port}/x")) as hop:
                net = Net().restrict_to("127.0.0.1")
                result = net.get(f"http://{hop.authority}/start")
            self.assertFalse(
                ftp.accepted,
                "the ftp redirect target was contacted: a Net capability "
                "escalated across protocols",
            )
        self.assertIn("redirect to scheme 'ftp'", result.error.message)

    def test_cross_scheme_redirect_refused_even_for_permitted_host(self):
        # The ftp target's HOST is permitted here, so only the scheme
        # bound can refuse it.
        with _RawListener() as ftp:
            with _Server(_redirect_to(
                    f"ftp://127.0.0.1:{ftp.port}/x")) as hop:
                net = Net().restrict_to("127.0.0.1")
                self.assertTrue(net.allows("127.0.0.1"))
                result = net.get(f"http://{hop.authority}/start")
            self.assertFalse(ftp.accepted)
        self.assertIn("does not permit a redirect to scheme", result.error.message)

    def test_non_http_url_is_refused_up_front(self):
        # An unrestricted Net permits every host, and a file: URL has no
        # host at all, so only the scheme bound stands between the
        # capability and urllib's FileHandler.
        for url in ("file:///etc/passwd", "ftp://127.0.0.1/x", "data:,hi"):
            with self.subTest(url=url):
                result = Net().get(url)
                self.assertIn(
                    "does not permit scheme", result.error.message,
                )

    def test_post_non_http_url_is_refused_up_front(self):
        result = Net().post("file:///etc/passwd", "payload")
        self.assertIn("does not permit scheme", result.error.message)


# ---- the wall-clock bound ---------------------------------------------


class TestWallClockBound(unittest.TestCase):
    """The documented bound is on the WHOLE request, not per socket
    operation. A dribbling server used to hold the call open forever."""

    def _dribble(self, total: int, gap: float):
        def handle(h):
            h.send_response(200)
            h.send_header("Content-Length", str(total))
            h.end_headers()
            for _ in range(total):
                try:
                    h.wfile.write(b"x")
                    h.wfile.flush()
                except OSError:
                    return
                time.sleep(gap)
        return handle

    def test_slow_body_is_abandoned_at_the_deadline(self):
        # 40 bytes at one every 0.3s is 12s of body, well past the 1s
        # budget this test installs. Bounded on BOTH sides so a failing
        # run cannot hang: the server stops dribbling after 40 bytes.
        with mock.patch.object(_capabilities, "_NET_TIMEOUT_SECS", 1.0):
            with _Server(self._dribble(40, 0.3)) as slow:
                started = time.monotonic()
                result = Net().get(f"http://{slow.authority}/slow")
                elapsed = time.monotonic() - started
        self.assertIsInstance(result.error, IoError)
        self.assertIn("timed out", result.error.message)
        self.assertLess(
            elapsed, 6.0,
            f"the call ran {elapsed:.1f}s against a 1s wall-clock bound",
        )

    def test_fast_body_is_unaffected(self):
        with mock.patch.object(_capabilities, "_NET_TIMEOUT_SECS", 5.0):
            with _Server(_body("QUICK")) as srv:
                result = Net().get(f"http://{srv.authority}/fast")
        self.assertEqual(result.value, "QUICK")


# ---- the response-size bound ------------------------------------------


class TestResponseSizeBound(unittest.TestCase):
    """A response body has a default ceiling a caller can raise, and
    exceeding it is a typed error rather than a crash or an unbounded
    allocation."""

    def test_body_under_the_default_is_returned_whole(self):
        with mock.patch.object(_capabilities, "_NET_DEFAULT_MAX_BYTES", 4096):
            with _Server(_body("a" * 4096)) as srv:
                result = Net().get(f"http://{srv.authority}/body")
        self.assertEqual(len(result.value), 4096)

    def test_body_over_the_default_is_an_err(self):
        with mock.patch.object(_capabilities, "_NET_DEFAULT_MAX_BYTES", 4096):
            with _Server(_body("a" * 4097)) as srv:
                result = Net().get(f"http://{srv.authority}/body")
                post_result = Net().post(
                    f"http://{srv.authority}/body", "payload",
                )
        for r in (result, post_result):
            self.assertIsInstance(r.error, IoError)
            self.assertIn("result cap", r.error.cause)
            self.assertIn("max_bytes", r.error.cause)

    def test_caller_can_raise_the_default(self):
        with mock.patch.object(_capabilities, "_NET_DEFAULT_MAX_BYTES", 4096):
            with _Server(_body("a" * 8192)) as srv:
                result = Net().get(
                    f"http://{srv.authority}/body", max_bytes=1_000_000,
                )
        self.assertEqual(len(result.value), 8192)

    def test_explicit_cap_still_raises_for_the_caller_that_set_it(self):
        # The foreign-component sandbox passes its own --foreign-result-cap
        # and translates this into a clean exit-1 diagnostic, so an
        # EXPLICIT cap must keep propagating rather than becoming an Err.
        with _Server(_body("a" * 8192)) as srv:
            with self.assertRaises(ResultCapExceeded):
                Net().get(f"http://{srv.authority}/body", max_bytes=1000)

    def test_default_ceiling_is_a_sane_size(self):
        # A guard on the constant itself: a ceiling small enough to break
        # ordinary API responses, or large enough to be no ceiling at all,
        # would both be silent regressions.
        self.assertGreaterEqual(_capabilities._NET_DEFAULT_MAX_BYTES, 1 << 20)
        self.assertLessEqual(_capabilities._NET_DEFAULT_MAX_BYTES, 1 << 30)


# ---- backend parity ---------------------------------------------------


_GATED_SRC = (
    "fun main(net: Net, stdio: Stdio)\n"
    "    let scoped = net.restrict_to(\"127.0.0.1\")\n"
    "    match scoped.get(\"http://{authority}/start\")\n"
    "        Ok(b) -> stdio.println(\"[${{b}}]\")\n"
    "        Err(e) -> stdio.println(\"ERR\")\n"
)


def _run_python(src: str) -> str:
    module = Parser(Lexer(src).lex(), source=src).parse_module()
    result = analyze(module, source=src)
    if not result.ok:
        raise AssertionError(f"analyzer errors: {result.errors}")
    code = transpile(module, types=result.types, bindings=result.bindings)
    out = io.StringIO()
    saved = sys.stdout
    sys.stdout = out
    try:
        exec(compile(code, "<net-hop-gate>", "exec"), {"__name__": "__main__"})
    finally:
        sys.stdout = saved
    return out.getvalue()


class TestBackendParity(unittest.TestCase):
    """The Python backend and the ``capa:host`` Wasm bridge run the SAME
    ``Net`` object (the bridge's ``net.get`` host function delegates to
    it), so the per-hop gate holds identically on both. ``--wasi`` is a
    third implementation, in the guest, which refuses ANY non-2xx and so
    never follows a redirect at all: on a forbidden hop all three agree on
    Err, and --wasi is strictly more restrictive on a PERMITTED hop, which
    it cannot follow because its request parts are resolved at compile
    time from a literal URL and a runtime ``Location`` is not one. See
    docs/design/wasi_mode.md."""

    def test_python_backend_refuses_the_forbidden_hop(self):
        with _Server(_body("BODY-FROM-FORBIDDEN-HOST")) as victim:
            with _Server(_redirect_to(
                    f"http://localhost:{victim.port}/PWNED")) as hop:
                out = _run_python(_GATED_SRC.format(authority=hop.authority))
            self.assertEqual(victim.seen, [])
        self.assertEqual(out, "ERR\n")

    @unittest.skipUnless(
        _has_component_tooling(), "wasm-tools / wasmtime component missing",
    )
    def test_capa_host_bridge_refuses_the_forbidden_hop(self):
        from capa.cli import _wrap_as_component
        from capa.ir import compile_wasm, compile_wit
        from capa.runtime._wasm_component_host import WasmComponentHost

        with _Server(_body("BODY-FROM-FORBIDDEN-HOST")) as victim:
            with _Server(_redirect_to(
                    f"http://localhost:{victim.port}/PWNED")) as hop:
                src = _GATED_SRC.format(authority=hop.authority)
                module = Parser(Lexer(src).lex(), source=src).parse_module()
                result = analyze(module, source=src)
                self.assertTrue(result.ok, result.errors)
                core = compile_wasm(module, types=result.types, wasi=False)
                wit = compile_wit(module, types=result.types, wasi=False)
                comp = _wrap_as_component(core, wit, wasi=False)
                out = io.StringIO()
                saved = sys.stdout
                sys.stdout = out
                try:
                    WasmComponentHost(wasi=False).run_main(comp)
                finally:
                    sys.stdout = saved
            self.assertEqual(victim.seen, [])
        self.assertEqual(out.getvalue(), "ERR\n")


if __name__ == "__main__":
    unittest.main()
