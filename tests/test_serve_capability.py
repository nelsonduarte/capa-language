"""Tests for the ``Serve`` capability (2026-07): the authority to
listen on a network address and accept inbound connections.

``Serve`` is the tenth built-in capability and the language's first
INBOUND authority. It is connection-level (listen / accept / recv /
send / close), Python-backend-only, and sequential: one open
connection at a time, no threads and no async inside the runtime.

Coverage, in the order the acceptance criteria were set:

- END TO END: a real Capa program binds an ephemeral loopback port,
  accepts one connection, reads the request bytes and writes a
  response, driven by a Python ``socket`` client that asserts the
  exact bytes on the wire.
- ATTENUATION: narrowing is intersection-only (adding a rule can never
  widen), and the denial is REAL -- a cap restricted to one port
  cannot bind another, and the port it was refused stays unbound, so
  the deny is not a relabelling of a bind that actually happened.
- SEQUENTIAL / BOUNDED: accept before listen, a second accept while a
  connection is open, and the accept timeout all return ``Err``.
- WASM REJECTION: the emitter names every offending site. This test
  deliberately does NOT need wasmtime (the rejection happens at emit
  time), so it runs on the no-wasm CI job, which is the job most
  likely to regress it.
- MANIFEST / SBOM / POLICY: ``Serve`` appears on exactly the functions
  that hold it, reaches the composed SBOM, and a ``forbid-capability``
  policy over it fires. These layers derive from ``CAPABILITY_NAMES``
  and needed no code changes; these tests verify that rather than
  assuming it.

NO wasm tooling is imported at module level anywhere in this file, so
the module always COLLECTS under ``python -m unittest discover`` on a
runner without the ``wasm`` extra installed.
"""

import io
import socket
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from capa import Lexer, Parser, analyze, transpile
from capa.builtins import METHODS
from capa.ir import lower
from capa.ir._capa_types import (
    BUILTIN_CAPS,
    ERASED_CAPS,
    HANDLE_BEARING_CAPS,
    PYTHON_ONLY_CAPS,
)
from capa.loader import ModuleLoader
from capa.manifest import (
    build_composed_sbom, build_manifest, evaluate_policies, find_policy_file,
    read_policy_file,
)
from capa.runtime._capabilities import Serve
from capa.typesys import CAPABILITY_NAMES


_EXAMPLES = Path(__file__).resolve().parent.parent / "examples" / "wasm"


def _parse_and_analyze(src: str, filename: str = "t.capa"):
    """Front end only: lex, parse, analyze, and fail loudly on a
    diagnostic. Same shape as the parity suite's helper."""
    tokens = Lexer(src).lex()
    module = Parser(tokens, source=src).parse_module()
    result = analyze(module, source=src, filename=filename)
    if not result.ok:
        raise AssertionError(f"analyzer errors: {result.errors}")
    return module, result


def _free_port() -> int:
    """Bind an ephemeral loopback port, note it, and release it.

    Used to pick a port to TEMPLATE INTO a Capa program (the program
    itself cannot report its port back to the test without a channel
    we would have to build). There is a theoretical race between
    release and the program's bind, but on loopback with no other
    listener it does not fire in practice, and a genuine collision
    surfaces as a loud bind failure rather than a silent pass.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])
    finally:
        s.close()


def _port_is_free(port: int) -> bool:
    """True iff nothing is listening on ``port``. This is what turns
    'the deny returned Err' into 'the deny actually prevented a bind'."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.settimeout(0.5)
        return s.connect_ex(("127.0.0.1", port)) != 0
    finally:
        s.close()


def _run_capa(source: str, filename: str, *cap_args) -> str:
    """Transpile ``source`` and run its ``main`` with the given caps,
    returning whatever ``main`` printed. Mirrors the in-process
    transpile+exec harness the parity suite uses (fast, no
    subprocess).

    ``__name__`` is deliberately NOT ``"__main__"`` here: the
    transpiled bootstrap would then construct its own capabilities and
    run ``main`` at import, and this caller needs to supply the caps
    itself (and to know when ``main`` returned)."""
    module, result = _parse_and_analyze(source, filename)
    code = transpile(
        module, filename=filename,
        types=result.types, bindings=result.bindings,
    )
    ns: dict = {"__name__": filename}
    exec(compile(code, filename, "exec"), ns)
    buf = io.StringIO()
    with redirect_stdout(buf):
        ns["main"](*cap_args)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# END TO END: a real Capa program serving a real client
# ---------------------------------------------------------------------------


_ECHO_SERVER = '''\
fun main(stdio: Stdio, serve: Serve)
    let local = serve.restrict_to("127.0.0.1:{port}")
    match local.listen("127.0.0.1", {port})
        Ok(_) -> stdio.println("listening")
        Err(e) -> stdio.println("listen failed: " + e.message)
    match local.accept()
        Ok(conn) ->
            match local.recv(conn, 1024)
                Ok(request) -> stdio.println("read ${{request.length()}} bytes")
                Err(e) -> stdio.println("read failed: " + e.message)
            match local.send(conn, "pong".bytes())
                Ok(_) -> stdio.println("wrote pong")
                Err(e) -> stdio.println("write failed: " + e.message)
            match local.close(conn)
                Ok(_) -> stdio.println("closed")
                Err(e) -> stdio.println("close failed: " + e.message)
        Err(e) -> stdio.println("accept failed: " + e.message)
    match local.stop()
        Ok(_) -> stdio.println("stopped")
        Err(e) -> stdio.println("stop failed: " + e.message)
'''


class TestServeEndToEnd(unittest.TestCase):
    """The headline acceptance row: a Capa program is a real server
    that a real (Python) client talks to over a real socket."""

    def test_capa_program_serves_one_client(self):
        from capa.runtime._capabilities import Stdio

        port = _free_port()
        source = _ECHO_SERVER.format(port=port)

        out: dict = {}

        def run_server():
            try:
                out["stdout"] = _run_capa(
                    source, "echo_server.capa", Stdio(), Serve(),
                )
            except BaseException as e:                # pragma: no cover
                out["error"] = e

        t = threading.Thread(target=run_server, daemon=True)
        t.start()

        # Give the program a moment to reach its bind, retrying rather
        # than sleeping a fixed amount so the test is not timing-fragile.
        client = None
        deadline = 5.0
        step = 0.02
        waited = 0.0
        while waited < deadline:
            c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            c.settimeout(2.0)
            if c.connect_ex(("127.0.0.1", port)) == 0:
                client = c
                break
            c.close()
            threading.Event().wait(step)
            waited += step
        self.assertIsNotNone(
            client, f"Capa program never bound 127.0.0.1:{port}",
        )

        try:
            client.sendall(b"ping")
            response = client.recv(64)
        finally:
            client.close()

        t.join(timeout=10.0)
        self.assertFalse(t.is_alive(), "the Capa program did not finish")
        self.assertNotIn("error", out, f"server raised: {out.get('error')!r}")

        # The bytes the client actually received off the wire.
        self.assertEqual(response, b"pong")
        # And the program's own view of the exchange.
        self.assertEqual(
            out["stdout"].splitlines(),
            [
                "listening",
                "read 4 bytes",
                "wrote pong",
                "closed",
                "stopped",
            ],
        )


# ---------------------------------------------------------------------------
# ATTENUATION
# ---------------------------------------------------------------------------


class TestServeAttenuation(unittest.TestCase):
    """``restrict_to`` narrows and only narrows, and the narrowing is
    enforced before the syscall."""

    def test_unrestricted_allows_anything(self):
        s = Serve()
        self.assertTrue(s.allows("127.0.0.1", 8080))
        self.assertTrue(s.allows("0.0.0.0", 1))

    def test_exact_addr_port_rule(self):
        s = Serve().restrict_to("127.0.0.1:8080")
        self.assertTrue(s.allows("127.0.0.1", 8080))
        self.assertFalse(s.allows("127.0.0.1", 8081))
        self.assertFalse(s.allows("0.0.0.0", 8080))

    def test_port_range_rule(self):
        s = Serve().restrict_to("127.0.0.1:8000-8100")
        self.assertTrue(s.allows("127.0.0.1", 8000))
        self.assertTrue(s.allows("127.0.0.1", 8050))
        self.assertTrue(s.allows("127.0.0.1", 8100))
        self.assertFalse(s.allows("127.0.0.1", 7999))
        self.assertFalse(s.allows("127.0.0.1", 8101))

    def test_wildcards(self):
        any_port = Serve().restrict_to("127.0.0.1:*")
        self.assertTrue(any_port.allows("127.0.0.1", 1))
        self.assertTrue(any_port.allows("127.0.0.1", 65535))
        self.assertFalse(any_port.allows("10.0.0.1", 80))

        any_addr = Serve().restrict_to("*:8080")
        self.assertTrue(any_addr.allows("10.0.0.1", 8080))
        self.assertFalse(any_addr.allows("10.0.0.1", 8081))

    def test_restrict_to_only_ever_narrows(self):
        # Chaining intersects: the surviving authority is exactly the
        # single port in BOTH rules.
        s = Serve().restrict_to("127.0.0.1:8000-8100")
        s = s.restrict_to("127.0.0.1:8080")
        self.assertTrue(s.allows("127.0.0.1", 8080))
        self.assertFalse(s.allows("127.0.0.1", 8081))

        # And a deliberate WIDENING attempt restores nothing: the
        # earlier rules still have to be satisfied.
        widened = s.restrict_to("*:*")
        self.assertTrue(widened.allows("127.0.0.1", 8080))
        self.assertFalse(widened.allows("127.0.0.1", 8081))
        self.assertFalse(widened.allows("10.0.0.1", 8080))

    def test_disjoint_rules_permit_nothing(self):
        s = Serve().restrict_to("127.0.0.1:8080").restrict_to("127.0.0.1:9090")
        self.assertFalse(s.allows("127.0.0.1", 8080))
        self.assertFalse(s.allows("127.0.0.1", 9090))

    def test_malformed_spec_fails_closed(self):
        # restrict_to returns a Serve, not a Result, so it cannot
        # report a parse error. A spec that does not parse must DENY,
        # because the alternative (ignore it) silently widens.
        for spec in ("nonsense", "127.0.0.1:", "127.0.0.1:abc",
                     "127.0.0.1:99999", "127.0.0.1:100-50", ":8080", ""):
            with self.subTest(spec=spec):
                s = Serve().restrict_to(spec)
                self.assertFalse(s.allows("127.0.0.1", 8080))
                self.assertFalse(s.allows("127.0.0.1", 0))

    def test_out_of_range_and_non_int_ports_denied(self):
        s = Serve().restrict_to("127.0.0.1:*")
        self.assertFalse(s.allows("127.0.0.1", -1))
        self.assertFalse(s.allows("127.0.0.1", 65536))
        self.assertFalse(s.allows("127.0.0.1", True))

    def test_allows_agrees_with_listen_on_invalid_ports(self):
        # ``allows`` documents itself as "would listen(a, p) be
        # permitted", so the two must not disagree. The port-validity
        # check used to sit AFTER the unrestricted early return, so an
        # unrestricted cap answered True for port 65536 while listen
        # refused: fail-safe, but a query that contradicts the
        # operation it describes defeats the purpose of having one.
        for label, cap in (
            ("unrestricted", Serve()),
            ("restricted", Serve().restrict_to("127.0.0.1:*")),
        ):
            for bad in (-1, 65536, True, "80"):
                with self.subTest(cap=label, port=bad):
                    self.assertFalse(cap.allows("127.0.0.1", bad))
                    r = cap.listen("127.0.0.1", bad)
                    self.assertTrue(r.is_err())
                    # One consistent diagnostic regardless of whether
                    # the cap is restricted; in particular never the
                    # self-contradictory "does not permit ... current
                    # restrictions: unrestricted".
                    self.assertIn("invalid port", r.error.message)

    def test_valid_ports_still_allowed_on_an_unrestricted_cap(self):
        # Guard against the validity check over-rejecting: 0 (ephemeral)
        # and 65535 (the boundary) must both survive.
        s = Serve()
        for good in (0, 1, 8080, 65535):
            with self.subTest(port=good):
                self.assertTrue(s.allows("127.0.0.1", good))

    def test_parent_is_not_mutated_by_restriction(self):
        parent = Serve()
        child = parent.restrict_to("127.0.0.1:8080")
        self.assertTrue(parent.allows("10.0.0.1", 9999))
        self.assertFalse(child.allows("10.0.0.1", 9999))


class TestServeAttenuationIsEnforced(unittest.TestCase):
    """The denial is real: a refused bind never happens, rather than
    happening and being relabelled."""

    def test_restricted_cap_cannot_bind_another_port(self):
        allowed = _free_port()
        forbidden = _free_port()
        self.assertNotEqual(allowed, forbidden)

        s = Serve().restrict_to(f"127.0.0.1:{allowed}")

        result = s.listen("127.0.0.1", forbidden)
        self.assertTrue(result.is_err(), "the forbidden bind was permitted")
        err = result.error
        self.assertIn("does not permit", err.message)
        self.assertIn(str(forbidden), err.message)

        # The load-bearing assertion: nothing is listening on the port
        # we were refused. A deny that merely returned Err after
        # binding would leave a live listener here.
        self.assertTrue(
            _port_is_free(forbidden),
            "the denied port was actually bound; the deny was a "
            "relabelling, not an enforcement",
        )

        # The permitted port still works, so the cap was narrowed and
        # not simply broken.
        ok = s.listen("127.0.0.1", allowed)
        self.assertTrue(ok.is_ok(), f"allowed bind failed: {ok}")
        try:
            self.assertEqual(s.local_port().unwrap(), allowed)
        finally:
            s.stop()

    def test_restricted_cap_cannot_bind_another_address(self):
        port = _free_port()
        s = Serve().restrict_to(f"127.0.0.1:{port}")
        result = s.listen("0.0.0.0", port)
        self.assertTrue(result.is_err())
        self.assertIn("does not permit", result.error.message)

    def test_narrow_range_forbids_ephemeral_port_zero(self):
        # Port 0 asks the OS to choose. A cap narrowed to a range that
        # excludes 0 must refuse, because otherwise the OS's choice
        # would escape the restriction.
        s = Serve().restrict_to("127.0.0.1:8000-8100")
        self.assertFalse(s.allows("127.0.0.1", 0))
        self.assertTrue(s.listen("127.0.0.1", 0).is_err())

    def test_ephemeral_bind_allowed_when_restriction_admits_zero(self):
        s = Serve().restrict_to("127.0.0.1:0")
        result = s.listen("127.0.0.1", 0)
        self.assertTrue(result.is_ok(), f"ephemeral bind failed: {result}")
        try:
            self.assertGreater(s.local_port().unwrap(), 0)
        finally:
            s.stop()


# ---------------------------------------------------------------------------
# SEQUENTIAL SEMANTICS AND BOUNDED WAITS
# ---------------------------------------------------------------------------


class TestServeLifecycle(unittest.TestCase):

    def test_accept_before_listen_is_an_error(self):
        r = Serve().accept()
        self.assertTrue(r.is_err())
        self.assertIn("not listening", r.error.message)

    def test_local_port_before_listen_is_an_error(self):
        self.assertTrue(Serve().local_port().is_err())

    def test_stop_before_listen_is_an_error(self):
        self.assertTrue(Serve().stop().is_err())

    def test_double_listen_is_an_error(self):
        s = Serve()
        self.assertTrue(s.listen("127.0.0.1", 0).is_ok())
        try:
            r = s.listen("127.0.0.1", 0)
            self.assertTrue(r.is_err())
            self.assertIn("already listening", r.error.message)
        finally:
            s.stop()

    def test_recv_and_send_on_unknown_connection_are_errors(self):
        s = Serve()
        for r in (s.recv(1, 16), s.send(1, [1, 2]), s.close(1)):
            self.assertTrue(r.is_err())
            self.assertIn("unknown connection", r.error.message)

    def test_accept_timeout_returns_err_not_a_hang(self):
        # Shrink the bound so the test is fast; the point is that the
        # wait TERMINATES with an Err rather than blocking forever.
        import capa.runtime._capabilities as caps
        original = caps._SERVE_ACCEPT_TIMEOUT_SECS
        caps._SERVE_ACCEPT_TIMEOUT_SECS = 0.1
        try:
            s = Serve()
            self.assertTrue(s.listen("127.0.0.1", 0).is_ok())
            try:
                r = s.accept()
                self.assertTrue(r.is_err())
                self.assertIn("timed out", r.error.message)
            finally:
                s.stop()
        finally:
            caps._SERVE_ACCEPT_TIMEOUT_SECS = original

    def test_one_connection_at_a_time(self):
        s = Serve()
        self.assertTrue(s.listen("127.0.0.1", 0).is_ok())
        port = s.local_port().unwrap()
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            client.settimeout(5.0)
            client.connect(("127.0.0.1", port))
            conn = s.accept().unwrap()

            # A second accept while a connection is open is refused
            # with an actionable message, NOT queued and NOT threaded.
            second = s.accept()
            self.assertTrue(second.is_err())
            self.assertIn(
                "one connection at a time", second.error.message,
            )

            self.assertTrue(s.close(conn).is_ok())
        finally:
            client.close()
            s.stop()

    def test_recv_reports_eof_as_an_empty_list(self):
        s = Serve()
        self.assertTrue(s.listen("127.0.0.1", 0).is_ok())
        port = s.local_port().unwrap()
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            client.settimeout(5.0)
            client.connect(("127.0.0.1", port))
            conn = s.accept().unwrap()
            client.shutdown(socket.SHUT_WR)
            self.assertEqual(list(s.recv(conn, 16).unwrap()), [])
        finally:
            client.close()
            s.stop()

    def test_bytes_round_trip_as_ints_masked_to_a_byte(self):
        s = Serve()
        self.assertTrue(s.listen("127.0.0.1", 0).is_ok())
        port = s.local_port().unwrap()
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            client.settimeout(5.0)
            client.connect(("127.0.0.1", port))
            conn = s.accept().unwrap()

            client.sendall(bytes([0, 1, 127, 128, 255]))
            got = list(s.recv(conn, 16).unwrap())
            self.assertEqual(got, [0, 1, 127, 128, 255])
            for b in got:
                self.assertTrue(0 <= b <= 255)

            # Out-of-range ints are masked with & 0xFF rather than
            # rejected, matching the byte convention elsewhere.
            self.assertTrue(s.send(conn, [256 + 65, 0x1FF]).is_ok())
            self.assertEqual(client.recv(8), bytes([65, 255]))
        finally:
            client.close()
            s.stop()

    def test_send_error_discloses_that_transmitted_count_is_unspecified(self):
        # ``sendall`` can push a PREFIX of the payload and only then
        # raise, so an Err does not mean "nothing was sent". A caller
        # that retries would duplicate the prefix. The error text has
        # to say so, because the type (Result<Unit, IoError>) cannot.
        s = Serve()
        self.assertTrue(s.listen("127.0.0.1", 0).is_ok())
        port = s.local_port().unwrap()
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            client.settimeout(5.0)
            client.connect(("127.0.0.1", port))
            conn = s.accept().unwrap()
            # Force the failure arm by closing the peer, then sending
            # enough to overflow any kernel buffer that would otherwise
            # absorb the write silently.
            client.close()
            r = s.send(conn, [65] * (4 << 20))
            if r.is_err():
                self.assertIn("unspecified", r.error.cause)
        finally:
            s.stop()

    def test_send_rejects_a_non_byte_payload(self):
        s = Serve()
        self.assertTrue(s.listen("127.0.0.1", 0).is_ok())
        port = s.local_port().unwrap()
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            client.settimeout(5.0)
            client.connect(("127.0.0.1", port))
            conn = s.accept().unwrap()
            r = s.send(conn, ["not a byte"])
            self.assertTrue(r.is_err())
            self.assertIn("not a list of byte values", r.error.message)
        finally:
            client.close()
            s.stop()

    def test_recv_size_must_be_positive(self):
        s = Serve()
        self.assertTrue(s.listen("127.0.0.1", 0).is_ok())
        port = s.local_port().unwrap()
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            client.settimeout(5.0)
            client.connect(("127.0.0.1", port))
            conn = s.accept().unwrap()
            r = s.recv(conn, 0)
            self.assertTrue(r.is_err())
            self.assertIn("must be positive", r.error.message)
        finally:
            client.close()
            s.stop()

    def test_restrict_to_yields_an_unbound_capability(self):
        # Socket state does not survive attenuation: a narrowed cap is
        # something you take BEFORE you listen, not a second handle on
        # an already-open listener.
        s = Serve()
        self.assertTrue(s.listen("127.0.0.1", 0).is_ok())
        try:
            narrowed = s.restrict_to("127.0.0.1:*")
            self.assertTrue(narrowed.local_port().is_err())
            self.assertTrue(narrowed.accept().is_err())
        finally:
            s.stop()


# ---------------------------------------------------------------------------
# REGISTRIES AND THE TYPE SURFACE
# ---------------------------------------------------------------------------


class TestServeIsRegistered(unittest.TestCase):
    """``Serve`` landed in every registry. The six guards in
    tests/test_cap_handles.py are the general cross-check; these pin
    the Serve-specific facts."""

    def test_serve_is_a_known_capability_on_both_sides(self):
        self.assertIn("Serve", CAPABILITY_NAMES)
        self.assertIn("Serve", BUILTIN_CAPS)

    def test_serve_is_python_only_and_therefore_erased(self):
        self.assertIn("Serve", PYTHON_ONLY_CAPS)
        self.assertIn("Serve", ERASED_CAPS)
        self.assertNotIn("Serve", HANDLE_BEARING_CAPS)

    def test_method_table_matches_the_runtime_class(self):
        # A method the checker accepts but the runtime lacks is an
        # AttributeError at run time, in a capability whose whole job
        # is to be a trust boundary.
        declared = {name for name, _ty, _tp in METHODS["Serve"]}
        self.assertEqual(
            declared,
            {"restrict_to", "allows", "listen", "local_port", "accept",
             "recv", "send", "close", "stop"},
        )
        for name in declared:
            self.assertTrue(
                callable(getattr(Serve, name, None)),
                f"capa.runtime Serve has no method {name!r}",
            )

    def test_runtime_exports_serve(self):
        import capa.runtime as rt
        self.assertIn("Serve", rt.__all__)
        self.assertIs(rt.Serve, Serve)

    def test_lsp_offers_serve(self):
        from capa.lsp.completion import _BUILTIN_CAPABILITIES
        self.assertIn("Serve", _BUILTIN_CAPABILITIES)

    def test_serve_send_is_an_ifc_sink_and_recv_is_not_a_secret_source(self):
        from capa.analyzer._ifc_tables import _PUBLIC_SINKS, _SECRET_SOURCES
        # Sending bytes to a client is exfiltration, like Net.post.
        # Argument 1 is the payload; argument 0 is the connection id.
        self.assertEqual(_PUBLIC_SINKS[("Serve", "send")], {1})
        # Inbound data is @public: untrusted, but not confidential.
        # Labelling it @secret would make echoing a request back to
        # its own sender a violation, which is the normal case.
        self.assertNotIn(("Serve", "recv"), _SECRET_SOURCES)
        self.assertNotIn(("Serve", "accept"), _SECRET_SOURCES)

    def test_sink_method_names_are_unique_per_capability(self):
        # THE INVARIANT ``_ifc_summary`` DEPENDS ON. Its cross-function
        # summary pass has no receiver type available, so it attributes
        # a built-in sink to a capability BY METHOD NAME alone. That is
        # sound only while each sink method name belongs to exactly one
        # capability.
        #
        # Serve was first drafted with a ``write``, which collided with
        # ``Fs.write`` and silently made every ``fs.write`` report Serve
        # as a reached capability -- a precision regression in a
        # security analysis, found by
        # tests/test_unaudited_secret_sink_fact.py. Renaming to ``send``
        # fixed it; this guard means the next capability cannot
        # reintroduce the collision quietly.
        from capa.analyzer._ifc_tables import _PUBLIC_SINKS
        seen: dict = {}
        collisions = []
        for cap, method in _PUBLIC_SINKS:
            if method in seen:
                collisions.append((method, sorted([seen[method], cap])))
            seen[method] = cap
        self.assertEqual(
            collisions, [],
            "two capabilities share a sink method name, so "
            "_ifc_summary's by-method-name attribution would tag both "
            f"for either one's calls: {collisions}",
        )

    def test_secret_source_method_names_are_unique_per_capability(self):
        # Same argument, for the source side: ``_ifc_summary`` matches
        # ``_SECRET_SOURCE_METHODS`` by name too.
        from capa.analyzer._ifc_tables import _SECRET_SOURCES
        methods = [m for _c, m in _SECRET_SOURCES]
        self.assertEqual(len(methods), len(set(methods)))


class TestServeTypeChecks(unittest.TestCase):

    def _check(self, source: str):
        return _parse_and_analyze(source)

    def test_serve_annotation_is_accepted(self):
        self._check(
            "fun main(serve: Serve)\n"
            "    let s = serve.restrict_to(\"127.0.0.1:8080\")\n"
            "    let _ = s.listen(\"127.0.0.1\", 8080)\n"
        )

    def test_serve_methods_are_capability_gated(self):
        # A function without a Serve parameter cannot listen: this is
        # the whole point of the capability.
        with self.assertRaises(Exception):
            self._check(
                "fun sneaky() -> Unit\n"
                "    let s = Serve()\n"
                "    let _ = s.listen(\"127.0.0.1\", 80)\n"
                "    return\n"
            )

    def test_demo_example_type_checks(self):
        source = (_EXAMPLES / "serve_demo.capa").read_text(encoding="utf-8")
        self._check(source)


# ---------------------------------------------------------------------------
# WASM REJECTION (no wasmtime required -- rejection happens at emit time)
# ---------------------------------------------------------------------------


class TestWasmRejectsServe(unittest.TestCase):
    """The Wasm backend refuses ``Serve`` up front, following the
    ``Unsafe`` precedent exactly: one early raise naming EVERY
    offending site, saying why, and saying what to do instead.

    Deliberately free of wasmtime: ``emit_wat`` is pure text
    generation and the rejection fires before anything is executed, so
    this runs on the CI job that has no wasm extra installed."""

    def _emit(self, module):
        # Local import: the emitter is pure Python (no wasmtime), but
        # keeping it out of the module-level import surface makes it
        # obvious at a glance that this file collects on a runner with
        # no wasm extra installed.
        from capa.ir import emit_wat
        return emit_wat(module)

    def _emit_source(self, source: str):
        module, result = _parse_and_analyze(source)
        return self._emit(lower(module, types=result.types))

    def _error(self):
        from capa.ir._emit_wasm._layout import WasmEmissionError
        return WasmEmissionError

    def test_serve_parameter_is_rejected_with_a_clear_message(self):
        source = (_EXAMPLES / "serve_demo.capa").read_text(encoding="utf-8")
        with self.assertRaises(self._error()) as ctx:
            self._emit_source(source)
        msg = str(ctx.exception)
        self.assertIn("Serve", msg)
        # WHY.
        self.assertIn("wasi:sockets", msg)
        # WHAT TO DO INSTEAD.
        self.assertIn("Python backend", msg)
        # WHERE.
        self.assertIn("main(serve: Serve)", msg)

    def test_every_offending_site_is_listed(self):
        source = (
            "fun one(a: Serve) -> Unit\n"
            "    let _ = a.listen(\"127.0.0.1\", 8080)\n"
            "    return\n"
            "fun two(b: Serve) -> Unit\n"
            "    let _ = b.listen(\"127.0.0.1\", 8081)\n"
            "    return\n"
            "fun main(serve: Serve)\n"
            "    one(serve)\n"
            "    two(serve)\n"
        )
        with self.assertRaises(self._error()) as ctx:
            self._emit_source(source)
        msg = str(ctx.exception)
        for site in ("one(a: Serve)", "two(b: Serve)", "main(serve: Serve)"):
            self.assertIn(site, msg)

    def test_serve_inside_a_struct_field_is_rejected(self):
        # Reachability, not a literal head: the same recursive walk
        # that closed the Unsafe hole (audit 2026-06-17 C5(b)).
        from capa.ir._nodes import (
            Module, Function, Param, StructDecl, StructField,
        )
        module = Module(
            functions=[
                Function(
                    name="f", params=[Param(name="w", ty="Wrapper")],
                    return_type="Unit", declared_caps=[], body=[],
                ),
            ],
            types=[
                StructDecl(
                    name="Wrapper",
                    fields=[StructField(name="s", ty="Serve")],
                ),
            ],
        )
        with self.assertRaises(self._error()) as ctx:
            self._emit(module)
        msg = str(ctx.exception)
        self.assertIn("Serve", msg)
        self.assertIn("f(w: Wrapper)", msg)

    def test_serve_in_a_generic_argument_is_rejected(self):
        from capa.ir._nodes import Module, Function, Param
        module = Module(
            functions=[
                Function(
                    name="f", params=[Param(name="xs", ty="List<Serve>")],
                    return_type="Unit", declared_caps=[], body=[],
                ),
            ],
        )
        with self.assertRaises(self._error()) as ctx:
            self._emit(module)
        self.assertIn("Serve", str(ctx.exception))

    def test_unsafe_rejection_still_names_unsafe_not_serve(self):
        # The scan is per-capability: generalising it must not blur the
        # two diagnostics into one unhelpful message.
        from capa.ir._nodes import Module, Function, Param
        module = Module(
            functions=[
                Function(
                    name="f", params=[Param(name="u", ty="Unsafe")],
                    return_type="Unit", declared_caps=[], body=[],
                ),
            ],
        )
        with self.assertRaises(self._error()) as ctx:
            self._emit(module)
        msg = str(ctx.exception)
        self.assertIn("Unsafe", msg)
        self.assertIn("FFI", msg)
        self.assertNotIn("Serve", msg)

    def test_a_serve_free_program_still_emits(self):
        wat = self._emit_source(
            "fun main(stdio: Stdio)\n    stdio.println(\"hi\")\n"
        )
        self.assertIn("(module", wat)


class TestWitRejectsPythonOnlyCaps(unittest.TestCase):
    """``capa --wit`` is a STANDALONE path: it never runs the Wasm
    emitter, so the discovery-time rejection does not fire for it.

    Before this was closed, ``--wit`` on a Serve program exited 0 and
    printed a document that silently omitted Serve -- and whose
    ``world`` block declared ``export main: func()`` while the real
    ``main`` took a ``Serve`` parameter. A document whose entire
    purpose is to describe the program's interface to a host was
    describing a different program.

    Both members of ``PYTHON_ONLY_CAPS`` are covered, because they
    reach the generator by DIFFERENT routes and only a
    signature-level scan catches both: ``Serve`` has methods and so
    lands in ``used``; ``Unsafe`` is method-less and never does (its
    authority goes through the ``py_import`` / ``py_invoke`` free
    functions), which is why the omission for Unsafe was invisible.
    """

    def _wit(self, source: str):
        from capa.ir import emit_wit
        module, result = _parse_and_analyze(source)
        return emit_wit(lower(module, types=result.types))

    def _error(self):
        from capa.ir._emit_wit import PythonOnlyCapabilityInWit
        return PythonOnlyCapabilityInWit

    def test_wit_rejects_serve(self):
        source = (_EXAMPLES / "serve_demo.capa").read_text(encoding="utf-8")
        with self.assertRaises(self._error()) as ctx:
            self._wit(source)
        msg = str(ctx.exception)
        self.assertIn("Serve", msg)
        self.assertIn("wasi:sockets", msg)
        self.assertIn("main(serve: Serve)", msg)
        self.assertEqual(ctx.exception.cap, "Serve")

    def test_wit_rejects_method_less_unsafe(self):
        # The regression that a ``used``-based check could never catch:
        # Unsafe has no capability methods, so it is invisible to
        # ``collect_used_capabilities``. Only the signature scan sees it.
        with self.assertRaises(self._error()) as ctx:
            self._wit(
                "fun main(stdio: Stdio, u: Unsafe)\n"
                "    let _m = py_import(u, \"math\")\n"
                "    stdio.println(\"x\")\n"
            )
        self.assertIn("Unsafe", str(ctx.exception))
        self.assertEqual(ctx.exception.cap, "Unsafe")

    def test_wit_still_emits_for_a_normal_program(self):
        wit = self._wit(
            "fun main(stdio: Stdio, fs: Fs)\n"
            "    let _ = fs.read(\"x.txt\")\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertIn("interface stdio {", wit)
        self.assertIn("interface fs {", wit)

    def test_cli_wit_exits_nonzero_on_serve(self):
        # End to end through the real CLI, because the silent-success
        # exit 0 was the actual user-visible bug.
        import subprocess
        import sys
        proc = subprocess.run(
            [sys.executable, "-m", "capa", "--wit",
             str(_EXAMPLES / "serve_demo.capa")],
            capture_output=True, text=True,
            cwd=str(_EXAMPLES.parent.parent),
        )
        self.assertEqual(proc.returncode, 1, proc.stdout)
        self.assertIn("Serve", proc.stderr)
        # And it must NOT have printed a WIT document.
        self.assertNotIn("package capa:host", proc.stdout)


# ---------------------------------------------------------------------------
# MANIFEST / SBOM / POLICY (derived layers -- verified, not assumed)
# ---------------------------------------------------------------------------


_TWO_FUNCTION_SOURCE = '''\
pub fun handles(serve: Serve) -> Unit
    let _ = serve.listen("127.0.0.1", 8080)
    return

pub fun pure_helper(n: Int) -> Int
    return n + 1

pub fun logs(stdio: Stdio) -> Unit
    stdio.println("no serve here")
    return
'''


class TestServeInTheManifest(unittest.TestCase):

    def _manifest(self, source: str, filename: str = "m.capa"):
        module, result = _parse_and_analyze(source, filename)
        return build_manifest(
            module, filename=filename, expr_labels=result.expr_labels,
            unaudited_secret_sinks=result.unaudited_secret_sinks,
        )

    def test_serve_appears_on_exactly_the_functions_that_hold_it(self):
        manifest = self._manifest(_TWO_FUNCTION_SOURCE)
        by_name = {f["name"]: f for f in manifest["functions"]}

        self.assertIn("Serve", by_name["handles"]["declared_capabilities"])
        self.assertIn(
            "Serve",
            by_name["handles"]["transitively_reachable_capabilities"],
        )

        # And on nothing else. A capability that leaks into unrelated
        # functions would make the manifest useless as an audit
        # artefact.
        for name in ("pure_helper", "logs"):
            self.assertNotIn(
                "Serve", by_name[name]["declared_capabilities"], name,
            )
            self.assertNotIn(
                "Serve",
                by_name[name]["transitively_reachable_capabilities"],
                name,
            )

    def test_serve_propagates_transitively_but_not_into_declared(self):
        manifest = self._manifest(
            "fun inner(serve: Serve) -> Unit\n"
            "    let _ = serve.listen(\"127.0.0.1\", 80)\n"
            "    return\n"
            "fun outer(serve: Serve) -> Unit\n"
            "    inner(serve)\n"
            "    return\n"
        )
        by_name = {f["name"]: f for f in manifest["functions"]}
        self.assertIn(
            "Serve", by_name["outer"]["transitively_reachable_capabilities"],
        )

    def test_restrict_to_is_recorded_as_an_attenuation(self):
        # ``restrict_to`` keeps its exact name so the existing
        # attenuation tracking in capa/manifest/_flow.py works on Serve
        # with no change. This confirms it does.
        manifest = self._manifest(
            "fun run(serve: Serve) -> Unit\n"
            "    let narrow = serve.restrict_to(\"127.0.0.1:8080\")\n"
            "    let _ = narrow.listen(\"127.0.0.1\", 8080)\n"
            "    return\n"
        )
        blob = str(manifest)
        self.assertIn("restrict_to", blob)
        self.assertIn("127.0.0.1:8080", blob)


class TestServeInSbomAndPolicy(unittest.TestCase):
    """``Serve`` reaches the composed SBOM and a ``forbid-capability``
    policy over it fires. Both layers derive from
    ``CAPABILITY_NAMES``; this is the verification of that, not an
    assumption about it."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def _write(self, rel: str, text: str) -> None:
        p = self.tmp / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")

    def _app(self, main_src: str, policy: str) -> Path:
        root = self.tmp / "app"
        self._write(
            "app/capa.toml",
            '[package]\nname = "app"\nversion = "0.1.0"\n',
        )
        self._write("app/main.capa", main_src)
        self._write("app/capa-policy.toml", policy)
        return root

    def _compose(self, root: Path):
        root = root.resolve()
        filename = str(root / "main.capa")
        source = Path(filename).read_text(encoding="utf-8")
        loader = ModuleLoader(search_paths=[root])
        linked = loader.load_root(source, filename)
        result = analyze(
            linked.module, source=source, filename=filename,
            sources=linked.sources, module_privates=linked.module_privates,
        )
        if not result.ok:
            raise AssertionError(f"analyzer errors: {result.errors}")
        manifest = build_manifest(
            linked.module, filename=filename,
            expr_labels=result.expr_labels,
            unaudited_secret_sinks=result.unaudited_secret_sinks,
        )
        return build_composed_sbom(linked.module, manifest, root)

    def _evaluate(self, root: Path, policy_id: str):
        composed = self._compose(root)
        policy_path = find_policy_file(root.resolve())
        policies = read_policy_file(policy_path) if policy_path else []
        report = evaluate_policies(composed, policies)
        for r in report["results"]:
            if r["policy"] == policy_id:
                return r
        raise AssertionError(f"no policy result {policy_id!r}")

    def test_serve_appears_in_the_composed_sbom(self):
        root = self._app(
            "pub fun run(serve: Serve) -> Unit\n"
            "    let _ = serve.listen(\"127.0.0.1\", 8080)\n"
            "    return\n",
            "",
        )
        composed = self._compose(root)
        self.assertIn("Serve", str(composed))

    def test_forbid_capability_policy_over_serve_fires(self):
        root = self._app(
            "pub fun run(serve: Serve) -> Unit\n"
            "    let _ = serve.listen(\"127.0.0.1\", 8080)\n"
            "    return\n",
            '[[policy]]\nid = "no-serve"\nkind = "forbid-capability"\n'
            'capability = "Serve"\n',
        )
        result = self._evaluate(root, "no-serve")
        self.assertFalse(result["pass"], "the forbid-capability did not fire")
        self.assertEqual(result["violations"][0]["capability"], "Serve")

    def test_forbid_capability_policy_passes_on_a_serve_free_product(self):
        root = self._app(
            "pub fun run(fs: Fs) -> Unit\n"
            "    let _ = fs.read(\"x.txt\")\n"
            "    return\n",
            '[[policy]]\nid = "no-serve"\nkind = "forbid-capability"\n'
            'capability = "Serve"\n',
        )
        self.assertTrue(self._evaluate(root, "no-serve")["pass"])


if __name__ == "__main__":
    unittest.main()
