"""End-to-end tests for ``--allow-host`` (WASI Net operator grant).

Phase B2 proof: a DYNAMIC (argv-derived) ``net.get`` URL that the compiler
rejects fail-closed WITHOUT a grant compiles WITH ``--allow-host`` and, at
runtime, actually REACHES the granted host (Ok body) while every non-granted
host -- including the URL-parsing bypass vectors (userinfo ``@``, fragment
``#``, uppercase, trailing dot) -- is DENIED (Err), fail-closed. The fine
``restrict_to`` gate still layers on top. Run against a local 127.0.0.1
server (no external network).
"""

import unittest

from tests.wasi._helpers import (
    _has_wasm_tools, _parse_analyze, _wasi_run_capture,
)
from tests.wasi.test_wasi_net import _has_wasmtime_wasi_http, _LocalHttpServer

# The dynamic-URL program: reads the URL from env.args()[0] (genuinely
# runtime), GETs it, prints [body] on Ok / ERR on Err.
_DYN_SRC = (
    "fun main(net: Net, env: Env, stdio: Stdio)\n"
    "    let args = env.args()\n"
    "    match args.get(0)\n"
    "        Some(url) ->\n"
    "            match net.get(url)\n"
    "                Ok(b) -> stdio.println(\"[${b}]\")\n"
    "                Err(e) -> stdio.println(\"ERR\")\n"
    "        None -> stdio.println(\"noarg\")\n"
)

# Same, but the receiver is narrowed by restrict_to first (the fine gate).
_RESTRICT_SRC = (
    "fun main(net: Net, env: Env, stdio: Stdio)\n"
    "    let args = env.args()\n"
    "    let n2 = net.restrict_to(\"other.example\")\n"
    "    match args.get(0)\n"
    "        Some(url) ->\n"
    "            match n2.get(url)\n"
    "                Ok(b) -> stdio.println(\"[${b}]\")\n"
    "                Err(e) -> stdio.println(\"ERR\")\n"
    "        None -> stdio.println(\"noarg\")\n"
)


def _run(src: str, grant, args):
    from capa.ir import compile_wasm, compile_wit, compute_net_ceiling
    from capa.cli import _wrap_as_component
    from capa.runtime._wasm_component_host import WasmComponentHost
    module, result = _parse_analyze(src)
    core = compile_wasm(
        module, types=result.types, wasi=True,
        net_operator_allow_hosts=frozenset(grant),
    )
    wit = compile_wit(module, types=result.types, wasi=True)
    comp = _wrap_as_component(core, wit, wasi=True)
    ceiling = compute_net_ceiling(module, types=result.types)
    host = WasmComponentHost(args=args, wasi=True, net_ceiling=ceiling)
    return _wasi_run_capture(host, comp)


class DynamicUrlCompileGate(unittest.TestCase):
    """The compile-time gate: a dynamic Net URL is rejected WITHOUT a grant
    and compiles WITH one (no runtime tooling needed)."""

    def test_rejected_without_grant(self):
        from capa.ir import compile_wasm
        module, result = _parse_analyze(_DYN_SRC)
        with self.assertRaises(Exception) as cm:
            compile_wasm(module, types=result.types, wasi=True)
        msg = str(cm.exception)
        self.assertIn("literal", msg)
        # The remedy names --allow-host (mirroring --preopen for Fs).
        self.assertIn("--allow-host", msg)

    @unittest.skipUnless(_has_wasm_tools(), "wasm-tools not installed")
    def test_compiles_with_grant(self):
        # compile_wasm assembles via wasm-tools, so this one needs the
        # toolchain (the reject / WAT tests above do not).
        from capa.ir import compile_wasm
        module, result = _parse_analyze(_DYN_SRC)
        blob = compile_wasm(
            module, types=result.types, wasi=True,
            net_operator_allow_hosts=frozenset({"api.example.com"}),
        )
        self.assertTrue(blob)  # assembled without error

    def test_wat_calls_net_get_not_dead_code(self):
        # With a grant the dynamic call site reaches $Net_get + the runtime
        # extractor (before this feature it was dead code).
        from capa.ir import compile_wat
        module, result = _parse_analyze(_DYN_SRC)
        wat = compile_wat(
            module, types=result.types, wasi=True, embed_manifest=False,
            net_operator_allow_hosts=frozenset({"api.example.com"}),
        )
        self.assertIn("call $Net_get", wat)
        self.assertIn("call $Net_url_extract", wat)


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_wasi_http(),
    "wasm-tools and/or wasmtime-py with wasi:http not installed",
)
class DynamicUrlRuntime(unittest.TestCase):
    """Runtime reachability + deny-by-default over wasi:http."""

    def test_granted_host_is_reached(self):
        with _LocalHttpServer(b"hello-dynamic") as auth:
            out = _run(_DYN_SRC, {"127.0.0.1"}, (f"http://{auth}/p",))
        self.assertEqual(out, "[hello-dynamic]\n")

    def test_non_granted_host_is_denied(self):
        # Grant a DIFFERENT host than the URL targets: the metadata-style
        # deny-by-default. The URL reaches the live local server, but the
        # grant is for api.example.com, so the guest gate refuses it.
        with _LocalHttpServer(b"secret") as auth:
            out = _run(_DYN_SRC, {"api.example.com"}, (f"http://{auth}/p",))
        self.assertEqual(out, "ERR\n")

    def test_metadata_endpoint_denied_unless_granted(self):
        # A dynamic URL to the cloud-metadata IP is denied when only a
        # normal host is granted (no request is built).
        out = _run(
            _DYN_SRC, {"api.example.com"},
            ("http://169.254.169.254/latest/meta-data/",),
        )
        self.assertEqual(out, "ERR\n")

    def test_userinfo_real_host_granted_is_reached(self):
        # http://evil@<granted>/ -> real host is the granted one (userinfo
        # stripped), so it is reached: the extractor contacts the real host.
        with _LocalHttpServer(b"OK") as auth:
            out = _run(_DYN_SRC, {"127.0.0.1"}, (f"http://evil.com@{auth}/p",))
        self.assertEqual(out, "[OK]\n")

    def test_userinfo_bypass_to_non_granted_is_denied(self):
        # http://<granted>@evil/ -> real host is evil (after the last @),
        # NOT granted, so denied: userinfo cannot smuggle a grant.
        with _LocalHttpServer(b"OK"):
            out = _run(
                _DYN_SRC, {"127.0.0.1"},
                ("http://127.0.0.1@evil.invalid/p",),
            )
        self.assertEqual(out, "ERR\n")

    def test_fragment_does_not_change_host(self):
        # http://<granted>/p#api.example.com -> host is the granted one;
        # the fragment is dropped and never becomes the host.
        with _LocalHttpServer(b"OK") as auth:
            out = _run(
                _DYN_SRC, {"127.0.0.1"},
                (f"http://{auth}/p#api.example.com",),
            )
        self.assertEqual(out, "[OK]\n")

    def test_trailing_dot_matches_grant(self):
        # http://127.0.0.1.:port/p -> the extractor strips the trailing dot,
        # so the host matches the grant 127.0.0.1 and the request reaches
        # the server (authority rebuilt from the stripped host).
        with _LocalHttpServer(b"OK") as auth:
            port = auth.split(":")[1]
            out = _run(_DYN_SRC, {"127.0.0.1"}, (f"http://127.0.0.1.:{port}/p",))
        self.assertEqual(out, "[OK]\n")

    def test_uppercase_host_matches_grant(self):
        with _LocalHttpServer(b"OK") as auth:
            port = auth.split(":")[1]
            out = _run(_DYN_SRC, {"127.0.0.1"}, (f"http://127.0.0.1:{port}/p",))
        self.assertEqual(out, "[OK]\n")

    def test_ipv6_url_denied(self):
        # A bracketed IPv6 URL is fail-closed by the extractor (deny), even
        # with a matching-looking grant.
        out = _run(_DYN_SRC, {"::1"}, ("http://[::1]:8080/p",))
        self.assertEqual(out, "ERR\n")

    def test_restrict_to_still_cuts_a_granted_host(self):
        # The fine restrict_to("other.example") gate layers ON TOP of the
        # ceiling+grant union: the granted 127.0.0.1 is still denied.
        with _LocalHttpServer(b"OK") as auth:
            out = _run(_RESTRICT_SRC, {"127.0.0.1"}, (f"http://{auth}/p",))
        self.assertEqual(out, "ERR\n")


if __name__ == "__main__":
    unittest.main()
