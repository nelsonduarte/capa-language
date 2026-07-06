"""Method-scoped ``--allow-host`` (Phase 2, 2026-07-06).

The operator can scope a Net grant to GET (read) or POST (write) with a
``:get`` / ``:post`` suffix. This module proves:

- the CLI spec parser recognises the suffix ONLY when the tail after the
  LAST ``:`` is exactly ``get`` / ``post`` and the head is a valid host, so
  a port (``h:8080``) or a bracketed IPv6 authority (``[::1]:8080``) is NOT
  mistaken for a suffix while ``[::1]:get`` IS;
- the two guest-side gates (``$Net_host_allowed_get`` /
  ``$Net_host_allowed_post``) admit the method-scoped host set (WAT
  structural proof, no toolchain);
- at runtime a ``h:get`` grant reaches a dynamic ``net.get`` to ``h`` but a
  dynamic ``net.post`` to ``h`` is DENIED, and vice versa for ``h:post``
  (the least-authority point), while a suffix-less grant reaches both
  (Phase-1 behaviour preserved);
- the SBOM records the access scope (get / post / connect).
"""

import sys
import unittest

sys.path.insert(0, "tests")
from test_wasi_mode import (  # noqa: E402
    _has_wasm_tools, _has_wasmtime_wasi_http, _parse_analyze,
    _LocalHttpServer, _LocalPostServer, _wasi_run_capture,
)

from capa.ir._net_host import NetGrant  # noqa: E402
from capa.cli import (  # noqa: E402
    _parse_allow_host_spec, _normalize_allow_hosts, _operator_grants_from_args,
)


_DYN_GET_SRC = (
    "fun main(net: Net, env: Env, stdio: Stdio)\n"
    "    let args = env.args()\n"
    "    match args.get(0)\n"
    "        Some(url) ->\n"
    "            match net.get(url)\n"
    "                Ok(b) -> stdio.println(\"[${b}]\")\n"
    "                Err(e) -> stdio.println(\"ERR\")\n"
    "        None -> stdio.println(\"noarg\")\n"
)

_DYN_POST_SRC = (
    "fun main(net: Net, env: Env, stdio: Stdio)\n"
    "    let args = env.args()\n"
    "    match args.get(0)\n"
    "        Some(url) ->\n"
    "            match net.post(url, \"hello\")\n"
    "                Ok(b) -> stdio.println(\"[${b}]\")\n"
    "                Err(e) -> stdio.println(\"ERR\")\n"
    "        None -> stdio.println(\"noarg\")\n"
)


class SpecParsing(unittest.TestCase):
    """The CLI suffix parser + the per-method normalizer (no toolchain)."""

    def test_get_suffix_scopes_to_get_only(self):
        host, access = _parse_allow_host_spec("api.example.com:get")
        self.assertEqual((host, access), ("api.example.com", "get"))

    def test_post_suffix_scopes_to_post_only(self):
        host, access = _parse_allow_host_spec("api.example.com:post")
        self.assertEqual((host, access), ("api.example.com", "post"))

    def test_no_suffix_is_both(self):
        host, access = _parse_allow_host_spec("api.example.com")
        self.assertEqual((host, access), ("api.example.com", "both"))

    def test_port_is_not_a_suffix(self):
        # h:8080 -> host h, port 8080 (NOT a method suffix); the whole spec
        # normalizes to the bare host and the grant is both.
        host, access = _parse_allow_host_spec("api.example.com:8080")
        self.assertEqual((host, access), ("api.example.com", "both"))

    def test_ipv6_with_get_suffix(self):
        # [::1]:get -> the head [::1] is a valid host, so :get IS a suffix.
        host, access = _parse_allow_host_spec("[::1]:get")
        self.assertEqual((host, access), ("::1", "get"))

    def test_ipv6_with_port_is_not_a_suffix(self):
        # [::1]:8080 -> host ::1, port 8080 (8080 is not get/post).
        host, access = _parse_allow_host_spec("[::1]:8080")
        self.assertEqual((host, access), ("::1", "both"))

    def test_bare_ipv6_is_both(self):
        host, access = _parse_allow_host_spec("[::1]")
        self.assertEqual((host, access), ("::1", "both"))

    def test_url_with_get_suffix(self):
        host, access = _parse_allow_host_spec("https://api.example.com/x:get")
        self.assertEqual((host, access), ("api.example.com", "get"))

    def test_empty_head_before_suffix_is_bad(self):
        # ":get" has an empty head, so :get is NOT a suffix and the whole
        # thing fails to normalize to a host.
        host, _access = _parse_allow_host_spec(":get")
        self.assertIsNone(host)

    def test_normalize_partitions_by_method(self):
        grant, bad = _normalize_allow_hosts(
            ["a.example:get", "b.example:post", "c.example"],
        )
        self.assertEqual(bad, [])
        self.assertEqual(grant.get_hosts, frozenset({"a.example", "c.example"}))
        self.assertEqual(grant.post_hosts, frozenset({"b.example", "c.example"}))

    def test_get_and_post_specs_for_same_host_union_to_connect(self):
        grant, bad = _normalize_allow_hosts(["h.example:get", "h.example:post"])
        self.assertEqual(bad, [])
        self.assertIn("h.example", grant.get_hosts)
        self.assertIn("h.example", grant.post_hosts)
        self.assertEqual(grant.access_of("h.example"), "connect")

    def test_access_of_labels(self):
        grant = NetGrant(frozenset({"g.example"}), frozenset({"p.example"}))
        self.assertEqual(grant.access_of("g.example"), "get")
        self.assertEqual(grant.access_of("p.example"), "post")

    def test_bad_spec_collected(self):
        _grant, bad = _normalize_allow_hosts(["http://", "ok.example"])
        self.assertIn("http://", bad)


def _gate_bodies(wat: str) -> tuple[str, str]:
    """Return the WAT text of the ``$Net_host_allowed_get`` and
    ``$Net_host_allowed_post`` function bodies."""
    gi = wat.index("(func $Net_host_allowed_get")
    pi = wat.index("(func $Net_host_allowed_post")
    get_body = wat[gi:pi]
    rest = wat[pi:]
    nxt = rest.find("(func ", len("(func $Net_host_allowed_post"))
    post_body = rest if nxt < 0 else rest[:nxt]
    return get_body, post_body


class GateScoping(unittest.TestCase):
    """WAT structural proof: the two gates carry the method-scoped set
    (no toolchain -- reads the emitted text)."""

    def _wat(self, src, grant):
        from capa.ir import compile_wat
        module, result = _parse_analyze(src)
        return compile_wat(
            module, types=result.types, wasi=True, embed_manifest=False,
            net_operator_allow_hosts=grant,
        )

    def test_get_only_grant_populates_get_gate_not_post(self):
        wat = self._wat(_DYN_GET_SRC, NetGrant(frozenset({"api.example.com"})))
        get_body, post_body = _gate_bodies(wat)
        # The get gate scans (has a $str_eq membership test); the post gate
        # is empty (falls straight through to i32.const 0).
        self.assertIn("call $str_eq", get_body)
        self.assertNotIn("call $str_eq", post_body)

    def test_post_only_grant_populates_post_gate_not_get(self):
        wat = self._wat(
            _DYN_POST_SRC,
            NetGrant(frozenset(), frozenset({"api.example.com"})),
        )
        get_body, post_body = _gate_bodies(wat)
        self.assertIn("call $str_eq", post_body)
        self.assertNotIn("call $str_eq", get_body)

    def test_no_suffix_grant_populates_both_gates(self):
        wat = self._wat(
            _DYN_GET_SRC,
            NetGrant(frozenset({"api.example.com"}),
                     frozenset({"api.example.com"})),
        )
        get_body, post_body = _gate_bodies(wat)
        self.assertIn("call $str_eq", get_body)
        self.assertIn("call $str_eq", post_body)


class SbomScope(unittest.TestCase):
    """The operator-declared-grants block + CycloneDX / SPDX render the
    access scope (no toolchain)."""

    def test_grants_block_records_access(self):
        block = _operator_grants_from_args(
            None, ["g.example:get", "p.example:post", "c.example"],
        )
        by_host = {e["host"]: e["access"] for e in block["allow_hosts"]}
        self.assertEqual(by_host["g.example"], "get")
        self.assertEqual(by_host["p.example"], "post")
        self.assertEqual(by_host["c.example"], "connect")

    def test_cyclonedx_renders_scope(self):
        from capa.manifest import build_cyclonedx
        module, _result = _parse_analyze(_DYN_GET_SRC)
        block = _operator_grants_from_args(None, ["g.example:get"])
        cdx = build_cyclonedx(
            module, operator_declared_grants=block,
            timestamp="2020-01-01T00:00:00Z",
            serial_number="urn:uuid:00000000-0000-0000-0000-000000000000",
        )
        props = cdx["metadata"]["properties"]
        vals = [
            p["value"] for p in props
            if p["name"] == "capa:operator_declared_grant:allow-host"
        ]
        self.assertEqual(vals, ["g.example [get]"])

    def test_spdx_renders_scope(self):
        from capa.manifest import build_spdx
        module, _result = _parse_analyze(_DYN_POST_SRC)
        block = _operator_grants_from_args(None, ["p.example:post"])
        spdx = build_spdx(
            module, operator_declared_grants=block,
            timestamp="2020-01-01T00:00:00Z",
        )
        comments = [
            a["comment"]
            for pkg in spdx.get("packages", [])
            for a in pkg.get("annotations", [])
        ]
        self.assertTrue(
            any("allow-host=p.example [post]" in c for c in comments),
            comments,
        )


def _run(src, grant, args, *, post_server=False):
    from capa.ir import compile_wasm, compile_wit, compute_net_ceiling
    from capa.cli import _wrap_as_component
    from capa.runtime._wasm_component_host import WasmComponentHost
    module, result = _parse_analyze(src)
    core = compile_wasm(
        module, types=result.types, wasi=True,
        net_operator_allow_hosts=grant,
    )
    wit = compile_wit(module, types=result.types, wasi=True)
    comp = _wrap_as_component(core, wit, wasi=True)
    ceiling = compute_net_ceiling(module, types=result.types)
    host = WasmComponentHost(args=args, wasi=True, net_ceiling=ceiling)
    return _wasi_run_capture(host, comp)


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_wasi_http(),
    "wasm-tools and/or wasmtime-py with wasi:http not installed",
)
class MethodScopeRuntime(unittest.TestCase):
    """Runtime enforcement over wasi:http: get-only denies post + vice
    versa; no-suffix reaches both."""

    def test_get_grant_reaches_get(self):
        with _LocalHttpServer(b"read-body") as auth:
            out = _run(
                _DYN_GET_SRC,
                NetGrant(frozenset({"127.0.0.1"})),
                (f"http://{auth}/p",),
            )
        self.assertEqual(out, "[read-body]\n")

    def test_get_grant_denies_post(self):
        # h:get grants READ only: a dynamic net.post to the SAME granted
        # host is denied by $Net_host_allowed_post (h not in the post set).
        with _LocalPostServer(mode="echo") as auth:
            out = _run(
                _DYN_POST_SRC,
                NetGrant(frozenset({"127.0.0.1"})),
                (f"http://{auth}/p",),
            )
        self.assertEqual(out, "ERR\n")

    def test_post_grant_reaches_post(self):
        with _LocalPostServer(mode="echo") as auth:
            out = _run(
                _DYN_POST_SRC,
                NetGrant(frozenset(), frozenset({"127.0.0.1"})),
                (f"http://{auth}/p",),
            )
        self.assertEqual(out, "[hello]\n")

    def test_post_grant_denies_get(self):
        with _LocalHttpServer(b"read-body") as auth:
            out = _run(
                _DYN_GET_SRC,
                NetGrant(frozenset(), frozenset({"127.0.0.1"})),
                (f"http://{auth}/p",),
            )
        self.assertEqual(out, "ERR\n")

    def test_no_suffix_grant_reaches_both(self):
        both = NetGrant(frozenset({"127.0.0.1"}), frozenset({"127.0.0.1"}))
        with _LocalHttpServer(b"read-body") as auth:
            got = _run(_DYN_GET_SRC, both, (f"http://{auth}/p",))
        self.assertEqual(got, "[read-body]\n")
        with _LocalPostServer(mode="echo") as auth:
            posted = _run(_DYN_POST_SRC, both, (f"http://{auth}/p",))
        self.assertEqual(posted, "[hello]\n")


if __name__ == "__main__":
    unittest.main()
