"""WASI Net emission (wasi:http + guest-side attenuation).

The host gate, get / post request chains, restrict_to / allows, url
extraction, and their error helpers. Split out of the former
single-file ``_wasi.py`` with no behaviour change.
"""

from __future__ import annotations

from ._constants import _WASI_NET_READ_CHUNK


class _WasiNetMixin:
    """Net wrappers of the ``--wasi`` emitter; folded into
    ``WasmEmitter`` via ``_WasiEmissionMixin``."""

    def _wasi_net_needs_str_eq(self) -> bool:
        """True when ``--wasi`` is active and the program reaches ANY Net
        op, all of which scan a ``(ptr, len)`` host list via ``$str_eq``:
        ``get`` / ``post`` (the static ceiling gate ``$Net_host_allowed``
        AND the fine allow-list gate ``$Net_handle_allows``), ``allows``
        (allow-list membership), and ``restrict_to`` (it consults the
        parent's allow-list to compute the intersection). The default path
        routes the host membership through the capa:host bridge, so this
        gate is WASI-only; it ensures ``$str_eq`` is emitted even when the
        program uses no other String-equality operation. (An empty Net
        ceiling / allow-list emits a gate with no ``$str_eq`` call, but
        gating on any Net op being present is simpler and the unused helper
        is a few harmless bytes.)"""
        return self._wasi and any(
            c == "Net" for (c, _m) in self._used_caps
        )


    def _wasi_net_uses_attenuation(self) -> bool:
        """True when ``--wasi`` is active and the program reaches
        ``Net.restrict_to`` (which allocates the fresh allow-list
        ``List<String>`` header + data buffer for the narrowed Net value
        via ``$alloc``). Gates the bump-allocator / heap-top emission so a
        narrow-only Net program (no get / post and no other heap user)
        still gets the allocator. ``allows`` alone does NOT allocate (it
        only scans an existing allow-list), so it is not gated here; a
        program that calls ``allows`` first called ``restrict_to`` to
        obtain a restricted Net, which already pulls the allocator in.
        ``get`` / ``post`` always pull ``$alloc`` through their
        canonical-ABI ret areas, so they are not gated here either."""
        return self._wasi and ("Net", "restrict_to") in self._used_caps


    def _emit_wasi_net_handle_allows_helper(self) -> None:
        """``$Net_handle_allows (handle i32, host_ptr i32, host_len i32)
        -> i32`` -> 1 iff the Net value ``handle`` admits ``host`` by the
        FINE attenuation (``restrict_to``) allow-list.

        The shared exact-hostname membership test behind both ``allows``
        (its whole body) and every Net request op (its fail-closed gate,
        layered ON TOP of the static ceiling ``$Net_host_allowed``):

          handle == 0  -> 1 (unrestricted root Net: every host allowed)
          else         -> handle is a pointer to a List<String> header
                          (len@0, data_ptr@8) of the hostnames the
                          ``restrict_to`` chain narrowed to. Scan the N
                          packed ``(str_ptr, str_len)`` entries; return 1
                          on the first ``$str_eq`` match, 0 if none match.

        Mirrors ``Net.allows`` (``self._allowed is None or host in
        self._allowed``) EXACTLY: membership is byte-exact equality
        (``$str_eq``), NOT prefix / substring containment (the Fs model)
        and NOT case-folding -- a host that is a substring or differing-
        case of an allowed host does NOT pass, which is the security
        point (``restrict_to("example.com")`` admits neither
        ``evil-example.com`` nor ``example.com.evil.com`` nor
        ``Example.com``). The oracle stores the ``restrict_to`` arg
        VERBATIM and only ``get`` / ``post`` lowercase the URL host before
        the membership test; this guest side matches because the
        ``restrict_to`` arg bytes are interned verbatim and the request-op
        gate passes the already-lowercased ``split_net_url`` host.

        An EMPTY allow-list (a non-zero header with len 0, produced by a
        ``restrict_to`` chain whose intersection collapsed, e.g.
        ``restrict_to(A).restrict_to(B)`` with A != B) admits NOTHING:
        the scan finds no entry and returns 0, matching the oracle's empty
        ``frozenset``."""
        self._write(
            "(func $Net_handle_allows (param $handle i32) "
            "(param $host_ptr i32) (param $host_len i32) (result i32)"
        )
        self._indent += 1
        self._write("(local $data i32)")
        self._write("(local $count i32)")
        self._write("(local $i i32)")
        self._write("(local $entry i32)")
        # Unrestricted root: handle 0 admits every host.
        self._write("local.get $handle")
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        self._write("i32.const 1")
        self._write("return")
        self._indent -= 1
        self._write("end")
        # Restricted: scan the allow-list List<String> the handle points
        # to. count = header.len@0; data = header.data_ptr@8.
        self._write("local.get $handle")
        self._write("i32.load offset=0")
        self._write("local.set $count")
        self._write("local.get $handle")
        self._write("i32.load offset=8")
        self._write("local.set $data")
        self._write("i32.const 0")
        self._write("local.set $i")
        self._write("(block $net_allow_done")
        self._indent += 1
        self._write("(loop $net_scan_hosts")
        self._indent += 1
        # if i >= count, break (no match).
        self._write("local.get $i")
        self._write("local.get $count")
        self._write("i32.ge_u")
        self._write("br_if $net_allow_done")
        # entry = data + i*8 (packed (str_ptr@0, str_len@4)).
        self._write("local.get $data")
        self._write("local.get $i")
        self._write("i32.const 8")
        self._write("i32.mul")
        self._write("i32.add")
        self._write("local.set $entry")
        # str_eq(entry.ptr@0, entry.len@4, host_ptr, host_len) -> hit.
        self._write("local.get $entry")
        self._write("i32.load offset=0")
        self._write("local.get $entry")
        self._write("i32.load offset=4")
        self._write("local.get $host_ptr")
        self._write("local.get $host_len")
        self._write("call $str_eq")
        self._write("if")
        self._indent += 1
        self._write("i32.const 1")
        self._write("return")
        self._indent -= 1
        self._write("end")
        # i += 1; continue.
        self._write("local.get $i")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $i")
        self._write("br $net_scan_hosts")
        self._indent -= 1
        self._write(")")
        self._indent -= 1
        self._write(")")
        # No match.
        self._write("i32.const 0")
        self._indent -= 1
        self._write(")")


    def _emit_wasi_net_allows_wrapper(self) -> None:
        """``$Net_allows (handle i32, host_ptr i32, host_len i32) ->
        i32`` -> the Bool result of ``net.allows(host)``.

        Matches the call shape ``_emit_cap_allows_with_handle`` produces
        (receiver handle + host (ptr, len) -> i32 Bool). Delegates
        straight to the shared ``$Net_handle_allows`` so the query answer
        is identical to the fine-attenuation gate every Net request op
        consults (no guest-side divergence) and to the Python oracle.

        Unlike ``get`` / ``post`` (which lowercase the URL host), this
        query passes the arg through UNCHANGED, exactly as the oracle's
        ``Net.allows`` does no case-folding on its argument: a query of a
        differing-case host against a verbatim-stored allow-list entry
        therefore returns false, byte-identical to the oracle."""
        self._write(
            "(func $Net_allows (param $handle i32) (param $host_ptr i32) "
            "(param $host_len i32) (result i32)"
        )
        self._indent += 1
        self._write("local.get $handle")
        self._write("local.get $host_ptr")
        self._write("local.get $host_len")
        self._write("call $Net_handle_allows")
        self._indent -= 1
        self._write(")")


    def _emit_wasi_net_restrict_to_wrapper(self) -> None:
        """``$Net_restrict_to (handle i32, host_ptr i32, host_len i32) ->
        i32`` -> a fresh Net value (pointer to a new ``List<String>``
        allow-list holding the single admitted host, or a non-zero
        zero-length header when the new host is NOT admitted by the
        parent -- a restricted-to-nothing Net).

        Matches the call shape ``_emit_net_restrict_to`` produces
        (receiver handle + the host String as (ptr, len)).

        Builds the INTERSECTION of the parent's allow-list with
        ``{host}``, identical to ``Net.restrict_to``
        (``new = frozenset({host}); if parent is not None: new = new &
        parent``, ``capa/runtime/_capabilities.py:565-569``):

          parent unrestricted (handle == 0): result = [host] (the root
            admits every host, so the intersection is the new host).
          parent restricted: result = [host] if the parent admits host
            (``$Net_handle_allows``), else [] (an empty allow-list = a
            Net that admits nothing). This is why a chain
            ``restrict_to(A).restrict_to(B)`` with A != B collapses to the
            empty set: B is not in the parent's ``{A}``, so the
            intersection is empty -- exactly the oracle's
            ``{B} & {A} == frozenset()``.

        Allocates a 16-byte List<String> header + a data buffer for at
        most ONE packed ``(str_ptr, str_len)`` entry. The host BYTES are
        SHARED, not copied (the arg already lives in linear memory for the
        program's lifetime); only the (ptr, len) pair is stored, VERBATIM
        (no case-folding, so the verbatim-host membership semantics of
        ``allows`` hold). The header is always non-zero (``$alloc`` never
        returns 0; the heap starts above the static data region), so an
        EMPTY intersection still yields a valid pointer to a zero-length
        allow-list = a restricted Net distinct from the unrestricted 0
        sentinel, matching the oracle's empty-but-not-None ``frozenset``.
        The parent header is never mutated (a fresh header is always
        allocated), so deriving a narrower child never affects the parent
        (the oracle's immutable ``Net`` value)."""
        self._write(
            "(func $Net_restrict_to (param $handle i32) "
            "(param $host_ptr i32) (param $host_len i32) (result i32)"
        )
        self._indent += 1
        self._write("(local $header i32)")
        self._write("(local $out_data i32)")
        self._write("(local $out_n i32)")
        # out_n = 1 iff the parent admits the new host, else 0. For an
        # unrestricted parent ($handle == 0) $Net_handle_allows returns 1,
        # so result = [host]; for a restricted parent it returns
        # membership, so result = {host} & parent (the intersection the
        # oracle computes).
        self._write("local.get $handle")
        self._write("local.get $host_ptr")
        self._write("local.get $host_len")
        self._write("call $Net_handle_allows")
        self._write("local.set $out_n")
        # Allocate the result header (16 bytes) + a data buffer sized for
        # the single packed (ptr, len) entry (8 bytes). The over-
        # allocation when out_n == 0 is harmless; the header.len records
        # the actual count so the scan never reads past it.
        self._write("i32.const 16")
        self._write("call $alloc")
        self._write("local.set $header")
        self._write("i32.const 8")
        self._write("call $alloc")
        self._write("local.set $out_data")
        # If admitted, store (host_ptr, host_len) as the single entry.
        self._write("local.get $out_n")
        self._write("if")
        self._indent += 1
        self._write("local.get $out_data")
        self._write("local.get $host_ptr")
        self._write("i32.store offset=0")
        self._write("local.get $out_data")
        self._write("local.get $host_len")
        self._write("i32.store offset=4")
        self._indent -= 1
        self._write("end")
        # Fill the List<String> header: len@0 = cap@4 = out_n,
        # data_ptr@8 = out_data, pad@12 = 0.
        self._write("local.get $header")
        self._write("local.get $out_n")
        self._write("i32.store offset=0")
        self._write("local.get $header")
        self._write("local.get $out_n")
        self._write("i32.store offset=4")
        self._write("local.get $header")
        self._write("local.get $out_data")
        self._write("i32.store offset=8")
        self._write("local.get $header")
        self._write("i32.const 0")
        self._write("i32.store offset=12")
        # Return the header pointer (the new restricted Net value).
        self._write("local.get $header")
        self._indent -= 1
        self._write(")")

    # ----- guest-side Fs attenuation (Level 2) -------------------


    def _emit_wasi_net_host_allowed_helper(self) -> None:
        """Emit the TWO per-method guest-side host-ceiling gates,
        ``$Net_host_allowed_get`` and ``$Net_host_allowed_post`` (each
        ``(host_ptr i32, host_len i32) -> i32``, 1 iff ``host`` is admitted
        for that method).

        The GUEST-SIDE host ceiling (codegen-enforced, the honest Net
        guarantee). Unlike Fs preopens / Env env-set -- both Level 1,
        imposed by the WASI host at instantiate -- wasmtime's wasi:http
        C-API (``set-wasi-http``) is ALLOW-ALL with no allowed-hosts
        surface in this release, so there is no host ceiling to map onto.
        The ceiling is enforced HERE, in compiler-generated guest code:
        each helper scans a set of hosts, each a data-segment literal
        interned up front, and returns 1 on the first ``$str_eq`` match, 0
        if none match.

        PER-METHOD SCOPE (--allow-host Phase 2, 2026-07-06): the admitted
        set is the UNION of the compiler-derived literal hosts
        (``NetCeiling.hosts``, COMBINED into both methods -- the literal
        ``net.get`` / ``net.post`` source is the truth) and the
        method-scoped operator grant: ``$Net_host_allowed_get`` adds the
        get-granted hosts, ``$Net_host_allowed_post`` adds the post-granted
        hosts. So a ``--allow-host h:get`` grant admits a dynamic
        ``net.get`` to ``h`` but the post gate denies a dynamic
        ``net.post`` to ``h`` (h is not in the post set), the least-
        authority point. A no-suffix grant lands in both sets, so both
        gates admit it (Phase-1 behaviour preserved). The fine
        ``restrict_to`` gate (``$Net_handle_allows``) still layers ON TOP,
        so a granted host can still be narrowed away at runtime.

        A DYNAMIC url contributes no literal host, so its host is never in
        the ceiling and, absent a matching method-scoped grant, the call is
        denied at runtime (fail-closed), matching the Fs dynamic-path
        fail-closed policy. An EMPTY set emits a gate that always returns 0,
        denying every host."""
        ceiling = self._net_ceiling
        ceiling_hosts = ceiling.hosts if ceiling is not None else frozenset()
        self._emit_wasi_net_host_allowed_variant(
            "$Net_host_allowed_get",
            ceiling_hosts | self._net_operator_get_hosts,
        )
        self._emit_wasi_net_host_allowed_variant(
            "$Net_host_allowed_post",
            ceiling_hosts | self._net_operator_post_hosts,
        )

    def _emit_wasi_net_host_allowed_variant(
        self, name: str, hosts: "frozenset[str]",
    ) -> None:
        """Emit one host-ceiling gate ``name (host_ptr, host_len) -> i32``
        that returns 1 iff ``host`` is in ``hosts`` (a linear ``$str_eq``
        scan). Shared body of the get / post gates; the only difference
        between them is the host set (see
        :meth:`_emit_wasi_net_host_allowed_helper`)."""
        self._write(
            f"(func {name} (param $host_ptr i32) "
            "(param $host_len i32) (result i32)"
        )
        self._indent += 1
        for h in sorted(hosts):
            off, length = self._intern_string(h)
            self._write("local.get $host_ptr")
            self._write("local.get $host_len")
            self._write(f"i32.const {off}")
            self._write(f"i32.const {length}")
            self._write("call $str_eq")
            self._write("if")
            self._indent += 1
            self._write("i32.const 1")
            self._write("return")
            self._indent -= 1
            self._write("end")
        self._write("i32.const 0")
        self._indent -= 1
        self._write(")")


    def _emit_wasi_net_get_wrapper(self) -> None:
        """``$Net_get (handle, host_ptr, host_len, scheme, auth_ptr,
        auth_len, path_ptr, path_len, ret_area)`` -> writes a
        ``result<string, io-error>`` (20-byte canonical-ABI shape) into
        ``ret_area``.

        Matches the call shape ``_emit_wasi_net_get_call`` produces, so the
        existing ``result_string_io_error`` materialiser lifts the result
        into a Capa ``Result<String, IoError>`` unchanged, exactly as the
        capa:host Net.get does. The url was split at the call site into its
        HOST (the ceiling key), SCHEME (0 HTTP / 1 HTTPS), AUTHORITY
        (host:port), and PATH-with-query (all compile-time literals); a
        DYNAMIC url never reaches this wrapper (the call site fail-closes
        directly).

        GUEST-SIDE HOST GATE (codegen-enforced ceiling): consult
        ``$Net_host_allowed_get(host)`` FIRST (the GET-scoped gate: the
        static ceiling plus the ``--allow-host h[:get]`` grant); a host not
        admitted for GET writes ``Err(IoError)`` and returns WITHOUT
        building any request -- the honest Net guarantee (wasi:http is
        allow-all host-side, so the ceiling lives here).

        wasi:http GET chain (validated end-to-end by the oracle spike
        against wasm-tools 1.249.0 / wasmtime 45.0.0; the scratch offsets
        are recorded in ``__init__._wasi_net_scratch_offset``):

          1. fields.new() -> own<fields>.
          2. outgoing-request.new(fields) [CONSUMES fields].
          3. set-method(GET=0); set-scheme(some(scheme));
             set-authority(some(authority));
             set-path-with-query(some(path)). Each returns a flat
             ``result`` i32 (no payload), dropped.
          4. req.body() -> result<own<outgoing-body>> @S+0 (value @+4).
          5. outgoing-body.finish(obody, none) -> result<_, ec> @S+8
             [CONSUMES obody].
          6. outgoing-handler.handle(req, none) ->
             result<own<future>, ec> @S+16 [CONSUMES req]. The Ok value is
             at @+8 (error-code forces 8-alignment). On Err: req + obody
             already consumed -> write Err, return.
          7. future.subscribe() -> own<pollable>; pollable.block();
             drop pollable. Synchronous wait.
          8. LOOP future.get() -> option<result<result<own<resp>, ec>>>
             @S+32 (option disc @+0, outer result disc @+8, inner result
             disc @+16, own<resp> @+24). none -> not ready: resubscribe,
             block, drop pollable, retry. some + outer Err -> already
             consumed -> Err. some + inner Err -> transport error -> Err.
          9. resp.status(); FAIL-CLOSED if status is NOT in [200,299] ->
             drop resp, write Err, return WITHOUT reading the body. This is
             a DELIBERATE, more-restrictive DIVERGENCE from the urllib
             oracle / capa:host (which FOLLOW redirects via urllib): the
             guest does NOT follow 3xx redirects, treating any non-2xx
             (3xx, <200, 4xx, 5xx) as Err, because an implicit redirect
             from an allowed host to a non-allowed one would bypass the
             Net host ceiling + fine allow-list (an SSRF / host-authority
             bypass). See docs/design/wasi_mode.md. Else consume() ->
             result<own<ibody>> @S+64 (value @+4); stream() ->
             result<own<istream>> @S+72 (@+4).
         10. LOOP input-stream.blocking-read(CHUNK) ->
             result<list<u8>, stream-error> @S+80, accumulating chunk bytes
             into a geometrically-grown heap buffer (identical to Fs.read).
             stream-error disc @+4: 1 == closed (EOF) -> break; 0 ==
             last-operation-failed -> drop the carried error @+8, drop
             stream + ibody + resp, write Err, return.
         11. drop input-stream, incoming-body, incoming-response; write
             Ok(String) = (buf, buf_len). The accumulated bytes are the raw
             response body; the Capa String is UTF-8 by construction,
             matching the oracle's ``resp.read().decode("utf-8")``.

        RESOURCE DROPS fire on EVERY exit path so no OWN handle leaks and
        none is dropped twice (the consuming calls -- outgoing-request by
        handle, outgoing-body by finish -- are the only handles NOT
        dropped, and only on the paths that reach them; the future is
        dropped after ``get`` on every path that read it). Proven by a
        1500-GET leak loop in the oracle spike with no handle
        exhaustion."""
        chunk = _WASI_NET_READ_CHUNK
        S = self._wasi_net_scratch_offset
        body_ret = S + 0
        finish_ret = S + 8
        handle_ret = S + 16
        get_ret = S + 32
        consume_ret = S + 64
        stream_ret = S + 72
        read_ret = S + 80
        msg_off, msg_len = self._intern_string("HTTP GET failed")
        self._write(
            "(func $Net_get (param $handle i32) (param $host_ptr i32) "
            "(param $host_len i32) (param $scheme i32) "
            "(param $auth_ptr i32) (param $auth_len i32) "
            "(param $path_ptr i32) (param $path_len i32) "
            "(param $ret_area i32)"
        )
        self._indent += 1
        for loc in ("$fields", "$req", "$obody", "$future", "$pollable",
                    "$resp", "$ibody", "$stream", "$status", "$buf",
                    "$buf_cap", "$buf_len", "$chunk_ptr", "$chunk_len",
                    "$need", "$newcap", "$newbuf"):
            self._write(f"(local {loc} i32)")
        # Host gate (static ceiling + GET-scoped operator grant): a host
        # not admitted for GET (never named as a literal and not granted
        # via --allow-host h[:get]) is denied here.
        self._write("local.get $host_ptr")
        self._write("local.get $host_len")
        self._write("call $Net_host_allowed_get")
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        self._emit_wasi_net_err(msg_off, msg_len)
        self._write("return")
        self._indent -= 1
        self._write("end")
        # Fine attenuation gate (restrict_to allow-list): a host outside
        # the receiver Net's allow-list is denied here, fail-closed, BEFORE
        # any request is built. Layered ON TOP of the ceiling: the request
        # passes only when the host is in the ceiling AND in the cap's fine
        # allow-list (the handle 0 root admits all, so this is a no-op for
        # an unrestricted Net). Mirrors the oracle's ``if not
        # self.allows(host): return Err(IoError(...))`` prologue.
        self._write("local.get $handle")
        self._write("local.get $host_ptr")
        self._write("local.get $host_len")
        self._write("call $Net_handle_allows")
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        self._emit_wasi_net_err(msg_off, msg_len)
        self._write("return")
        self._indent -= 1
        self._write("end")
        # Build the request.
        self._write("call $wasi_http_fields_new")
        self._write("local.set $fields")
        self._write("local.get $fields")
        self._write("call $wasi_http_request_new")
        self._write("local.set $req")
        self._write("local.get $req")
        self._write("i32.const 0")
        self._write("i32.const 0")
        self._write("i32.const 0")
        self._write("call $wasi_http_set_method")
        self._write("drop")
        self._write("local.get $req")
        self._write("i32.const 1")
        self._write("local.get $scheme")
        self._write("i32.const 0")
        self._write("i32.const 0")
        self._write("call $wasi_http_set_scheme")
        self._write("drop")
        self._write("local.get $req")
        self._write("i32.const 1")
        self._write("local.get $auth_ptr")
        self._write("local.get $auth_len")
        self._write("call $wasi_http_set_authority")
        self._write("drop")
        self._write("local.get $req")
        self._write("i32.const 1")
        self._write("local.get $path_ptr")
        self._write("local.get $path_len")
        self._write("call $wasi_http_set_path")
        self._write("drop")
        # obody = req.body().value @body_ret+4.
        self._write("local.get $req")
        self._write(f"i32.const {body_ret}")
        self._write("call $wasi_http_request_body")
        self._write(f"i32.const {body_ret}")
        self._write("i32.load offset=4")
        self._write("local.set $obody")
        # finish(obody, none) [CONSUMES obody].
        self._write("local.get $obody")
        self._write("i32.const 0")
        self._write("i32.const 0")
        self._write(f"i32.const {finish_ret}")
        self._write("call $wasi_http_body_finish")
        # handle(req, none) [CONSUMES req].
        self._write("local.get $req")
        self._write("i32.const 0")
        self._write("i32.const 0")
        self._write(f"i32.const {handle_ret}")
        self._write("call $wasi_http_handle")
        self._write(f"i32.const {handle_ret}")
        self._write("i32.load8_u offset=0")
        self._write("if")
        self._indent += 1
        self._emit_wasi_net_err(msg_off, msg_len)
        self._write("return")
        self._indent -= 1
        self._write("end")
        # future = handle_ret.value @+8.
        self._write(f"i32.const {handle_ret}")
        self._write("i32.load offset=8")
        self._write("local.set $future")
        # subscribe + block + drop, then loop get.
        self._write("local.get $future")
        self._write("call $wasi_http_future_subscribe")
        self._write("local.set $pollable")
        self._write("local.get $pollable")
        self._write("call $wasi_io_pollable_block")
        self._write("local.get $pollable")
        self._write("call $wasi_io_drop_pollable")
        self._write("(block $net_got")
        self._indent += 1
        self._write("(loop $net_poll")
        self._indent += 1
        self._write("local.get $future")
        self._write(f"i32.const {get_ret}")
        self._write("call $wasi_http_future_get")
        self._write(f"i32.const {get_ret}")
        self._write("i32.load8_u offset=0")
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        self._write("local.get $future")
        self._write("call $wasi_http_future_subscribe")
        self._write("local.set $pollable")
        self._write("local.get $pollable")
        self._write("call $wasi_io_pollable_block")
        self._write("local.get $pollable")
        self._write("call $wasi_io_drop_pollable")
        self._write("br $net_poll")
        self._indent -= 1
        self._write("end")
        self._write("br $net_got")
        self._indent -= 1
        self._write(")")
        self._indent -= 1
        self._write(")")
        # outer result disc @get_ret+8 != 0 -> already consumed -> Err.
        self._write(f"i32.const {get_ret}")
        self._write("i32.load8_u offset=8")
        self._write("if")
        self._indent += 1
        self._write("local.get $future")
        self._write("call $wasi_http_drop_future")
        self._emit_wasi_net_err(msg_off, msg_len)
        self._write("return")
        self._indent -= 1
        self._write("end")
        # inner result disc @get_ret+16 != 0 -> transport error -> Err.
        self._write(f"i32.const {get_ret}")
        self._write("i32.load8_u offset=16")
        self._write("if")
        self._indent += 1
        self._write("local.get $future")
        self._write("call $wasi_http_drop_future")
        self._emit_wasi_net_err(msg_off, msg_len)
        self._write("return")
        self._indent -= 1
        self._write("end")
        # resp = own<incoming-response> @get_ret+24.
        self._write(f"i32.const {get_ret}")
        self._write("i32.load offset=24")
        self._write("local.set $resp")
        self._write("local.get $future")
        self._write("call $wasi_http_drop_future")
        # FAIL-CLOSED on any non-2xx status. Only 200-299 yields Ok(body);
        # ANY other status (3xx redirects, <200, and 4xx/5xx as before)
        # drops the response and returns Err WITHOUT reading the body. This
        # DELIBERATELY diverges (in the more restrictive direction) from the
        # urllib oracle / capa:host, which FOLLOW redirects via urllib: the
        # guest does NOT follow redirects, because an implicit redirect from
        # an allowed host to a non-allowed host would bypass the static Net
        # ceiling + the fine host allow-list (an SSRF / host-authority bypass
        # vector). Refusing 3xx preserves the host/capability guarantee
        # (secure-by-default; CRA / NIS2 aligned). See
        # docs/design/wasi_mode.md. status NOT in [200,299] -> Err.
        self._write("local.get $resp")
        self._write("call $wasi_http_response_status")
        self._write("local.set $status")
        self._write("local.get $status")
        self._write("i32.const 200")
        self._write("i32.lt_u")
        self._write("local.get $status")
        self._write("i32.const 299")
        self._write("i32.gt_u")
        self._write("i32.or")
        self._write("if")
        self._indent += 1
        self._write("local.get $resp")
        self._write("call $wasi_http_drop_response")
        self._emit_wasi_net_err(msg_off, msg_len)
        self._write("return")
        self._indent -= 1
        self._write("end")
        # consume -> result<own<incoming-body>> @consume_ret (value @+4).
        self._write("local.get $resp")
        self._write(f"i32.const {consume_ret}")
        self._write("call $wasi_http_response_consume")
        self._write(f"i32.const {consume_ret}")
        self._write("i32.load8_u offset=0")
        self._write("if")
        self._indent += 1
        self._write("local.get $resp")
        self._write("call $wasi_http_drop_response")
        self._emit_wasi_net_err(msg_off, msg_len)
        self._write("return")
        self._indent -= 1
        self._write("end")
        self._write(f"i32.const {consume_ret}")
        self._write("i32.load offset=4")
        self._write("local.set $ibody")
        # stream -> result<own<input-stream>> @stream_ret (value @+4).
        self._write("local.get $ibody")
        self._write(f"i32.const {stream_ret}")
        self._write("call $wasi_http_body_stream")
        self._write(f"i32.const {stream_ret}")
        self._write("i32.load8_u offset=0")
        self._write("if")
        self._indent += 1
        self._write("local.get $ibody")
        self._write("call $wasi_http_drop_incoming_body")
        self._write("local.get $resp")
        self._write("call $wasi_http_drop_response")
        self._emit_wasi_net_err(msg_off, msg_len)
        self._write("return")
        self._indent -= 1
        self._write("end")
        self._write(f"i32.const {stream_ret}")
        self._write("i32.load offset=4")
        self._write("local.set $stream")
        # Accumulation buffer.
        self._write("i32.const 0")
        self._write("call $alloc")
        self._write("local.set $buf")
        self._write("i32.const 0")
        self._write("local.set $buf_cap")
        self._write("i32.const 0")
        self._write("local.set $buf_len")
        # blocking-read loop.
        self._write("(block $net_read_done")
        self._indent += 1
        self._write("(loop $net_read")
        self._indent += 1
        self._write("local.get $stream")
        self._write(f"i64.const {chunk}")
        self._write(f"i32.const {read_ret}")
        self._write("call $wasi_io_blocking_read")
        self._write(f"i32.const {read_ret}")
        self._write("i32.load8_u offset=0")
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        self._write(f"i32.const {read_ret}")
        self._write("i32.load offset=4")
        self._write("local.set $chunk_ptr")
        self._write(f"i32.const {read_ret}")
        self._write("i32.load offset=8")
        self._write("local.set $chunk_len")
        self._write("local.get $buf_len")
        self._write("local.get $chunk_len")
        self._write("i32.add")
        self._write("local.set $need")
        self._write("local.get $need")
        self._write("local.get $buf_cap")
        self._write("i32.gt_u")
        self._write("if")
        self._indent += 1
        self._write("local.get $buf_cap")
        self._write("i32.const 1")
        self._write("i32.shl")
        self._write("local.get $need")
        self._write("i32.lt_u")
        self._write("if (result i32)")
        self._indent += 1
        self._write("local.get $need")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        self._write("local.get $buf_cap")
        self._write("i32.const 1")
        self._write("i32.shl")
        self._indent -= 1
        self._write("end")
        self._write("local.set $newcap")
        self._write("local.get $newcap")
        self._write("call $alloc")
        self._write("local.set $newbuf")
        self._write("local.get $newbuf")
        self._write("local.get $buf")
        self._write("local.get $buf_len")
        self._write("memory.copy")
        self._write("local.get $newbuf")
        self._write("local.set $buf")
        self._write("local.get $newcap")
        self._write("local.set $buf_cap")
        self._indent -= 1
        self._write("end")
        self._write("local.get $buf")
        self._write("local.get $buf_len")
        self._write("i32.add")
        self._write("local.get $chunk_ptr")
        self._write("local.get $chunk_len")
        self._write("memory.copy")
        self._write("local.get $buf_len")
        self._write("local.get $chunk_len")
        self._write("i32.add")
        self._write("local.set $buf_len")
        self._write("br $net_read")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        self._write(f"i32.const {read_ret}")
        self._write("i32.load offset=4")
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        self._write(f"i32.const {read_ret}")
        self._write("i32.load offset=8")
        self._write("call $wasi_io_drop_error")
        self._write("local.get $stream")
        self._write("call $wasi_io_drop_input_stream")
        self._write("local.get $ibody")
        self._write("call $wasi_http_drop_incoming_body")
        self._write("local.get $resp")
        self._write("call $wasi_http_drop_response")
        self._emit_wasi_net_err(msg_off, msg_len)
        self._write("return")
        self._indent -= 1
        self._write("end")
        self._write("br $net_read_done")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write(")")
        self._indent -= 1
        self._write(")")
        # EOF: drop stream, ibody, resp.
        self._write("local.get $stream")
        self._write("call $wasi_io_drop_input_stream")
        self._write("local.get $ibody")
        self._write("call $wasi_http_drop_incoming_body")
        self._write("local.get $resp")
        self._write("call $wasi_http_drop_response")
        # Ok(String).
        self._write("local.get $ret_area")
        self._write("i32.const 0")
        self._write("i32.store offset=0")
        self._write("local.get $ret_area")
        self._write("local.get $buf")
        self._write("i32.store offset=4")
        self._write("local.get $ret_area")
        self._write("local.get $buf_len")
        self._write("i32.store offset=8")
        self._indent -= 1
        self._write(")")


    def _emit_wasi_net_post_wrapper(self) -> None:
        """``$Net_post (handle, host_ptr, host_len, scheme, auth_ptr,
        auth_len, path_ptr, path_len, body_ptr, body_len, ret_area)`` ->
        writes a ``result<string, io-error>`` (20-byte canonical-ABI shape)
        into ``ret_area``.

        REUSES the entire ``$Net_get`` chain (the host gate, the
        Fields -> OutgoingRequest -> set-* -> body -> finish -> handle ->
        future poll -> status -> consume -> stream -> input-stream read
        loop, the triple-result lift, the fail-closed non-2xx mapping
        (only 200-299 -> Ok; 3xx redirects are NOT followed, any non-2xx
        -> Err; see ``$Net_get``), and the
        resource drops on every exit path) and changes only TWO things:

          1. set-method sends POST (the ``method`` variant discriminant 2)
             instead of GET (0). No string is interned: a non-``other``
             method variant carries no payload, so the method ptr/len args
             are 0.
          2. BEFORE finish, the REQUEST body is written through the
             outgoing-body's output-stream (the NINTH OWN resource, unique
             to post): ``outgoing-body.write()`` -> output-stream, then the
             FLOW-CONTROLLED write loop the wasi:io contract mandates for a
             not-yet-sent body -- ``check-write`` for the permitted budget;
             a non-blocking ``write`` of <= budget bytes straight from
             linear memory (no copy); ``subscribe`` + ``pollable.block`` to
             await more permits when the budget is momentarily 0; a final
             non-blocking ``flush``. (The BLOCKING write-and-flush that
             Fs.write uses DEADLOCKS here: a wasi:http outgoing-body stream
             only drains once the request is sent at ``handle``, which runs
             AFTER the write loop, so blocking past the initial permit
             window never returns -- a 4097-byte body hangs while 4096
             succeeds.) The output-stream is then DROPPED (it is a CHILD of
             the outgoing-body and MUST be dropped before finish, else finish
             traps), and only then ``finish(obody, none)`` runs. A
             zero-length body runs the loop zero times (empty request body),
             matching the oracle's ``body.encode(\"utf-8\")`` of an empty
             string.

        The error message is the fixed ``HTTP POST failed`` (parity is on
        the Result DISCRIMINANT, as the get / Fs paths assert). Every OWN
        resource is dropped on every exit path: the GET chain's eight plus
        the output-stream (dropped before finish on success, and on each
        error branch that reaches AFTER the stream is created but before it
        is dropped). The body bytes that follow ``body()`` and precede
        ``finish`` are the ONLY structural difference from get; the rest of
        the wrapper is line-for-line the get wrapper."""
        chunk_r = _WASI_NET_READ_CHUNK
        S = self._wasi_net_scratch_offset
        body_ret = S + 0
        finish_ret = S + 8
        handle_ret = S + 16
        get_ret = S + 32
        consume_ret = S + 64
        stream_ret = S + 72
        read_ret = S + 80
        write_ret = S + 96      # output-stream.write / flush result
        obw_ret = S + 112       # outgoing-body.write result
        cw_ret = S + 128        # output-stream.check-write result (16B)
        msg_off, msg_len = self._intern_string("HTTP POST failed")
        self._write(
            "(func $Net_post (param $handle i32) (param $host_ptr i32) "
            "(param $host_len i32) (param $scheme i32) "
            "(param $auth_ptr i32) (param $auth_len i32) "
            "(param $path_ptr i32) (param $path_len i32) "
            "(param $body_ptr i32) (param $body_len i32) "
            "(param $ret_area i32)"
        )
        self._indent += 1
        for loc in ("$fields", "$req", "$obody", "$ostream", "$future",
                    "$pollable", "$resp", "$ibody", "$stream", "$status",
                    "$buf", "$buf_cap", "$buf_len", "$chunk_ptr",
                    "$chunk_len", "$need", "$newcap", "$newbuf",
                    "$cursor", "$remaining", "$n", "$budget", "$wp"):
            self._write(f"(local {loc} i32)")
        # Host gate (static ceiling + POST-scoped operator grant): a host
        # not admitted for POST (never named as a literal and not granted
        # via --allow-host h[:post]) writes Err WITHOUT building any
        # request. A host granted only for GET (--allow-host h:get) is
        # denied HERE, the least-authority point.
        self._write("local.get $host_ptr")
        self._write("local.get $host_len")
        self._write("call $Net_host_allowed_post")
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        self._emit_wasi_net_err(msg_off, msg_len)
        self._write("return")
        self._indent -= 1
        self._write("end")
        # Fine attenuation gate (restrict_to allow-list; shared with get):
        # a host outside the receiver Net's allow-list writes Err WITHOUT
        # building any request, layered ON TOP of the ceiling. Handle 0
        # (unrestricted root) admits all.
        self._write("local.get $handle")
        self._write("local.get $host_ptr")
        self._write("local.get $host_len")
        self._write("call $Net_handle_allows")
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        self._emit_wasi_net_err(msg_off, msg_len)
        self._write("return")
        self._indent -= 1
        self._write("end")
        # Build the request (method = POST, the only set-* difference).
        self._write("call $wasi_http_fields_new")
        self._write("local.set $fields")
        self._write("local.get $fields")
        self._write("call $wasi_http_request_new")
        self._write("local.set $req")
        self._write("local.get $req")
        self._write("i32.const 2")            # method variant POST = 2
        self._write("i32.const 0")            # method payload ptr (unused)
        self._write("i32.const 0")            # method payload len (unused)
        self._write("call $wasi_http_set_method")
        self._write("drop")
        self._write("local.get $req")
        self._write("i32.const 1")
        self._write("local.get $scheme")
        self._write("i32.const 0")
        self._write("i32.const 0")
        self._write("call $wasi_http_set_scheme")
        self._write("drop")
        self._write("local.get $req")
        self._write("i32.const 1")
        self._write("local.get $auth_ptr")
        self._write("local.get $auth_len")
        self._write("call $wasi_http_set_authority")
        self._write("drop")
        self._write("local.get $req")
        self._write("i32.const 1")
        self._write("local.get $path_ptr")
        self._write("local.get $path_len")
        self._write("call $wasi_http_set_path")
        self._write("drop")
        # obody = req.body().value @body_ret+4.
        self._write("local.get $req")
        self._write(f"i32.const {body_ret}")
        self._write("call $wasi_http_request_body")
        self._write(f"i32.const {body_ret}")
        self._write("i32.load offset=4")
        self._write("local.set $obody")
        # ostream = obody.write().value @obw_ret+4 (the NINTH OWN resource,
        # a child of obody). On Err: req + obody not yet consumed -> drop
        # both, write Err, return.
        self._write("local.get $obody")
        self._write(f"i32.const {obw_ret}")
        self._write("call $wasi_http_outgoing_body_write")
        self._write(f"i32.const {obw_ret}")
        self._write("i32.load8_u offset=0")
        self._write("if")
        self._indent += 1
        self._write("local.get $obody")
        self._write("call $wasi_http_drop_outgoing_body")
        self._write("local.get $req")
        self._write("call $wasi_http_drop_request")
        self._emit_wasi_net_err(msg_off, msg_len)
        self._write("return")
        self._indent -= 1
        self._write("end")
        self._write(f"i32.const {obw_ret}")
        self._write("i32.load offset=4")
        self._write("local.set $ostream")
        # Write the request body through the output-stream with the
        # FLOW-CONTROLLED wasi:io pattern (NOT blocking-write-and-flush: a
        # not-yet-handled outgoing-body stream never drains, so blocking
        # past the initial permit window deadlocks -- a 4097-byte body hangs
        # while 4096 succeeds). Each iteration: check-write for the
        # permitted budget; if 0, subscribe + block on the stream pollable
        # until the host grants more permits (it buffers the not-yet-sent
        # body); else non-blocking write of <= budget bytes straight from
        # linear memory (no copy). cursor = 0; remaining = body_len. A
        # zero-length body runs the loop zero times (empty request body).
        self._write("i32.const 0")
        self._write("local.set $cursor")
        self._write("local.get $body_len")
        self._write("local.set $remaining")
        self._write("(block $post_write_done")
        self._indent += 1
        self._write("(loop $post_write_loop")
        self._indent += 1
        self._write("local.get $remaining")
        self._write("i32.eqz")
        self._write("br_if $post_write_done")
        # check-write(ostream, cw_ret) -> result<u64, stream-error>.
        self._write("local.get $ostream")
        self._write(f"i32.const {cw_ret}")
        self._write("call $wasi_io_check_write")
        # On Err (disc @cw_ret+0 != 0): clean up the write path and bail.
        # check-write is result<u64, stream-error> (8-aligned), so its Err
        # stream-error sits at disc @+8, error @+12 (not the +4/+8 of the
        # 4-aligned write / flush results).
        self._write(f"i32.const {cw_ret}")
        self._write("i32.load8_u offset=0")
        self._write("if")
        self._indent += 1
        self._emit_wasi_net_post_write_err(
            cw_ret, msg_off, msg_len, disc_field=8, err_field=12,
        )
        self._write("return")
        self._indent -= 1
        self._write("end")
        # budget = cw_ret value (u64 @+8) truncated to i32 (request bodies
        # fit i32; a budget > 2^31 is clamped harmlessly by the per-write
        # min with remaining).
        self._write(f"i32.const {cw_ret}")
        self._write("i64.load offset=8")
        self._write("i32.wrap_i64")
        self._write("local.set $budget")
        # budget == 0 -> await permits: subscribe + block + drop, retry.
        self._write("local.get $budget")
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        self._write("local.get $ostream")
        self._write("call $wasi_io_stream_subscribe")
        self._write("local.set $wp")
        self._write("local.get $wp")
        self._write("call $wasi_io_pollable_block")
        self._write("local.get $wp")
        self._write("call $wasi_io_drop_pollable")
        self._write("br $post_write_loop")
        self._indent -= 1
        self._write("end")
        # n = min(remaining, budget).
        self._write("local.get $remaining")
        self._write("local.get $budget")
        self._write("i32.lt_u")
        self._write("if (result i32)")
        self._indent += 1
        self._write("local.get $remaining")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        self._write("local.get $budget")
        self._indent -= 1
        self._write("end")
        self._write("local.set $n")
        # write(ostream, body_ptr+cursor, n, write_ret) -- non-blocking,
        # <= the permitted budget, returns immediately.
        self._write("local.get $ostream")
        self._write("local.get $body_ptr")
        self._write("local.get $cursor")
        self._write("i32.add")
        self._write("local.get $n")
        self._write(f"i32.const {write_ret}")
        self._write("call $wasi_io_stream_write")
        # On Err (disc @write_ret+0 != 0): clean up the write path and bail.
        self._write(f"i32.const {write_ret}")
        self._write("i32.load8_u offset=0")
        self._write("if")
        self._indent += 1
        self._emit_wasi_net_post_write_err(
            write_ret, msg_off, msg_len,
        )
        self._write("return")
        self._indent -= 1
        self._write("end")
        # cursor += n; remaining -= n; continue.
        self._write("local.get $cursor")
        self._write("local.get $n")
        self._write("i32.add")
        self._write("local.set $cursor")
        self._write("local.get $remaining")
        self._write("local.get $n")
        self._write("i32.sub")
        self._write("local.set $remaining")
        self._write("br $post_write_loop")
        self._indent -= 1
        self._write(")")
        self._indent -= 1
        self._write(")")
        # flush(ostream, write_ret) -- non-blocking; signals the body is
        # complete (the host drains the buffered bytes on handle). Harmless
        # when nothing was written (empty body).
        self._write("local.get $ostream")
        self._write(f"i32.const {write_ret}")
        self._write("call $wasi_io_stream_flush")
        self._write(f"i32.const {write_ret}")
        self._write("i32.load8_u offset=0")
        self._write("if")
        self._indent += 1
        self._emit_wasi_net_post_write_err(
            write_ret, msg_off, msg_len,
        )
        self._write("return")
        self._indent -= 1
        self._write("end")
        # Drop the output-stream BEFORE finish (it is a child of obody;
        # finish would trap if the stream were still live).
        self._write("local.get $ostream")
        self._write("call $wasi_io_drop_output_stream")
        # finish(obody, none) [CONSUMES obody].
        self._write("local.get $obody")
        self._write("i32.const 0")
        self._write("i32.const 0")
        self._write(f"i32.const {finish_ret}")
        self._write("call $wasi_http_body_finish")
        # handle(req, none) [CONSUMES req].
        self._write("local.get $req")
        self._write("i32.const 0")
        self._write("i32.const 0")
        self._write(f"i32.const {handle_ret}")
        self._write("call $wasi_http_handle")
        self._write(f"i32.const {handle_ret}")
        self._write("i32.load8_u offset=0")
        self._write("if")
        self._indent += 1
        self._emit_wasi_net_err(msg_off, msg_len)
        self._write("return")
        self._indent -= 1
        self._write("end")
        # future = handle_ret.value @+8.
        self._write(f"i32.const {handle_ret}")
        self._write("i32.load offset=8")
        self._write("local.set $future")
        # subscribe + block + drop, then loop get (identical to get).
        self._write("local.get $future")
        self._write("call $wasi_http_future_subscribe")
        self._write("local.set $pollable")
        self._write("local.get $pollable")
        self._write("call $wasi_io_pollable_block")
        self._write("local.get $pollable")
        self._write("call $wasi_io_drop_pollable")
        self._write("(block $post_got")
        self._indent += 1
        self._write("(loop $post_poll")
        self._indent += 1
        self._write("local.get $future")
        self._write(f"i32.const {get_ret}")
        self._write("call $wasi_http_future_get")
        self._write(f"i32.const {get_ret}")
        self._write("i32.load8_u offset=0")
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        self._write("local.get $future")
        self._write("call $wasi_http_future_subscribe")
        self._write("local.set $pollable")
        self._write("local.get $pollable")
        self._write("call $wasi_io_pollable_block")
        self._write("local.get $pollable")
        self._write("call $wasi_io_drop_pollable")
        self._write("br $post_poll")
        self._indent -= 1
        self._write("end")
        self._write("br $post_got")
        self._indent -= 1
        self._write(")")
        self._indent -= 1
        self._write(")")
        # outer result disc @get_ret+8 != 0 -> already consumed -> Err.
        self._write(f"i32.const {get_ret}")
        self._write("i32.load8_u offset=8")
        self._write("if")
        self._indent += 1
        self._write("local.get $future")
        self._write("call $wasi_http_drop_future")
        self._emit_wasi_net_err(msg_off, msg_len)
        self._write("return")
        self._indent -= 1
        self._write("end")
        # inner result disc @get_ret+16 != 0 -> transport error -> Err.
        self._write(f"i32.const {get_ret}")
        self._write("i32.load8_u offset=16")
        self._write("if")
        self._indent += 1
        self._write("local.get $future")
        self._write("call $wasi_http_drop_future")
        self._emit_wasi_net_err(msg_off, msg_len)
        self._write("return")
        self._indent -= 1
        self._write("end")
        # resp = own<incoming-response> @get_ret+24.
        self._write(f"i32.const {get_ret}")
        self._write("i32.load offset=24")
        self._write("local.set $resp")
        self._write("local.get $future")
        self._write("call $wasi_http_drop_future")
        # FAIL-CLOSED on any non-2xx status. Only 200-299 yields Ok(body);
        # ANY other status (3xx redirects, <200, and 4xx/5xx as before)
        # drops the response and returns Err WITHOUT reading the body. This
        # DELIBERATELY diverges (in the more restrictive direction) from the
        # urllib oracle / capa:host, which FOLLOW redirects via urllib: the
        # guest does NOT follow redirects, because an implicit redirect from
        # an allowed host to a non-allowed host would bypass the static Net
        # ceiling + the fine host allow-list (an SSRF / host-authority bypass
        # vector). Refusing 3xx preserves the host/capability guarantee
        # (secure-by-default; CRA / NIS2 aligned). See
        # docs/design/wasi_mode.md. status NOT in [200,299] -> Err.
        self._write("local.get $resp")
        self._write("call $wasi_http_response_status")
        self._write("local.set $status")
        self._write("local.get $status")
        self._write("i32.const 200")
        self._write("i32.lt_u")
        self._write("local.get $status")
        self._write("i32.const 299")
        self._write("i32.gt_u")
        self._write("i32.or")
        self._write("if")
        self._indent += 1
        self._write("local.get $resp")
        self._write("call $wasi_http_drop_response")
        self._emit_wasi_net_err(msg_off, msg_len)
        self._write("return")
        self._indent -= 1
        self._write("end")
        # consume -> result<own<incoming-body>> @consume_ret (value @+4).
        self._write("local.get $resp")
        self._write(f"i32.const {consume_ret}")
        self._write("call $wasi_http_response_consume")
        self._write(f"i32.const {consume_ret}")
        self._write("i32.load8_u offset=0")
        self._write("if")
        self._indent += 1
        self._write("local.get $resp")
        self._write("call $wasi_http_drop_response")
        self._emit_wasi_net_err(msg_off, msg_len)
        self._write("return")
        self._indent -= 1
        self._write("end")
        self._write(f"i32.const {consume_ret}")
        self._write("i32.load offset=4")
        self._write("local.set $ibody")
        # stream -> result<own<input-stream>> @stream_ret (value @+4).
        self._write("local.get $ibody")
        self._write(f"i32.const {stream_ret}")
        self._write("call $wasi_http_body_stream")
        self._write(f"i32.const {stream_ret}")
        self._write("i32.load8_u offset=0")
        self._write("if")
        self._indent += 1
        self._write("local.get $ibody")
        self._write("call $wasi_http_drop_incoming_body")
        self._write("local.get $resp")
        self._write("call $wasi_http_drop_response")
        self._emit_wasi_net_err(msg_off, msg_len)
        self._write("return")
        self._indent -= 1
        self._write("end")
        self._write(f"i32.const {stream_ret}")
        self._write("i32.load offset=4")
        self._write("local.set $stream")
        # Response-body accumulation buffer (identical to get).
        self._write("i32.const 0")
        self._write("call $alloc")
        self._write("local.set $buf")
        self._write("i32.const 0")
        self._write("local.set $buf_cap")
        self._write("i32.const 0")
        self._write("local.set $buf_len")
        # blocking-read loop (identical to get).
        self._write("(block $post_read_done")
        self._indent += 1
        self._write("(loop $post_read")
        self._indent += 1
        self._write("local.get $stream")
        self._write(f"i64.const {chunk_r}")
        self._write(f"i32.const {read_ret}")
        self._write("call $wasi_io_blocking_read")
        self._write(f"i32.const {read_ret}")
        self._write("i32.load8_u offset=0")
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        self._write(f"i32.const {read_ret}")
        self._write("i32.load offset=4")
        self._write("local.set $chunk_ptr")
        self._write(f"i32.const {read_ret}")
        self._write("i32.load offset=8")
        self._write("local.set $chunk_len")
        self._write("local.get $buf_len")
        self._write("local.get $chunk_len")
        self._write("i32.add")
        self._write("local.set $need")
        self._write("local.get $need")
        self._write("local.get $buf_cap")
        self._write("i32.gt_u")
        self._write("if")
        self._indent += 1
        self._write("local.get $buf_cap")
        self._write("i32.const 1")
        self._write("i32.shl")
        self._write("local.get $need")
        self._write("i32.lt_u")
        self._write("if (result i32)")
        self._indent += 1
        self._write("local.get $need")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        self._write("local.get $buf_cap")
        self._write("i32.const 1")
        self._write("i32.shl")
        self._indent -= 1
        self._write("end")
        self._write("local.set $newcap")
        self._write("local.get $newcap")
        self._write("call $alloc")
        self._write("local.set $newbuf")
        self._write("local.get $newbuf")
        self._write("local.get $buf")
        self._write("local.get $buf_len")
        self._write("memory.copy")
        self._write("local.get $newbuf")
        self._write("local.set $buf")
        self._write("local.get $newcap")
        self._write("local.set $buf_cap")
        self._indent -= 1
        self._write("end")
        self._write("local.get $buf")
        self._write("local.get $buf_len")
        self._write("i32.add")
        self._write("local.get $chunk_ptr")
        self._write("local.get $chunk_len")
        self._write("memory.copy")
        self._write("local.get $buf_len")
        self._write("local.get $chunk_len")
        self._write("i32.add")
        self._write("local.set $buf_len")
        self._write("br $post_read")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        self._write(f"i32.const {read_ret}")
        self._write("i32.load offset=4")
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        self._write(f"i32.const {read_ret}")
        self._write("i32.load offset=8")
        self._write("call $wasi_io_drop_error")
        self._write("local.get $stream")
        self._write("call $wasi_io_drop_input_stream")
        self._write("local.get $ibody")
        self._write("call $wasi_http_drop_incoming_body")
        self._write("local.get $resp")
        self._write("call $wasi_http_drop_response")
        self._emit_wasi_net_err(msg_off, msg_len)
        self._write("return")
        self._indent -= 1
        self._write("end")
        self._write("br $post_read_done")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write(")")
        self._indent -= 1
        self._write(")")
        # EOF: drop stream, ibody, resp.
        self._write("local.get $stream")
        self._write("call $wasi_io_drop_input_stream")
        self._write("local.get $ibody")
        self._write("call $wasi_http_drop_incoming_body")
        self._write("local.get $resp")
        self._write("call $wasi_http_drop_response")
        # Ok(String).
        self._write("local.get $ret_area")
        self._write("i32.const 0")
        self._write("i32.store offset=0")
        self._write("local.get $ret_area")
        self._write("local.get $buf")
        self._write("i32.store offset=4")
        self._write("local.get $ret_area")
        self._write("local.get $buf_len")
        self._write("i32.store offset=8")
        self._indent -= 1
        self._write(")")


    def _emit_wasi_net_post_write_err(
        self, ret: int, msg_off: int, msg_len: int,
        disc_field: int = 4, err_field: int = 8,
    ) -> None:
        """Shared error cleanup for a failed request-body stream op
        (``check-write`` / ``write`` / ``flush``) in ``$Net_post``.
        ``$ostream``, ``$obody`` and ``$req`` are in scope (all created
        before any write op runs, and neither obody nor req has been
        consumed yet -- finish / handle come AFTER the write loop).

        Drops the carried error resource when the stream-error variant is
        last-operation-failed (disc @ret+disc_field == 0; the error handle
        @ret+err_field is an OWN resource), then drops the output-stream
        (the child), the outgoing-body and the outgoing-request (neither
        consumed yet), and writes Err(IoError). The ``closed`` variant
        (disc == 1) carries no error handle, so it skips the error drop.

        ``disc_field`` / ``err_field`` locate the stream-error inside the
        ret area: a ``result<_, stream-error>`` (write / flush) is 4-aligned
        with disc @+4, error @+8 (the defaults); a ``result<u64,
        stream-error>`` (check-write) is 8-aligned, so its Err stream-error
        sits at disc @+8, error @+12."""
        self._write(f"i32.const {ret}")
        self._write(f"i32.load offset={disc_field}")
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        self._write(f"i32.const {ret}")
        self._write(f"i32.load offset={err_field}")
        self._write("call $wasi_io_drop_error")
        self._indent -= 1
        self._write("end")
        self._write("local.get $ostream")
        self._write("call $wasi_io_drop_output_stream")
        self._write("local.get $obody")
        self._write("call $wasi_http_drop_outgoing_body")
        self._write("local.get $req")
        self._write("call $wasi_http_drop_request")
        self._emit_wasi_net_err(msg_off, msg_len)


    def _emit_wasi_net_err(self, msg_off: int, msg_len: int) -> None:
        """Write an ``Err(IoError)`` into ``$ret_area`` for the
        ``result_string_io_error`` 20-byte shape: tag@0 = 1, message = the
        interned fixed string (m_ptr@4, m_len@8), empty cause (c_ptr@12 =
        0, c_len@16 = 0).

        The message is fixed (``HTTP GET failed`` for get, ``HTTP POST
        failed`` for post -- the caller passes the offsets) rather than the
        Python
        oracle's transport-specific cause, which carries OS / URL bytes no
        cross-backend comparison can reproduce; parity is on the Result
        DISCRIMINANT (is_err), as the Fs read / write / metadata error
        paths already assert. ``$ret_area`` is in scope (the wrapper's
        trailing param)."""
        self._write("local.get $ret_area")
        self._write("i32.const 1")
        self._write("i32.store offset=0")
        self._write("local.get $ret_area")
        self._write(f"i32.const {msg_off}")
        self._write("i32.store offset=4")
        self._write("local.get $ret_area")
        self._write(f"i32.const {msg_len}")
        self._write("i32.store offset=8")
        self._write("local.get $ret_area")
        self._write("i32.const 0")
        self._write("i32.store offset=12")
        self._write("local.get $ret_area")
        self._write("i32.const 0")
        self._write("i32.store offset=16")

    # ----- Net dynamic-URL runtime extractor (--allow-host) -------


    def _emit_wasi_is_url_ws_helper(self) -> None:
        """``$is_url_ws (c) -> i32`` -- 1 iff ``c`` is an ASCII whitespace
        byte the runtime URL extractor trims (space / tab / LF / CR), the
        exact set :data:`capa.ir._net_host._URL_TRIM` strips on the Python
        reference side."""
        self._write(
            "(func $is_url_ws (param $c i32) (result i32)\n"
            "  (i32.or\n"
            "    (i32.or (i32.eq (local.get $c) (i32.const 9))\n"
            "            (i32.eq (local.get $c) (i32.const 10)))\n"
            "    (i32.or (i32.eq (local.get $c) (i32.const 13))\n"
            "            (i32.eq (local.get $c) (i32.const 32)))))"
        )


    def _emit_wasi_net_url_extract_helper(self) -> None:
        """``$ascii_lc`` + ``$Net_url_extract`` -- the guest-side RUNTIME URL
        extractor that unblocks a DYNAMIC (argv-derived / computed) Net URL
        under an operator ``--allow-host`` grant.

        ``$Net_url_extract (url_ptr, url_len, scratch, out) -> i32`` parses a
        runtime URL string into ``(host, is_https, authority, path)``, writing
        the derived bytes sequentially into the caller's ``scratch`` buffer
        and the ptr/len results into the 28-byte ``out`` struct
        (host_ptr@0, host_len@4, is_https@8, auth_ptr@12, auth_len@16,
        path_ptr@20, path_len@24). Returns 1 to PROCEED (the caller then gates
        ``host`` through ``$Net_host_allowed`` and builds the request from
        ``authority`` / ``path`` / ``is_https``) or 0 to FAIL-CLOSED (deny).

        This is the WAT realization of
        :func:`capa.ir._net_host.extract_url_parts` (its executable spec),
        validated byte-for-byte against it by the differential WAT-vs-Python
        harness over an adversarial corpus. The SECURITY CONTRACT:
        ``authority`` is BUILT FROM the same ``host`` this returns (host,
        optionally ``:port``), so the host verified against the allowlist is
        exactly the host the wasi:http request contacts -- there is no second
        parser (wasi:http receives this authority, never a re-parsed raw URL).
        It FAILS CLOSED (returns 0) on: no ``://``; a scheme other than
        http/https; a bracketed IPv6 authority; a non-numeric port; or an
        empty host -- denying rather than guessing.

        ``scratch`` must hold at least ``3 * url_len + 8`` bytes (host +
        authority + path are each <= url_len + 1); the caller allocates it.

        DNS-rebinding LIMITATION (honest residual): this is a hostname
        allowlist. wasi:http is host-side allow-all, so a granted host that
        resolves to an internal IP at connect time is NOT filtered here. See
        ``capa.ir._net_host`` and ``docs/design/wasi_mode.md``."""
        # ASCII lowercase: 'A'..'Z' -> +32, else unchanged.
        self._write(
            "(func $ascii_lc (param $c i32) (result i32)\n"
            "  (select\n"
            "    (i32.add (local.get $c) (i32.const 32))\n"
            "    (local.get $c)\n"
            "    (i32.and\n"
            "      (i32.ge_u (local.get $c) (i32.const 65))\n"
            "      (i32.le_u (local.get $c) (i32.const 90)))))"
        )
        body = r"""
(func $Net_url_extract
    (param $url_ptr i32) (param $url_len i32)
    (param $scratch i32) (param $out i32) (result i32)
  (local $b i32) (local $e i32) (local $i i32) (local $c i32)
  (local $scheme_end i32) (local $found i32) (local $rest i32)
  (local $auth_end i32) (local $tail i32) (local $at i32)
  (local $hs i32) (local $he i32) (local $ps i32) (local $pe i32)
  (local $has_port i32) (local $cur i32) (local $host_ptr i32)
  (local $host_len i32) (local $is_https i32) (local $fe i32)
  (local $auth_ptr i32) (local $path_ptr i32)
  ;; --- trim leading/trailing ASCII whitespace (9,10,13,32) ---
  (local.set $b (local.get $url_ptr))
  (local.set $e (i32.add (local.get $url_ptr) (local.get $url_len)))
  (block $tl_done (loop $tl
    (br_if $tl_done (i32.ge_u (local.get $b) (local.get $e)))
    (local.set $c (i32.load8_u (local.get $b)))
    (br_if $tl_done (i32.eqz (call $is_url_ws (local.get $c))))
    (local.set $b (i32.add (local.get $b) (i32.const 1)))
    (br $tl)))
  (block $tr_done (loop $tr
    (br_if $tr_done (i32.ge_u (local.get $b) (local.get $e)))
    (local.set $c (i32.load8_u (i32.sub (local.get $e) (i32.const 1))))
    (br_if $tr_done (i32.eqz (call $is_url_ws (local.get $c))))
    (local.set $e (i32.sub (local.get $e) (i32.const 1)))
    (br $tr)))
  (if (i32.ge_u (local.get $b) (local.get $e)) (then (return (i32.const 0))))
  ;; --- find "://" ---
  (local.set $found (i32.const 0))
  (local.set $i (local.get $b))
  (block $sc_done (loop $sc
    (br_if $sc_done
      (i32.gt_u (i32.add (local.get $i) (i32.const 3)) (local.get $e)))
    (if (i32.and
          (i32.eq (i32.load8_u (local.get $i)) (i32.const 58))
          (i32.and
            (i32.eq (i32.load8_u (i32.add (local.get $i) (i32.const 1)))
                    (i32.const 47))
            (i32.eq (i32.load8_u (i32.add (local.get $i) (i32.const 2)))
                    (i32.const 47))))
      (then
        (local.set $scheme_end (local.get $i))
        (local.set $found (i32.const 1))
        (br $sc_done)))
    (local.set $i (i32.add (local.get $i) (i32.const 1)))
    (br $sc)))
  (if (i32.eqz (local.get $found)) (then (return (i32.const 0))))
  ;; --- scheme: http (is_https=0) / https (is_https=1), else deny ---
  (if (i32.and
        (i32.eq (i32.sub (local.get $scheme_end) (local.get $b))
                (i32.const 5))
        (i32.and
          (i32.eq (call $ascii_lc (i32.load8_u (local.get $b)))
                  (i32.const 104))
          (i32.and
            (i32.eq (call $ascii_lc
                      (i32.load8_u (i32.add (local.get $b) (i32.const 1))))
                    (i32.const 116))
            (i32.and
              (i32.eq (call $ascii_lc
                        (i32.load8_u (i32.add (local.get $b) (i32.const 2))))
                      (i32.const 116))
              (i32.and
                (i32.eq (call $ascii_lc
                          (i32.load8_u (i32.add (local.get $b) (i32.const 3))))
                        (i32.const 112))
                (i32.eq (call $ascii_lc
                          (i32.load8_u (i32.add (local.get $b) (i32.const 4))))
                        (i32.const 115)))))))
    (then (local.set $is_https (i32.const 1)))
    (else
      (if (i32.and
            (i32.eq (i32.sub (local.get $scheme_end) (local.get $b))
                    (i32.const 4))
            (i32.and
              (i32.eq (call $ascii_lc (i32.load8_u (local.get $b)))
                      (i32.const 104))
              (i32.and
                (i32.eq (call $ascii_lc
                          (i32.load8_u (i32.add (local.get $b) (i32.const 1))))
                        (i32.const 116))
                (i32.and
                  (i32.eq (call $ascii_lc
                            (i32.load8_u (i32.add (local.get $b) (i32.const 2))))
                          (i32.const 116))
                  (i32.eq (call $ascii_lc
                            (i32.load8_u (i32.add (local.get $b) (i32.const 3))))
                          (i32.const 112))))))
        (then (local.set $is_https (i32.const 0)))
        (else (return (i32.const 0))))))
  ;; --- authority region: [rest, auth_end) ends at first / ? # ---
  (local.set $rest (i32.add (local.get $scheme_end) (i32.const 3)))
  (local.set $auth_end (local.get $e))
  (local.set $i (local.get $rest))
  (block $ae_done (loop $ae
    (br_if $ae_done (i32.ge_u (local.get $i) (local.get $e)))
    (local.set $c (i32.load8_u (local.get $i)))
    (if (i32.or
          (i32.eq (local.get $c) (i32.const 47))
          (i32.or (i32.eq (local.get $c) (i32.const 63))
                  (i32.eq (local.get $c) (i32.const 35))))
      (then (local.set $auth_end (local.get $i)) (br $ae_done)))
    (local.set $i (i32.add (local.get $i) (i32.const 1)))
    (br $ae)))
  (local.set $tail (local.get $auth_end))
  ;; --- userinfo: strip up to the LAST '@' in [rest, auth_end) ---
  (local.set $at (i32.const -1))
  (local.set $i (local.get $rest))
  (block $ui_done (loop $ui
    (br_if $ui_done (i32.ge_u (local.get $i) (local.get $auth_end)))
    (if (i32.eq (i32.load8_u (local.get $i)) (i32.const 64))
      (then (local.set $at (local.get $i))))
    (local.set $i (i32.add (local.get $i) (i32.const 1)))
    (br $ui)))
  (local.set $hs
    (if (result i32) (i32.ge_s (local.get $at) (i32.const 0))
      (then (i32.add (local.get $at) (i32.const 1)))
      (else (local.get $rest))))
  ;; --- bracketed IPv6 -> deny ---
  (local.set $i (local.get $hs))
  (block $brk_done (loop $brk
    (br_if $brk_done (i32.ge_u (local.get $i) (local.get $auth_end)))
    (local.set $c (i32.load8_u (local.get $i)))
    (if (i32.or (i32.eq (local.get $c) (i32.const 91))
                (i32.eq (local.get $c) (i32.const 93)))
      (then (return (i32.const 0))))
    (local.set $i (i32.add (local.get $i) (i32.const 1)))
    (br $brk)))
  ;; --- port: first ':' in [hs, auth_end) ---
  (local.set $he (local.get $auth_end))
  (local.set $ps (local.get $auth_end))
  (local.set $pe (local.get $auth_end))
  (local.set $has_port (i32.const 0))
  (local.set $i (local.get $hs))
  (block $pt_done (loop $pt
    (br_if $pt_done (i32.ge_u (local.get $i) (local.get $auth_end)))
    (if (i32.eq (i32.load8_u (local.get $i)) (i32.const 58))
      (then
        (local.set $he (local.get $i))
        (local.set $ps (i32.add (local.get $i) (i32.const 1)))
        (local.set $pe (local.get $auth_end))
        (local.set $has_port (i32.const 1))
        (br $pt_done)))
    (local.set $i (i32.add (local.get $i) (i32.const 1)))
    (br $pt)))
  ;; an empty port (``host:``) is treated as NO port (matches urlsplit);
  ;; a present port must be all digits, else deny.
  (if (local.get $has_port)
    (then
      (if (i32.ge_u (local.get $ps) (local.get $pe))
        (then (local.set $has_port (i32.const 0)))
        (else
          (local.set $i (local.get $ps))
          (block $pv_done (loop $pv
            (br_if $pv_done (i32.ge_u (local.get $i) (local.get $pe)))
            (local.set $c (i32.load8_u (local.get $i)))
            (if (i32.or (i32.lt_u (local.get $c) (i32.const 48))
                        (i32.gt_u (local.get $c) (i32.const 57)))
              (then (return (i32.const 0))))
            (local.set $i (i32.add (local.get $i) (i32.const 1)))
            (br $pv)))))))
  ;; --- build host into scratch (lowercased) ---
  (local.set $cur (local.get $scratch))
  (local.set $host_ptr (local.get $cur))
  (local.set $i (local.get $hs))
  (block $hb_done (loop $hb
    (br_if $hb_done (i32.ge_u (local.get $i) (local.get $he)))
    (i32.store8 (local.get $cur)
      (call $ascii_lc (i32.load8_u (local.get $i))))
    (local.set $cur (i32.add (local.get $cur) (i32.const 1)))
    (local.set $i (i32.add (local.get $i) (i32.const 1)))
    (br $hb)))
  (local.set $host_len (i32.sub (local.get $cur) (local.get $host_ptr)))
  ;; strip a single trailing dot
  (if (i32.and (i32.gt_s (local.get $host_len) (i32.const 0))
               (i32.eq (i32.load8_u (i32.sub (local.get $cur) (i32.const 1)))
                       (i32.const 46)))
    (then
      (local.set $cur (i32.sub (local.get $cur) (i32.const 1)))
      (local.set $host_len (i32.sub (local.get $host_len) (i32.const 1)))))
  (if (i32.eqz (local.get $host_len)) (then (return (i32.const 0))))
  ;; --- build authority into scratch (host [+ ':' port]) ---
  (local.set $auth_ptr (local.get $cur))
  (local.set $i (i32.const 0))
  (block $ab_done (loop $ab
    (br_if $ab_done (i32.ge_u (local.get $i) (local.get $host_len)))
    (i32.store8 (local.get $cur)
      (i32.load8_u (i32.add (local.get $host_ptr) (local.get $i))))
    (local.set $cur (i32.add (local.get $cur) (i32.const 1)))
    (local.set $i (i32.add (local.get $i) (i32.const 1)))
    (br $ab)))
  (if (local.get $has_port)
    (then
      (i32.store8 (local.get $cur) (i32.const 58))
      (local.set $cur (i32.add (local.get $cur) (i32.const 1)))
      (local.set $i (local.get $ps))
      (block $pb_done (loop $pb
        (br_if $pb_done (i32.ge_u (local.get $i) (local.get $pe)))
        (i32.store8 (local.get $cur) (i32.load8_u (local.get $i)))
        (local.set $cur (i32.add (local.get $cur) (i32.const 1)))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $pb)))))
  ;; --- build path into scratch (drop #fragment; empty -> '/') ---
  (local.set $path_ptr (local.get $cur))
  (local.set $fe (local.get $e))
  (local.set $i (local.get $tail))
  (block $fg_done (loop $fg
    (br_if $fg_done (i32.ge_u (local.get $i) (local.get $e)))
    (if (i32.eq (i32.load8_u (local.get $i)) (i32.const 35))
      (then (local.set $fe (local.get $i)) (br $fg_done)))
    (local.set $i (i32.add (local.get $i) (i32.const 1)))
    (br $fg)))
  (if (i32.ge_u (local.get $tail) (local.get $fe))
    (then
      (i32.store8 (local.get $cur) (i32.const 47))
      (local.set $cur (i32.add (local.get $cur) (i32.const 1))))
    (else
      (if (i32.eq (i32.load8_u (local.get $tail)) (i32.const 63))
        (then
          (i32.store8 (local.get $cur) (i32.const 47))
          (local.set $cur (i32.add (local.get $cur) (i32.const 1)))))
      (local.set $i (local.get $tail))
      (block $cp_done (loop $cp
        (br_if $cp_done (i32.ge_u (local.get $i) (local.get $fe)))
        (i32.store8 (local.get $cur) (i32.load8_u (local.get $i)))
        (local.set $cur (i32.add (local.get $cur) (i32.const 1)))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $cp)))))
  ;; --- write the out struct + proceed ---
  (i32.store offset=0 (local.get $out) (local.get $host_ptr))
  (i32.store offset=4 (local.get $out) (local.get $host_len))
  (i32.store offset=8 (local.get $out) (local.get $is_https))
  (i32.store offset=12 (local.get $out) (local.get $auth_ptr))
  (i32.store offset=16 (local.get $out)
    (i32.sub (local.get $path_ptr) (local.get $auth_ptr)))
  (i32.store offset=20 (local.get $out) (local.get $path_ptr))
  (i32.store offset=24 (local.get $out)
    (i32.sub (local.get $cur) (local.get $path_ptr)))
  (i32.const 1))
"""
        for line in body.strip("\n").split("\n"):
            self._write(line)
