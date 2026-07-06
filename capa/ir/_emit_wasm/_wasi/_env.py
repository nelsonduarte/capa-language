"""WASI Env emission (guest-side attenuation).

get / args / restrict_to_keys / allows and their helpers. Split out
of the former single-file ``_wasi.py`` with no behaviour change.
"""

from __future__ import annotations


class _WasiEnvMixin:
    """Env wrappers of the ``--wasi`` emitter; folded into
    ``WasmEmitter`` via ``_WasiEmissionMixin``."""

    def _wasi_env_uses_get_or_args(self) -> bool:
        """True when ``--wasi`` is active and the program reaches an
        Env method that needs the bump allocator: ``get`` / ``args``
        (their option / list materialisers allocate) or
        ``restrict_to_keys`` (it allocates the fresh allow-list
        ``List<String>`` for the narrowed Env value). Gates the
        ``$alloc`` / heap-top emission so an Env-only WASI program (no
        struct / sum layouts and no other heap user) still gets the
        allocator. The default ``capa:host`` Env path reaches the same
        materialisers, but those programs always pull ``$alloc`` in
        through their downstream Option / List use; the WASI wrappers
        make the dependency explicit so a minimal Env smoke test
        compiles standalone.

        ``allows`` alone does NOT need ``$alloc`` (it only scans an
        existing allow-list), so it is not gated here; but in practice
        a program that calls ``allows`` first called
        ``restrict_to_keys`` to obtain a restricted Env, which already
        pulls the allocator in."""
        return self._wasi and (
            ("Env", "get") in self._used_caps
            or ("Env", "args") in self._used_caps
            or ("Env", "restrict_to_keys") in self._used_caps
        )


    def _wasi_env_get_needs_str_eq(self) -> bool:
        """True when ``--wasi`` is active and the program reaches an
        Env method whose guest-side wrapper linear-scans a
        ``(ptr, len)`` key list via ``$str_eq``: ``get`` (scans
        ``get-environment``), ``restrict_to_keys`` (intersects two
        allow-lists), or ``allows`` (membership in the allow-list).
        The default path routes the comparison through the host, so
        this gate is WASI-only."""
        return self._wasi and (
            ("Env", "get") in self._used_caps
            or ("Env", "restrict_to_keys") in self._used_caps
            or ("Env", "allows") in self._used_caps
        )


    def _emit_wasi_env_get_wrapper(self) -> None:
        """``$Env_get (handle i32, key_ptr i32, key_len i32,
        ret_area i32)`` -> writes an ``option<string>`` into
        ``ret_area``.

        Matches the call shape ``_emit_indirect_with_cap_handle``
        produces for ``Env.get`` (receiver handle + key (ptr, len) +
        ret_area), so the call-site emitter and the ``option_string``
        materialiser are unchanged.

        Calls ``get-environment`` (indirect-return
        ``list<tuple<string, string>>``) into the reserved 8-byte
        scratch (data_ptr @0, len @4). Each list element is a 16-byte
        record (k_ptr @0, k_len @4, v_ptr @8, v_len @12). Linear-scans
        for the requested key via ``$str_eq`` and writes:

          found:     ret_area = (tag=1, ptr=v_ptr, len=v_len)
          not found: ret_area = (tag=0, ...)

        The tag follows the WIT ``option`` convention (none=0, some=1);
        the ``option_string`` materialiser XOR-flips it to the Capa
        internal convention (Some=0, None=1). A missing key yields
        ``none``, fail-closed, identical to the Python ``Env.get`` and
        the ``capa:host`` host bridge.

        FAIL-CLOSED ATTENUATION (guest-side, Level 2): before reading
        the environment, consult the receiver's allow-list via
        ``$Env_key_allowed(handle, key)``. When the Env is restricted
        and the key is not allowed, write ``none`` and return WITHOUT
        calling ``get-environment`` -- byte-identical to the Python
        oracle (``if not self.allows(name): return None_``). An
        unrestricted Env (``handle == 0``) short-circuits to allowed
        and the scan proceeds exactly as before."""
        scratch = self._wasi_env_scratch_offset
        self._write(
            "(func $Env_get (param $handle i32) (param $key_ptr i32) "
            "(param $key_len i32) (param $ret_area i32)"
        )
        self._indent += 1
        self._write("(local $data i32)")
        self._write("(local $count i32)")
        self._write("(local $i i32)")
        self._write("(local $elem i32)")
        # Fail-closed: if the receiver Env is restricted and the key is
        # not in its allow-list, write none and return without touching
        # the environment (identical to Python's Env.get).
        self._write("local.get $handle")
        self._write("local.get $key_ptr")
        self._write("local.get $key_len")
        self._write("call $Env_key_allowed")
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        self._write("local.get $ret_area")
        self._write("i32.const 0")
        self._write("i32.store offset=0")
        self._write("return")
        self._indent -= 1
        self._write("end")
        # get-environment(scratch_ptr)
        self._write(f"i32.const {scratch}")
        self._write("call $wasi_get_environment")
        # data = scratch[0]; count = scratch[4]
        self._write(f"i32.const {scratch}")
        self._write("i32.load offset=0")
        self._write("local.set $data")
        self._write(f"i32.const {scratch}")
        self._write("i32.load offset=4")
        self._write("local.set $count")
        # Default to none (tag 0) until a match is found.
        self._write("local.get $ret_area")
        self._write("i32.const 0")
        self._write("i32.store offset=0")
        # i = 0
        self._write("i32.const 0")
        self._write("local.set $i")
        self._write("(block $done")
        self._indent += 1
        self._write("(loop $scan")
        self._indent += 1
        # if i >= count, break
        self._write("local.get $i")
        self._write("local.get $count")
        self._write("i32.ge_u")
        self._write("br_if $done")
        # elem = data + i*16
        self._write("local.get $data")
        self._write("local.get $i")
        self._write("i32.const 16")
        self._write("i32.mul")
        self._write("i32.add")
        self._write("local.set $elem")
        # str_eq(elem.k_ptr@0, elem.k_len@4, key_ptr, key_len)
        self._write("local.get $elem")
        self._write("i32.load offset=0")
        self._write("local.get $elem")
        self._write("i32.load offset=4")
        self._write("local.get $key_ptr")
        self._write("local.get $key_len")
        self._write("call $str_eq")
        self._write("if")
        self._indent += 1
        # Match: ret_area = (tag=1, ptr=v_ptr@8, len=v_len@12)
        self._write("local.get $ret_area")
        self._write("i32.const 1")
        self._write("i32.store offset=0")
        self._write("local.get $ret_area")
        self._write("local.get $elem")
        self._write("i32.load offset=8")
        self._write("i32.store offset=4")
        self._write("local.get $ret_area")
        self._write("local.get $elem")
        self._write("i32.load offset=12")
        self._write("i32.store offset=8")
        self._write("br $done")
        self._indent -= 1
        self._write("end")
        # i = i + 1; continue
        self._write("local.get $i")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $i")
        self._write("br $scan")
        self._indent -= 1
        self._write(")")
        self._indent -= 1
        self._write(")")
        self._indent -= 1
        self._write(")")


    def _emit_wasi_env_args_wrapper(self) -> None:
        """``$Env_args (handle i32, ret_area i32)`` -> writes a
        ``list<string>`` flat header (data_ptr @0, len @4) into
        ``ret_area``.

        Matches the call shape ``_emit_indirect_with_cap_handle``
        produces for ``Env.args`` (receiver handle + ret_area), so the
        call-site emitter and the ``list_string`` materialiser are
        unchanged.

        Calls ``get-arguments`` (indirect-return ``list<string>``)
        into the reserved 8-byte scratch (data_ptr @0, len @4) and
        copies the two i32 fields straight through. The canonical-ABI
        ``list<string>`` data layout (N packed ``(str_ptr, str_len)``
        i32 pairs) is byte-identical to a Capa List<String> data
        array, so the materialiser wraps it in a 16-byte header with no
        per-element copy."""
        scratch = self._wasi_env_scratch_offset
        self._write(
            "(func $Env_args (param $handle i32) (param $ret_area i32)"
        )
        self._indent += 1
        # get-arguments(scratch_ptr)
        self._write(f"i32.const {scratch}")
        self._write("call $wasi_get_arguments")
        # ret_area[0] = scratch[0] (data_ptr)
        self._write("local.get $ret_area")
        self._write(f"i32.const {scratch}")
        self._write("i32.load offset=0")
        self._write("i32.store offset=0")
        # ret_area[4] = scratch[4] (len)
        self._write("local.get $ret_area")
        self._write(f"i32.const {scratch}")
        self._write("i32.load offset=4")
        self._write("i32.store offset=4")
        self._indent -= 1
        self._write(")")

    # ----- guest-side Env attenuation (Level 2) ------------------


    def _emit_wasi_env_key_allowed_helper(self) -> None:
        """``$Env_key_allowed (handle i32, key_ptr i32, key_len i32)
        -> i32`` -> 1 iff the Env value ``handle`` admits ``key``.

        The shared allow-list membership test behind both ``allows``
        (its whole body) and ``get`` (its fail-closed prologue):

          handle == 0  -> 1 (unrestricted root Env: every key allowed)
          else         -> handle is a pointer to a List<String> header
                          (len@0, data_ptr@8). Scan the N packed
                          ``(str_ptr, str_len)`` entries; return 1 on
                          the first ``$str_eq`` match, 0 if none match.

        Mirrors ``Env.allows`` (``self._allowed_keys is None or
        name in self._allowed_keys``)."""
        self._write(
            "(func $Env_key_allowed (param $handle i32) "
            "(param $key_ptr i32) (param $key_len i32) (result i32)"
        )
        self._indent += 1
        self._write("(local $data i32)")
        self._write("(local $count i32)")
        self._write("(local $i i32)")
        self._write("(local $entry i32)")
        # Unrestricted root: handle 0 admits every key.
        self._write("local.get $handle")
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        self._write("i32.const 1")
        self._write("return")
        self._indent -= 1
        self._write("end")
        # Restricted: scan the allow-list List<String> the handle
        # points to. count = header.len@0; data = header.data_ptr@8.
        self._write("local.get $handle")
        self._write("i32.load offset=0")
        self._write("local.set $count")
        self._write("local.get $handle")
        self._write("i32.load offset=8")
        self._write("local.set $data")
        self._write("i32.const 0")
        self._write("local.set $i")
        self._write("(block $found_done")
        self._indent += 1
        self._write("(loop $scan_keys")
        self._indent += 1
        # if i >= count, break (no match).
        self._write("local.get $i")
        self._write("local.get $count")
        self._write("i32.ge_u")
        self._write("br_if $found_done")
        # entry = data + i*8  (packed (str_ptr@0, str_len@4))
        self._write("local.get $data")
        self._write("local.get $i")
        self._write("i32.const 8")
        self._write("i32.mul")
        self._write("i32.add")
        self._write("local.set $entry")
        # str_eq(entry.ptr@0, entry.len@4, key_ptr, key_len) -> hit
        self._write("local.get $entry")
        self._write("i32.load offset=0")
        self._write("local.get $entry")
        self._write("i32.load offset=4")
        self._write("local.get $key_ptr")
        self._write("local.get $key_len")
        self._write("call $str_eq")
        self._write("if")
        self._indent += 1
        self._write("i32.const 1")
        self._write("return")
        self._indent -= 1
        self._write("end")
        # i += 1; continue
        self._write("local.get $i")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $i")
        self._write("br $scan_keys")
        self._indent -= 1
        self._write(")")
        self._indent -= 1
        self._write(")")
        # No match.
        self._write("i32.const 0")
        self._indent -= 1
        self._write(")")


    def _emit_wasi_env_allows_wrapper(self) -> None:
        """``$Env_allows (handle i32, key_ptr i32, key_len i32) ->
        i32`` -> the Bool result of ``env.allows(key)``.

        Matches the call shape ``_emit_cap_allows_with_handle``
        produces (receiver handle + key (ptr, len) -> i32 Bool).
        Delegates straight to the shared ``$Env_key_allowed`` so the
        query answer is identical to the ``get`` fail-closed gate (no
        guest-side divergence) and to the Python oracle."""
        self._write(
            "(func $Env_allows (param $handle i32) (param $key_ptr i32) "
            "(param $key_len i32) (result i32)"
        )
        self._indent += 1
        self._write("local.get $handle")
        self._write("local.get $key_ptr")
        self._write("local.get $key_len")
        self._write("call $Env_key_allowed")
        self._indent -= 1
        self._write(")")


    def _emit_wasi_env_restrict_to_keys_wrapper(self) -> None:
        """``$Env_restrict_to_keys (handle i32, keys_data_ptr i32,
        keys_len i32) -> i32`` -> a fresh Env value (pointer to a new
        ``List<String>`` allow-list, or 0 if -- only -- the result is
        empty AND the parent was unrestricted, which still represents
        a restricted-to-nothing Env, see below).

        Matches the call shape ``_emit_env_restrict_to_keys`` produces
        (receiver handle + the keys List<String> as (data_ptr, len)).

        Builds the INTERSECTION of the parent's allow-list with
        ``keys`` (monotonic narrowing, never widens), identical to
        ``Env.restrict_to_keys`` (``new & self._allowed_keys``):

          parent unrestricted (handle == 0): result = keys (every
            requested key passes, since the parent admits all).
          parent restricted: result = { k in keys : parent admits k }.

        Allocates a 16-byte List<String> header + a data buffer of up
        to ``keys_len`` packed ``(str_ptr, str_len)`` entries, copies
        the admitted keys' (ptr, len) straight through (the key bytes
        themselves are shared, not copied -- the keys list args already
        live in linear memory for the program's lifetime), and returns
        the header pointer. The header is always non-zero (``$alloc``
        never returns 0; the heap starts above the static data
        region), so an EMPTY intersection yields a valid pointer to a
        zero-length allow-list = a restricted Env that admits nothing,
        distinct from the unrestricted 0 sentinel. This matches the
        oracle: ``restrict_to_keys([])`` on any parent produces an Env
        whose ``allows`` is always false."""
        self._write(
            "(func $Env_restrict_to_keys (param $handle i32) "
            "(param $keys_data_ptr i32) (param $keys_len i32) (result i32)"
        )
        self._indent += 1
        self._write("(local $header i32)")
        self._write("(local $out_data i32)")
        self._write("(local $i i32)")
        self._write("(local $out_n i32)")
        self._write("(local $src i32)")
        self._write("(local $k_ptr i32)")
        self._write("(local $k_len i32)")
        # Allocate the result header (16 bytes) + a data buffer sized
        # for the worst case (all keys admitted): keys_len * 8 bytes.
        # An over-allocation is harmless; the header.len records the
        # actual admitted count so the scan never reads past it.
        self._write("i32.const 16")
        self._write("call $alloc")
        self._write("local.set $header")
        # data buffer: keys_len * 8 bytes. A zero-length keys list
        # still allocates 0 bytes ($alloc(0) returns the current heap
        # top, a stable non-overlapping pointer); the loop runs zero
        # times and header.len stays 0.
        self._write("local.get $keys_len")
        self._write("i32.const 8")
        self._write("i32.mul")
        self._write("call $alloc")
        self._write("local.set $out_data")
        self._write("i32.const 0")
        self._write("local.set $i")
        self._write("i32.const 0")
        self._write("local.set $out_n")
        self._write("(block $rk_done")
        self._indent += 1
        self._write("(loop $rk_scan")
        self._indent += 1
        # if i >= keys_len, break
        self._write("local.get $i")
        self._write("local.get $keys_len")
        self._write("i32.ge_u")
        self._write("br_if $rk_done")
        # src = keys_data_ptr + i*8; k_ptr = src[0]; k_len = src[4]
        self._write("local.get $keys_data_ptr")
        self._write("local.get $i")
        self._write("i32.const 8")
        self._write("i32.mul")
        self._write("i32.add")
        self._write("local.set $src")
        self._write("local.get $src")
        self._write("i32.load offset=0")
        self._write("local.set $k_ptr")
        self._write("local.get $src")
        self._write("i32.load offset=4")
        self._write("local.set $k_len")
        # Admit this key iff the PARENT (handle) allows it. For an
        # unrestricted parent ($handle == 0) $Env_key_allowed returns
        # 1 for every key, so result = keys; for a restricted parent
        # it returns membership, so result = keys & parent (the
        # intersection the oracle computes).
        self._write("local.get $handle")
        self._write("local.get $k_ptr")
        self._write("local.get $k_len")
        self._write("call $Env_key_allowed")
        self._write("if")
        self._indent += 1
        # out_data[out_n] = (k_ptr, k_len); out_n += 1
        self._write("local.get $out_data")
        self._write("local.get $out_n")
        self._write("i32.const 8")
        self._write("i32.mul")
        self._write("i32.add")
        self._write("local.get $k_ptr")
        self._write("i32.store offset=0")
        self._write("local.get $out_data")
        self._write("local.get $out_n")
        self._write("i32.const 8")
        self._write("i32.mul")
        self._write("i32.add")
        self._write("local.get $k_len")
        self._write("i32.store offset=4")
        self._write("local.get $out_n")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $out_n")
        self._indent -= 1
        self._write("end")
        # i += 1; continue
        self._write("local.get $i")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $i")
        self._write("br $rk_scan")
        self._indent -= 1
        self._write(")")
        self._indent -= 1
        self._write(")")
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
        # Return the header pointer (the new restricted Env value).
        self._write("local.get $header")
        self._indent -= 1
        self._write(")")

    # ----- guest-side Net fine attenuation (Level 2, Phase 3) ----

