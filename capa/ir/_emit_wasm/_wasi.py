"""Experimental WASI Preview 2 import emission (opt-in ``--wasi``).

A proof-of-concept that migrates the PURE-READER capability
touch-points off the custom ``capa:host`` interfaces and onto
canonical WASI Preview 2 (``0.2.0``) interfaces:

- ``Random.system_seed``   -> ``wasi:random/random@0.2.0`` ``get-random-u64``
- ``Clock.now_monotonic``  -> ``wasi:clocks/monotonic-clock@0.2.0`` ``now``
- ``Clock.now_secs``       -> ``wasi:clocks/wall-clock@0.2.0`` ``now``
- ``Env.get``              -> ``wasi:cli/environment@0.2.0`` ``get-environment``
- ``Env.args``             -> ``wasi:cli/environment@0.2.0`` ``get-arguments``

Everything else the program uses (typically ``Stdio`` for printing
the results, plus any other capability) stays on ``capa:host``. The
component therefore imports the wasi:* interfaces AND the capa:host
ones simultaneously; the host satisfies the former via wasmtime's
``Linker.add_wasip2()`` and the latter via the existing custom
registrations (see ``capa.runtime._wasm_component_host``).

Design choices that keep the rest of the emitter untouched:

- The raw wasi:* imports are bound to private ``$wasi_*`` names.
- A thin adapter wrapper exposes the exact ``$Cap_method`` binding
  the existing call-site emitters already ``call`` (so neither the
  Random helpers, ``_emit_clock_primitive_with_handle`` nor
  ``_emit_indirect_with_cap_handle`` change):

    * ``$Random_system_seed () -> i64``   = ``call $wasi_random_u64``
    * ``$Clock_now_monotonic (i32) -> f64`` drops the handle, reads
      ``monotonic-clock.now`` (u64 nanoseconds) and divides by 1e9.
    * ``$Clock_now_secs (i32) -> f64`` drops the handle, calls
      ``wall-clock.now`` into a fixed 16-byte scratch area, then
      computes ``seconds + nanoseconds / 1e9``.
    * ``$Env_get (handle, key_ptr, key_len, ret_area)`` drops the
      handle, calls ``get-environment`` (an indirect-return
      ``list<tuple<string, string>>``) into a fixed 8-byte scratch,
      linear-scans the (key, value) pairs for ``key``, and writes an
      ``option<string>`` (WIT tag convention) into ``ret_area`` so the
      existing ``option_string`` materialiser is unchanged. A missing
      key yields ``none`` (fail-closed, identical to the Python
      ``Env.get`` and the ``capa:host`` host bridge).
    * ``$Env_args (handle, ret_area)`` drops the handle, calls
      ``get-arguments`` (an indirect-return ``list<string>``) into a
      fixed 8-byte scratch, and copies the ``(data_ptr, len)`` pair
      into ``ret_area``. The canonical-ABI ``list<string>`` data
      layout (N packed ``(str_ptr, str_len)`` i32 pairs) is
      byte-identical to a Capa List<String> data array, so the
      existing ``list_string`` materialiser wraps it in a 16-byte
      header unchanged.

The unit / shape conversions are done guest-side in WAT (the same
strategy the Clock wrappers use for nanos->seconds), so the Capa
surface keeps exposing ``f64`` seconds and ``Option<String>`` /
``List<String>`` identically to the default backend.

Excluded from this mode (rejected with a clear error so a program
never silently miscompiles):

- ``Clock.sleep``  -> would pull ``wasi:io/streams`` / poll, out of
  scope.
- Clock attenuation (``restrict_to_after``) -> the wasi:clocks
  interfaces are pure readers with no host-side handle table to
  enforce a deadline; a future design item.
- Env attenuation (``restrict_to_keys``, ``allows``) -> ``wasi:cli/
  environment`` is a pure reader with no host-side cap object to
  consult, so the in-program allow-list narrowing has no WASI runtime
  home in this phase (Level 2 of ``docs/design/wasi-attenuation.md``).
  Mapping ``main``'s Env CEILING to the host env-set is a later
  increment; until then the attenuators are rejected rather than
  silently dropped.
"""

from __future__ import annotations

from ._layout import WasmEmissionError


# (cap, method) touch-points this mode reroutes to wasi:*. The import
# loop in ``WasmEmitter.emit`` skips these for the ``capa:host`` path;
# ``_emit_wasi_imports`` / ``_emit_wasi_wrappers`` handle them.
_WASI_MIGRATED_METHODS: frozenset[tuple[str, str]] = frozenset({
    ("Random", "system_seed"),
    ("Clock", "now_secs"),
    ("Clock", "now_monotonic"),
    ("Env", "get"),
    ("Env", "args"),
})


# Versioned WASI import strings. Bumping the WASI release these target
# means editing both these strings and the vendored WIT package
# versions in ``capa/wasi_wit``.
_WASI_RANDOM = "wasi:random/random@0.2.0"
_WASI_MONOTONIC = "wasi:clocks/monotonic-clock@0.2.0"
_WASI_WALL = "wasi:clocks/wall-clock@0.2.0"
_WASI_ENVIRONMENT = "wasi:cli/environment@0.2.0"


class _WasiEmissionMixin:
    """Mixin folded into ``WasmEmitter``; active only when
    ``self._wasi`` is True (the opt-in ``--wasi`` flag)."""

    def _validate_wasi_caps(self) -> None:
        """Reject the Clock / Env surface this mode does not migrate.

        ``Clock.sleep`` and the clock attenuator
        ``Clock.restrict_to_after`` have no canonical wasi:clocks
        backing in this PoC; ``Env.restrict_to_keys`` and ``Env.allows``
        likewise have no canonical ``wasi:cli/environment`` backing
        (it is a pure reader with no host-side cap object to consult,
        so the in-program allow-list narrowing has no WASI runtime
        home in this phase). Rather than emit something wrong we fail
        loudly so the user knows to fall back to the default backend.
        """
        for cap, method in self._used_caps:
            if cap == "Clock" and method not in (
                "now_secs", "now_monotonic",
            ):
                # sleep -> wasi:io/streams (out of scope); allows /
                # restrict_to_after -> clock attenuation (no host
                # handle table on the pure-reader wasi:clocks side).
                raise WasmEmissionError(
                    f"Clock.{method} is not supported in the WASI mode "
                    f"yet; use the default capa:host backend (drop "
                    f"--wasi)."
                )
            if cap == "Env" and method not in ("get", "args"):
                # restrict_to_keys / allows -> Env attenuation. The
                # wasi:cli/environment interface is a pure reader; the
                # in-program allow-list narrowing (Level 2 of
                # docs/design/wasi-attenuation.md) has no WASI runtime
                # home in this phase. Reject rather than silently drop
                # the restriction (which would widen the cap's
                # effective authority).
                raise WasmEmissionError(
                    f"Env.{method} is not supported in the WASI mode "
                    f"yet; use the default capa:host backend (drop "
                    f"--wasi)."
                )

    def _wasi_env_uses_get_or_args(self) -> bool:
        """True when ``--wasi`` is active and the program reaches
        ``Env.get`` or ``Env.args``. Gates the ``$alloc`` / heap-top
        emission so an Env-only WASI program (no struct / sum layouts
        and no other heap user) still gets the allocator the option /
        list materialisers depend on. The default ``capa:host`` Env
        path reaches the same materialisers, but those programs always
        pull ``$alloc`` in through their downstream Option / List use;
        the WASI wrappers make the dependency explicit so a minimal
        ``env.get`` smoke test compiles standalone."""
        return self._wasi and (
            ("Env", "get") in self._used_caps
            or ("Env", "args") in self._used_caps
        )

    def _wasi_env_get_needs_str_eq(self) -> bool:
        """True when ``--wasi`` is active and the program reaches
        ``Env.get``, whose guest-side wrapper linear-scans the
        ``get-environment`` list comparing each key against the
        requested one via ``$str_eq``. The default path routes the
        comparison through the host, so this gate is WASI-only."""
        return self._wasi and ("Env", "get") in self._used_caps

    def _emit_wasi_imports(self) -> None:
        """Emit the raw ``wasi:*`` imports for whichever migrated
        methods the program actually uses, bound to private
        ``$wasi_*`` names the adapter wrappers call."""
        used = self._used_caps
        if ("Random", "system_seed") in used:
            # get-random-u64: func() -> u64  (u64 lowers to core i64).
            self._write(
                f'(import "{_WASI_RANDOM}" "get-random-u64" '
                f'(func $wasi_random_u64 (result i64)))'
            )
        if ("Clock", "now_monotonic") in used:
            # monotonic-clock now: func() -> instant(u64 nanos).
            self._write(
                f'(import "{_WASI_MONOTONIC}" "now" '
                f'(func $wasi_monotonic_now (result i64)))'
            )
        if ("Clock", "now_secs") in used:
            # wall-clock now: func() -> datetime{seconds:u64,
            # nanoseconds:u32}. The record lowers to an indirect
            # return: one i32 return-area pointer param, no result.
            self._write(
                f'(import "{_WASI_WALL}" "now" '
                f'(func $wasi_wall_now (param i32)))'
            )
        if ("Env", "get") in used:
            # get-environment: func() -> list<tuple<string, string>>.
            # The list lowers to an indirect return: one i32
            # return-area pointer param (receives data_ptr @0, len @4),
            # no result.
            self._write(
                f'(import "{_WASI_ENVIRONMENT}" "get-environment" '
                f'(func $wasi_get_environment (param i32)))'
            )
        if ("Env", "args") in used:
            # get-arguments: func() -> list<string>. Same indirect
            # return shape (data_ptr @0, len @4).
            self._write(
                f'(import "{_WASI_ENVIRONMENT}" "get-arguments" '
                f'(func $wasi_get_arguments (param i32)))'
            )

    def _emit_wasi_wrappers(self) -> None:
        """Emit the ``$Cap_method`` adapter functions that bridge the
        existing call-site bindings to the raw wasi:* imports."""
        used = self._used_caps
        if ("Random", "system_seed") in used:
            self._emit_wasi_random_seed_wrapper()
        if ("Clock", "now_monotonic") in used:
            self._emit_wasi_monotonic_wrapper()
        if ("Clock", "now_secs") in used:
            self._emit_wasi_wall_wrapper()
        if ("Env", "get") in used:
            self._emit_wasi_env_get_wrapper()
        if ("Env", "args") in used:
            self._emit_wasi_env_args_wrapper()

    # ----- adapter wrappers -------------------------------------

    def _emit_wasi_random_seed_wrapper(self) -> None:
        """``$Random_system_seed () -> i64`` = ``get-random-u64``.

        The Random SplitMix64 helpers call ``$Random_system_seed``
        once to seed an unseeded ``Random()``; the WASI entropy is a
        drop-in for the ``capa:host/random/system-seed`` import."""
        self._write("(func $Random_system_seed (result i64)")
        self._indent += 1
        self._write("call $wasi_random_u64")
        self._indent -= 1
        self._write(")")

    def _emit_wasi_monotonic_wrapper(self) -> None:
        """``$Clock_now_monotonic (handle i32) -> f64``.

        Drops the (now-unused) handle, reads monotonic-clock.now (u64
        nanoseconds), converts to f64 seconds (nanos / 1e9). Unsigned
        i64 -> f64 conversion so the high bit is not misread as a sign
        once the nanosecond counter passes 2**63."""
        self._write(
            "(func $Clock_now_monotonic (param $handle i32) (result f64)"
        )
        self._indent += 1
        self._write("call $wasi_monotonic_now")
        self._write("f64.convert_i64_u")
        self._write("f64.const 1000000000")
        self._write("f64.div")
        self._indent -= 1
        self._write(")")

    def _emit_wasi_wall_wrapper(self) -> None:
        """``$Clock_now_secs (handle i32) -> f64``.

        Drops the handle, calls wall-clock.now into the reserved
        16-byte scratch area (datetime: u64 seconds @0, u32
        nanoseconds @8), then returns ``seconds + nanoseconds / 1e9``
        as f64. Unsigned conversions on both fields."""
        scratch = self._wasi_walltime_scratch_offset
        self._write(
            "(func $Clock_now_secs (param $handle i32) (result f64)"
        )
        self._indent += 1
        # wall-clock.now(scratch_ptr)
        self._write(f"i32.const {scratch}")
        self._write("call $wasi_wall_now")
        # seconds (u64 @0) -> f64
        self._write(f"i32.const {scratch}")
        self._write("i64.load")
        self._write("f64.convert_i64_u")
        # nanoseconds (u32 @8) -> f64 / 1e9
        self._write(f"i32.const {scratch}")
        self._write("i32.load offset=8")
        self._write("f64.convert_i32_u")
        self._write("f64.const 1000000000")
        self._write("f64.div")
        # seconds + nanos/1e9
        self._write("f64.add")
        self._indent -= 1
        self._write(")")

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
        the ``capa:host`` host bridge."""
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
