"""Experimental WASI Preview 2 import emission (opt-in ``--wasi``).

A proof-of-concept that migrates the PURE-READER capability
touch-points off the custom ``capa:host`` interfaces and onto
canonical WASI Preview 2 (``0.2.0``) interfaces:

- ``Random.system_seed``   -> ``wasi:random/random@0.2.0`` ``get-random-u64``
- ``Clock.now_monotonic``  -> ``wasi:clocks/monotonic-clock@0.2.0`` ``now``
- ``Clock.now_secs``       -> ``wasi:clocks/wall-clock@0.2.0`` ``now``
- ``Env.get``              -> ``wasi:cli/environment@0.2.0`` ``get-environment``
- ``Env.args``             -> ``wasi:cli/environment@0.2.0`` ``get-arguments``
- ``Env.restrict_to_keys`` -> GUEST-SIDE allow-list narrowing (no host)
- ``Env.allows``           -> GUEST-SIDE allow-list membership (no host)

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

Env GUEST-SIDE ATTENUATION (Level 2 of
``docs/design/wasi-attenuation.md``)
------------------------------------------------------------------
``wasi:cli/environment`` is a pure reader: there is no host-side cap
object to hold an allow-list, so Env attenuation has no host runtime
home. Rather than reject it (the prior PoC behaviour), this mode
implements the narrowing GUEST-SIDE, with semantics byte-identical to
the Python oracle (``capa/runtime/_capabilities.py:355-372``).

The Env value (an i32 the host passes to ``main``, and that
``restrict_to_keys`` returns) is REINTERPRETED guest-side:

- ``0``       = UNRESTRICTED (the root Env ``main`` receives; the host
  passes 0 in this mode, since the capa:host handle has no meaning on
  the wasi path).
- non-zero    = a pointer to a ``List<String>`` header (16 bytes:
  len@0, cap@4, data_ptr@8, pad@12) whose data array holds the
  ALLOW-LIST: N packed ``(str_ptr, str_len)`` i32 pairs. The same
  layout a Capa ``List<String>`` uses, so the keys argument of
  ``restrict_to_keys`` (itself a ``List<String>``) and the produced
  allow-list share one shape and one scan helper (``$str_eq``).

The three operations, all in WAT (the wrappers below):

- ``$Env_restrict_to_keys (handle, keys_data_ptr, keys_len) -> i32``
  builds a NEW allow-list = INTERSECTION of the current allow-list
  with ``keys`` (monotonic, never widens; an unrestricted ``handle``
  intersected with ``keys`` becomes restricted to ``keys``), allocates
  a fresh ``List<String>`` for it, returns the pointer. Identical to
  ``Env.restrict_to_keys`` (``new & self._allowed_keys``).
- ``$Env_allows (handle, key_ptr, key_len) -> i32`` returns 1 iff
  ``handle == 0`` (unrestricted) OR ``key`` is in the allow-list.
- ``$Env_get`` is extended to FAIL CLOSED: when ``handle`` is
  restricted and ``key`` is not in the allow-list it writes ``none``
  WITHOUT reading the environment, identical to the Python
  ``Env.get`` (``if not self.allows(name): return None_``).

GUARANTEE LEVEL (honest): this is Level 2. The host still
``inherit_env``s the FULL environment to the component (the ceiling is
NOT yet materialised via env-set, that is Level 1, a later increment),
so the fine allow-list narrowing is imposed by the COMPILER-GENERATED
guest code, not by the WASI host. It is PROVED by the compiler (the
guest only ever narrows) and REINFORCED by our host (which generated
the guest); under a stock / tampered WASI host the full environment is
reachable and the narrowing would not be re-checked.

``Env.args`` is NOT attenuated (matching the oracle: ``Env`` has no
arg restriction); its wrapper ignores the handle.

Excluded from this mode (rejected with a clear error so a program
never silently miscompiles):

- ``Clock.sleep``  -> would pull ``wasi:io/streams`` / poll, out of
  scope.
- Clock attenuation (``restrict_to_after``) -> the wasi:clocks
  interfaces are pure readers with no host-side handle table to
  enforce a deadline; a future design item.
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
    # Guest-side attenuation (Level 2): no host import, but listed here
    # so the import loop in ``WasmEmitter.emit`` does NOT try to emit a
    # ``capa:host/env`` import for them (the host provides no such
    # function in WASI mode). Their ``$Env_*`` bindings are emitted as
    # guest WAT wrappers by ``_emit_wasi_wrappers``.
    ("Env", "restrict_to_keys"),
    ("Env", "allows"),
    # Fs metadata migration (2026-06-27): exists / is_dir / mkdir route
    # to wasi:filesystem (stat-at / create-directory-at) against the
    # host-granted preopen descriptors rather than the capa:host/fs
    # bridge. read / write / list_dir / restrict_to / allows are NOT
    # migrated (read / write / list_dir need wasi:io streams; the
    # attenuators are the fine-grained Level 2 layer) and are rejected
    # by ``_validate_wasi_caps`` so a program never silently
    # miscompiles; the same programs run on the default capa:host
    # backend.
    ("Fs", "exists"),
    ("Fs", "is_dir"),
    ("Fs", "mkdir"),
})


# Versioned WASI import strings. Bumping the WASI release these target
# means editing both these strings and the vendored WIT package
# versions in ``capa/wasi_wit``.
_WASI_RANDOM = "wasi:random/random@0.2.0"
_WASI_MONOTONIC = "wasi:clocks/monotonic-clock@0.2.0"
_WASI_WALL = "wasi:clocks/wall-clock@0.2.0"
_WASI_ENVIRONMENT = "wasi:cli/environment@0.2.0"
_WASI_FS_TYPES = "wasi:filesystem/types@0.2.0"
_WASI_FS_PREOPENS = "wasi:filesystem/preopens@0.2.0"

# Fs metadata methods this WASI increment migrates to wasi:filesystem.
_WASI_FS_METADATA: frozenset[str] = frozenset({"exists", "is_dir", "mkdir"})

# Fs methods rejected in WASI mode for now (with a clear compile-time
# error): read / write / list_dir need wasi:io streams; restrict_to /
# allows are the fine-grained attenuation layer (a later increment).
_WASI_FS_REJECTED: frozenset[str] = frozenset({
    "read", "write", "list_dir", "restrict_to", "allows",
})


class _WasiEmissionMixin:
    """Mixin folded into ``WasmEmitter``; active only when
    ``self._wasi`` is True (the opt-in ``--wasi`` flag)."""

    def _validate_wasi_caps(self) -> None:
        """Reject the Clock surface this mode does not migrate.

        ``Clock.sleep`` and the clock attenuator
        ``Clock.restrict_to_after`` have no canonical wasi:clocks
        backing in this PoC (the wasi:clocks interfaces are pure
        readers with no host-side handle table to enforce a deadline).
        Rather than emit something wrong we fail loudly so the user
        knows to fall back to the default backend.

        Env is FULLY supported in WASI mode: ``get`` / ``args`` route
        to ``wasi:cli/environment``, and the attenuators
        ``restrict_to_keys`` / ``allows`` are implemented GUEST-SIDE
        (Level 2 of ``docs/design/wasi-attenuation.md``), so no Env
        method is rejected here.

        Fs in WASI mode supports the METADATA operations only
        (``exists`` / ``is_dir`` / ``mkdir`` -> wasi:filesystem
        stat-at / create-directory-at against the host preopens). The
        stream-bearing ``read`` / ``write`` / ``list_dir`` and the
        fine-grained attenuators ``restrict_to`` / ``allows`` are
        rejected here; they land in later increments.
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
            if cap == "Fs" and method in _WASI_FS_REJECTED:
                # read / write / list_dir need wasi:io streams;
                # restrict_to / allows are the fine-grained attenuation
                # layer. Only the metadata ops are migrated so far.
                raise WasmEmissionError(
                    f"Fs.{method} is not supported in the WASI mode "
                    f"yet (only the metadata operations exists / "
                    f"is_dir / mkdir are migrated to wasi:filesystem); "
                    f"use the default capa:host backend (drop --wasi)."
                )
        # Fail-closed proof obligation: if the program uses a migrated
        # Fs metadata op but its static path ceiling is NOT closed (a
        # dynamic path), there is no preopen to address and the wrapper
        # cannot run. Reject at compile time with a clear message
        # rather than emit code that always denies at runtime.
        if any(
            cap == "Fs" and method in _WASI_FS_METADATA
            for cap, method in self._used_caps
        ) and self._fs_ceiling is not None and not self._fs_ceiling.closed:
            raise WasmEmissionError(
                "Fs in WASI mode requires every filesystem path to be a "
                "string literal (the static preopen ceiling must be "
                "closed); this program passes a dynamic path to an Fs "
                "operation, so no preopen can be derived (fail-closed). "
                "Use the default capa:host backend (drop --wasi)."
            )

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
        # Fs metadata (2026-06-27): exists / is_dir / mkdir import the
        # wasi:filesystem preopens + descriptor methods. The imports
        # are shared, so emit each at most once when ANY metadata op is
        # used. The core ABI shapes were validated against
        # wasm-tools 1.249.0 / wasmtime add_wasip2():
        #   preopens.get-directories       -> (param i32)  [ret area]
        #   [method]descriptor.stat-at     -> (param i32 i32 i32 i32 i32)
        #       (self-handle, path-flags, path_ptr, path_len, ret_area)
        #   [method]descriptor.create-directory-at
        #                                  -> (param i32 i32 i32 i32)
        #       (self-handle, path_ptr, path_len, ret_area)
        #   [resource-drop]descriptor      -> (param i32)
        if any(m in _WASI_FS_METADATA for (c, m) in used if c == "Fs"):
            self._write(
                f'(import "{_WASI_FS_PREOPENS}" "get-directories" '
                f'(func $wasi_fs_get_directories (param i32)))'
            )
            self._write(
                f'(import "{_WASI_FS_TYPES}" "[method]descriptor.stat-at" '
                f'(func $wasi_fs_stat_at '
                f'(param i32) (param i32) (param i32) (param i32) (param i32)))'
            )
            if ("Fs", "mkdir") in used:
                self._write(
                    f'(import "{_WASI_FS_TYPES}" '
                    f'"[method]descriptor.create-directory-at" '
                    f'(func $wasi_fs_create_directory_at '
                    f'(param i32) (param i32) (param i32) (param i32)))'
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
        # The shared allow-list membership helper backs both the
        # ``get`` fail-closed prologue and the ``allows`` body; emit it
        # once if either reaches it. (``restrict_to_keys`` also calls
        # it, but a program never narrows without later querying or
        # reading, so gating on get/allows is sufficient; emit it for
        # restrict_to_keys too for a standalone narrow-only program.)
        if (("Env", "get") in used
                or ("Env", "allows") in used
                or ("Env", "restrict_to_keys") in used):
            self._emit_wasi_env_key_allowed_helper()
        if ("Env", "get") in used:
            self._emit_wasi_env_get_wrapper()
        if ("Env", "args") in used:
            self._emit_wasi_env_args_wrapper()
        # Guest-side Env attenuation (Level 2). A program that calls
        # ``allows`` without ``restrict_to_keys`` is possible (it just
        # always returns true on the unrestricted root), so gate each
        # wrapper independently on its own touch-point.
        if ("Env", "restrict_to_keys") in used:
            self._emit_wasi_env_restrict_to_keys_wrapper()
        if ("Env", "allows") in used:
            self._emit_wasi_env_allows_wrapper()
        # Fs metadata (2026-06-27). The shared preopen-descriptor
        # resolver backs all three metadata wrappers; emit it once when
        # any of them is used.
        fs_meta_used = [
            m for (c, m) in used if c == "Fs" and m in _WASI_FS_METADATA
        ]
        if fs_meta_used:
            self._emit_wasi_fs_preopen_desc_helper()
        if ("Fs", "exists") in used:
            self._emit_wasi_fs_exists_wrapper()
        if ("Fs", "is_dir") in used:
            self._emit_wasi_fs_is_dir_wrapper()
        if ("Fs", "mkdir") in used:
            self._emit_wasi_fs_mkdir_wrapper()

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

    # ----- Fs metadata via wasi:filesystem (no streams) ----------

    def _emit_wasi_fs_preopen_desc_helper(self) -> None:
        """``$__wasi_fs_preopen_desc (idx i32) -> i32`` -> the
        directory descriptor handle for preopen ``idx``.

        Lazily calls ``preopens.get-directories`` ONCE (an
        indirect-return ``list<tuple<descriptor, string>>``) into the
        reserved 8-byte scratch (data_ptr @0, len @4), caches the data
        pointer in the ``$__wasi_fs_pre_data`` global, and returns the
        descriptor handle of the ``idx``-th element. Each element is a
        12-byte record: descriptor(own i32) @0, str_ptr @4, str_len
        @8; only the handle @0 is needed (the compiler resolved each
        literal Fs path to its preopen index + basename, so the guest
        never matches the preopen path strings at runtime).

        The descriptors are returned in the host's preopen registration
        order, which the host installs in the SAME sorted order the
        compiler used to assign indices (see capa.ir._fs_ceiling), so
        index K names directory K. The descriptors live for the
        component's lifetime (they are the preopen roots, never
        dropped); caching the list pointer is sound."""
        scratch = self._wasi_fs_scratch_offset
        self._write(
            "(func $__wasi_fs_preopen_desc (param $idx i32) (result i32)"
        )
        self._indent += 1
        # First call: fetch + cache the preopen list data pointer.
        self._write("global.get $__wasi_fs_pre_inited")
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        self._write(f"i32.const {scratch}")
        self._write("call $wasi_fs_get_directories")
        self._write(f"i32.const {scratch}")
        self._write("i32.load offset=0")
        self._write("global.set $__wasi_fs_pre_data")
        self._write("i32.const 1")
        self._write("global.set $__wasi_fs_pre_inited")
        self._indent -= 1
        self._write("end")
        # desc = pre_data[idx].handle@0 = *(pre_data + idx*12)
        self._write("global.get $__wasi_fs_pre_data")
        self._write("local.get $idx")
        self._write("i32.const 12")
        self._write("i32.mul")
        self._write("i32.add")
        self._write("i32.load offset=0")
        self._indent -= 1
        self._write(")")

    def _emit_wasi_fs_exists_wrapper(self) -> None:
        """``$Fs_exists (idx i32, rel_ptr i32, rel_len i32) -> i32``.

        stat-at(preopen_desc(idx), path-flags=symlink-follow(1),
        rel_path) into the reserved scratch; the result discriminant
        @0 is 0 on Ok (the entry exists) and non-zero on Err
        (no-entry, ...). Returns 1 when the entry exists, 0 otherwise
        -- byte-identical to the Python oracle's
        ``os.path.exists`` gated by the cap (here the preopen IS the
        gate: a path outside every preopen is unreachable, fail-closed
        as absent)."""
        scratch = self._wasi_fs_scratch_offset
        self._write(
            "(func $Fs_exists (param $idx i32) (param $rel_ptr i32) "
            "(param $rel_len i32) (result i32)"
        )
        self._indent += 1
        self._write("local.get $idx")
        self._write("call $__wasi_fs_preopen_desc")
        self._write("i32.const 1")  # path-flags: symlink-follow
        self._write("local.get $rel_ptr")
        self._write("local.get $rel_len")
        self._write(f"i32.const {scratch}")
        self._write("call $wasi_fs_stat_at")
        # exists iff discriminant byte @0 == 0 (Ok).
        self._write(f"i32.const {scratch}")
        self._write("i32.load8_u offset=0")
        self._write("i32.eqz")
        self._indent -= 1
        self._write(")")

    def _emit_wasi_fs_is_dir_wrapper(self) -> None:
        """``$Fs_is_dir (idx i32, rel_ptr i32, rel_len i32) -> i32``.

        stat-at as ``exists``; on Ok, the ``descriptor-stat`` Ok
        payload starts at offset 8 (u64 alignment), and its first
        field ``%type`` is a ``descriptor-type`` enum (1 byte), where
        value 3 == ``directory`` in the wasi:filesystem 0.2.0 enum
        order. Returns 1 iff the stat succeeded AND the type is
        directory, else 0 -- byte-identical to the oracle's
        ``os.path.isdir`` (a denied / absent path reports false, so the
        cap leaks no path type)."""
        scratch = self._wasi_fs_scratch_offset
        self._write(
            "(func $Fs_is_dir (param $idx i32) (param $rel_ptr i32) "
            "(param $rel_len i32) (result i32)"
        )
        self._indent += 1
        self._write("local.get $idx")
        self._write("call $__wasi_fs_preopen_desc")
        self._write("i32.const 1")
        self._write("local.get $rel_ptr")
        self._write("local.get $rel_len")
        self._write(f"i32.const {scratch}")
        self._write("call $wasi_fs_stat_at")
        # if Err (disc != 0) -> 0; else type@+8 == 3 (directory).
        self._write(f"i32.const {scratch}")
        self._write("i32.load8_u offset=0")
        self._write("if (result i32)")
        self._indent += 1
        self._write("i32.const 0")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        self._write(f"i32.const {scratch}")
        self._write("i32.load8_u offset=8")
        self._write("i32.const 3")
        self._write("i32.eq")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write(")")

    def _emit_wasi_fs_mkdir_wrapper(self) -> None:
        """``$Fs_mkdir (idx i32, rel_ptr i32, rel_len i32,
        ret_area i32)`` -> writes a ``result<_, io-error>`` (20-byte
        canonical-ABI shape) into ``ret_area``.

        Matches the call shape ``_emit_wasi_fs_metadata_call`` produces
        for mkdir (preopen index + rel (ptr, len) + ret_area), so the
        existing ``result_unit_io_error`` materialiser lifts the result
        into a Capa ``Result<Unit, IoError>`` unchanged, exactly as the
        capa:host mkdir does.

        create-directory-at(preopen_desc(idx), rel_path) into the
        wasi-call scratch. Idempotent (matching the oracle's
        ``os.makedirs(path, exist_ok=True)``): an Ok (disc @0 == 0) is
        success, and an Err whose error-code @+1 == 7 (``exist`` in the
        wasi:filesystem 0.2.0 enum order) is also treated as success;
        both write ``ret_area.tag = 0`` (Ok<Unit>). Any other Err
        writes ``ret_area.tag = 1`` plus an IoError record (message =
        the interned ``mkdir failed`` string, empty cause) into the
        Err arm fields the materialiser reads (m_ptr @4, m_len @8,
        c_ptr @12, c_len @16).

        Single-segment only: ``create-directory-at`` creates ONE
        directory relative to the preopen descriptor. The full
        recursive ``os.makedirs`` (creating missing intermediate
        segments) is NOT replicated in this increment; a literal
        ``fs.mkdir("dir/sub")`` whose parent ``dir`` is the preopen
        creates ``sub`` directly, which is the common case. Deeper
        nested creation is a documented follow-up (it needs per-segment
        open-at descriptor walking)."""
        scratch = self._wasi_fs_scratch_offset
        msg_off, msg_len = self._intern_string("mkdir failed")
        self._write(
            "(func $Fs_mkdir (param $idx i32) (param $rel_ptr i32) "
            "(param $rel_len i32) (param $ret_area i32)"
        )
        self._indent += 1
        self._write("local.get $idx")
        self._write("call $__wasi_fs_preopen_desc")
        self._write("local.get $rel_ptr")
        self._write("local.get $rel_len")
        self._write(f"i32.const {scratch}")
        self._write("call $wasi_fs_create_directory_at")
        # success = Ok (disc @0 == 0) OR Err code @+1 == 7 (exist).
        self._write(f"i32.const {scratch}")
        self._write("i32.load8_u offset=0")
        self._write("i32.eqz")
        self._write(f"i32.const {scratch}")
        self._write("i32.load8_u offset=1")
        self._write("i32.const 7")
        self._write("i32.eq")
        self._write("i32.or")
        self._write("if")
        self._indent += 1
        # Ok<Unit>: tag = 0.
        self._write("local.get $ret_area")
        self._write("i32.const 0")
        self._write("i32.store offset=0")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        # Err<io-error>: tag = 1; message = interned string; cause "".
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
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write(")")
