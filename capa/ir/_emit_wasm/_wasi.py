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
    # Stdio output migration (Phase 1, 2026-06-29): print / println /
    # eprintln route to wasi:cli/stdout (print / println) and
    # wasi:cli/stderr (eprintln) + wasi:io/streams. Each guest wrapper
    # calls get-stdout / get-stderr -> output-stream, writes the text
    # in <= 4096-byte chunks via blocking-write-and-flush, then drops
    # the output-stream. println / eprintln append a trailing "\n"
    # (matching the capa:host semantics, where the host wrote
    # ``msg + "\n"``). Listed here so the import loop in
    # ``WasmEmitter.emit`` does NOT emit a ``capa:host/stdio`` import for
    # them; their ``$Stdio_*`` bindings are guest WAT wrappers emitted by
    # ``_emit_wasi_wrappers``.
    ("Stdio", "print"),
    ("Stdio", "println"),
    ("Stdio", "eprintln"),
    # Stdio.read_line migration (Phase 2, 2026-06-29): read_line routes to
    # wasi:cli/stdin (get-stdin -> input-stream) + wasi:io/streams
    # (input-stream.blocking-read, byte-at-a-time until "\n" or EOF). It
    # reuses Fs.read's blocking-read / accumulation / input-stream-drop
    # machinery but stops at the first "\n" (not at EOF). Listed here so
    # the import loop in ``WasmEmitter.emit`` does NOT emit a
    # ``capa:host/stdio`` import for it; its ``$Stdio_read_line`` binding
    # is a guest WAT wrapper emitted by ``_emit_wasi_wrappers``. With this
    # phase, ONLY ``panic`` remains on capa:host for a --wasi program.
    ("Stdio", "read_line"),
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
    # bridge.
    ("Fs", "exists"),
    ("Fs", "is_dir"),
    ("Fs", "mkdir"),
    # Fs.read migration (2026-06-28): read routes to wasi:filesystem
    # (descriptor.open-at -> read-via-stream) + wasi:io/streams
    # (input-stream.blocking-read) against the host-granted preopen
    # descriptors. This is the first touch-point that uses streams.
    ("Fs", "read"),
    # Fs.write migration (2026-06-28): write routes to wasi:filesystem
    # (descriptor.open-at with create|truncate + write -> write-via-
    # stream) + wasi:io/streams (output-stream.blocking-write-and-flush
    # loop + blocking-flush) against the host-granted preopen
    # descriptors. The inverse of read, reusing the same stream
    # machinery.
    ("Fs", "write"),
    # Fs.list_dir migration (2026-06-28): list_dir routes to
    # wasi:filesystem (descriptor.open-at with the directory open-flag +
    # descriptor.read-directory -> directory-entry-stream) and a loop of
    # directory-entry-stream.read-directory-entry to accumulate the entry
    # names, then a guest-side lexicographic sort (via $str_cmp) to match
    # the oracle's ``sorted(os.listdir(path))`` ORDER byte-for-byte (wasi
    # returns entries in filesystem order, not sorted).
    ("Fs", "list_dir"),
    # Fs FINE ATTENUATION (2026-06-28): restrict_to / allows are
    # implemented GUEST-SIDE (Level 2 of docs/design/wasi-attenuation.md),
    # analogous to Env's restrict_to_keys / allows but with path-prefix
    # containment (with lexical ``.``/``..`` normalisation; symlinks
    # unresolved) in place of key equality. No capa:host/fs import: their
    # ``$Fs_restrict_to`` / ``$Fs_allows`` bindings are emitted as guest
    # WAT wrappers by ``_emit_wasi_wrappers``. Listed here so the import
    # loop does NOT try to emit a capa:host/fs import for them (the host
    # provides no such function on the wasi path).
    ("Fs", "restrict_to"),
    ("Fs", "allows"),
    # Net.get migration (2026-06-28, Phase 1) / Net.post migration
    # (2026-06-28, Phase 2): both route to wasi:http (outgoing-handler.
    # handle + the outgoing-request / future-incoming-response /
    # incoming-response / incoming-body resource chain) plus wasi:io/streams
    # (input-stream.blocking-read loop for the response; post ALSO writes
    # the request body via output-stream.blocking-write-and-flush) and
    # wasi:io/poll (the synchronous pollable.block). Both get and post are
    # listed here so the import loop does NOT emit a capa:host/net import
    # for them (the host serves them through wasi:http instead).
    ("Net", "get"),
    ("Net", "post"),
    # Net FINE ATTENUATION (2026-06-29, Phase 3): restrict_to / allows are
    # implemented GUEST-SIDE (Level 2 of docs/design/wasi-attenuation.md),
    # analogous to Env's restrict_to_keys / allows -- exact-hostname
    # equality membership of a List<String> allow-list, sentinel 0 =
    # unrestricted root. No capa:host/net import: their ``$Net_restrict_to``
    # / ``$Net_allows`` bindings are emitted as guest WAT wrappers by
    # ``_emit_wasi_wrappers``. Listed here so the import loop does NOT try
    # to emit a capa:host/net import for them (the host provides no such
    # function on the wasi path). This CLOSES the Net surface in --wasi
    # (get / post / restrict_to / allows).
    ("Net", "restrict_to"),
    ("Net", "allows"),
})


# Versioned WASI import strings. Bumping the WASI release these target
# means editing both these strings and the vendored WIT package
# versions in ``capa/wasi_wit``.
_WASI_RANDOM = "wasi:random/random@0.2.0"
_WASI_MONOTONIC = "wasi:clocks/monotonic-clock@0.2.0"
_WASI_WALL = "wasi:clocks/wall-clock@0.2.0"
_WASI_ENVIRONMENT = "wasi:cli/environment@0.2.0"
_WASI_CLI_STDOUT = "wasi:cli/stdout@0.2.0"
_WASI_CLI_STDERR = "wasi:cli/stderr@0.2.0"
_WASI_CLI_STDIN = "wasi:cli/stdin@0.2.0"
_WASI_FS_TYPES = "wasi:filesystem/types@0.2.0"
_WASI_FS_PREOPENS = "wasi:filesystem/preopens@0.2.0"
_WASI_IO_STREAMS = "wasi:io/streams@0.2.0"
_WASI_IO_ERROR = "wasi:io/error@0.2.0"
_WASI_IO_POLL = "wasi:io/poll@0.2.0"
_WASI_HTTP_TYPES = "wasi:http/types@0.2.0"
_WASI_HTTP_HANDLER = "wasi:http/outgoing-handler@0.2.0"

# Net methods this WASI increment migrates (Phase 1: get; Phase 2: post;
# Phase 3: restrict_to / allows, the fine host-set attenuators implemented
# GUEST-SIDE, Level 2). The Net surface is now COMPLETE in --wasi.
_WASI_NET_MIGRATED: frozenset[str] = frozenset(
    {"get", "post", "restrict_to", "allows"}
)

# The size, in bytes, of each blocking-read chunk request on the Net
# input-stream. One OS page; mirrors the Fs.read chunk. Net.post's REQUEST
# body write is NOT chunked by a fixed page: a wasi:http outgoing-body
# stream is flow-controlled, so the write loop is bounded per iteration by
# the host's ``check-write`` permit budget instead (see ``$Net_post``).
_WASI_NET_READ_CHUNK = 4096

# Fs metadata methods this WASI increment migrates to wasi:filesystem.
_WASI_FS_METADATA: frozenset[str] = frozenset({"exists", "is_dir", "mkdir"})

# Fs stream-bearing / preopen-resource methods migrated to
# wasi:filesystem (+ wasi:io/streams for read / write). All three share
# the preopen-descriptor resolver and the open-at / descriptor-drop
# imports:
# ``read``     (open-at -> read-via-stream -> blocking-read loop),
# ``write``    (open-at create|truncate -> write-via-stream ->
#               blocking-write-and-flush loop -> blocking-flush),
# ``list_dir`` (open-at directory -> read-directory ->
#               read-directory-entry loop -> guest-side sort).
_WASI_FS_STREAM: frozenset[str] = frozenset({"read", "write", "list_dir"})

# Fs methods rejected in WASI mode. EMPTY as of 2026-06-28: every Fs
# method is now migrated -- the metadata ops (exists / is_dir / mkdir),
# the stream-bearing ops (read / write / list_dir), AND the fine
# attenuators (restrict_to / allows, implemented guest-side, Level 2).
# Kept as a (now empty) frozenset so ``_validate_wasi_caps`` and any
# future re-introduction of a rejected method stay structurally
# unchanged.
_WASI_FS_REJECTED: frozenset[str] = frozenset()

# The size, in bytes, of each blocking-read chunk request. read-via-stream
# yields the whole file as a single stream; the guest pulls it in fixed
# chunks, accumulating into a heap buffer until stream-error::closed (EOF).
# A larger chunk means fewer host round-trips; 4096 matches a typical page.
_WASI_FS_READ_CHUNK = 4096

# The maximum number of bytes handed to a single
# ``output-stream.blocking-write-and-flush`` call. The WASI 0.2 stream
# contract bounds a single blocking-write-and-flush to one OS page
# (4096 bytes); larger content is written in a loop of <= this many
# bytes per call. blocking-write-and-flush self-limits AND flushes, so
# the wrapper never has to track the check-write permit window itself
# (the simplest provably-correct write loop, the inverse of the read
# loop's blocking-read(CHUNK) accumulation).
_WASI_FS_WRITE_CHUNK = 4096

# Stdio output methods this WASI increment migrates to wasi:cli (Phase 1,
# 2026-06-29). print / println route to wasi:cli/stdout (get-stdout);
# eprintln routes to wasi:cli/stderr (get-stderr); all three write via
# wasi:io/streams (output-stream.blocking-write-and-flush). read_line is
# NOT here (it stays on capa:host/stdio for now).
_WASI_STDIO_MIGRATED: frozenset[str] = frozenset(
    {"print", "println", "eprintln"}
)

# The maximum number of bytes handed to a single
# ``output-stream.blocking-write-and-flush`` call on the stdout / stderr
# stream. Identical bound and rationale to ``_WASI_FS_WRITE_CHUNK``: the
# WASI 0.2 contract caps one blocking-write-and-flush at one OS page
# (4096), and a single write past that TRAPS, so the wrapper loops in
# <= 4096-byte chunks. blocking-write-and-flush self-limits AND flushes,
# so no check-write permit window has to be tracked (stdout / stderr
# drain on their own, unlike the flow-controlled wasi:http request body).
_WASI_STDIO_WRITE_CHUNK = 4096


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

        Fs is FULLY supported in WASI mode (2026-06-28): the METADATA
        operations (``exists`` / ``is_dir`` / ``mkdir`` ->
        wasi:filesystem stat-at / create-directory-at against the host
        preopens), the stream-bearing ``read`` (open-at -> read-via-
        stream -> blocking-read loop), ``write`` (open-at create|
        truncate -> write-via-stream -> blocking-write-and-flush loop ->
        blocking-flush) and ``list_dir`` (open-at directory ->
        read-directory enumeration -> guest-side sort) over
        wasi:io/streams, AND the fine-grained attenuators ``restrict_to``
        / ``allows`` implemented GUEST-SIDE (Level 2 of
        ``docs/design/wasi-attenuation.md``), with path-prefix containment
        that lexically normalises ``.``/``..`` (oracle parity for those)
        but does NOT resolve symlinks (the honest TOCTOU / symlink loss
        documented there). No Fs method is rejected here
        (``_WASI_FS_REJECTED`` is now empty); the fail-closed preopen
        ceiling obligation below still applies to any op that touches the
        filesystem.

        Net (``get`` / ``post``) is supported in WASI mode over wasi:http,
        but ONLY when every url is a string literal, so the static
        allowed-host ceiling can be materialised. A dynamic / interpolated
        url is REJECTED here (2026-06-29), SYMMETRIC with the Fs
        dynamic-path rule: previously a dynamic url compiled to a runtime
        fail-closed (an ``Err(IoError)`` without touching the network) that
        an ``Err(_) -> ()`` arm could swallow silently, degrading output
        with no warning. Rejecting at compile time makes the problem
        visible. The runtime fail-closed in the call-site emitter is kept
        as defence-in-depth. (Env is the one capability that stays at
        Level 2 inherit_env on a dynamic key and is intentionally NOT
        aligned with this fail-closed rule.)
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
                # _WASI_FS_REJECTED is empty as of 2026-06-28 (every Fs
                # method is migrated). Kept structurally so a future
                # rejected method re-uses this branch unchanged.
                raise WasmEmissionError(
                    f"Fs.{method} is not supported in the WASI mode; "
                    f"use the default capa:host backend (drop --wasi)."
                )
            if cap == "Net" and method not in _WASI_NET_MIGRATED:
                # The Net surface is COMPLETE in --wasi (2026-06-29):
                # get / post (the request-building ops over wasi:http) and
                # restrict_to / allows (the fine host-set attenuators,
                # guest-side Level 2 with exact-hostname equality). Any
                # method outside this set is an analyzer addition we do not
                # yet handle; reject it loudly so a program never silently
                # miscompiles.
                raise WasmEmissionError(
                    f"Net.{method} is not supported in the WASI mode; "
                    f"use the default capa:host backend (drop --wasi)."
                )
        # Fail-closed proof obligation: if the program uses a migrated
        # Fs op (metadata or the stream-bearing read) but its static
        # path ceiling is NOT closed (a dynamic path), there is no
        # preopen to address and the wrapper cannot run. Reject at
        # compile time with a clear message rather than emit code that
        # always denies at runtime.
        #
        # WASI Fs layer b1 (operator preopen, 2026-06-30): when the
        # operator declared ``--preopen <dir>`` (``self._wasi_dynamic_fs``),
        # the dynamic path is RESOLVED AT RUNTIME relative to that single
        # operator preopen (the WASI ``--dir`` model). The rejection is
        # SUPPRESSED -- the operator has explicitly granted the authority
        # the compiler could not derive, a LEVEL-2 operator-DECLARED grant
        # (recorded in the SBOM, distinct from the derived surface). Without
        # ``--preopen`` the rejection stands exactly as before (the prior
        # behaviour is intentionally preserved).
        if any(
            cap == "Fs" and method in (_WASI_FS_METADATA | _WASI_FS_STREAM)
            for cap, method in self._used_caps
        ) and self._fs_ceiling is not None and not self._fs_ceiling.closed \
                and not self._wasi_dynamic_fs:
            raise WasmEmissionError(
                "Fs in WASI mode requires every filesystem path to be a "
                "string literal (the static preopen ceiling must be "
                "closed); this program passes a dynamic path to an Fs "
                "operation, so no preopen can be derived (fail-closed). "
                "Use the default capa:host backend (drop --wasi)."
            )
        # Fail-closed proof obligation for Net, SYMMETRIC with Fs above: if
        # the program uses a request-building Net op (``get`` / ``post``)
        # but its static host ceiling is NOT closed (a dynamic / interpolated
        # url reaches get/post), the allowed-host ceiling cannot be
        # materialised. Reject at COMPILE time with a clear message rather
        # than emit a call site that always FAILS CLOSED at runtime (an
        # ``Err(IoError)`` without touching the network): a program that
        # swallows that Err (``Err(_) -> ()``) would otherwise degrade its
        # output SILENTLY with no warning. This mirrors the Fs rule exactly
        # (a dynamic Fs path rejects); the runtime fail-closed in the
        # call-site emitter is RETAINED as defence-in-depth but is no longer
        # the normal path for a dynamic url. (Env stays at Level 2
        # inherit_env and is intentionally NOT aligned here.)
        if any(
            cap == "Net" and method in ("get", "post")
            for cap, method in self._used_caps
        ) and self._net_ceiling is not None and not self._net_ceiling.closed:
            raise WasmEmissionError(
                "Net in WASI mode requires every URL passed to get/post to "
                "be a string literal so the allowed-host ceiling can be "
                "materialised; this program passes a dynamic URL (a local, "
                "parameter, interpolated or computed value) to a Net "
                "operation, so no host ceiling can be derived (fail-closed). "
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

    def _wasi_fs_list_dir_needs_str_cmp(self) -> bool:
        """True when ``--wasi`` is active and the program reaches
        ``Fs.list_dir``, whose guest-side wrapper sorts the directory
        entry names via ``$str_cmp`` to match the oracle's
        ``sorted(os.listdir(path))`` order. The default path routes the
        sort through the Python host's ``sorted``, so this gate is
        WASI-only; it ensures ``$str_cmp`` is emitted even when the
        program uses no String ``<`` / ``>`` operator."""
        return self._wasi and ("Fs", "list_dir") in self._used_caps

    def _wasi_fs_uses_attenuation(self) -> bool:
        """True when ``--wasi`` is active and the program reaches the
        FINE Fs attenuators ``restrict_to`` / ``allows`` (Level 2 of
        ``docs/design/wasi-attenuation.md``) OR any privileged Fs op
        that the attenuation gate sits in front of (exists / is_dir /
        mkdir / read / write / list_dir).

        Gates the emission of the guest-side attenuation helpers
        (``$Fs_path_contained`` / ``$Fs_path_allowed``) and the
        ``$Fs_restrict_to`` / ``$Fs_allows`` wrappers. Every migrated Fs
        op consults ``$Fs_path_allowed`` in its fail-closed prologue, so
        the helper must be present whenever any Fs op is, not only when
        ``restrict_to`` / ``allows`` appear textually: a program that
        receives a restricted Fs from a CALLER (across a function
        boundary) and only ever reads through it must still re-check the
        allow-list it carries."""
        return self._wasi and any(
            cap == "Fs"
            and method in (
                "restrict_to", "allows",
                "exists", "is_dir", "mkdir", "read", "write", "list_dir",
            )
            for (cap, method) in self._used_caps
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
        # get-directories backs the shared preopen-descriptor resolver,
        # used by every migrated Fs op (metadata AND read).
        if any(
            m in (_WASI_FS_METADATA | _WASI_FS_STREAM)
            for (c, m) in used if c == "Fs"
        ):
            self._write(
                f'(import "{_WASI_FS_PREOPENS}" "get-directories" '
                f'(func $wasi_fs_get_directories (param i32)))'
            )
        if any(m in _WASI_FS_METADATA for (c, m) in used if c == "Fs"):
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
        # Fs.read (2026-06-28) + Fs.write (2026-06-28) + Fs.list_dir
        # (2026-06-28): the ops that open-at a descriptor relative to a
        # preopen. ``read`` is open-at + read-via-stream + blocking-read;
        # ``write`` is open-at + write-via-stream +
        # blocking-write-and-flush + blocking-flush; ``list_dir`` is
        # open-at (directory open-flag) + read-directory +
        # read-directory-entry loop. The SHARED imports (open-at and the
        # descriptor drop) are emitted once if ANY of the three is used;
        # the per-op method imports are gated individually. The io-error
        # drop is shared by read + write only (their blocking stream-error
        # carries an ``error`` OWN resource); list_dir's read-directory /
        # read-directory-entry fail with an ``error-code`` ENUM, which
        # carries no resource, so list_dir does not import it. The
        # core-ABI shapes were validated against wasm-tools 1.249.0 /
        # wasmtime 44.0.1 add_wasip2():
        #   descriptor.open-at         -> (param i32 i32 i32 i32 i32 i32 i32)
        #     (self, path-flags, path_ptr, path_len, open-flags,
        #      descriptor-flags, ret_area)
        #   descriptor.read-via-stream -> (param i32 i64 i32)
        #     (self-handle, offset(filesize=u64), ret_area)
        #   descriptor.write-via-stream -> (param i32 i64 i32)
        #     (self-handle, offset(filesize=u64), ret_area)
        #   descriptor.read-directory  -> (param i32 i32)
        #     (self-handle, ret_area) -> result<directory-entry-stream,
        #     error-code> (disc @0, stream-own @4)
        #   directory-entry-stream.read-directory-entry -> (param i32 i32)
        #     (self-handle, ret_area) -> result<option<directory-entry>,
        #     error-code> (result-disc @0, option-disc @4, entry.type @8,
        #     entry.name_ptr @12, entry.name_len @16)
        #   input-stream.blocking-read  -> (param i32 i64 i32)
        #     (self-handle, len(u64), ret_area)
        #   output-stream.blocking-write-and-flush -> (param i32 i32 i32 i32)
        #     (self-handle, contents_ptr, contents_len, ret_area)
        #   output-stream.blocking-flush -> (param i32 i32)
        #     (self-handle, ret_area)
        #   [resource-drop]descriptor              (wasi:filesystem/types) -> (param i32)
        #   [resource-drop]directory-entry-stream  (wasi:filesystem/types) -> (param i32)
        #   [resource-drop]input-stream            (wasi:io/streams)       -> (param i32)
        #   [resource-drop]output-stream           (wasi:io/streams)       -> (param i32)
        #   [resource-drop]error                   (wasi:io/error)         -> (param i32)
        open_at_used = (
            ("Fs", "read") in used
            or ("Fs", "write") in used
            or ("Fs", "list_dir") in used
        )
        if open_at_used:
            # Shared by read + write + list_dir.
            self._write(
                f'(import "{_WASI_FS_TYPES}" "[method]descriptor.open-at" '
                f'(func $wasi_fs_open_at '
                f'(param i32) (param i32) (param i32) (param i32) '
                f'(param i32) (param i32) (param i32)))'
            )
            self._write(
                f'(import "{_WASI_FS_TYPES}" "[resource-drop]descriptor" '
                f'(func $wasi_fs_drop_descriptor (param i32)))'
            )
        if ("Fs", "read") in used or ("Fs", "write") in used:
            # The io-error drop is needed only by the blocking stream
            # ops (read / write); list_dir's enumeration errors are an
            # error-code enum with no carried resource.
            self._write(
                f'(import "{_WASI_IO_ERROR}" "[resource-drop]error" '
                f'(func $wasi_io_drop_error (param i32)))'
            )
        if ("Fs", "list_dir") in used:
            self._write(
                f'(import "{_WASI_FS_TYPES}" '
                f'"[method]descriptor.read-directory" '
                f'(func $wasi_fs_read_directory '
                f'(param i32) (param i32)))'
            )
            self._write(
                f'(import "{_WASI_FS_TYPES}" '
                f'"[method]directory-entry-stream.read-directory-entry" '
                f'(func $wasi_fs_read_directory_entry '
                f'(param i32) (param i32)))'
            )
            self._write(
                f'(import "{_WASI_FS_TYPES}" '
                f'"[resource-drop]directory-entry-stream" '
                f'(func $wasi_fs_drop_dir_entry_stream (param i32)))'
            )
        if ("Fs", "read") in used:
            self._write(
                f'(import "{_WASI_FS_TYPES}" '
                f'"[method]descriptor.read-via-stream" '
                f'(func $wasi_fs_read_via_stream '
                f'(param i32) (param i64) (param i32)))'
            )
            self._write(
                f'(import "{_WASI_IO_STREAMS}" '
                f'"[method]input-stream.blocking-read" '
                f'(func $wasi_io_blocking_read '
                f'(param i32) (param i64) (param i32)))'
            )
            self._write(
                f'(import "{_WASI_IO_STREAMS}" '
                f'"[resource-drop]input-stream" '
                f'(func $wasi_io_drop_input_stream (param i32)))'
            )
        if ("Fs", "write") in used:
            self._write(
                f'(import "{_WASI_FS_TYPES}" '
                f'"[method]descriptor.write-via-stream" '
                f'(func $wasi_fs_write_via_stream '
                f'(param i32) (param i64) (param i32)))'
            )
            self._write(
                f'(import "{_WASI_IO_STREAMS}" '
                f'"[method]output-stream.blocking-write-and-flush" '
                f'(func $wasi_io_blocking_write_and_flush '
                f'(param i32) (param i32) (param i32) (param i32)))'
            )
            self._write(
                f'(import "{_WASI_IO_STREAMS}" '
                f'"[method]output-stream.blocking-flush" '
                f'(func $wasi_io_blocking_flush '
                f'(param i32) (param i32)))'
            )
            self._write(
                f'(import "{_WASI_IO_STREAMS}" '
                f'"[resource-drop]output-stream" '
                f'(func $wasi_io_drop_output_stream (param i32)))'
            )
        # Net.get (2026-06-28, Phase 1) / Net.post (2026-06-28, Phase 2):
        # the wasi:http outbound request chain (shared imports). All
        # core-ABI shapes were validated by the oracle spike against
        # wasm-tools 1.249.0 / wasmtime 45.0.0 (the receipt + the OWN
        # resources + the triple-result lift; see ``$Net_get`` /
        # ``$Net_post``). A ``result`` with no payload type lowers to a flat
        # i32 (the set-* methods); a ``result<own<T>, error-code>`` lowers
        # indirect and is 8-ALIGNED (error-code carries an option<u64>), so
        # the Ok value sits at ret+8, not ret+4; a ``result<own<T>, _>``
        # (body / consume / stream) is 4-aligned with the value at ret+4.
        # Net.post reuses every GET import and ADDS only the output-stream
        # write/flush/drop imports (already shared with Fs.write) to push
        # the request body before the handle.
        net_used = ("Net", "get") in used or ("Net", "post") in used
        if net_used:
            self._write(
                f'(import "{_WASI_HTTP_TYPES}" "[constructor]fields" '
                f'(func $wasi_http_fields_new (result i32)))'
            )
            self._write(
                f'(import "{_WASI_HTTP_TYPES}" '
                f'"[constructor]outgoing-request" '
                f'(func $wasi_http_request_new (param i32) (result i32)))'
            )
            self._write(
                f'(import "{_WASI_HTTP_TYPES}" '
                f'"[method]outgoing-request.set-method" '
                f'(func $wasi_http_set_method '
                f'(param i32) (param i32) (param i32) (param i32) '
                f'(result i32)))'
            )
            self._write(
                f'(import "{_WASI_HTTP_TYPES}" '
                f'"[method]outgoing-request.set-scheme" '
                f'(func $wasi_http_set_scheme '
                f'(param i32) (param i32) (param i32) (param i32) '
                f'(param i32) (result i32)))'
            )
            self._write(
                f'(import "{_WASI_HTTP_TYPES}" '
                f'"[method]outgoing-request.set-authority" '
                f'(func $wasi_http_set_authority '
                f'(param i32) (param i32) (param i32) (param i32) '
                f'(result i32)))'
            )
            self._write(
                f'(import "{_WASI_HTTP_TYPES}" '
                f'"[method]outgoing-request.set-path-with-query" '
                f'(func $wasi_http_set_path '
                f'(param i32) (param i32) (param i32) (param i32) '
                f'(result i32)))'
            )
            self._write(
                f'(import "{_WASI_HTTP_TYPES}" '
                f'"[method]outgoing-request.body" '
                f'(func $wasi_http_request_body (param i32) (param i32)))'
            )
            self._write(
                f'(import "{_WASI_HTTP_TYPES}" '
                f'"[static]outgoing-body.finish" '
                f'(func $wasi_http_body_finish '
                f'(param i32) (param i32) (param i32) (param i32)))'
            )
            self._write(
                f'(import "{_WASI_HTTP_HANDLER}" "handle" '
                f'(func $wasi_http_handle '
                f'(param i32) (param i32) (param i32) (param i32)))'
            )
            self._write(
                f'(import "{_WASI_HTTP_TYPES}" '
                f'"[method]future-incoming-response.subscribe" '
                f'(func $wasi_http_future_subscribe '
                f'(param i32) (result i32)))'
            )
            self._write(
                f'(import "{_WASI_IO_POLL}" "[method]pollable.block" '
                f'(func $wasi_io_pollable_block (param i32)))'
            )
            self._write(
                f'(import "{_WASI_HTTP_TYPES}" '
                f'"[method]future-incoming-response.get" '
                f'(func $wasi_http_future_get (param i32) (param i32)))'
            )
            self._write(
                f'(import "{_WASI_HTTP_TYPES}" '
                f'"[method]incoming-response.status" '
                f'(func $wasi_http_response_status '
                f'(param i32) (result i32)))'
            )
            self._write(
                f'(import "{_WASI_HTTP_TYPES}" '
                f'"[method]incoming-response.consume" '
                f'(func $wasi_http_response_consume '
                f'(param i32) (param i32)))'
            )
            self._write(
                f'(import "{_WASI_HTTP_TYPES}" '
                f'"[method]incoming-body.stream" '
                f'(func $wasi_http_body_stream (param i32) (param i32)))'
            )
            # input-stream.blocking-read (shared with Fs.read's import name
            # space only if Fs.read is also used; emit it here when Net.get
            # is used but Fs.read is not, so the symbol always exists).
            if ("Fs", "read") not in used:
                self._write(
                    f'(import "{_WASI_IO_STREAMS}" '
                    f'"[method]input-stream.blocking-read" '
                    f'(func $wasi_io_blocking_read '
                    f'(param i32) (param i64) (param i32)))'
                )
                self._write(
                    f'(import "{_WASI_IO_STREAMS}" '
                    f'"[resource-drop]input-stream" '
                    f'(func $wasi_io_drop_input_stream (param i32)))'
                )
            # io/error drop, shared with Fs.read / Fs.write; emit here only
            # if neither imported it.
            if ("Fs", "read") not in used and ("Fs", "write") not in used:
                self._write(
                    f'(import "{_WASI_IO_ERROR}" "[resource-drop]error" '
                    f'(func $wasi_io_drop_error (param i32)))'
                )
            # OWN-resource drops for the http chain (the preopen-style
            # roots have no analogue here -- every http resource is owned
            # and dropped). outgoing-request is CONSUMED by handle and
            # outgoing-body by finish, so neither needs a drop on the
            # success path; but a failure BEFORE the consuming call must
            # drop them, so both drops are imported.
            self._write(
                f'(import "{_WASI_HTTP_TYPES}" '
                f'"[resource-drop]outgoing-request" '
                f'(func $wasi_http_drop_request (param i32)))'
            )
            self._write(
                f'(import "{_WASI_HTTP_TYPES}" '
                f'"[resource-drop]outgoing-body" '
                f'(func $wasi_http_drop_outgoing_body (param i32)))'
            )
            self._write(
                f'(import "{_WASI_HTTP_TYPES}" '
                f'"[resource-drop]future-incoming-response" '
                f'(func $wasi_http_drop_future (param i32)))'
            )
            self._write(
                f'(import "{_WASI_IO_POLL}" "[resource-drop]pollable" '
                f'(func $wasi_io_drop_pollable (param i32)))'
            )
            self._write(
                f'(import "{_WASI_HTTP_TYPES}" '
                f'"[resource-drop]incoming-response" '
                f'(func $wasi_http_drop_response (param i32)))'
            )
            self._write(
                f'(import "{_WASI_HTTP_TYPES}" '
                f'"[resource-drop]incoming-body" '
                f'(func $wasi_http_drop_incoming_body (param i32)))'
            )
            # Net.post (Phase 2) writes the REQUEST body through the
            # outgoing-body's output-stream BEFORE the handle. Unlike a file
            # descriptor (Fs.write), a wasi:http outgoing-body stream has a
            # FLOW-CONTROL window: the host only drains buffered bytes once
            # the request is actually sent (at ``handle``, which runs AFTER
            # the write loop), so a BLOCKING write past the initial permit
            # window deadlocks forever (proven: a 4097-byte body hangs while
            # 4096 succeeds). The body is therefore written with the
            # FLOW-CONTROLLED pattern the wasi:io contract mandates:
            #   check-write -> permitted budget (u64);
            #   write       -> non-blocking, <= the budget, returns at once;
            #   subscribe + pollable.block -> await more permits when the
            #     budget is momentarily 0 (the host grants them as it buffers
            #     the not-yet-sent body);
            #   flush       -> non-blocking, signals the bytes are complete
            #     (the host drains them on handle).
            # outgoing-body.write fetches the stream (a CHILD of the
            # outgoing-body that MUST be dropped before finish, else finish
            # traps). check-write / write / flush / output-stream.subscribe /
            # the output-stream drop are Net.post-only (Net.get sends no body,
            # and Fs.write's file-descriptor path uses the blocking variants
            # that are safe there). pollable.block / pollable drop are SHARED
            # with the response-poll path (already imported above).
            if ("Net", "post") in used:
                self._write(
                    f'(import "{_WASI_HTTP_TYPES}" '
                    f'"[method]outgoing-body.write" '
                    f'(func $wasi_http_outgoing_body_write '
                    f'(param i32) (param i32)))'
                )
                self._write(
                    f'(import "{_WASI_IO_STREAMS}" '
                    f'"[method]output-stream.check-write" '
                    f'(func $wasi_io_check_write '
                    f'(param i32) (param i32)))'
                )
                self._write(
                    f'(import "{_WASI_IO_STREAMS}" '
                    f'"[method]output-stream.write" '
                    f'(func $wasi_io_stream_write '
                    f'(param i32) (param i32) (param i32) (param i32)))'
                )
                self._write(
                    f'(import "{_WASI_IO_STREAMS}" '
                    f'"[method]output-stream.flush" '
                    f'(func $wasi_io_stream_flush '
                    f'(param i32) (param i32)))'
                )
                self._write(
                    f'(import "{_WASI_IO_STREAMS}" '
                    f'"[method]output-stream.subscribe" '
                    f'(func $wasi_io_stream_subscribe '
                    f'(param i32) (result i32)))'
                )
                # The output-stream resource-drop is SHARED with Fs.write;
                # import it here only if Fs.write did not already, so the
                # symbol exists exactly once.
                if ("Fs", "write") not in used:
                    self._write(
                        f'(import "{_WASI_IO_STREAMS}" '
                        f'"[resource-drop]output-stream" '
                        f'(func $wasi_io_drop_output_stream (param i32)))'
                    )
        # Stdio output (Phase 1, 2026-06-29): print / println / eprintln.
        # get-stdout / get-stderr return an OWNED output-stream; the
        # wrappers write the text in <= 4096-byte chunks via
        # blocking-write-and-flush and then drop the stream. The two
        # wasi:io/streams imports (blocking-write-and-flush + the
        # output-stream resource-drop) are SHARED with Fs.write and
        # Net.post; emit each only if no earlier user already did, so the
        # symbol exists EXACTLY once (a core module re-declaring the same
        # import is rejected by wasm-tools).
        stdio_out_used = any(
            m in _WASI_STDIO_MIGRATED for (c, m) in used if c == "Stdio"
        )
        if stdio_out_used:
            if any((c, m) in used for (c, m) in (
                ("Stdio", "print"), ("Stdio", "println"),
            )):
                self._write(
                    f'(import "{_WASI_CLI_STDOUT}" "get-stdout" '
                    f'(func $wasi_cli_get_stdout (result i32)))'
                )
            if ("Stdio", "eprintln") in used:
                self._write(
                    f'(import "{_WASI_CLI_STDERR}" "get-stderr" '
                    f'(func $wasi_cli_get_stderr (result i32)))'
                )
            # blocking-write-and-flush: imported ONLY by Fs.write (Net.post
            # uses the FLOW-CONTROLLED write / flush, not the blocking
            # variant, so it does NOT import blocking-write-and-flush).
            # Emit it here unless Fs.write already did.
            wbwf_already = ("Fs", "write") in used
            if not wbwf_already:
                self._write(
                    f'(import "{_WASI_IO_STREAMS}" '
                    f'"[method]output-stream.blocking-write-and-flush" '
                    f'(func $wasi_io_blocking_write_and_flush '
                    f'(param i32) (param i32) (param i32) (param i32)))'
                )
            # output-stream resource-drop: shared with Fs.write and
            # Net.post (Net.post imports it only when Fs.write is absent).
            drop_already = (
                ("Fs", "write") in used or ("Net", "post") in used
            )
            if not drop_already:
                self._write(
                    f'(import "{_WASI_IO_STREAMS}" '
                    f'"[resource-drop]output-stream" '
                    f'(func $wasi_io_drop_output_stream (param i32)))'
                )
            # error resource-drop: the chunked write helper drops the
            # ``error`` OWN handle a ``last-operation-failed`` stream-error
            # carries before it traps. Shared with Fs.read / Fs.write AND
            # Net.get / Net.post (the http chain imports it too); emit it
            # only if NONE of those already did, so the symbol exists once.
            err_drop_already = (
                ("Fs", "read") in used
                or ("Fs", "write") in used
                or ("Net", "get") in used
                or ("Net", "post") in used
            )
            if not err_drop_already:
                self._write(
                    f'(import "{_WASI_IO_ERROR}" "[resource-drop]error" '
                    f'(func $wasi_io_drop_error (param i32)))'
                )
        # Stdio.read_line (Phase 2, 2026-06-29): get-stdin returns an OWNED
        # input-stream; the wrapper reads it BYTE-AT-A-TIME via
        # input-stream.blocking-read(1) until it sees "\n" or EOF, then
        # drops the stream. The three wasi:io/streams + wasi:io/error
        # imports (blocking-read, the input-stream resource-drop, and the
        # error resource-drop) are SHARED with Fs.read and Net.get; emit
        # each only if no earlier user already did, so the symbol exists
        # EXACTLY once (a core module re-declaring the same import is
        # rejected by wasm-tools). The position of the underlying stdin is
        # owned by the host descriptor, NOT the input-stream resource, so a
        # fresh get-stdin + drop per read_line preserves the read cursor
        # across calls (proven by the oracle spike: three successive
        # read_line over "a\nb\nc\n" yield a, b, c with no byte lost or
        # repeated).
        if ("Stdio", "read_line") in used:
            self._write(
                f'(import "{_WASI_CLI_STDIN}" "get-stdin" '
                f'(func $wasi_cli_get_stdin (result i32)))'
            )
            # blocking-read + input-stream drop: imported by Fs.read and
            # (when Fs.read is absent) Net.get. Emit here only if neither
            # already did.
            br_already = (
                ("Fs", "read") in used or ("Net", "get") in used
            )
            if not br_already:
                self._write(
                    f'(import "{_WASI_IO_STREAMS}" '
                    f'"[method]input-stream.blocking-read" '
                    f'(func $wasi_io_blocking_read '
                    f'(param i32) (param i64) (param i32)))'
                )
                self._write(
                    f'(import "{_WASI_IO_STREAMS}" '
                    f'"[resource-drop]input-stream" '
                    f'(func $wasi_io_drop_input_stream (param i32)))'
                )
            # error resource-drop: shared with Fs.read / Fs.write, Net.get /
            # Net.post, AND the Stdio-output chunked-write helper. Emit only
            # if none of those already did.
            stdio_out_used_local = any(
                m in _WASI_STDIO_MIGRATED for (c, m) in used if c == "Stdio"
            )
            err_drop_already_rl = (
                ("Fs", "read") in used
                or ("Fs", "write") in used
                or ("Net", "get") in used
                or ("Net", "post") in used
                or stdio_out_used_local
            )
            if not err_drop_already_rl:
                self._write(
                    f'(import "{_WASI_IO_ERROR}" "[resource-drop]error" '
                    f'(func $wasi_io_drop_error (param i32)))'
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
        # Fs metadata (2026-06-27) + read (2026-06-28). The shared
        # preopen-descriptor resolver backs every Fs wrapper (metadata
        # and read); emit it once when any migrated Fs op is used.
        fs_preopen_used = [
            m for (c, m) in used
            if c == "Fs" and m in (_WASI_FS_METADATA | _WASI_FS_STREAM)
        ]
        if fs_preopen_used:
            self._emit_wasi_fs_preopen_desc_helper()
        # Guest-side Fs attenuation (Level 2). The shared lexical
        # containment helpers back the fail-closed prologue of every
        # migrated Fs op AND the ``restrict_to`` / ``allows`` wrappers;
        # emit them once when any Fs op (or attenuator) is present.
        if self._wasi_fs_uses_attenuation():
            self._emit_wasi_fs_normalize_helper()
            self._emit_wasi_fs_path_contained_helper()
            self._emit_wasi_fs_path_allowed_helper()
        if ("Fs", "restrict_to") in used:
            self._emit_wasi_fs_restrict_to_wrapper()
        if ("Fs", "allows") in used:
            self._emit_wasi_fs_allows_wrapper()
        if ("Fs", "exists") in used:
            self._emit_wasi_fs_exists_wrapper()
        if ("Fs", "is_dir") in used:
            self._emit_wasi_fs_is_dir_wrapper()
        if ("Fs", "mkdir") in used:
            self._emit_wasi_fs_mkdir_wrapper()
            # Layer b1: a DYNAMIC mkdir path cannot be unrolled into
            # cumulative prefixes at compile time, so emit the runtime
            # recursive sequencer (over the existing single-segment
            # ``$Fs_mkdir``) when an operator preopen admits dynamic paths.
            if self._wasi_dynamic_fs:
                self._emit_wasi_fs_mkdir_recursive_helper()
        if ("Fs", "read") in used:
            self._emit_wasi_fs_read_wrapper()
        if ("Fs", "write") in used:
            self._emit_wasi_fs_write_wrapper()
        if ("Fs", "list_dir") in used:
            self._emit_wasi_fs_list_dir_wrapper()
        # Net.get (2026-06-28, Phase 1) / Net.post (2026-06-28, Phase 2):
        # the SHARED guest-side host ceiling gate plus the per-op wasi:http
        # chain wrapper. Emit the ceiling gate once when either request op
        # is used; emit each wrapper on its own touch-point.
        if ("Net", "get") in used or ("Net", "post") in used:
            self._emit_wasi_net_host_allowed_helper()
        # Net fine attenuation (2026-06-29, Phase 3, Level 2 guest-side):
        # the SHARED exact-hostname allow-list membership helper backs the
        # ``allows`` body, the ``restrict_to`` intersection, AND the
        # fail-closed fine gate every Net request op consults on top of the
        # ceiling. Emit it once whenever ANY Net op is present: a program
        # that receives a restricted Net from a CALLER and only ever reads
        # through it (get / post) must still re-check the allow-list it
        # carries, so the helper must be present whenever a request op is,
        # not only when restrict_to / allows appear textually.
        if any(c == "Net" for (c, _m) in used):
            self._emit_wasi_net_handle_allows_helper()
        if ("Net", "restrict_to") in used:
            self._emit_wasi_net_restrict_to_wrapper()
        if ("Net", "allows") in used:
            self._emit_wasi_net_allows_wrapper()
        if ("Net", "get") in used:
            self._emit_wasi_net_get_wrapper()
        if ("Net", "post") in used:
            self._emit_wasi_net_post_wrapper()
        # Stdio output (Phase 1, 2026-06-29). The shared 4096-chunk
        # write loop helper backs all three wrappers; emit it once when
        # any of print / println / eprintln is reached. Each wrapper then
        # gets-stdout / gets-stderr, writes, and drops the stream.
        if any(m in _WASI_STDIO_MIGRATED for (c, m) in used if c == "Stdio"):
            self._emit_wasi_stdio_write_helper()
        if ("Stdio", "print") in used:
            self._emit_wasi_stdio_print_wrapper()
        if ("Stdio", "println") in used:
            self._emit_wasi_stdio_println_wrapper()
        if ("Stdio", "eprintln") in used:
            self._emit_wasi_stdio_eprintln_wrapper()
        # Stdio.read_line (Phase 2, 2026-06-29): get-stdin -> input-stream,
        # read byte-at-a-time until "\n" / EOF, drop the stream, build the
        # Result<String, IoError>.
        if ("Stdio", "read_line") in used:
            self._emit_wasi_stdio_read_line_wrapper()

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

    # ----- Stdio output via wasi:cli/stdout|stderr + wasi:io/streams ----

    def _emit_wasi_stdio_write_helper(self) -> None:
        """``$__wasi_stdio_write (stream i32, ptr i32, len i32)``.

        The shared chunked write loop backing print / println / eprintln:
        writes ``len`` bytes at ``ptr`` to ``stream`` in <= 4096-byte
        chunks via ``output-stream.blocking-write-and-flush`` (the WASI
        0.2 one-OS-page bound; a single write past a page TRAPS, so the
        loop is mandatory). blocking-write-and-flush self-limits AND
        flushes, so no check-write permit window is tracked -- stdout /
        stderr drain on their own (unlike the flow-controlled wasi:http
        request body). A zero-length write runs the loop zero times.

        Error handling: stdout / stderr essentially never fail, but on a
        carried ``stream-error`` the helper drops the error resource (when
        the variant is ``last-operation-failed``) and TRAPS via
        ``unreachable``. The Capa surface is void (no Result to thread),
        so a hard fault is the only honest signal -- mirroring the Python
        oracle, where ``sys.stdout.write`` raising propagates as an
        uncaught error. The OWNED stream is dropped by the CALLER (the
        print / println / eprintln wrapper) on the success path; on the
        trap path the store is torn down, so the un-dropped stream leaks
        nothing observable."""
        wf_ret = self._wasi_stdio_scratch_offset                # 12 bytes
        chunk = _WASI_STDIO_WRITE_CHUNK
        self._write(
            "(func $__wasi_stdio_write (param $stream i32) "
            "(param $ptr i32) (param $len i32)"
        )
        self._indent += 1
        self._write("(local $cursor i32)")
        self._write("(local $remaining i32)")
        self._write("(local $n i32)")
        self._write("i32.const 0")
        self._write("local.set $cursor")
        self._write("local.get $len")
        self._write("local.set $remaining")
        self._write("(block $write_done")
        self._indent += 1
        self._write("(loop $write_loop")
        self._indent += 1
        # if remaining == 0, done.
        self._write("local.get $remaining")
        self._write("i32.eqz")
        self._write("br_if $write_done")
        # n = min(remaining, CHUNK).
        self._write("local.get $remaining")
        self._write(f"i32.const {chunk}")
        self._write("i32.lt_u")
        self._write("if (result i32)")
        self._indent += 1
        self._write("local.get $remaining")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        self._write(f"i32.const {chunk}")
        self._indent -= 1
        self._write("end")
        self._write("local.set $n")
        # blocking-write-and-flush(stream, ptr+cursor, n, wf_ret).
        self._write("local.get $stream")
        self._write("local.get $ptr")
        self._write("local.get $cursor")
        self._write("i32.add")
        self._write("local.get $n")
        self._write(f"i32.const {wf_ret}")
        self._write("call $wasi_io_blocking_write_and_flush")
        # if Err (disc @0 != 0): drop a carried error resource, trap.
        self._write(f"i32.const {wf_ret}")
        self._write("i32.load8_u offset=0")
        self._write("if")
        self._indent += 1
        # stream-error variant disc @+4: 0 = last-operation-failed (error
        # OWN handle @+8 to drop), 1 = closed (no resource).
        self._write(f"i32.const {wf_ret}")
        self._write("i32.load offset=4")
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        self._write(f"i32.const {wf_ret}")
        self._write("i32.load offset=8")
        self._write("call $wasi_io_drop_error")
        self._indent -= 1
        self._write("end")
        self._write("unreachable")
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
        self._write("br $write_loop")
        self._indent -= 1
        self._write(")")
        self._indent -= 1
        self._write(")")
        self._indent -= 1
        self._write(")")

    def _emit_wasi_stdio_print_wrapper(self) -> None:
        """``$Stdio_print (msg_ptr i32, msg_len i32)``.

        Matches the call shape the generic cap-call emitter produces for
        a ``func(msg: string)`` method (two i32s, no result), so the call
        site (``call $Stdio_print``) is byte-identical to the capa:host
        path. get-stdout -> output-stream, write the text via the shared
        chunked loop, drop the stream. No trailing newline (print)."""
        self._write("(func $Stdio_print (param $msg_ptr i32) (param $msg_len i32)")
        self._indent += 1
        self._write("(local $stream i32)")
        self._write("call $wasi_cli_get_stdout")
        self._write("local.set $stream")
        self._write("local.get $stream")
        self._write("local.get $msg_ptr")
        self._write("local.get $msg_len")
        self._write("call $__wasi_stdio_write")
        self._write("local.get $stream")
        self._write("call $wasi_io_drop_output_stream")
        self._indent -= 1
        self._write(")")

    def _emit_wasi_stdio_println_wrapper(self) -> None:
        """``$Stdio_println (msg_ptr i32, msg_len i32)``.

        Same as print plus a trailing ``"\\n"`` byte (the capa:host
        println wrote ``msg + "\\n"`` host-side; here the guest appends
        it), written as a second 1-byte chunk through the SAME stream
        before the drop. The newline lives in the interned-string data
        segment (a one-byte literal), so no allocation is needed."""
        nl_off, nl_len = self._intern_string("\n")
        self._write("(func $Stdio_println (param $msg_ptr i32) (param $msg_len i32)")
        self._indent += 1
        self._write("(local $stream i32)")
        self._write("call $wasi_cli_get_stdout")
        self._write("local.set $stream")
        self._write("local.get $stream")
        self._write("local.get $msg_ptr")
        self._write("local.get $msg_len")
        self._write("call $__wasi_stdio_write")
        self._write("local.get $stream")
        self._write(f"i32.const {nl_off}")
        self._write(f"i32.const {nl_len}")
        self._write("call $__wasi_stdio_write")
        self._write("local.get $stream")
        self._write("call $wasi_io_drop_output_stream")
        self._indent -= 1
        self._write(")")

    def _emit_wasi_stdio_eprintln_wrapper(self) -> None:
        """``$Stdio_eprintln (msg_ptr i32, msg_len i32)``.

        Like println but on STDERR (get-stderr), keeping standard error
        a stream distinct from standard output. Appends a trailing
        ``"\\n"`` byte (matching capa:host's ``msg + "\\n"``)."""
        nl_off, nl_len = self._intern_string("\n")
        self._write("(func $Stdio_eprintln (param $msg_ptr i32) (param $msg_len i32)")
        self._indent += 1
        self._write("(local $stream i32)")
        self._write("call $wasi_cli_get_stderr")
        self._write("local.set $stream")
        self._write("local.get $stream")
        self._write("local.get $msg_ptr")
        self._write("local.get $msg_len")
        self._write("call $__wasi_stdio_write")
        self._write("local.get $stream")
        self._write(f"i32.const {nl_off}")
        self._write(f"i32.const {nl_len}")
        self._write("call $__wasi_stdio_write")
        self._write("local.get $stream")
        self._write("call $wasi_io_drop_output_stream")
        self._indent -= 1
        self._write(")")

    def _emit_wasi_stdio_read_line_wrapper(self) -> None:
        """``$Stdio_read_line (ret_area i32)`` -> writes a
        ``result<string, io-error>`` (20-byte canonical-ABI shape) into
        ``ret_area``.

        Matches the call shape ``_cap_method_wasm_sig`` produces for
        ``Stdio.read_line`` (a single ret_area i32, no args), so the
        existing ``result_string_io_error`` materialiser lifts the result
        into a Capa ``Result<String, IoError>`` unchanged, exactly as the
        capa:host read_line does.

        Sequence (convention confirmed empirically by the oracle spike
        BEFORE this WAT, against wasm-tools 1.249.0 / wasmtime 44.0.0;
        see docs/design/wasi_mode.md):

          1. ``get-stdin()`` -> an OWNED input-stream.
          2. LOOP ``blocking-read(stream, 1)`` ->
             result<list<u8>, stream-error>:
               * Ok with 1 byte:
                   - if the byte is ``"\\n"`` (0x0a): the line terminator
                     -- STOP without storing it (the "\\n" is NOT part of
                     the result, matching the oracle's ``rstrip("\\n")``).
                   - else: append the byte to a heap accumulation buffer,
                     continue.
                 (A spurious Ok of 0 bytes just continues.)
               * Err(stream-error): disc @+4 == 1 is ``closed`` = EOF.
                 If NOTHING was accumulated, this is a true end of input
                 -> drop the stream, write ``Err(IoError("end of input"))``
                 and return (byte-identical, on the Result discriminant
                 and the message, to the Python oracle's EOF
                 ``Err(IoError("end of input"))``). If a partial line WAS
                 accumulated (last line with no trailing "\\n"), STOP and
                 build the String from it (next read_line then hits EOF).
                 disc @+4 == 0 is ``last-operation-failed`` -> drop the
                 carried error handle (@+8), drop the stream, write Err,
                 return.
          3. strip a SINGLE trailing ``"\\r"`` (0x0d) from the accumulated
             bytes: stdin under the Python oracle is TEXT MODE (universal
             newlines), which translates ``"\\r\\n"`` -> ``"\\n"`` BEFORE
             ``rstrip("\\n")``, so the oracle never sees the ``"\\r"``. The
             WASI byte stream is RAW, so a Windows ``"abc\\r\\n"`` line read
             up to ``"\\n"`` leaves ``"abc\\r"``; dropping the trailing
             ``"\\r"`` restores byte-parity with the oracle for BOTH
             ``"\\n"`` and ``"\\r\\n"`` line endings (confirmed by the
             spike).

             DELIBERATE DIVERGENCE (lone ``"\\r"``, documented, not a bug).
             This wrapper recognises ONLY ``"\\n"`` and ``"\\r\\n"`` as line
             terminators (the modern terminal / pipe / file endings). It does
             NOT implement full universal-newlines: a lone ``"\\r"`` -- a CR
             that is NOT immediately followed by ``"\\n"`` -- is treated as an
             ORDINARY byte at ANY position, never as a line break. The Python
             oracle's text mode, by contrast, breaks a line on ANY isolated
             ``"\\r"``. So this wrapper and the oracle diverge whenever the
             input contains an embedded or terminal lone CR, EVEN when the
             input also ends in ``"\\n"``. Examples (oracle -> --wasi):

               * ``"a\\rb\\n"``      -> oracle: ["a", "b"]; --wasi: ["a\\rb"]
               * ``"x\\ry\\rz\\r"``  -> oracle: ["x","y","z"]; --wasi:
                 ["x\\ry\\rz"]  (classic pre-2001 Mac line endings)

             We ACCEPT this divergence rather than emit the lookahead a
             correct lone-CR split would need (it risks over-consuming the
             next line's first byte across a blocking-read boundary). The
             lone-CR text format is the legacy Mac OS (pre-2001) convention,
             practically extinct on terminals, pipes and files; the byte
             parity claim for read_line is qualified to ``"\\n"`` and
             ``"\\r\\n"`` inputs accordingly (see CHANGELOG.md and
             docs/design/wasi_mode.md, "read_line lone-CR divergence").
          4. drop the input-stream and write Ok(String) = (buffer ptr,
             buffer length). The accumulated bytes are the raw line bytes;
             the Capa String is UTF-8 by construction, matching the
             oracle.

        The input-stream is dropped on EVERY exit path (EOF, partial-line
        EOF, last-operation-failed, and the Ok/"\\n"-terminated path) so no
        OWN handle leaks. The underlying stdin POSITION is owned by the
        host descriptor, not the input-stream resource, so a fresh
        get-stdin + drop per read_line preserves the read cursor across
        calls (the spike read three lines via three successive read_line
        with a per-call get-stdin + drop and lost / repeated no bytes).
        The accumulation buffer grows geometrically (realloc + copy on
        overflow) reusing ``$alloc`` + ``memory.copy``, exactly like
        Fs.read."""
        br_ret = self._wasi_stdin_scratch_offset                # 12 bytes
        eof_off, eof_len = self._intern_string("end of input")
        self._write("(func $Stdio_read_line (param $ret_area i32)")
        self._indent += 1
        self._write("(local $stream i32)")
        self._write("(local $buf i32)")
        self._write("(local $buf_cap i32)")
        self._write("(local $buf_len i32)")
        self._write("(local $byte i32)")
        self._write("(local $newcap i32)")
        self._write("(local $newbuf i32)")
        # get-stdin() -> input-stream.
        self._write("call $wasi_cli_get_stdin")
        self._write("local.set $stream")
        # Accumulation buffer: start empty (a zero-size alloc gives a
        # stable non-overlapping heap pointer, like Fs.read).
        self._write("i32.const 0")
        self._write("call $alloc")
        self._write("local.set $buf")
        self._write("i32.const 0")
        self._write("local.set $buf_cap")
        self._write("i32.const 0")
        self._write("local.set $buf_len")
        # Loop blocking-read(stream, 1, br_ret).
        self._write("(block $line_done")
        self._indent += 1
        self._write("(loop $read_loop")
        self._indent += 1
        self._write("local.get $stream")
        self._write("i64.const 1")
        self._write(f"i32.const {br_ret}")
        self._write("call $wasi_io_blocking_read")
        # if Ok (disc @0 == 0): handle the byte; else stream-error.
        self._write(f"i32.const {br_ret}")
        self._write("i32.load8_u offset=0")
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        # bytes read = br_ret.len @8; if 0, spurious -> continue.
        self._write(f"i32.const {br_ret}")
        self._write("i32.load offset=8")
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        self._write("br $read_loop")
        self._indent -= 1
        self._write("end")
        # byte = *(br_ret.data_ptr @4).
        self._write(f"i32.const {br_ret}")
        self._write("i32.load offset=4")
        self._write("i32.load8_u")
        self._write("local.set $byte")
        # if byte == 0x0a ("\n"): line terminator, stop (do not store).
        self._write("local.get $byte")
        self._write("i32.const 10")
        self._write("i32.eq")
        self._write("if")
        self._indent += 1
        self._write("br $line_done")
        self._indent -= 1
        self._write("end")
        # Grow the buffer if buf_len + 1 > buf_cap.
        self._write("local.get $buf_len")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.get $buf_cap")
        self._write("i32.gt_u")
        self._write("if")
        self._indent += 1
        # newcap = max(buf_cap*2, buf_len+1, 16); geometric growth so a
        # long line does not realloc once per byte.
        self._write("local.get $buf_cap")
        self._write("i32.const 1")
        self._write("i32.shl")
        self._write("local.set $newcap")
        self._write("local.get $newcap")
        self._write("i32.const 16")
        self._write("i32.lt_u")
        self._write("if")
        self._indent += 1
        self._write("i32.const 16")
        self._write("local.set $newcap")
        self._indent -= 1
        self._write("end")
        # newbuf = alloc(newcap); copy old bytes; buf = newbuf.
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
        # *(buf + buf_len) = byte; buf_len += 1; continue.
        self._write("local.get $buf")
        self._write("local.get $buf_len")
        self._write("i32.add")
        self._write("local.get $byte")
        self._write("i32.store8")
        self._write("local.get $buf_len")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $buf_len")
        self._write("br $read_loop")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        # Err(stream-error): disc @+4. 1 == closed (EOF). 0 ==
        # last-operation-failed(error) -> drop the carried error handle.
        self._write(f"i32.const {br_ret}")
        self._write("i32.load offset=4")
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        # last-operation-failed: drop the error resource.
        self._write(f"i32.const {br_ret}")
        self._write("i32.load offset=8")
        self._write("call $wasi_io_drop_error")
        # EOF (after a possible partial line) OR a hard failure both end
        # the read; if NOTHING accumulated, write Err("end of input")
        # below (the EOF arm), else build the partial line. Fall through
        # to $line_done; the post-loop tail distinguishes by buf_len.
        self._indent -= 1
        self._write("end")
        self._write("br $line_done")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write(")")
        self._indent -= 1
        self._write(")")
        # Out of the loop. If buf_len == 0 AND we exited via EOF (an Ok
        # "\n" terminator leaves buf_len possibly 0 too, e.g. an empty
        # line "\n" -> Ok("")). Distinguish EOF-with-nothing from an empty
        # "\n" line using a re-check is not needed: the loop only reaches
        # here on "\n" (Ok) or stream-error (Err). We must tell those
        # apart. Re-read the discriminant of the LAST blocking-read: disc
        # @0 == 0 means the last op was Ok (the "\n" terminator) -> always
        # build the String (possibly empty). disc @0 != 0 means the last
        # op was a stream-error -> EOF: build the String IF a partial line
        # was accumulated, else write Err("end of input").
        self._write(f"i32.const {br_ret}")
        self._write("i32.load8_u offset=0")
        self._write("if")
        self._indent += 1
        # Last op was a stream-error (EOF / failure). If buf_len == 0 ->
        # Err("end of input"); else build the partial-line String.
        self._write("local.get $buf_len")
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        self._write("local.get $stream")
        self._write("call $wasi_io_drop_input_stream")
        self._emit_wasi_read_line_err(eof_off, eof_len)
        self._write("return")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")
        # Build Ok(String): strip a SINGLE trailing "\r" (0x0d) for
        # text-mode parity (a "\r\n" line read to "\n" leaves "...\r").
        self._write("local.get $buf_len")
        self._write("if")
        self._indent += 1
        self._write("local.get $buf")
        self._write("local.get $buf_len")
        self._write("i32.const 1")
        self._write("i32.sub")
        self._write("i32.add")
        self._write("i32.load8_u")
        self._write("i32.const 13")
        self._write("i32.eq")
        self._write("if")
        self._indent += 1
        self._write("local.get $buf_len")
        self._write("i32.const 1")
        self._write("i32.sub")
        self._write("local.set $buf_len")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")
        # drop the input-stream.
        self._write("local.get $stream")
        self._write("call $wasi_io_drop_input_stream")
        # Ok(String): tag=0, ptr=buf @4, len=buf_len @8.
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

    def _emit_wasi_read_line_err(self, msg_off: int, msg_len: int) -> None:
        """Write an ``Err(IoError)`` into ``$ret_area`` for the
        ``result_string_io_error`` 20-byte shape: tag@0 = 1, message = the
        interned fixed string (m_ptr@4, m_len@8), empty cause (c_ptr@12 =
        0, c_len@16 = 0). ``$ret_area`` is in scope (the wrapper's param).
        Same shape as ``_emit_wasi_fs_read_err``; the message here is the
        oracle's ``"end of input"`` so the Err arm is byte-identical."""
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

    # ----- guest-side Net fine attenuation (Level 2, Phase 3) ----

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

    def _emit_wasi_fs_normalize_helper(self) -> None:
        """``$__fs_normalize (src_ptr i32, src_len i32, dst_ptr i32) ->
        i32`` -> writes the LEXICALLY normalised path into ``[dst_ptr,
        dst_ptr+ret)`` and returns its length ``ret``.

        Collapses ``.`` and ``..`` segments the way ``os.path.realpath``
        does for the NO-SYMLINK case (the lexical part the guest can
        reproduce without a kernel walk), so the containment gate matches
        the Python oracle (``Fs.allows``, which canonicalises via
        ``realpath``) for ``.`` / ``..``. Symlinks are still NOT resolved
        -- that remains the documented Level-2 loss
        (``docs/design/wasi_mode.md``).

        Rules (validated byte-for-byte against ``os.path.normpath`` and a
        9331-input fuzz of the segment reference, scratchpad
        ``wat_sim2.py``):
          - split on ``/``; drop empty segments (``//``, trailing ``/``)
            and ``.``;
          - ``..`` POPS the previous emitted segment when one exists AND
            it is not itself a (locked) leading ``..``; otherwise, for an
            ABSOLUTE path it is dropped (cannot escape root), for a
            RELATIVE path it is KEPT (a leading ``..`` escapes the prefix,
            so containment must fail);
          - an absolute path keeps its single leading ``/``; a relative
            path that normalises to empty becomes ``.``.
        The output is never longer than the input, so the caller sizes the
        destination buffer at ``max(src_len, 1)``.

        WAT-local helpers are inlined: segment append (prepend ``/`` when
        ``dst_len > 0``) and the ``..`` pop / last-segment-is-``..`` test
        (scan back from ``dst_len`` to the previous ``/`` or to 0)."""
        self._write(
            "(func $__fs_normalize (param $src_ptr i32) "
            "(param $src_len i32) (param $dst_ptr i32) (result i32)"
        )
        self._indent += 1
        self._write("(local $is_abs i32)")
        self._write("(local $i i32)")
        self._write("(local $dst_len i32)")
        self._write("(local $seg_start i32)")
        self._write("(local $seg_len i32)")
        self._write("(local $last_start i32)")
        self._write("(local $j i32)")
        # is_abs = src_len > 0 && src[0] == '/'.
        self._write("local.get $src_len")
        self._write("i32.const 0")
        self._write("i32.gt_u")
        self._write("if (result i32)")
        self._indent += 1
        self._write("local.get $src_ptr")
        self._write("i32.load8_u")
        self._write("i32.const 47")
        self._write("i32.eq")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        self._write("i32.const 0")
        self._indent -= 1
        self._write("end")
        self._write("local.set $is_abs")
        # If absolute, the leading '/' is emitted at the end; dst here
        # holds only the RELATIVE remainder (so the pop / leading-'..'
        # logic never crosses the root slash). dst_len starts at 0.
        self._write("i32.const 0")
        self._write("local.set $dst_len")
        self._write("i32.const 0")
        self._write("local.set $i")
        self._write("(block $scan_done")
        self._indent += 1
        self._write("(loop $scan")
        self._indent += 1
        self._write("local.get $i")
        self._write("local.get $src_len")
        self._write("i32.ge_u")
        self._write("br_if $scan_done")
        # skip a '/' run.
        self._write("local.get $src_ptr")
        self._write("local.get $i")
        self._write("i32.add")
        self._write("i32.load8_u")
        self._write("i32.const 47")
        self._write("i32.eq")
        self._write("if")
        self._indent += 1
        self._write("local.get $i")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $i")
        self._write("br $scan")
        self._indent -= 1
        self._write("end")
        # segment = [seg_start, i) until next '/' or end.
        self._write("local.get $i")
        self._write("local.set $seg_start")
        self._write("(block $seg_done")
        self._indent += 1
        self._write("(loop $seg")
        self._indent += 1
        self._write("local.get $i")
        self._write("local.get $src_len")
        self._write("i32.ge_u")
        self._write("br_if $seg_done")
        self._write("local.get $src_ptr")
        self._write("local.get $i")
        self._write("i32.add")
        self._write("i32.load8_u")
        self._write("i32.const 47")
        self._write("i32.eq")
        self._write("br_if $seg_done")
        self._write("local.get $i")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $i")
        self._write("br $seg")
        self._indent -= 1
        self._write(")")
        self._indent -= 1
        self._write(")")
        self._write("local.get $i")
        self._write("local.get $seg_start")
        self._write("i32.sub")
        self._write("local.set $seg_len")
        # '.' (len 1, byte '.') -> drop.
        self._write("local.get $seg_len")
        self._write("i32.const 1")
        self._write("i32.eq")
        self._write("local.get $src_ptr")
        self._write("local.get $seg_start")
        self._write("i32.add")
        self._write("i32.load8_u")
        self._write("i32.const 46")
        self._write("i32.eq")
        self._write("i32.and")
        self._write("if")
        self._indent += 1
        self._write("br $scan")
        self._indent -= 1
        self._write("end")
        # '..' (len 2, both bytes '.') -> pop / drop / keep.
        self._write("local.get $seg_len")
        self._write("i32.const 2")
        self._write("i32.eq")
        self._write("local.get $src_ptr")
        self._write("local.get $seg_start")
        self._write("i32.add")
        self._write("i32.load8_u")
        self._write("i32.const 46")
        self._write("i32.eq")
        self._write("i32.and")
        self._write("local.get $src_ptr")
        self._write("local.get $seg_start")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("i32.add")
        self._write("i32.load8_u")
        self._write("i32.const 46")
        self._write("i32.eq")
        self._write("i32.and")
        self._write("if")
        self._indent += 1
        # last_start = start of the last emitted segment in dst: scan back
        # from dst_len for the previous '/'; 0 if none.
        self._write("i32.const 0")
        self._write("local.set $last_start")
        self._write("local.get $dst_len")
        self._write("local.set $j")
        self._write("(block $back_done")
        self._indent += 1
        self._write("(loop $back")
        self._indent += 1
        self._write("local.get $j")
        self._write("i32.eqz")
        self._write("br_if $back_done")
        self._write("local.get $dst_ptr")
        self._write("local.get $j")
        self._write("i32.const 1")
        self._write("i32.sub")
        self._write("i32.add")
        self._write("i32.load8_u")
        self._write("i32.const 47")
        self._write("i32.eq")
        self._write("if")
        self._indent += 1
        self._write("local.get $j")
        self._write("local.set $last_start")
        self._write("br $back_done")
        self._indent -= 1
        self._write("end")
        self._write("local.get $j")
        self._write("i32.const 1")
        self._write("i32.sub")
        self._write("local.set $j")
        self._write("br $back")
        self._indent -= 1
        self._write(")")
        self._indent -= 1
        self._write(")")
        # can_pop = dst_len > 0 AND last segment != '..'. The last segment
        # is '..' iff (dst_len - last_start == 2) and both its bytes are
        # '.'. Compute "last_is_dotdot".
        # If dst_len == 0 -> not poppable.
        self._write("local.get $dst_len")
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        # empty dst: absolute drops, relative keeps '..'.
        self._write("local.get $is_abs")
        self._write("if")
        self._indent += 1
        self._write("br $scan")
        self._indent -= 1
        self._write("end")
        # relative + empty: append '..' (no leading '/').
        self._write("local.get $dst_ptr")
        self._write("i32.const 46")
        self._write("i32.store8")
        self._write("local.get $dst_ptr")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("i32.const 46")
        self._write("i32.store8")
        self._write("i32.const 2")
        self._write("local.set $dst_len")
        self._write("br $scan")
        self._indent -= 1
        self._write("end")
        # dst_len > 0: is the last segment exactly '..'?
        self._write("local.get $dst_len")
        self._write("local.get $last_start")
        self._write("i32.sub")
        self._write("i32.const 2")
        self._write("i32.eq")
        self._write("local.get $dst_ptr")
        self._write("local.get $last_start")
        self._write("i32.add")
        self._write("i32.load8_u")
        self._write("i32.const 46")
        self._write("i32.eq")
        self._write("i32.and")
        self._write("local.get $dst_ptr")
        self._write("local.get $last_start")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("i32.add")
        self._write("i32.load8_u")
        self._write("i32.const 46")
        self._write("i32.eq")
        self._write("i32.and")
        self._write("if")
        self._indent += 1
        # last segment is a locked leading '..': absolute can't happen here
        # (a leading '..' is only kept for relative), so keep another '..'.
        self._write("local.get $is_abs")
        self._write("if")
        self._indent += 1
        self._write("br $scan")
        self._indent -= 1
        self._write("end")
        # append '/..' (dst_len > 0 so prepend a separator).
        self._write("local.get $dst_ptr")
        self._write("local.get $dst_len")
        self._write("i32.add")
        self._write("i32.const 47")
        self._write("i32.store8")
        self._write("local.get $dst_ptr")
        self._write("local.get $dst_len")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("i32.add")
        self._write("i32.const 46")
        self._write("i32.store8")
        self._write("local.get $dst_ptr")
        self._write("local.get $dst_len")
        self._write("i32.const 2")
        self._write("i32.add")
        self._write("i32.add")
        self._write("i32.const 46")
        self._write("i32.store8")
        self._write("local.get $dst_len")
        self._write("i32.const 3")
        self._write("i32.add")
        self._write("local.set $dst_len")
        self._write("br $scan")
        self._indent -= 1
        self._write("end")
        # poppable: truncate dst to last_start (drop the '/segment').
        # last_start is the byte AFTER the separator, so the new length is
        # last_start - 1 when last_start > 0 (drop the separator too), or 0.
        self._write("local.get $last_start")
        self._write("i32.eqz")
        self._write("if (result i32)")
        self._indent += 1
        self._write("i32.const 0")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        self._write("local.get $last_start")
        self._write("i32.const 1")
        self._write("i32.sub")
        self._indent -= 1
        self._write("end")
        self._write("local.set $dst_len")
        self._write("br $scan")
        self._indent -= 1
        self._write("end")
        # normal segment: append it (prepend '/' when dst_len > 0).
        self._write("local.get $dst_len")
        self._write("i32.const 0")
        self._write("i32.gt_u")
        self._write("if")
        self._indent += 1
        self._write("local.get $dst_ptr")
        self._write("local.get $dst_len")
        self._write("i32.add")
        self._write("i32.const 47")
        self._write("i32.store8")
        self._write("local.get $dst_len")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $dst_len")
        self._indent -= 1
        self._write("end")
        # copy seg_len bytes src[seg_start..] -> dst[dst_len..].
        self._write("i32.const 0")
        self._write("local.set $j")
        self._write("(block $copy_done")
        self._indent += 1
        self._write("(loop $copy")
        self._indent += 1
        self._write("local.get $j")
        self._write("local.get $seg_len")
        self._write("i32.ge_u")
        self._write("br_if $copy_done")
        self._write("local.get $dst_ptr")
        self._write("local.get $dst_len")
        self._write("i32.add")
        self._write("local.get $src_ptr")
        self._write("local.get $seg_start")
        self._write("i32.add")
        self._write("local.get $j")
        self._write("i32.add")
        self._write("i32.load8_u")
        self._write("i32.store8")
        self._write("local.get $dst_len")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $dst_len")
        self._write("local.get $j")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $j")
        self._write("br $copy")
        self._indent -= 1
        self._write(")")
        self._indent -= 1
        self._write(")")
        self._write("br $scan")
        self._indent -= 1
        self._write(")")
        self._indent -= 1
        self._write(")")
        # Post-loop: build the final layout.
        # Absolute: shift the relative remainder one byte right and write a
        # leading '/'. dst currently holds [0, dst_len) of the relative
        # remainder; we move it up so index 0 is '/'.
        self._write("local.get $is_abs")
        self._write("if")
        self._indent += 1
        # shift bytes right by 1, from the top down (no overlap clobber).
        self._write("local.get $dst_len")
        self._write("local.set $j")
        self._write("(block $shift_done")
        self._indent += 1
        self._write("(loop $shift")
        self._indent += 1
        self._write("local.get $j")
        self._write("i32.eqz")
        self._write("br_if $shift_done")
        self._write("local.get $dst_ptr")
        self._write("local.get $j")
        self._write("i32.add")
        self._write("local.get $dst_ptr")
        self._write("local.get $j")
        self._write("i32.const 1")
        self._write("i32.sub")
        self._write("i32.add")
        self._write("i32.load8_u")
        self._write("i32.store8")
        self._write("local.get $j")
        self._write("i32.const 1")
        self._write("i32.sub")
        self._write("local.set $j")
        self._write("br $shift")
        self._indent -= 1
        self._write(")")
        self._indent -= 1
        self._write(")")
        self._write("local.get $dst_ptr")
        self._write("i32.const 47")
        self._write("i32.store8")
        self._write("local.get $dst_len")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("return")
        self._indent -= 1
        self._write("end")
        # Relative + empty result -> '.'.
        self._write("local.get $dst_len")
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        self._write("local.get $dst_ptr")
        self._write("i32.const 46")
        self._write("i32.store8")
        self._write("i32.const 1")
        self._write("return")
        self._indent -= 1
        self._write("end")
        self._write("local.get $dst_len")
        self._indent -= 1
        self._write(")")

    def _emit_wasi_fs_path_contained_helper(self) -> None:
        """``$Fs_path_contained (path_ptr i32, path_len i32,
        pre_ptr i32, pre_len i32) -> i32`` -> 1 iff ``path`` is the
        directory/file ``prefix`` itself or lies under it, by path-segment
        containment AFTER lexical ``.``/``..`` normalisation.

        This is the guest-side analogue of the Python oracle's
        ``Path(os.path.realpath(path)).is_relative_to(
        os.path.realpath(prefix))`` (``Fs.allows``,
        ``capa/runtime/_capabilities.py:173-183``). The guest cannot
        ``realpath`` (no kernel syscall), but it FIRST normalises ``.`` and
        ``..`` in BOTH the path and the prefix lexically (``$__fs_normalize``,
        the ``os.path.normpath``-style collapse), reproducing what
        ``realpath`` does for those segments in the no-symlink case. So
        ``sub/../secret.txt`` normalises to ``secret.txt`` (NOT contained
        in ``sub`` -> denied, matching the oracle) and ``sub/../sub/ok.txt``
        normalises to ``sub/ok.txt`` (contained -> allowed). For paths
        whose ONLY non-canonical feature is ``.``/``..`` the result is now
        BYTE-IDENTICAL to the oracle (``realpath`` also prepends the SAME
        process CWD to a relative path and its relative prefix, so the CWD
        cancels in the containment). SYMLINKS are still NOT resolved -- a
        symlink inside the prefix that points outside it is admitted here
        (caught only by the Level-1 preopen ceiling); that is the only
        remaining Level-2 loss (TOCTOU / symlink) in
        ``docs/design/wasi_mode.md``.

        Algorithm (matching the segment-aware ``is_relative_to``), run on
        the NORMALISED path / prefix:

          1. strip trailing ``/`` from both path and prefix (keep a lone
             ``/`` as ``/``), so ``dir/`` and ``dir`` compare equal.
          2. if the stripped prefix is LONGER than the stripped path,
             not contained.
          3. the first ``pre_len`` bytes of path must equal prefix
             byte-for-byte.
          4. SEGMENT BOUNDARY: either the lengths are equal (path IS the
             prefix) or the byte at ``path[pre_len]`` is ``/`` (the
             prefix ends on a separator, so ``data/ab`` is NOT contained
             in ``data/a``)."""
        self._write(
            "(func $Fs_path_contained (param $path_ptr i32) "
            "(param $path_len i32) (param $pre_ptr i32) "
            "(param $pre_len i32) (result i32)"
        )
        self._indent += 1
        self._write("(local $pl i32)")
        self._write("(local $ql i32)")
        self._write("(local $i i32)")
        self._write("(local $npath_ptr i32)")
        self._write("(local $npath_len i32)")
        self._write("(local $npre_ptr i32)")
        self._write("(local $npre_len i32)")
        # LEXICAL normalisation of '.' / '..' FIRST, on BOTH path and
        # prefix, so the containment matches the oracle (which canonicalises
        # both via realpath). e.g. "sub/../secret.txt" normalises to
        # "secret.txt" (NOT contained in "sub" -> denied), while
        # "sub/../sub/ok.txt" normalises to "sub/ok.txt" (contained ->
        # allowed). Each output is <= its input length; allocate
        # max(len, 1) so an empty input still has a 1-byte buffer for the
        # '.' result. Symlinks are NOT resolved (the documented Level-2
        # loss); only '.' / '..' are collapsed.
        self._write("local.get $path_len")
        self._write("i32.const 1")
        self._write("local.get $path_len")
        self._write("i32.const 0")
        self._write("i32.gt_u")
        self._write("select")
        self._write("call $alloc")
        self._write("local.set $npath_ptr")
        self._write("local.get $path_ptr")
        self._write("local.get $path_len")
        self._write("local.get $npath_ptr")
        self._write("call $__fs_normalize")
        self._write("local.set $npath_len")
        self._write("local.get $pre_len")
        self._write("i32.const 1")
        self._write("local.get $pre_len")
        self._write("i32.const 0")
        self._write("i32.gt_u")
        self._write("select")
        self._write("call $alloc")
        self._write("local.set $npre_ptr")
        self._write("local.get $pre_ptr")
        self._write("local.get $pre_len")
        self._write("local.get $npre_ptr")
        self._write("call $__fs_normalize")
        self._write("local.set $npre_len")
        # From here the compare runs on the NORMALISED buffers.
        self._write("local.get $npath_ptr")
        self._write("local.set $path_ptr")
        self._write("local.get $npath_len")
        self._write("local.set $path_len")
        self._write("local.get $npre_ptr")
        self._write("local.set $pre_ptr")
        self._write("local.get $npre_len")
        self._write("local.set $pre_len")
        # pl = strip_trailing_slash_len(path); ql = ...(prefix). A
        # trailing '/' is dropped unless the string is a lone '/'.
        self._write("local.get $path_ptr")
        self._write("local.get $path_len")
        self._write("call $__fs_strip_slash_len")
        self._write("local.set $pl")
        self._write("local.get $pre_ptr")
        self._write("local.get $pre_len")
        self._write("call $__fs_strip_slash_len")
        self._write("local.set $ql")
        # if ql > pl, not contained.
        self._write("local.get $ql")
        self._write("local.get $pl")
        self._write("i32.gt_u")
        self._write("if")
        self._indent += 1
        self._write("i32.const 0")
        self._write("return")
        self._indent -= 1
        self._write("end")
        # Compare the first ql bytes: path[i] == prefix[i] for i<ql.
        self._write("i32.const 0")
        self._write("local.set $i")
        self._write("(block $cmp_done")
        self._indent += 1
        self._write("(loop $cmp")
        self._indent += 1
        self._write("local.get $i")
        self._write("local.get $ql")
        self._write("i32.ge_u")
        self._write("br_if $cmp_done")
        # if path_ptr[i] != pre_ptr[i] -> return 0
        self._write("local.get $path_ptr")
        self._write("local.get $i")
        self._write("i32.add")
        self._write("i32.load8_u")
        self._write("local.get $pre_ptr")
        self._write("local.get $i")
        self._write("i32.add")
        self._write("i32.load8_u")
        self._write("i32.ne")
        self._write("if")
        self._indent += 1
        self._write("i32.const 0")
        self._write("return")
        self._indent -= 1
        self._write("end")
        self._write("local.get $i")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $i")
        self._write("br $cmp")
        self._indent -= 1
        self._write(")")
        self._indent -= 1
        self._write(")")
        # Segment boundary: equal lengths (path IS prefix) -> contained.
        self._write("local.get $pl")
        self._write("local.get $ql")
        self._write("i32.eq")
        self._write("if")
        self._indent += 1
        self._write("i32.const 1")
        self._write("return")
        self._indent -= 1
        self._write("end")
        # Otherwise contained iff path[ql] == '/' (0x2f).
        self._write("local.get $path_ptr")
        self._write("local.get $ql")
        self._write("i32.add")
        self._write("i32.load8_u")
        self._write("i32.const 47")
        self._write("i32.eq")
        self._indent -= 1
        self._write(")")

    def _emit_wasi_fs_strip_slash_helper(self) -> None:
        """``$__fs_strip_slash_len (ptr i32, len i32) -> i32`` -> the
        length of ``[ptr, ptr+len)`` with trailing ``/`` bytes removed,
        but never below 1 (a lone ``/`` keeps length 1).

        Matches the oracle's ``rstrip('/')`` normalisation used before
        the containment compare so ``dir/`` and ``dir`` are the same
        prefix. Pure length arithmetic; reads no bytes past ``ptr+len``."""
        self._write(
            "(func $__fs_strip_slash_len (param $ptr i32) "
            "(param $len i32) (result i32)"
        )
        self._indent += 1
        self._write("(block $strip_done")
        self._indent += 1
        self._write("(loop $strip")
        self._indent += 1
        # if len <= 1, stop (keep a lone '/' or empty as-is).
        self._write("local.get $len")
        self._write("i32.const 1")
        self._write("i32.le_u")
        self._write("br_if $strip_done")
        # if last byte (ptr + len - 1) != '/', stop.
        self._write("local.get $ptr")
        self._write("local.get $len")
        self._write("i32.add")
        self._write("i32.const 1")
        self._write("i32.sub")
        self._write("i32.load8_u")
        self._write("i32.const 47")
        self._write("i32.ne")
        self._write("br_if $strip_done")
        # len -= 1; continue.
        self._write("local.get $len")
        self._write("i32.const 1")
        self._write("i32.sub")
        self._write("local.set $len")
        self._write("br $strip")
        self._indent -= 1
        self._write(")")
        self._indent -= 1
        self._write(")")
        self._write("local.get $len")
        self._indent -= 1
        self._write(")")

    def _emit_wasi_fs_path_allowed_helper(self) -> None:
        """``$Fs_path_allowed (handle i32, path_ptr i32, path_len i32)
        -> i32`` -> 1 iff the Fs value ``handle`` admits ``path``.

        The shared containment test behind both ``allows`` (its whole
        body) and every privileged Fs op (its fail-closed prologue):

          handle == 0  -> 1 (unrestricted root Fs: every path allowed)
          else         -> handle is a pointer to a List<String> header
                          (len@0, data_ptr@8) whose entries are the
                          canonicalised prefixes accumulated by
                          ``restrict_to``. ``path`` is admitted iff it is
                          contained (``$Fs_path_contained``) in EVERY
                          stored prefix.

        Mirrors ``Fs.allows`` exactly: the oracle requires
        ``is_relative_to`` ALL prefixes (the INTERSECTION of the prefix
        containments, ``capa/runtime/_capabilities.py:180-183``), so a
        single non-containing prefix denies. An empty prefix list (which
        ``restrict_to`` never produces -- it always adds one prefix)
        would vacuously allow; a fresh non-zero allow-list always holds
        at least one prefix."""
        self._emit_wasi_fs_strip_slash_helper()
        self._write(
            "(func $Fs_path_allowed (param $handle i32) "
            "(param $path_ptr i32) (param $path_len i32) (result i32)"
        )
        self._indent += 1
        self._write("(local $data i32)")
        self._write("(local $count i32)")
        self._write("(local $i i32)")
        self._write("(local $entry i32)")
        # Unrestricted root: handle 0 admits every path.
        self._write("local.get $handle")
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        self._write("i32.const 1")
        self._write("return")
        self._indent -= 1
        self._write("end")
        # Restricted: require containment in EVERY stored prefix.
        # count = header.len@0; data = header.data_ptr@8.
        self._write("local.get $handle")
        self._write("i32.load offset=0")
        self._write("local.set $count")
        self._write("local.get $handle")
        self._write("i32.load offset=8")
        self._write("local.set $data")
        self._write("i32.const 0")
        self._write("local.set $i")
        self._write("(block $allow_done")
        self._indent += 1
        self._write("(loop $scan_prefixes")
        self._indent += 1
        # if i >= count, every prefix contained -> break (allowed).
        self._write("local.get $i")
        self._write("local.get $count")
        self._write("i32.ge_u")
        self._write("br_if $allow_done")
        # entry = data + i*8 (packed (pre_ptr@0, pre_len@4)).
        self._write("local.get $data")
        self._write("local.get $i")
        self._write("i32.const 8")
        self._write("i32.mul")
        self._write("i32.add")
        self._write("local.set $entry")
        # if NOT contained(path, entry.prefix) -> return 0 (denied).
        self._write("local.get $path_ptr")
        self._write("local.get $path_len")
        self._write("local.get $entry")
        self._write("i32.load offset=0")
        self._write("local.get $entry")
        self._write("i32.load offset=4")
        self._write("call $Fs_path_contained")
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        self._write("i32.const 0")
        self._write("return")
        self._indent -= 1
        self._write("end")
        # i += 1; continue.
        self._write("local.get $i")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $i")
        self._write("br $scan_prefixes")
        self._indent -= 1
        self._write(")")
        self._indent -= 1
        self._write(")")
        # Contained in all prefixes (or count was 0): allowed.
        self._write("i32.const 1")
        self._indent -= 1
        self._write(")")

    def _emit_wasi_fs_allows_wrapper(self) -> None:
        """``$Fs_allows (handle i32, path_ptr i32, path_len i32) ->
        i32`` -> the Bool result of ``fs.allows(path)``.

        Matches the call shape ``_emit_cap_allows_with_handle`` produces
        (receiver handle + path (ptr, len) -> i32 Bool). Delegates
        straight to the shared ``$Fs_path_allowed`` so the query answer
        is identical to the gate every privileged Fs op consults (no
        guest-side divergence) and to the Python oracle for canonical
        paths."""
        self._write(
            "(func $Fs_allows (param $handle i32) (param $path_ptr i32) "
            "(param $path_len i32) (result i32)"
        )
        self._indent += 1
        self._write("local.get $handle")
        self._write("local.get $path_ptr")
        self._write("local.get $path_len")
        self._write("call $Fs_path_allowed")
        self._indent -= 1
        self._write(")")

    def _emit_wasi_fs_restrict_to_wrapper(self) -> None:
        """``$Fs_restrict_to (handle i32, pre_ptr i32, pre_len i32) ->
        i32`` -> a fresh Fs value (pointer to a new ``List<String>``
        prefix allow-list).

        Matches the call shape ``_emit_fs_restrict_to`` produces
        (receiver handle + the prefix String as (ptr, len)).

        Builds the UNION of the parent's prefix list with the new
        ``prefix``, identical to ``Fs.restrict_to``
        (``existing | {canon}``, ``capa/runtime/_capabilities.py:168-171``):

          parent unrestricted (handle == 0): result = [prefix].
          parent restricted: result = parent's prefixes ++ [prefix].

        Unlike Env (which INTERSECTS its key set), Fs ACCUMULATES
        prefixes by union and ``allows`` then requires containment in ALL
        of them (so the EFFECTIVE admitted set is the intersection of the
        containments -- the monotone narrowing the model intends; see the
        design doc section 2.2). The prefix BYTES are shared, not copied
        (the prefix arg already lives in linear memory for the program's
        lifetime); only the (ptr, len) pairs are stored. The new header
        is always non-zero (``$alloc`` never returns 0), so a restricted
        Fs is always distinguishable from the unrestricted 0 sentinel."""
        self._write(
            "(func $Fs_restrict_to (param $handle i32) "
            "(param $pre_ptr i32) (param $pre_len i32) (result i32)"
        )
        self._indent += 1
        self._write("(local $header i32)")
        self._write("(local $out_data i32)")
        self._write("(local $parent_n i32)")
        self._write("(local $parent_data i32)")
        self._write("(local $out_n i32)")
        # Parent prefix count: 0 when handle is the unrestricted root,
        # else header.len@0.
        self._write("local.get $handle")
        self._write("i32.eqz")
        self._write("if (result i32)")
        self._indent += 1
        self._write("i32.const 0")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        self._write("local.get $handle")
        self._write("i32.load offset=0")
        self._indent -= 1
        self._write("end")
        self._write("local.set $parent_n")
        # out_n = parent_n + 1 (the new prefix).
        self._write("local.get $parent_n")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $out_n")
        # Allocate the result header (16 bytes) + data buffer
        # (out_n * 8 bytes for the packed (ptr, len) pairs).
        self._write("i32.const 16")
        self._write("call $alloc")
        self._write("local.set $header")
        self._write("local.get $out_n")
        self._write("i32.const 8")
        self._write("i32.mul")
        self._write("call $alloc")
        self._write("local.set $out_data")
        # Copy the parent's prefix pairs (parent_n * 8 bytes) into the
        # front of out_data, when the parent is restricted.
        self._write("local.get $parent_n")
        self._write("if")
        self._indent += 1
        self._write("local.get $handle")
        self._write("i32.load offset=8")
        self._write("local.set $parent_data")
        # memory.copy(dst=out_data, src=parent_data, n=parent_n*8).
        self._write("local.get $out_data")
        self._write("local.get $parent_data")
        self._write("local.get $parent_n")
        self._write("i32.const 8")
        self._write("i32.mul")
        self._write("memory.copy")
        self._indent -= 1
        self._write("end")
        # Append the new prefix at out_data[parent_n] = (pre_ptr, pre_len).
        self._write("local.get $out_data")
        self._write("local.get $parent_n")
        self._write("i32.const 8")
        self._write("i32.mul")
        self._write("i32.add")
        self._write("local.get $pre_ptr")
        self._write("i32.store offset=0")
        self._write("local.get $out_data")
        self._write("local.get $parent_n")
        self._write("i32.const 8")
        self._write("i32.mul")
        self._write("i32.add")
        self._write("local.get $pre_len")
        self._write("i32.store offset=4")
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
        # Return the header pointer (the new restricted Fs value).
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
        """``$Fs_exists (handle i32, full_ptr i32, full_len i32,
        idx i32, rel_ptr i32, rel_len i32) -> i32``.

        FAIL-CLOSED ATTENUATION (guest-side, Level 2): before touching
        the filesystem, consult the receiver Fs's prefix allow-list via
        ``$Fs_path_allowed(handle, full_path)`` (the FULL original
        literal path, against which the ``restrict_to`` prefixes were
        recorded). When the Fs is restricted and the path is not
        admitted, return 0 (fail-closed-as-absent) WITHOUT any
        ``stat-at`` -- byte-identical to the Python oracle
        (``if not self.allows(path): return False``,
        ``capa/runtime/_capabilities.py:259-261``). An unrestricted Fs
        (``handle == 0``) short-circuits to allowed.

        stat-at(preopen_desc(idx), path-flags=symlink-follow(1),
        rel_path) into the reserved scratch; the result discriminant
        @0 is 0 on Ok (the entry exists) and non-zero on Err
        (no-entry, ...). Returns 1 when the entry exists, 0 otherwise
        -- byte-identical to the Python oracle's
        ``os.path.exists`` gated by the cap (the preopen is the Level-1
        ceiling, the allow-list the Level-2 fine attenuation)."""
        scratch = self._wasi_fs_scratch_offset
        self._write(
            "(func $Fs_exists (param $handle i32) (param $full_ptr i32) "
            "(param $full_len i32) (param $idx i32) (param $rel_ptr i32) "
            "(param $rel_len i32) (result i32)"
        )
        self._indent += 1
        # Fail-closed: denied path reports absent (0) without a syscall.
        self._write("local.get $handle")
        self._write("local.get $full_ptr")
        self._write("local.get $full_len")
        self._write("call $Fs_path_allowed")
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        self._write("i32.const 0")
        self._write("return")
        self._indent -= 1
        self._write("end")
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
        cap leaks no path type).

        FAIL-CLOSED ATTENUATION (guest-side, Level 2): same prologue as
        ``$Fs_exists`` -- a path the receiver Fs does not admit reports
        false (0) WITHOUT a ``stat-at``, matching the Python oracle
        (``if not self.allows(path): return False``,
        ``capa/runtime/_capabilities.py:267-269``)."""
        scratch = self._wasi_fs_scratch_offset
        self._write(
            "(func $Fs_is_dir (param $handle i32) (param $full_ptr i32) "
            "(param $full_len i32) (param $idx i32) (param $rel_ptr i32) "
            "(param $rel_len i32) (result i32)"
        )
        self._indent += 1
        # Fail-closed: denied path reports not-a-dir (0) without a syscall.
        self._write("local.get $handle")
        self._write("local.get $full_ptr")
        self._write("local.get $full_len")
        self._write("call $Fs_path_allowed")
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        self._write("i32.const 0")
        self._write("return")
        self._indent -= 1
        self._write("end")
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

        One segment per call: ``create-directory-at`` creates ONE
        directory relative to the preopen descriptor. The full
        recursive ``os.makedirs(exist_ok=True)`` (creating every missing
        intermediate segment) is replicated at the CALL SITE, not here:
        ``_emit_wasi_fs_metadata_call`` splits the resolved relative
        path into its cumulative prefixes (``a`` / ``a/b`` / ``a/b/c``,
        all compile-time literals) and calls this wrapper once per
        prefix in order, sharing one ret area and short-circuiting on a
        genuine error. Each call here is idempotent, so re-creating an
        already-existing intermediate (or the leaf) is an Ok, matching
        the oracle. This wrapper therefore stays a single-segment
        primitive; the recursion is the sequence the call site emits.

        FAIL-CLOSED ATTENUATION (guest-side, Level 2): before any
        ``create-directory-at``, consult ``$Fs_path_allowed(handle,
        full_path)``. When the Fs is restricted and the path is not
        admitted, write the deny ``Err(IoError)`` and return WITHOUT
        creating anything -- byte-identical (on the Result discriminant)
        to the Python oracle (``if not self.allows(path): return
        self._deny(...)``, ``capa/runtime/_capabilities.py:275-276``).
        Because the call site calls this wrapper once per cumulative
        mkdir prefix sharing one full path + ret area, the gate is the
        SAME full literal for every prefix call; a denied target denies
        the whole sequence on the first prefix and short-circuits."""
        scratch = self._wasi_fs_scratch_offset
        msg_off, msg_len = self._intern_string("mkdir failed")
        self._write(
            "(func $Fs_mkdir (param $handle i32) (param $full_ptr i32) "
            "(param $full_len i32) (param $idx i32) (param $rel_ptr i32) "
            "(param $rel_len i32) (param $ret_area i32)"
        )
        self._indent += 1
        # Fail-closed: denied path writes Err(IoError), creates nothing.
        self._write("local.get $handle")
        self._write("local.get $full_ptr")
        self._write("local.get $full_len")
        self._write("call $Fs_path_allowed")
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        self._emit_wasi_fs_unit_err(msg_off, msg_len)
        self._write("return")
        self._indent -= 1
        self._write("end")
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

    def _emit_wasi_fs_unit_err(self, msg_off: int, msg_len: int) -> None:
        """Write an ``Err(IoError)`` into ``$ret_area`` for the
        ``result_unit_io_error`` 20-byte shape: tag@0 = 1, message = the
        interned fixed string (m_ptr@4, m_len@8), empty cause (c_ptr@12 =
        0, c_len@16 = 0). Shared by the ``mkdir`` fail-closed prologue
        (the deny path) and identical to ``_emit_wasi_fs_write_err``'s
        body; ``$ret_area`` is in scope (the wrapper's trailing param)."""
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

    def _emit_wasi_fs_mkdir_recursive_helper(self) -> None:
        """``$Fs_mkdir_recursive (handle, full_ptr, full_len, idx,
        rel_ptr, rel_len, ret_area)`` -> recursive ``mkdir`` over a
        RUNTIME relative path (WASI Fs layer b1, dynamic ``--preopen``).

        A dynamic ``fs.mkdir(path)`` path is not known at compile time, so
        the literal call site's cumulative-prefix unrolling cannot run.
        This helper replicates ``os.makedirs(exist_ok=True)`` AT RUNTIME:
        it scans the relative path for ``/`` separators and calls the
        existing single-segment ``$Fs_mkdir`` once per cumulative prefix
        (``a`` then ``a/b`` then ``a/b/c``), in order, each idempotent
        (``$Fs_mkdir`` maps ``exist`` to Ok). It SHORT-CIRCUITS the
        moment a prefix writes a genuine ``Err`` (ret_area tag@0 != 0),
        leaving that Err in ``ret_area`` for the materialiser -- exactly
        the literal path's behaviour, so a multi-segment dynamic mkdir is
        byte-parity with the oracle. The FULL path is passed unchanged to
        every ``$Fs_mkdir`` call so the fine-attenuation gate sees the
        same full path each time (a denied target denies the first
        prefix). ``$Fs_mkdir`` is REUSED verbatim; this helper only
        sequences the prefixes a runtime path cannot pre-enumerate."""
        self._write(
            "(func $Fs_mkdir_recursive (param $handle i32) "
            "(param $full_ptr i32) (param $full_len i32) (param $idx i32) "
            "(param $rel_ptr i32) (param $rel_len i32) (param $ret_area i32)"
        )
        self._indent += 1
        self._write("(local $k i32)")
        # Walk k = 1 .. rel_len; at each k that is either a '/' boundary
        # (rel[k] == '/') or the end (k == rel_len), mkdir the prefix
        # rel[0:k]. A leading '/' yields a zero-length first prefix the
        # boundary loop never emits (k starts at 1 and rel[0]=='/' is a
        # boundary that mkdirs rel[0:1] == "/", which $Fs_mkdir handles).
        self._write("i32.const 1")
        self._write("local.set $k")
        self._write("(block $done")
        self._indent += 1
        self._write("(loop $seg")
        self._indent += 1
        # if k > rel_len -> done.
        self._write("local.get $k")
        self._write("local.get $rel_len")
        self._write("i32.gt_u")
        self._write("br_if $done")
        # boundary = (k == rel_len) OR (rel[k] == '/'). Guard the load
        # behind the end check so k == rel_len never reads out of range.
        self._write("local.get $k")
        self._write("local.get $rel_len")
        self._write("i32.eq")
        self._write("if (result i32)")
        self._indent += 1
        self._write("i32.const 1")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        self._write("local.get $rel_ptr")
        self._write("local.get $k")
        self._write("i32.add")
        self._write("i32.load8_u offset=0")
        self._write("i32.const 47")  # '/'
        self._write("i32.eq")
        self._indent -= 1
        self._write("end")
        self._write("if")
        self._indent += 1
        # mkdir(prefix = rel[0:k]).
        self._write("local.get $handle")
        self._write("local.get $full_ptr")
        self._write("local.get $full_len")
        self._write("local.get $idx")
        self._write("local.get $rel_ptr")    # prefix ptr = rel_ptr
        self._write("local.get $k")          # prefix len = k
        self._write("local.get $ret_area")
        self._write("call $Fs_mkdir")
        # Short-circuit on a genuine Err (tag@0 != 0).
        self._write("local.get $ret_area")
        self._write("i32.load8_u offset=0")
        self._write("br_if $done")
        self._indent -= 1
        self._write("end")
        # k += 1; continue.
        self._write("local.get $k")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $k")
        self._write("br $seg")
        self._indent -= 1
        self._write(")")
        self._indent -= 1
        self._write(")")
        self._indent -= 1
        self._write(")")

    # ----- Fs.read via wasi:filesystem + wasi:io/streams ---------

    def _emit_wasi_fs_read_wrapper(self) -> None:
        """``$Fs_read (idx i32, rel_ptr i32, rel_len i32, ret_area i32)``
        -> writes a ``result<string, io-error>`` (20-byte canonical-ABI
        shape) into ``ret_area``.

        Matches the call shape ``_emit_wasi_fs_read_call`` produces
        (preopen index + rel (ptr, len) + ret_area), so the existing
        ``result_string_io_error`` materialiser lifts the result into a
        Capa ``Result<String, IoError>`` unchanged, exactly as the
        capa:host read does.

        Sequence (validated against wasm-tools 1.249.0 / wasmtime
        44.0.1; convention captured in docs/design/wasi_mode.md):

          1. resolve the preopen descriptor for ``idx``.
          2. ``open-at(desc, symlink-follow, rel, open-flags=0,
             descriptor-flags=read)`` -> result<descriptor, error-code>.
             On Err: write Err(IoError) and return (nothing opened).
          3. ``read-via-stream(file_desc, offset=0)`` ->
             result<input-stream, error-code>. On Err: drop the opened
             descriptor, write Err, return.
          4. LOOP ``blocking-read(stream, CHUNK)`` ->
             result<list<u8>, stream-error>:
               * Ok(chunk): append chunk bytes to a heap accumulation
                 buffer, continue.
               * Err(stream-error): variant disc @+4 == 1 is ``closed``
                 = EOF (the normal terminator) -> break and build the
                 String. disc @+4 == 0 is ``last-operation-failed`` ->
                 drop the carried error handle (@+8), drop the stream +
                 descriptor, write Err, return.
          5. drop the input-stream, then drop the opened descriptor
             (resource OWN handles; the preopen ROOTS are never
             dropped), and write Ok(String) = (accumulated buffer ptr,
             accumulated length). The accumulated bytes are the raw file
             bytes; the Capa String is UTF-8 by construction, matching
             the Python oracle's ``f.read()`` (UTF-8 decode) and the
             capa:host bridge.

        Resource drops fire on EVERY exit path (success, EOF, and the
        two error paths) so no OWN handle leaks and none is dropped
        twice. The accumulation buffer grows by re-allocating a larger
        block and copying when a chunk would overflow the current
        capacity, reusing ``$alloc`` + ``$memcpy`` (the same heap infra
        the List / String builders use)."""
        open_ret = self._wasi_fs_read_scratch_offset            # 8 bytes
        rvs_ret = self._wasi_fs_read_scratch_offset + 8         # 8 bytes
        br_ret = self._wasi_fs_read_scratch_offset + 16         # 12 bytes
        chunk = _WASI_FS_READ_CHUNK
        msg_off, msg_len = self._intern_string("failed to read file")
        self._write(
            "(func $Fs_read (param $handle i32) (param $full_ptr i32) "
            "(param $full_len i32) (param $idx i32) (param $rel_ptr i32) "
            "(param $rel_len i32) (param $ret_area i32)"
        )
        self._indent += 1
        self._write("(local $desc i32)")
        self._write("(local $stream i32)")
        self._write("(local $buf i32)")
        self._write("(local $buf_cap i32)")
        self._write("(local $buf_len i32)")
        self._write("(local $chunk_ptr i32)")
        self._write("(local $chunk_len i32)")
        self._write("(local $need i32)")
        self._write("(local $newcap i32)")
        self._write("(local $newbuf i32)")
        # Fail-closed attenuation (guest-side, Level 2): a path the
        # receiver Fs does not admit writes Err(IoError) and returns
        # WITHOUT opening anything, byte-identical (on the Result
        # discriminant) to the Python oracle (``if not self.allows(path):
        # return self._deny("read", path)``,
        # capa/runtime/_capabilities.py:231-232).
        self._write("local.get $handle")
        self._write("local.get $full_ptr")
        self._write("local.get $full_len")
        self._write("call $Fs_path_allowed")
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        self._emit_wasi_fs_read_err(msg_off, msg_len)
        self._write("return")
        self._indent -= 1
        self._write("end")
        # open-at(preopen_desc(idx), path-flags=symlink-follow(1), rel,
        # open-flags=0, descriptor-flags=read(1), open_ret).
        self._write("local.get $idx")
        self._write("call $__wasi_fs_preopen_desc")
        self._write("i32.const 1")            # path-flags: symlink-follow
        self._write("local.get $rel_ptr")
        self._write("local.get $rel_len")
        self._write("i32.const 0")            # open-flags: none
        self._write("i32.const 1")            # descriptor-flags: read
        self._write(f"i32.const {open_ret}")
        self._write("call $wasi_fs_open_at")
        # if open Err (disc @0 != 0): write Err, return.
        self._write(f"i32.const {open_ret}")
        self._write("i32.load8_u offset=0")
        self._write("if")
        self._indent += 1
        self._emit_wasi_fs_read_err(msg_off, msg_len)
        self._write("return")
        self._indent -= 1
        self._write("end")
        # desc = open_ret.value @4 (the opened OWN descriptor).
        self._write(f"i32.const {open_ret}")
        self._write("i32.load offset=4")
        self._write("local.set $desc")
        # read-via-stream(desc, offset=0, rvs_ret).
        self._write("local.get $desc")
        self._write("i64.const 0")
        self._write(f"i32.const {rvs_ret}")
        self._write("call $wasi_fs_read_via_stream")
        # if rvs Err: drop desc, write Err, return.
        self._write(f"i32.const {rvs_ret}")
        self._write("i32.load8_u offset=0")
        self._write("if")
        self._indent += 1
        self._write("local.get $desc")
        self._write("call $wasi_fs_drop_descriptor")
        self._emit_wasi_fs_read_err(msg_off, msg_len)
        self._write("return")
        self._indent -= 1
        self._write("end")
        # stream = rvs_ret.value @4 (the OWN input-stream).
        self._write(f"i32.const {rvs_ret}")
        self._write("i32.load offset=4")
        self._write("local.set $stream")
        # Accumulation buffer: start empty (len 0, cap 0, ptr from a
        # zero-size alloc, a stable non-overlapping heap pointer).
        self._write("i32.const 0")
        self._write("call $alloc")
        self._write("local.set $buf")
        self._write("i32.const 0")
        self._write("local.set $buf_cap")
        self._write("i32.const 0")
        self._write("local.set $buf_len")
        # Loop blocking-read(stream, CHUNK, br_ret).
        self._write("(block $read_done")
        self._indent += 1
        self._write("(loop $read_loop")
        self._indent += 1
        self._write("local.get $stream")
        self._write(f"i64.const {chunk}")
        self._write(f"i32.const {br_ret}")
        self._write("call $wasi_io_blocking_read")
        # if Ok (disc @0 == 0): append chunk; else handle stream-error.
        self._write(f"i32.const {br_ret}")
        self._write("i32.load8_u offset=0")
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        # chunk_ptr = br_ret.data_ptr @4; chunk_len = br_ret.len @8.
        self._write(f"i32.const {br_ret}")
        self._write("i32.load offset=4")
        self._write("local.set $chunk_ptr")
        self._write(f"i32.const {br_ret}")
        self._write("i32.load offset=8")
        self._write("local.set $chunk_len")
        # Grow the buffer if buf_len + chunk_len > buf_cap.
        self._write("local.get $buf_len")
        self._write("local.get $chunk_len")
        self._write("i32.add")
        self._write("local.set $need")
        self._write("local.get $need")
        self._write("local.get $buf_cap")
        self._write("i32.gt_u")
        self._write("if")
        self._indent += 1
        # newcap = max(need, buf_cap*2, CHUNK); grow geometrically so a
        # large file does not realloc once per chunk.
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
        # newbuf = alloc(newcap); copy old bytes; buf = newbuf.
        self._write("local.get $newcap")
        self._write("call $alloc")
        self._write("local.set $newbuf")
        # memory.copy(dst=newbuf, src=buf, n=buf_len).
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
        # memory.copy(dst=buf + buf_len, src=chunk_ptr, n=chunk_len).
        self._write("local.get $buf")
        self._write("local.get $buf_len")
        self._write("i32.add")
        self._write("local.get $chunk_ptr")
        self._write("local.get $chunk_len")
        self._write("memory.copy")
        # buf_len += chunk_len; continue.
        self._write("local.get $buf_len")
        self._write("local.get $chunk_len")
        self._write("i32.add")
        self._write("local.set $buf_len")
        self._write("br $read_loop")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        # Err(stream-error): variant disc @+4. 1 == closed (EOF,
        # normal). 0 == last-operation-failed(error) -> drop the carried
        # error handle @+8, then fall through to the shared cleanup as
        # an error path.
        self._write(f"i32.const {br_ret}")
        self._write("i32.load offset=4")
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        # last-operation-failed: drop the error resource, drop stream +
        # descriptor, write Err, return.
        self._write(f"i32.const {br_ret}")
        self._write("i32.load offset=8")
        self._write("call $wasi_io_drop_error")
        self._write("local.get $stream")
        self._write("call $wasi_io_drop_input_stream")
        self._write("local.get $desc")
        self._write("call $wasi_fs_drop_descriptor")
        self._emit_wasi_fs_read_err(msg_off, msg_len)
        self._write("return")
        self._indent -= 1
        self._write("end")
        # closed: EOF, the normal terminator. Break to build the String.
        self._write("br $read_done")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write(")")
        self._indent -= 1
        self._write(")")
        # EOF reached: drop the stream, then the opened descriptor.
        self._write("local.get $stream")
        self._write("call $wasi_io_drop_input_stream")
        self._write("local.get $desc")
        self._write("call $wasi_fs_drop_descriptor")
        # Ok(String): tag=0, ptr=buf @4, len=buf_len @8.
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

    def _emit_wasi_fs_read_err(self, msg_off: int, msg_len: int) -> None:
        """Write an ``Err(IoError)`` into ``$ret_area`` for the
        ``result_string_io_error`` 20-byte shape: tag@0 = 1, message =
        the interned fixed string (m_ptr@4, m_len@8), empty cause
        (c_ptr@12 = 0, c_len@16 = 0).

        The message is fixed (``failed to read file``) rather than the
        Python oracle's path-and-errno cause, which carries OS-specific
        bytes no cross-backend comparison can reproduce; parity is on
        the Result DISCRIMINANT (is_err), as the metadata / Net error
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

    # ----- Fs.write via wasi:filesystem + wasi:io/streams --------

    def _emit_wasi_fs_write_wrapper(self) -> None:
        """``$Fs_write (idx i32, rel_ptr i32, rel_len i32,
        content_ptr i32, content_len i32, ret_area i32)`` -> writes a
        ``result<_, io-error>`` (20-byte canonical-ABI shape) into
        ``ret_area``.

        Matches the call shape ``_emit_wasi_fs_write_call`` produces
        (preopen index + rel (ptr, len) + content (ptr, len) + ret_area),
        so the existing ``result_unit_io_error`` materialiser lifts the
        result into a Capa ``Result<Unit, IoError>`` unchanged, exactly
        as the capa:host write does.

        Sequence (the inverse of ``$Fs_read``; convention captured in
        docs/design/wasi_mode.md):

          1. resolve the preopen descriptor for ``idx``.
          2. ``open-at(desc, symlink-follow, rel, open-flags=create|
             truncate (9), descriptor-flags=write (2))`` ->
             result<descriptor, error-code>. create makes a new file,
             truncate empties an existing one (matching the Python
             oracle's ``open(p, "w")`` create-or-truncate). On Err: write
             Err(IoError) and return (nothing opened).
          3. ``write-via-stream(file_desc, offset=0)`` ->
             result<output-stream, error-code>. On Err: drop the opened
             descriptor, write Err, return.
          4. LOOP over ``content`` in chunks of <= ``_WASI_FS_WRITE_CHUNK``
             (4096, one OS page) bytes:
               ``blocking-write-and-flush(stream, (cursor, n))`` ->
               result<_, stream-error>. blocking-write-and-flush
               self-limits to a page AND flushes, so the wrapper never
               has to track the check-write permit window. On Err: drop
               the carried error handle (last-operation-failed), drop
               stream + descriptor, write Err, return.
             A zero-length ``content`` runs the loop zero times; the file
             is already truncated empty by open, so a 0-byte file results
             (matching ``open(p, "w")`` + ``write("")``).
          5. ``blocking-flush(stream)`` -> result<_, stream-error> for
             durability of any buffered bytes (harmless when nothing was
             written). On Err: same drop+Err cleanup.
          6. drop the output-stream, then drop the opened descriptor
             (resource OWN handles; the preopen ROOTS are never dropped),
             and write Ok(Unit) = tag 0.

        Resource drops fire on EVERY exit path (success and the error
        paths) so no OWN handle leaks and none is dropped twice. The
        content bytes are NOT copied: they already live in linear memory
        (the String ``content`` argument) and each chunk is handed to
        blocking-write-and-flush as ``(content_ptr + cursor, n)``."""
        wvs_ret = self._wasi_fs_write_scratch_offset            # 8 bytes
        wf_ret = self._wasi_fs_write_scratch_offset + 8         # 12 bytes
        chunk = _WASI_FS_WRITE_CHUNK
        msg_off, msg_len = self._intern_string("failed to write file")
        self._write(
            "(func $Fs_write (param $handle i32) (param $full_ptr i32) "
            "(param $full_len i32) (param $idx i32) (param $rel_ptr i32) "
            "(param $rel_len i32) (param $content_ptr i32) "
            "(param $content_len i32) (param $ret_area i32)"
        )
        self._indent += 1
        self._write("(local $desc i32)")
        self._write("(local $stream i32)")
        self._write("(local $cursor i32)")
        self._write("(local $remaining i32)")
        self._write("(local $n i32)")
        # Fail-closed attenuation (guest-side, Level 2): a path the
        # receiver Fs does not admit writes Err(IoError) and returns
        # WITHOUT opening / truncating anything, byte-identical (on the
        # Result discriminant) to the Python oracle (``if not
        # self.allows(path): return self._deny("write", path)``,
        # capa/runtime/_capabilities.py:242-243). The oracle never
        # touches the file on a deny, and neither does this (open-at is
        # reached only after the gate passes), so no empty file is left
        # behind for a denied write -- the same guarantee the capa:host
        # post-open guard gives.
        self._write("local.get $handle")
        self._write("local.get $full_ptr")
        self._write("local.get $full_len")
        self._write("call $Fs_path_allowed")
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        self._emit_wasi_fs_write_err(msg_off, msg_len)
        self._write("return")
        self._indent -= 1
        self._write("end")
        # open-at(preopen_desc(idx), path-flags=symlink-follow(1), rel,
        # open-flags=create|truncate(9), descriptor-flags=write(2),
        # wvs_ret). The 8-byte wvs_ret slot holds open-at's
        # result<descriptor, error-code> first, then is reused for
        # write-via-stream's result<output-stream, error-code>: the two
        # never overlap in time (write-via-stream runs only after open's
        # result has been consumed into $desc).
        self._write("local.get $idx")
        self._write("call $__wasi_fs_preopen_desc")
        self._write("i32.const 1")            # path-flags: symlink-follow
        self._write("local.get $rel_ptr")
        self._write("local.get $rel_len")
        self._write("i32.const 9")            # open-flags: create|truncate
        self._write("i32.const 2")            # descriptor-flags: write
        self._write(f"i32.const {wvs_ret}")
        self._write("call $wasi_fs_open_at")
        # if open Err (disc @0 != 0): write Err, return (nothing opened).
        self._write(f"i32.const {wvs_ret}")
        self._write("i32.load8_u offset=0")
        self._write("if")
        self._indent += 1
        self._emit_wasi_fs_write_err(msg_off, msg_len)
        self._write("return")
        self._indent -= 1
        self._write("end")
        # desc = open result.value @4 (the opened OWN descriptor).
        self._write(f"i32.const {wvs_ret}")
        self._write("i32.load offset=4")
        self._write("local.set $desc")
        # write-via-stream(desc, offset=0, wvs_ret).
        self._write("local.get $desc")
        self._write("i64.const 0")
        self._write(f"i32.const {wvs_ret}")
        self._write("call $wasi_fs_write_via_stream")
        # if wvs Err: drop desc, write Err, return.
        self._write(f"i32.const {wvs_ret}")
        self._write("i32.load8_u offset=0")
        self._write("if")
        self._indent += 1
        self._write("local.get $desc")
        self._write("call $wasi_fs_drop_descriptor")
        self._emit_wasi_fs_write_err(msg_off, msg_len)
        self._write("return")
        self._indent -= 1
        self._write("end")
        # stream = wvs_ret.value @4 (the OWN output-stream).
        self._write(f"i32.const {wvs_ret}")
        self._write("i32.load offset=4")
        self._write("local.set $stream")
        # cursor = 0; remaining = content_len.
        self._write("i32.const 0")
        self._write("local.set $cursor")
        self._write("local.get $content_len")
        self._write("local.set $remaining")
        # Loop blocking-write-and-flush(stream, (content_ptr+cursor, n)).
        self._write("(block $write_done")
        self._indent += 1
        self._write("(loop $write_loop")
        self._indent += 1
        # if remaining == 0, done.
        self._write("local.get $remaining")
        self._write("i32.eqz")
        self._write("br_if $write_done")
        # n = min(remaining, CHUNK).
        self._write("local.get $remaining")
        self._write(f"i32.const {chunk}")
        self._write("i32.lt_u")
        self._write("if (result i32)")
        self._indent += 1
        self._write("local.get $remaining")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        self._write(f"i32.const {chunk}")
        self._indent -= 1
        self._write("end")
        self._write("local.set $n")
        # blocking-write-and-flush(stream, content_ptr+cursor, n, wf_ret).
        self._write("local.get $stream")
        self._write("local.get $content_ptr")
        self._write("local.get $cursor")
        self._write("i32.add")
        self._write("local.get $n")
        self._write(f"i32.const {wf_ret}")
        self._write("call $wasi_io_blocking_write_and_flush")
        # if Err (disc @0 != 0): handle stream-error and bail.
        self._write(f"i32.const {wf_ret}")
        self._write("i32.load8_u offset=0")
        self._write("if")
        self._indent += 1
        self._emit_wasi_fs_write_stream_err(wf_ret, msg_off, msg_len)
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
        self._write("br $write_loop")
        self._indent -= 1
        self._write(")")
        self._indent -= 1
        self._write(")")
        # Final blocking-flush(stream, wf_ret) for durability.
        self._write("local.get $stream")
        self._write(f"i32.const {wf_ret}")
        self._write("call $wasi_io_blocking_flush")
        self._write(f"i32.const {wf_ret}")
        self._write("i32.load8_u offset=0")
        self._write("if")
        self._indent += 1
        self._emit_wasi_fs_write_stream_err(wf_ret, msg_off, msg_len)
        self._write("return")
        self._indent -= 1
        self._write("end")
        # Success: drop the output-stream, then the opened descriptor.
        self._write("local.get $stream")
        self._write("call $wasi_io_drop_output_stream")
        self._write("local.get $desc")
        self._write("call $wasi_fs_drop_descriptor")
        # Ok(Unit): tag = 0.
        self._write("local.get $ret_area")
        self._write("i32.const 0")
        self._write("i32.store offset=0")
        self._indent -= 1
        self._write(")")

    def _emit_wasi_fs_write_stream_err(
        self, wf_ret: int, msg_off: int, msg_len: int,
    ) -> None:
        """Shared error cleanup for a failed
        ``blocking-write-and-flush`` / ``blocking-flush``. ``$stream``
        and ``$desc`` are in scope (both already opened by the time any
        stream op runs). Drops the carried error resource when the
        variant is last-operation-failed (disc @+4 == 0; the error
        handle @+8 is an OWN resource that must be dropped), then drops
        the output-stream and the opened descriptor (the preopen ROOT is
        never dropped), and writes Err(IoError) into ``$ret_area``.

        The ``closed`` variant (disc @+4 == 1) carries no error handle,
        so it skips the error drop and just drops stream + descriptor."""
        self._write(f"i32.const {wf_ret}")
        self._write("i32.load offset=4")
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        # last-operation-failed: drop the carried error resource @+8.
        self._write(f"i32.const {wf_ret}")
        self._write("i32.load offset=8")
        self._write("call $wasi_io_drop_error")
        self._indent -= 1
        self._write("end")
        self._write("local.get $stream")
        self._write("call $wasi_io_drop_output_stream")
        self._write("local.get $desc")
        self._write("call $wasi_fs_drop_descriptor")
        self._emit_wasi_fs_write_err(msg_off, msg_len)

    def _emit_wasi_fs_write_err(self, msg_off: int, msg_len: int) -> None:
        """Write an ``Err(IoError)`` into ``$ret_area`` for the
        ``result_unit_io_error`` 20-byte shape: tag@0 = 1, message = the
        interned fixed string (m_ptr@4, m_len@8), empty cause (c_ptr@12 =
        0, c_len@16 = 0).

        The message is fixed (``failed to write file``) rather than the
        Python oracle's path-and-errno cause, which carries OS-specific
        bytes no cross-backend comparison can reproduce; parity is on the
        Result DISCRIMINANT (is_err), as the read / metadata / Net error
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

    # ----- Fs.list_dir via wasi:filesystem directory enumeration -----

    def _emit_wasi_fs_list_dir_wrapper(self) -> None:
        """``$Fs_list_dir (idx i32, rel_ptr i32, rel_len i32,
        ret_area i32)`` -> writes a ``result<list<string>, io-error>``
        (20-byte canonical-ABI shape) into ``ret_area``.

        Matches the call shape ``_emit_wasi_fs_list_dir_call`` produces
        (preopen index + rel (ptr, len) + ret_area), so the existing
        ``result_list_string_io_error`` materialiser lifts the result
        into a Capa ``Result<List<String>, IoError>`` unchanged, exactly
        as the capa:host list_dir does.

        Sequence (validated against wasm-tools 1.249.0 / wasmtime 44.0.1;
        convention captured in docs/design/wasi_mode.md):

          1. resolve the preopen descriptor for ``idx``.
          2. ``open-at(desc, symlink-follow, rel, open-flags=directory(2),
             descriptor-flags=read(1))`` -> result<descriptor,
             error-code>. The ``directory`` open-flag makes opening a
             non-directory (a regular file) fail at open-at (confirmed by
             oracle). On Err: write Err(IoError) and return (nothing
             opened).
          3. ``read-directory(dir_desc)`` ->
             result<directory-entry-stream, error-code>. On Err: drop the
             opened descriptor, write Err, return. The OWN
             directory-entry-stream is value @4.
          4. LOOP ``read-directory-entry(stream)`` ->
             result<option<directory-entry>, error-code>:
               * result disc @0 != 0 (Err): drop stream + descriptor,
                 write Err, return.
               * option disc @4 == 0 (none): END of stream (the normal
                 terminator, NOT an error) -> break.
               * option disc @4 == 1 (some): the directory-entry record
                 starts at @8 (type @8 ignored; name_ptr @12, name_len
                 @16). Append the (name_ptr, name_len) pair to a heap
                 accumulation buffer (8 bytes per pair, grown
                 geometrically), continue.
          5. SORT the accumulated (ptr, len) pairs lexicographically via
             ``$str_cmp`` (unsigned byte compare == Python's code-point
             ``sorted()`` over str), an in-place stable insertion sort.
             wasi returns entries in FILESYSTEM order; the oracle returns
             ``sorted(os.listdir(path))``, so the guest-side sort is what
             makes the ORDER byte-identical across the three backends.
             read-directory does NOT include "." / ".." (confirmed by
             oracle, matching os.listdir), so no filtering is needed.
          6. drop the directory-entry-stream, then drop the opened
             descriptor (OWN handles; the preopen ROOT is never dropped),
             and write Ok(list<string>): ret_area Ok arm = data_ptr @4,
             count @8. The materialiser wraps the (ptr, len)-pair buffer
             in a 16-byte List<String> header.

        Resource drops fire on EVERY exit path (success, EOF, and the two
        error paths) so no OWN handle leaks and none is dropped twice. The
        name BYTES are NOT copied: the host wrote each entry name into
        canonical-ABI memory (via the component's cabi_realloc) that lives
        for the call's duration, and the accumulation buffer stores only
        the (ptr, len) pairs pointing at them, exactly as the
        get-arguments / get-environment readers do for their string
        lists."""
        rd_ret = self._wasi_fs_list_dir_scratch_offset          # 8 bytes
        rde_ret = self._wasi_fs_list_dir_scratch_offset + 8     # 20 bytes
        msg_off, msg_len = self._intern_string("failed to list directory")
        self._write(
            "(func $Fs_list_dir (param $handle i32) (param $full_ptr i32) "
            "(param $full_len i32) (param $idx i32) (param $rel_ptr i32) "
            "(param $rel_len i32) (param $ret_area i32)"
        )
        self._indent += 1
        self._write("(local $desc i32)")
        self._write("(local $stream i32)")
        self._write("(local $buf i32)")        # pair buffer base (8B/pair)
        self._write("(local $buf_cap i32)")    # capacity in PAIRS
        self._write("(local $count i32)")      # accumulated entry count
        self._write("(local $name_ptr i32)")
        self._write("(local $name_len i32)")
        self._write("(local $newcap i32)")
        self._write("(local $newbuf i32)")
        self._write("(local $i i32)")
        self._write("(local $j i32)")
        self._write("(local $a i32)")          # &pairs[j]
        self._write("(local $b i32)")          # &pairs[j-1]
        self._write("(local $t0 i32)")         # swap temp ptr
        self._write("(local $t1 i32)")         # swap temp len
        # Fail-closed attenuation (guest-side, Level 2): a path the
        # receiver Fs does not admit writes Err(IoError) and returns
        # WITHOUT opening the directory, byte-identical (on the Result
        # discriminant) to the Python oracle (``if not self.allows(path):
        # return self._deny("list_dir", path)``,
        # capa/runtime/_capabilities.py:288-289).
        self._write("local.get $handle")
        self._write("local.get $full_ptr")
        self._write("local.get $full_len")
        self._write("call $Fs_path_allowed")
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        self._emit_wasi_fs_list_dir_err(msg_off, msg_len)
        self._write("return")
        self._indent -= 1
        self._write("end")
        # open-at(preopen_desc(idx), symlink-follow(1), rel,
        # open-flags=directory(2), descriptor-flags=read(1), rd_ret).
        self._write("local.get $idx")
        self._write("call $__wasi_fs_preopen_desc")
        self._write("i32.const 1")            # path-flags: symlink-follow
        self._write("local.get $rel_ptr")
        self._write("local.get $rel_len")
        self._write("i32.const 2")            # open-flags: directory
        self._write("i32.const 1")            # descriptor-flags: read
        self._write(f"i32.const {rd_ret}")
        self._write("call $wasi_fs_open_at")
        # if open Err (disc @0 != 0): write Err, return (nothing opened).
        self._write(f"i32.const {rd_ret}")
        self._write("i32.load8_u offset=0")
        self._write("if")
        self._indent += 1
        self._emit_wasi_fs_list_dir_err(msg_off, msg_len)
        self._write("return")
        self._indent -= 1
        self._write("end")
        # desc = open_ret.value @4 (the opened OWN directory descriptor).
        self._write(f"i32.const {rd_ret}")
        self._write("i32.load offset=4")
        self._write("local.set $desc")
        # read-directory(desc, rd_ret) -> result<dir-entry-stream, ec>.
        # rd_ret (8 bytes) is reused: open-at's result was consumed into
        # $desc, so the slot is free.
        self._write("local.get $desc")
        self._write(f"i32.const {rd_ret}")
        self._write("call $wasi_fs_read_directory")
        # if read-directory Err: drop desc, write Err, return.
        self._write(f"i32.const {rd_ret}")
        self._write("i32.load8_u offset=0")
        self._write("if")
        self._indent += 1
        self._write("local.get $desc")
        self._write("call $wasi_fs_drop_descriptor")
        self._emit_wasi_fs_list_dir_err(msg_off, msg_len)
        self._write("return")
        self._indent -= 1
        self._write("end")
        # stream = rd_ret.value @4 (the OWN directory-entry-stream).
        self._write(f"i32.const {rd_ret}")
        self._write("i32.load offset=4")
        self._write("local.set $stream")
        # Accumulation buffer: start empty (count 0, cap 0 pairs, ptr from
        # a zero-size alloc, a stable non-overlapping heap pointer).
        self._write("i32.const 0")
        self._write("call $alloc")
        self._write("local.set $buf")
        self._write("i32.const 0")
        self._write("local.set $buf_cap")
        self._write("i32.const 0")
        self._write("local.set $count")
        # Loop read-directory-entry(stream, rde_ret).
        self._write("(block $list_done")
        self._indent += 1
        self._write("(loop $list_loop")
        self._indent += 1
        self._write("local.get $stream")
        self._write(f"i32.const {rde_ret}")
        self._write("call $wasi_fs_read_directory_entry")
        # if result Err (disc @0 != 0): drop stream + desc, write Err,
        # return.
        self._write(f"i32.const {rde_ret}")
        self._write("i32.load8_u offset=0")
        self._write("if")
        self._indent += 1
        self._write("local.get $stream")
        self._write("call $wasi_fs_drop_dir_entry_stream")
        self._write("local.get $desc")
        self._write("call $wasi_fs_drop_descriptor")
        self._emit_wasi_fs_list_dir_err(msg_off, msg_len)
        self._write("return")
        self._indent -= 1
        self._write("end")
        # option disc @4 == 0 (none): END of stream -> break.
        self._write(f"i32.const {rde_ret}")
        self._write("i32.load8_u offset=4")
        self._write("i32.eqz")
        self._write("br_if $list_done")
        # some(directory-entry): name_ptr @12, name_len @16.
        self._write(f"i32.const {rde_ret}")
        self._write("i32.load offset=12")
        self._write("local.set $name_ptr")
        self._write(f"i32.const {rde_ret}")
        self._write("i32.load offset=16")
        self._write("local.set $name_len")
        # Grow the pair buffer if count == buf_cap (need one more pair).
        self._write("local.get $count")
        self._write("local.get $buf_cap")
        self._write("i32.ge_u")
        self._write("if")
        self._indent += 1
        # newcap = max(buf_cap*2, 4) pairs; geometric growth so a large
        # directory does not realloc once per entry.
        self._write("local.get $buf_cap")
        self._write("i32.const 1")
        self._write("i32.shl")
        self._write("local.tee $newcap")
        self._write("i32.const 4")
        self._write("i32.lt_u")
        self._write("if")
        self._indent += 1
        self._write("i32.const 4")
        self._write("local.set $newcap")
        self._indent -= 1
        self._write("end")
        # newbuf = alloc(newcap * 8 bytes); copy old (count*8) bytes.
        self._write("local.get $newcap")
        self._write("i32.const 8")
        self._write("i32.mul")
        self._write("call $alloc")
        self._write("local.set $newbuf")
        self._write("local.get $newbuf")
        self._write("local.get $buf")
        self._write("local.get $count")
        self._write("i32.const 8")
        self._write("i32.mul")
        self._write("memory.copy")
        self._write("local.get $newbuf")
        self._write("local.set $buf")
        self._write("local.get $newcap")
        self._write("local.set $buf_cap")
        self._indent -= 1
        self._write("end")
        # pairs[count] = (name_ptr, name_len); count += 1.
        self._write("local.get $buf")
        self._write("local.get $count")
        self._write("i32.const 8")
        self._write("i32.mul")
        self._write("i32.add")
        self._write("local.get $name_ptr")
        self._write("i32.store offset=0")
        self._write("local.get $buf")
        self._write("local.get $count")
        self._write("i32.const 8")
        self._write("i32.mul")
        self._write("i32.add")
        self._write("local.get $name_len")
        self._write("i32.store offset=4")
        self._write("local.get $count")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $count")
        self._write("br $list_loop")
        self._indent -= 1
        self._write(")")
        self._indent -= 1
        self._write(")")
        # Sort the accumulated (ptr, len) pairs lexicographically to
        # match the oracle's sorted(os.listdir(path)). Stable insertion
        # sort over the pair buffer; $str_cmp returns -1/0/1 for the
        # unsigned byte order (== Python str code-point order). i from 1.
        self._write("i32.const 1")
        self._write("local.set $i")
        self._write("(block $sort_done")
        self._indent += 1
        self._write("(loop $sort_outer")
        self._indent += 1
        self._write("local.get $i")
        self._write("local.get $count")
        self._write("i32.ge_u")
        self._write("br_if $sort_done")
        # j = i; while j > 0 and pairs[j] < pairs[j-1]: swap; j -= 1.
        self._write("local.get $i")
        self._write("local.set $j")
        self._write("(block $inner_done")
        self._indent += 1
        self._write("(loop $sort_inner")
        self._indent += 1
        # if j == 0, stop.
        self._write("local.get $j")
        self._write("i32.eqz")
        self._write("br_if $inner_done")
        # a = &pairs[j]; b = &pairs[j-1].
        self._write("local.get $buf")
        self._write("local.get $j")
        self._write("i32.const 8")
        self._write("i32.mul")
        self._write("i32.add")
        self._write("local.set $a")
        self._write("local.get $buf")
        self._write("local.get $j")
        self._write("i32.const 1")
        self._write("i32.sub")
        self._write("i32.const 8")
        self._write("i32.mul")
        self._write("i32.add")
        self._write("local.set $b")
        # if str_cmp(a.ptr, a.len, b.ptr, b.len) >= 0, in order: stop.
        self._write("local.get $a")
        self._write("i32.load offset=0")
        self._write("local.get $a")
        self._write("i32.load offset=4")
        self._write("local.get $b")
        self._write("i32.load offset=0")
        self._write("local.get $b")
        self._write("i32.load offset=4")
        self._write("call $str_cmp")
        self._write("i32.const 0")
        self._write("i32.ge_s")
        self._write("br_if $inner_done")
        # swap pairs[j] and pairs[j-1] (both i32 fields).
        self._write("local.get $a")
        self._write("i32.load offset=0")
        self._write("local.set $t0")
        self._write("local.get $a")
        self._write("i32.load offset=4")
        self._write("local.set $t1")
        self._write("local.get $a")
        self._write("local.get $b")
        self._write("i32.load offset=0")
        self._write("i32.store offset=0")
        self._write("local.get $a")
        self._write("local.get $b")
        self._write("i32.load offset=4")
        self._write("i32.store offset=4")
        self._write("local.get $b")
        self._write("local.get $t0")
        self._write("i32.store offset=0")
        self._write("local.get $b")
        self._write("local.get $t1")
        self._write("i32.store offset=4")
        # j -= 1; continue inner.
        self._write("local.get $j")
        self._write("i32.const 1")
        self._write("i32.sub")
        self._write("local.set $j")
        self._write("br $sort_inner")
        self._indent -= 1
        self._write(")")
        self._indent -= 1
        self._write(")")
        # i += 1; continue outer.
        self._write("local.get $i")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $i")
        self._write("br $sort_outer")
        self._indent -= 1
        self._write(")")
        self._indent -= 1
        self._write(")")
        # EOF + sorted: drop the directory-entry-stream, then the opened
        # descriptor (the preopen ROOT is never dropped).
        self._write("local.get $stream")
        self._write("call $wasi_fs_drop_dir_entry_stream")
        self._write("local.get $desc")
        self._write("call $wasi_fs_drop_descriptor")
        # Ok(list<string>): tag=0, data_ptr=buf @4, count @8. The data
        # buffer holds N packed (str_ptr, str_len) i32 pairs, exactly the
        # canonical list<string> data layout the materialiser wraps.
        self._write("local.get $ret_area")
        self._write("i32.const 0")
        self._write("i32.store offset=0")
        self._write("local.get $ret_area")
        self._write("local.get $buf")
        self._write("i32.store offset=4")
        self._write("local.get $ret_area")
        self._write("local.get $count")
        self._write("i32.store offset=8")
        self._indent -= 1
        self._write(")")

    def _emit_wasi_fs_list_dir_err(self, msg_off: int, msg_len: int) -> None:
        """Write an ``Err(IoError)`` into ``$ret_area`` for the
        ``result_list_string_io_error`` 20-byte shape: tag@0 = 1, message
        = the interned fixed string (m_ptr@4, m_len@8), empty cause
        (c_ptr@12 = 0, c_len@16 = 0).

        The message is fixed (``failed to list directory``) rather than
        the Python oracle's path-and-errno cause, which carries OS-specific
        bytes no cross-backend comparison can reproduce; parity is on the
        Result DISCRIMINANT (is_err), as the read / write / metadata / Net
        error paths already assert. ``$ret_area`` is in scope (the
        wrapper's trailing param)."""
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


    # ----- Net.get via wasi:http (Phase 1) -----------------------

    def _emit_wasi_net_host_allowed_helper(self) -> None:
        """``$Net_host_allowed (host_ptr i32, host_len i32) -> i32`` ->
        1 iff ``host`` is in the program's static Net ceiling.

        The GUEST-SIDE host ceiling (codegen-enforced, the honest Net
        guarantee). Unlike Fs preopens / Env env-set -- both Level 1,
        imposed by the WASI host at instantiate -- wasmtime's wasi:http
        C-API (``set-wasi-http``) is ALLOW-ALL with no allowed-hosts
        surface in this release, so there is no host ceiling to map onto.
        The ceiling is enforced HERE, in compiler-generated guest code:
        the helper scans the set of hosts the program names as a string
        LITERAL in ``net.get`` (the static ``NetCeiling.hosts``), each a
        data-segment literal interned up front, and returns 1 on the first
        ``$str_eq`` match, 0 if none match.

        A DYNAMIC ``net.get`` url contributes no literal host, so its host
        is never in this set and the call is denied at runtime
        (fail-closed), matching the Fs dynamic-path fail-closed policy (a
        wrongly-admitted host is real outbound authority). An EMPTY ceiling
        (only a dynamic ``net.get``) emits a helper that always returns 0,
        denying every host."""
        ceiling = self._net_ceiling
        hosts = sorted(ceiling.hosts) if ceiling is not None else []
        self._write(
            "(func $Net_host_allowed (param $host_ptr i32) "
            "(param $host_len i32) (result i32)"
        )
        self._indent += 1
        for h in hosts:
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
        ``$Net_host_allowed(host)`` FIRST; a host not in the static ceiling
        writes ``Err(IoError)`` and returns WITHOUT building any request --
        the honest Net guarantee (wasi:http is allow-all host-side, so the
        ceiling lives here).

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
        # Host gate (static ceiling): a host the program never names as a
        # literal is denied here.
        self._write("local.get $host_ptr")
        self._write("local.get $host_len")
        self._write("call $Net_host_allowed")
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
        # Host gate (shared with get; a host outside the static ceiling
        # writes Err WITHOUT building any request).
        self._write("local.get $host_ptr")
        self._write("local.get $host_len")
        self._write("call $Net_host_allowed")
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
