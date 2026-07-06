"""WASI emission: validation, imports, dispatch, Stdio and Clock.

The shared / dispatch surface of the ``--wasi`` emitter: capability
validation, the wasi:* import block, the wrapper dispatch, plus the
small Stdio and Clock wrappers. Split out of the former single-file
``_wasi.py`` with no behaviour change.
"""

from __future__ import annotations

from .._layout import WasmEmissionError
from ._constants import (
    _WASI_RANDOM, _WASI_MONOTONIC, _WASI_WALL, _WASI_ENVIRONMENT,
    _WASI_CLI_STDOUT, _WASI_CLI_STDERR, _WASI_CLI_STDIN,
    _WASI_FS_TYPES, _WASI_FS_PREOPENS, _WASI_IO_STREAMS, _WASI_IO_ERROR,
    _WASI_IO_POLL, _WASI_HTTP_TYPES, _WASI_HTTP_HANDLER,
    _WASI_NET_MIGRATED, _WASI_FS_METADATA, _WASI_FS_STREAM,
    _WASI_FS_REJECTED, _WASI_STDIO_MIGRATED, _WASI_STDIO_WRITE_CHUNK,
)


class _WasiCoreMixin:
    """Validation + imports + dispatch + Stdio/Clock wrappers of the
    ``--wasi`` emitter; folded into ``WasmEmitter`` via
    ``_WasiEmissionMixin``."""

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
                "operation, so no preopen can be derived (fail-closed)."
                + self._path_arg_hint("Fs")
                + " Run with --preopen <dir> to grant the component "
                "filesystem authority over the directory containing that "
                "path (the operator-declared WASI --dir model), or use the "
                "default capa:host backend (drop --wasi)."
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
        # WASI Net operator grant (--allow-host, 2026-07-05): when the
        # operator declared ``--allow-host <host>`` (``self._net_operator_allow``),
        # the granted hosts are UNIONED into the guest-side host ceiling
        # (``$Net_host_allowed``), so a dynamic URL whose host is granted is
        # reachable at runtime. The rejection is SUPPRESSED -- the operator
        # has explicitly granted the network authority the compiler could not
        # derive, a LEVEL-2 operator-DECLARED grant (recorded in the SBOM,
        # distinct from the derived surface). This mirrors the Fs
        # ``not self._wasi_dynamic_fs`` suppression above. Without
        # ``--allow-host`` the rejection stands exactly as before.
        if any(
            cap == "Net" and method in ("get", "post")
            for cap, method in self._used_caps
        ) and self._net_ceiling is not None and not self._net_ceiling.closed \
                and not self._net_operator_allow:
            raise WasmEmissionError(
                "Net in WASI mode requires every URL passed to get/post to "
                "be a string literal so the allowed-host ceiling can be "
                "materialised; this program passes a dynamic URL (a local, "
                "parameter, interpolated or computed value) to a Net "
                "operation, so no host ceiling can be derived (fail-closed)."
                + self._path_arg_hint("Net")
                + " Run with --allow-host <host> to grant the component "
                "network authority to reach that host (the operator-declared "
                "Net grant, the Net analogue of --preopen), or use the "
                "default capa:host backend (drop --wasi)."
            )


    def _path_arg_hint(self, cap: str) -> str:
        """A trailing sentence naming the proven argv -> sink facts for
        ``cap`` (WASI Layer 1), so the fail-closed message is ACTIONABLE:
        the operator sees exactly which argv argument reaches the sink and
        with what access. Empty string when the surface proves no argv ->
        ``cap`` flow (the dynamic path came from elsewhere) or the AST is
        unavailable."""
        module = getattr(self, "_wasi_ast_module", None)
        if module is None:
            return ""
        try:
            from ..._wasi_path_arg_surface import compute_path_arg_surface
            surface = compute_path_arg_surface(module)
        except Exception:
            # The hint is best-effort; never let surface computation turn
            # a clean fail-closed rejection into a crash.
            return ""
        facts = [f for f in surface.facts if f.cap == cap]
        if not facts:
            return ""
        joined = "; ".join(f.describe() for f in facts)
        return (
            f" The compiler proved this program routes argv (env.args()) "
            f"to {cap}: {joined}."
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
            # WASI Net operator grant (--allow-host): the RUNTIME URL
            # extractor that unblocks a dynamic (argv-derived) net.get /
            # net.post URL. Emitted only when a grant is active; without a
            # grant the dynamic call site fail-closes and never calls it.
            if self._net_operator_allow:
                self._emit_wasi_is_url_ws_helper()
                self._emit_wasi_net_url_extract_helper()
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

