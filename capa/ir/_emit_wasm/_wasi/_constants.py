"""Shared WASI interface constants for the ``_wasi`` sub-package.

A dependency-free leaf module so every capability mixin can import the
constants it needs without risking an import cycle. Moved verbatim from
the former single-file ``_wasi.py`` during the structural split.
"""

from __future__ import annotations


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
