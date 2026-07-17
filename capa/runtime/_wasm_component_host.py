"""Component Model host for Capa Wasm artifacts.

Companion to ``_wasm_host.py``, which speaks the *core* Wasm
import protocol (raw pointers + canonical-ABI return areas).
This module instead drives a Component-Model-wrapped Capa
artifact: ``wasmtime.component.Component`` plus a high-level
linker where each capability method is a Python function that
receives lifted WIT values (strings, lists, options, results,
records) and returns the same shape -- no manual pointer work.

The two hosts share semantics. Capa Wasm artifacts built with
``capa --wasm --output app.wasm`` are core modules and load
through ``WasmHost``; artifacts built with
``capa --wasm --component --output app.wasm`` are components
and load through ``WasmComponentHost``.

Slice 25.8 (2026-05-30): cap-handle threading parity with the
core host. Slices 25.2 - 25.6 wired Fs / Net / Db / Proc / Env /
Clock through a per-instance handle table on the core host so a
restricted cap survives crossing function boundaries (audit slice
25 F1). This module now mirrors that discipline: every cap
import takes ``handle: u32`` first, the host looks up the
receiver cap in the table and enforces its restriction, and
``main`` is dispatched with the root handles in the slots
declared by the world's ``export main`` signature. Pre-slice the
CM host registered handlers with no handle arg and the WIT world
was hardcoded to ``export main: func();``; this was both a
correctness gap (the host bridge never enforced attenuation) and
a hard link-time failure for every program whose ``main`` took a
handle-bearing cap.

Trust-boundary note (audit M1, 2026-05): ``env.get`` here reads
``os.environ.get(name)`` without filtering, identical to the core
host. Unrestricted Env caps see every host env var, including
secrets. The attenuation system narrows the cap; the recommendation
for any production / untrusted-guest use is to call
``env.restrict_to_keys([...])`` on a literal allow-list before
handing the cap on. See ``_wasm_host.py`` for the full discussion.
"""

from __future__ import annotations

import json as _stdlib_json
import os
import sys
from typing import Any, Iterable, Optional

import wasmtime
import wasmtime.component as wc

from ._capabilities import Clock, Db, Env, Fs, Net, Proc, Stdio, _write_safe
from ._fs_guard import PostOpenDenied
from ._cap_handles import (
    CapHandleError,
    CapHandleTable,
    bootstrap_root_handles,
)
from ._result import Ok


class IoErrorRecord(wc.Record):
    """Record subclass matching the WIT ``io-error`` shape with
    ``message`` and ``cause`` string fields. wasmtime.component's
    RecordType.convert_to_c uses ``getattr(val, name)`` plus
    ``isinstance(val, wc.Record)`` so any Record subclass with
    the right attrs works."""

    def __init__(self, message: str, cause: str = "") -> None:
        self.message = message
        self.cause = cause


def _deny_record(err) -> "IoErrorRecord":
    """Render a shared Fs/Db/Proc ``_deny()`` result (an ``Err(IoError)``)
    into an ``IoErrorRecord`` so the CM host's deny message + restriction
    cause match the Python backend byte for byte."""
    io = err.error
    return IoErrorRecord(message=io.message, cause=io.cause)


class WasmComponentHost:
    """Wraps a Component Model ``.wasm`` artifact in a wasmtime
    linker pre-populated with Capa's ``capa:host/*`` interfaces.

    Construction takes the program ``argv`` (visible to the
    component via ``Env.args()``); ``run_main`` instantiates
    and dispatches to the world's ``main`` export with the right
    root capability handle threaded into each declared cap slot."""

    def __init__(
        self,
        args: Iterable[str] = (),
        *,
        wasi: bool = False,
        env_ceiling: Optional["object"] = None,
        fs_ceiling: Optional["object"] = None,
        fs_operator_preopen: Optional[tuple] = None,
        net_ceiling: Optional["object"] = None,
        stdin: Optional[bytes] = None,
    ):
        self._args = list(args)
        # WASI Stdio.read_line Phase 2 (2026-06-29): the bytes to feed the
        # component's standard input, or None to inherit the host process
        # stdin. In --wasi the guest reads ``Stdio.read_line`` from
        # ``wasi:cli/stdin`` (get-stdin -> input-stream.blocking-read),
        # which add_wasip2() serves from this WasiConfig's stdin source.
        # When provided, the bytes are written to a temp file installed as
        # ``WasiConfig.stdin_file`` (the wasmtime-py stdin setter takes a
        # path); the temp file is cleaned up when the host is closed /
        # garbage-collected. Only consulted in --wasi mode; the default
        # capa:host path reads ``sys.stdin`` directly in the read-line
        # host bridge. ``b""`` means an EMPTY stdin (immediate EOF), which
        # is distinct from ``None`` (inherit the host stdin).
        self._stdin = stdin
        self._stdin_tmp_path: Optional[str] = None
        # WASI Fs Phase 0 (2026-06-27): the statically-computed Fs
        # preopen ceiling (``capa.ir.FsCeiling``) for the program being
        # run, or None when not computed. When the ceiling is CLOSED,
        # the host preopens exactly its directories (parents of the
        # literal Fs paths) with the derived perms (READ_WRITE if a
        # mutating op targets the directory, else READ_ONLY), in the
        # SAME sorted order the compiler assigned preopen indices, so
        # ``wasi:filesystem/preopens.get-directories`` hands the guest
        # the descriptors index-aligned with the call sites. When the
        # ceiling is NOT closed (a dynamic Fs path), the host
        # materialises NO preopens at all (fail-closed) -- the compiler
        # already rejected such a program in --wasi mode, so this is
        # belt-and-braces. Only consulted in ``--wasi`` mode.
        self._fs_ceiling = fs_ceiling
        # WASI Fs layer b1 (operator preopen, 2026-06-30): an OPERATOR-
        # DECLARED filesystem grant, ``(host_dir, read_write)`` or None.
        # When the operator passes ``--preopen <dir>[:ro|:rw]`` the host
        # registers that directory as a preopen AFTER every
        # compiler-derived ceiling preopen, so its guest index is
        # ``len(ceiling.preopens)``. In the dynamic-path case the derived
        # ceiling is NOT closed (no derived preopens), so the operator
        # preopen lands at index 0 -- the constant the dynamic-path
        # call-site emitter addresses. This is the WASI ``--dir`` model
        # (wasmtime's ``--dir``): authority DECLARED by the operator
        # (Level 2), distinct from the COMPILER-DERIVED ceiling. It is the
        # ONLY thing that lets a dynamic Fs path resolve at runtime; the
        # compiler suppresses its dynamic-path rejection symmetrically
        # (``--wasi-dynamic-fs``). Only consulted in ``--wasi`` mode.
        self._fs_operator_preopen = fs_operator_preopen
        # Records the preopens actually installed on the WasiConfig in
        # WASI mode (a list of (host_path, "ro"|"rw") tuples), exposed
        # for tests / diagnostics so the ceiling guarantee is
        # inspectable without reaching into wasmtime internals.
        self._wasi_fs_applied: Optional[object] = None
        # WASI Env Level 1 (2026-06-27): the statically-computed Env
        # authority ceiling (``capa.ir.EnvCeiling``) for the program
        # being run, or None when not computed. When the ceiling is
        # CLOSED, the WASI env-set is restricted to exactly its keys
        # (read from the host environment) instead of ``inherit_env``,
        # so the component never receives a variable outside the
        # ceiling -- the leak-by-default fix. When None or not closed,
        # the host keeps ``inherit_env`` (Level 2). Only consulted in
        # ``--wasi`` mode; the default ``capa:host`` path ignores it.
        self._env_ceiling = env_ceiling
        # Records the env-set actually installed on the WasiConfig in
        # WASI mode (a dict for a closed ceiling, or the sentinel
        # ``"inherit"`` when ``inherit_env`` was used). Exposed for
        # tests and diagnostics so the leak-closed guarantee is
        # inspectable without reaching into wasmtime internals.
        self._wasi_env_applied: Optional[object] = None
        # WASI Net Phase 1 (2026-06-28): the statically-computed Net host
        # ceiling (``capa.ir.NetCeiling``) for the program being run, or
        # None when the program does not use ``Net.get``. Passing a
        # NetCeiling is the host's signal that the program uses Net.get,
        # which gates linking wasi:http (the FFI receipt below). The
        # ceiling itself is enforced GUEST-SIDE (codegen) because
        # wasmtime's wasi:http C-API is allow-all with no host allowed-
        # hosts surface; the host records it for inspection only. Only
        # consulted in ``--wasi`` mode.
        self._net_ceiling = net_ceiling
        # Records whether wasi:http was linked on this host (True only in
        # WASI mode when the program uses Net.get). Exposed for tests so
        # the "only link wasi:http when Net is used" rule is inspectable.
        self._wasi_http_linked: bool = False
        self._engine = wasmtime.Engine()
        self._store = wasmtime.Store(self._engine)
        self._linker = wc.Linker(self._engine)
        # Experimental WASI mode (2026-06-27): when True, the migrated
        # Random / Clock touch-points import canonical wasi:random /
        # wasi:clocks interfaces, satisfied by wasmtime's own WASI P2
        # host via ``add_wasip2()`` + a ``WasiConfig`` on the store.
        # The custom ``capa:host`` registrations below still run, so
        # the SAME linker satisfies both the wasi:* imports (random /
        # clocks) and the capa:host:* imports (stdio, etc.) -- this is
        # the hybrid coexistence the PoC proves. Default (False) keeps
        # the all-``capa:host`` behaviour untouched.
        self._wasi = wasi
        # WASI stdout / stderr capture (Stdio Phase 1, 2026-06-29). In
        # --wasi the guest writes print / println to wasi:cli/stdout and
        # eprintln to wasi:cli/stderr (output-stream.blocking-write-and-
        # flush), which add_wasip2 serves from this WasiConfig. Rather
        # than inherit the host process fds (which would bypass any
        # sys.stdout redirection a caller / test installs), the config
        # installs custom-output callbacks that do TWO things per chunk:
        #
        #  1. ECHO the bytes onward, decoded, to the live ``sys.stdout`` /
        #     ``sys.stderr`` through the SAME ``_write_safe`` writer the
        #     capa:host bridge used pre-migration. This keeps the
        #     observable output byte-identical to the default backend
        #     (and to the pre-migration capa:host path), keeps the CLI
        #     ``--run --wasi`` output visible with no CLI change, and
        #     preserves panic ORDERING: the panic host import flushes
        #     ``sys.stdout`` before writing its stderr line, and program
        #     output has already reached ``sys.stdout`` here.
        #  2. ACCUMULATE the raw UTF-8 bytes so ``captured_stdout()`` /
        #     ``captured_stderr()`` expose exactly what the guest wrote,
        #     for tests / callers that prefer reading the buffer over
        #     redirecting ``sys.stdout``.
        #
        # The streams are read at CALL time (``sys.stdout`` each chunk),
        # so a redirect installed AFTER construction still captures, like
        # the core host's deferred-lookup stdio. The decode mirrors the
        # core host: WTF-8 (surrogatepass) with a replace fallback for
        # genuinely invalid bytes, so a Capa string with a lone surrogate
        # prints identically across backends. The callbacks return None,
        # signalling "all bytes consumed" to the custom-output contract.
        self._captured_stdout = bytearray()
        self._captured_stderr = bytearray()
        if wasi:
            wasi_cfg = wasmtime.WasiConfig()

            def _decode_wtf8(data: bytes) -> str:
                raw = bytes(data)
                try:
                    return raw.decode("utf-8", errors="surrogatepass")
                except UnicodeDecodeError:
                    return raw.decode("utf-8", errors="replace")

            def _capture_stdout(data: bytes):
                self._captured_stdout.extend(data)
                _write_safe(sys.stdout, _decode_wtf8(data))
                try:
                    sys.stdout.flush()
                except Exception:
                    # Best-effort flush: the bytes are already written
                    # above, so a failed flush (closed stream raising
                    # ValueError, an I/O OSError, or a quirk of a caller-
                    # installed sys.stdout replacement) must NOT abort the
                    # capture or the guest's write. Kept broad on purpose:
                    # sys.stdout may be an arbitrary test double / redirect
                    # whose flush() can raise outside ValueError/OSError.
                    pass
                return None

            def _capture_stderr(data: bytes):
                self._captured_stderr.extend(data)
                _write_safe(sys.stderr, _decode_wtf8(data))
                try:
                    sys.stderr.flush()
                except Exception:
                    # Best-effort flush: the bytes are already written
                    # above, so a failed flush (closed stream raising
                    # ValueError, an I/O OSError, or a quirk of a caller-
                    # installed sys.stderr replacement) must NOT abort the
                    # capture or the guest's write. Kept broad on purpose:
                    # sys.stderr may be an arbitrary test double / redirect
                    # whose flush() can raise outside ValueError/OSError.
                    pass
                return None

            wasi_cfg.stdout_custom = _capture_stdout
            wasi_cfg.stderr_custom = _capture_stderr
            # Stdio.read_line Phase 2 (2026-06-29): standard input source.
            # When the caller supplied explicit bytes, write them to a
            # temp file and install it as the component's stdin (the
            # wasmtime-py ``WasiConfig.stdin_file`` setter takes a path,
            # not a buffer). The guest's wasi:cli/stdin get-stdin then
            # reads from these bytes via input-stream.blocking-read; an
            # empty buffer yields immediate EOF (the guest's read_line
            # returns Err("end of input")). When no bytes were supplied
            # (the common CLI case), inherit the host process stdin so an
            # interactive / piped program reads the real terminal. The
            # temp file lives until the host is finalized (see ``__del__``,
            # which unlinks it) so wasmtime can read it lazily during the
            # run.
            if self._stdin is not None:
                import tempfile
                fd, self._stdin_tmp_path = tempfile.mkstemp(
                    prefix="capa-wasi-stdin-",
                )
                with os.fdopen(fd, "wb") as fh:
                    fh.write(self._stdin)
                wasi_cfg.stdin_file = self._stdin_tmp_path
            else:
                wasi_cfg.inherit_stdin()
            # Env migration (2026-06-27): in WASI mode ``Env.get`` /
            # ``Env.args`` read ``wasi:cli/environment`` (get-environment
            # / get-arguments), which ``add_wasip2()`` serves from this
            # WasiConfig rather than the ``capa:host/env`` bridge.
            #
            # - inherit_env(): the guest's get-environment returns the
            #   host process environment, so ``env.get(KEY)`` of a key
            #   the host has set returns its value (and ``none`` for an
            #   absent key, fail-closed). This mirrors the default
            #   ``capa:host`` Env, which reads ``os.environ`` directly.
            # - argv: Capa's ``Env.args()`` is ``sys.argv[1:]`` (no
            #   argv[0]). WASI's get-arguments returns whatever argv the
            #   host configures, so we set it to exactly the program
            #   args the host was constructed with (no synthetic argv[0])
            #   to keep ``env.args()`` byte-identical to the default
            #   backend and the core-Wasm host.
            #
            # Env Level 1 (2026-06-27): when the static Env ceiling is
            # CLOSED (every ``env.get`` key is a string literal), the
            # env-set is restricted to exactly those keys read from the
            # host environment, via ``env`` rather than ``inherit_env``.
            # The component then NEVER receives a variable outside the
            # ceiling (the leak-by-default fix, docs/design/
            # wasi-attenuation.md Level 1). The program's observable
            # behaviour is unchanged: it only ever reads ceiling keys,
            # and a ceiling key absent from the host environment still
            # reads as ``none`` (fail-closed), identical to inherit_env.
            # When the ceiling is absent or NOT closed (a dynamic
            # ``env.get`` key), fall back to ``inherit_env`` (Level 2);
            # the guest-side allow-list still narrows under our host.
            ceiling = self._env_ceiling
            if ceiling is not None and getattr(ceiling, "closed", False):
                env_set = ceiling.host_env_set(dict(os.environ))
                # wasmtime's WasiConfig.env takes the FULL env-set as a
                # list of (key, value) pairs in one assignment (it
                # replaces, not appends), so build it once. An empty
                # ceiling yields an empty env-set: the component gets a
                # completely empty environment, the tightest leak-closed
                # outcome.
                wasi_cfg.env = list(env_set.items())
                self._wasi_env_applied = dict(env_set)
            else:
                wasi_cfg.inherit_env()
                self._wasi_env_applied = "inherit"
            wasi_cfg.argv = list(self._args)
            self._apply_fs_preopens(wasi_cfg)
            self._store.set_wasi(wasi_cfg)
            self._linker.add_wasip2()
            # Net.get Phase 1 (2026-06-28): link wasi:http ONLY when the
            # program uses Net.get (signalled by a non-None net_ceiling).
            # wasmtime 44+ does not expose ``add_wasi_http`` on the
            # high-level component API, so we reach the C-ABI through
            # ``wasmtime._bindings`` (the same pattern the high-level
            # ``add_wasip2`` / ``set_wasi`` wrap). The OBLIGATORY
            # ``set_wasi_http`` on the store context arms the http
            # implementation; WITHOUT it the C-API panics
            # (Option::unwrap-on-None) the moment a wasi:http import is
            # linked. We DO NOT link/arm wasi:http when the program does
            # not use Net (a clean total deny, and it also avoids that
            # context panic for non-Net programs). The C-API is ALLOW-ALL
            # (no allowed-hosts surface), so the Net ceiling is enforced
            # guest-side (codegen); see docs/design/wasi-attenuation.md.
            if self._net_ceiling is not None:
                import wasmtime._bindings as _wt_bindings
                err = _wt_bindings.wasmtime_component_linker_add_wasi_http(
                    self._linker.ptr(),
                )
                if err:
                    raise wasmtime.WasmtimeError._from_ptr(err)
                _wt_bindings.wasmtime_context_set_wasi_http(
                    self._store._context(),
                )
                self._wasi_http_linked = True
        # Slice 25.8 (2026-05-30): per-instance cap handle table,
        # the Component Model mirror of ``WasmHost._cap_handles``.
        # Each privileged host op looks up the receiver cap by its
        # u32 handle and enforces the restriction before performing
        # the syscall, so a restricted cap threaded across a
        # function boundary on the guest side keeps its restriction
        # (audit slice 25 F1).
        self._cap_handles = CapHandleTable()
        # Root caps the host hands the program; lazy-constructed in
        # ``run_main`` only for the slots ``main`` actually declares
        # so a test that only uses Stdio doesn't pay for an Fs
        # instance.
        self._root_fs: Optional[Fs] = None
        self._root_net: Optional[Net] = None
        self._root_db: Optional[Db] = None
        self._root_proc: Optional[Proc] = None
        self._root_env: Optional[Env] = None
        self._root_clock: Optional[Clock] = None
        self._root_stdio: Optional[Stdio] = None
        # Set True by the panic host import once it has written the
        # canonical ``panic: <message>`` line; the CLI uses it to
        # exit cleanly on the guest's follow-up ``unreachable`` trap
        # rather than print a host traceback. A genuine runtime trap
        # leaves it False and still reports with detail. Re-cleared at
        # the start of every run (see ``run_main``) so a reused host
        # cannot carry a stale latch from one program into the next.
        self.panicked = False
        self._register_all()

    def __del__(self):
        # Remove the WASI stdin temp file (Phase 2) when the host is
        # collected. Best-effort: a missing file or an OS quirk on
        # interpreter shutdown must not raise from a finalizer.
        path = getattr(self, "_stdin_tmp_path", None)
        if path:
            try:
                os.unlink(path)
            except OSError:
                pass

    def captured_stdout(self) -> bytes:
        """The raw UTF-8 bytes the guest wrote to wasi:cli/stdout
        (Stdio.print / Stdio.println) so far, in --wasi mode. Empty in
        the default (non-wasi) path, where Stdio output goes straight to
        ``sys.stdout`` through the capa:host bridge. Accumulates across a
        run; a caller that reuses the host should snapshot it per run."""
        return bytes(self._captured_stdout)

    def captured_stderr(self) -> bytes:
        """The raw UTF-8 bytes the guest wrote to wasi:cli/stderr
        (Stdio.eprintln) so far, in --wasi mode. Does NOT include the
        ``panic: <msg>`` line, which the host writes to ``sys.stderr``
        directly (panic stays on capa:host/panic in this phase), not
        through wasi:cli/stderr."""
        return bytes(self._captured_stderr)

    def _apply_fs_preopens(self, wasi_cfg) -> None:
        """Register the Fs ceiling's preopened directories on the
        WasiConfig (WASI mode only).

        For a CLOSED ceiling, preopen each directory in the ceiling's
        ORDERED list (the compiler's preopen index order) at a guest
        path equal to its host path, with READ_WRITE perms when the
        directory hosts a mutating op (mkdir / write) and READ_ONLY
        otherwise. wasmtime's ``get-directories`` returns descriptors
        in registration order, so guest preopen index K names the K-th
        ceiling directory -- the binding the compiler resolved each
        literal Fs path against.

        Fail-closed: a non-closed ceiling (a dynamic Fs path) or a
        missing ceiling registers NO preopens, so the component cannot
        open any directory. The compiler already rejects such a program
        in --wasi mode (``_validate_wasi_caps``); this host policy is
        the matching runtime guarantee. A directory that does not exist
        on the host is skipped (the guest's stat / mkdir then sees no
        descriptor for that index and reports absent / fails, the same
        fail-closed-as-absent the capability oracle uses).

        Preopens are a HARD runtime ceiling: wasmtime denies path
        traversal outside a preopened directory and denies a write
        through a READ_ONLY preopen, independent of guest behaviour."""
        ceiling = self._fs_ceiling
        if ceiling is None or not getattr(ceiling, "closed", False):
            # No derived preopens. In layer b1 an OPERATOR ``--preopen``
            # may still grant authority for dynamic paths: register it
            # alone (at index 0, matching the dynamic call-site emitter's
            # ``_wasi_operator_preopen_index() == 0`` for an open ceiling).
            self._wasi_fs_applied = self._apply_operator_preopen(wasi_cfg, 0)
            return
        # ``get-directories`` returns descriptors ONLY for the preopens
        # actually registered, in registration order, so EVERY ceiling
        # slot must register exactly one preopen to keep the guest's
        # index K aligned with ceiling[K]. A ceiling directory that
        # does not exist on the host is registered against a shared,
        # empty placeholder directory (READ_ONLY): the slot stays
        # aligned, and any stat / mkdir the guest attempts on that
        # index sees an empty directory, so exists / is_dir report
        # false (fail-closed-as-absent, matching the capability
        # oracle's denied-as-absent convention) and a mkdir there is
        # contained to the throwaway placeholder, granting no real
        # authority over the intended (non-existent) host path.
        # The GUEST path each preopen is mounted at is a synthetic
        # ``/capa-preopen-K`` (POSIX form): the guest never matches
        # preopen path strings (it addresses preopens by the
        # compiler-assigned INDEX, which equals registration order), so
        # the guest path only has to be a valid, distinct WASI path.
        # Using the host's native ``C:\...`` path as the guest path
        # would feed a non-POSIX string to the WASI layer; the
        # synthetic name sidesteps that entirely.
        applied: list[tuple[str, str]] = []
        placeholder: Optional[str] = None
        for k, pre in enumerate(ceiling.preopens):
            host_path = pre.host_path
            guest_path = f"/capa-preopen-{k}"
            if not os.path.isdir(host_path):
                if placeholder is None:
                    import tempfile
                    placeholder = tempfile.mkdtemp(prefix="capa-wasi-fs-")
                wasi_cfg.preopen_dir(
                    placeholder, guest_path,
                    wasmtime.DirPerms.READ_ONLY,
                    wasmtime.FilePerms.READ_ONLY,
                )
                applied.append((host_path, "absent"))
                continue
            if pre.read_write:
                dir_perms = wasmtime.DirPerms.READ_WRITE
                file_perms = wasmtime.FilePerms.READ_WRITE
                applied.append((host_path, "rw"))
            else:
                dir_perms = wasmtime.DirPerms.READ_ONLY
                file_perms = wasmtime.FilePerms.READ_ONLY
                applied.append((host_path, "ro"))
            wasi_cfg.preopen_dir(
                host_path, guest_path, dir_perms, file_perms,
            )
        # Layer b1: append the operator ``--preopen`` AFTER the derived
        # preopens so it never shifts a derived index (index ==
        # len(ceiling.preopens)). For an all-literal program this preopen
        # is registered + recorded but unused by the guest (no dynamic
        # call site); the grant stays honest in the SBOM regardless.
        applied += self._apply_operator_preopen(
            wasi_cfg, len(ceiling.preopens),
        )
        self._wasi_fs_applied = applied

    def _apply_operator_preopen(self, wasi_cfg, index: int):
        """Register the operator ``--preopen`` directory (layer b1) at the
        given guest preopen ``index`` and return the list of applied
        records (empty when no operator preopen was declared).

        The operator preopen is an explicit Level-2 operator grant: the
        directory is mounted READ_WRITE or READ_ONLY per its declared
        permission. A non-existent host directory is skipped (no record),
        so a dynamic path resolved against a missing preopen sees no
        descriptor at ``index`` and fails fail-closed-as-absent, matching
        the derived-ceiling convention."""
        grant = self._fs_operator_preopen
        if not grant:
            return []
        host_dir, read_write = grant[0], bool(grant[1])
        if not os.path.isdir(host_dir):
            return []
        guest_path = f"/capa-preopen-{index}"
        if read_write:
            wasi_cfg.preopen_dir(
                host_dir, guest_path,
                wasmtime.DirPerms.READ_WRITE,
                wasmtime.FilePerms.READ_WRITE,
            )
            return [(host_dir, "operator-rw")]
        wasi_cfg.preopen_dir(
            host_dir, guest_path,
            wasmtime.DirPerms.READ_ONLY,
            wasmtime.FilePerms.READ_ONLY,
        )
        return [(host_dir, "operator-ro")]

    def _register_all(self) -> None:
        root = self._linker.root()
        self._register_stdio(root)
        self._register_panic(root)
        self._register_clock(root)
        self._register_env(root)
        self._register_fs(root)
        self._register_json(root)
        self._register_random(root)
        self._register_net(root)
        self._register_db(root)
        self._register_proc(root)
        root.close()

    # ---- per-interface registration ----------------------------

    def _register_stdio(self, root: wc.LinkerInstance) -> None:
        stdio = root.add_instance("capa:host/stdio")
        # Stdio output migration (Phase 1, 2026-06-29): in --wasi the
        # guest routes print / println / eprintln to wasi:cli/stdout |
        # wasi:cli/stderr (satisfied by add_wasip2 + the WasiConfig
        # stdout_custom / stderr_custom capture callbacks installed in
        # __init__), so the capa:host/stdio print / println / eprintln
        # methods are NOT registered here in WASI mode -- the component
        # imports none of them. read_line is ALSO migrated in WASI mode
        # now (Phase 2, 2026-06-29): the guest routes it to wasi:cli/stdin
        # (get-stdin -> input-stream.blocking-read), served by add_wasip2 +
        # the WasiConfig stdin source installed in __init__, so the
        # capa:host/stdio read-line method is NOT registered here in WASI
        # mode either. Only ``panic`` stays on capa:host/panic. In the
        # DEFAULT (non-wasi) path all three writers AND read-line are
        # registered as before, forwarding to sys.stdout / sys.stderr /
        # sys.stdin.
        #
        # Stdio has no handle threading (no attenuation surface);
        # signatures stay (msg) -> () like the core host.
        # Wrap each writer in ``_write_safe`` so a non-cp1252 char on a
        # Windows console falls back to replacement instead of crashing
        # the program. Same convention applied to the Python runtime
        # and the core Wasm host so the three backends print identical
        # bytes on a terminal that cannot encode the source character.
        if not self._wasi:
            stdio.add_func(
                "print",
                lambda _store, msg: _write_safe(sys.stdout, msg),
            )
            stdio.add_func(
                "println",
                lambda _store, msg: _write_safe(sys.stdout, msg + "\n"),
            )
            stdio.add_func(
                "eprintln",
                lambda _store, msg: _write_safe(sys.stderr, msg + "\n"),
            )

        if not self._wasi:
            def stdio_read_line(_store):
                # result<string, io-error>: dispatch by Python type.
                # Return str on Ok, IoErrorRecord on Err (EOF, OS
                # error). Mirrors the Python runtime's
                # ``sys.stdin.readline().rstrip("\n")`` shape.
                try:
                    line = sys.stdin.readline()
                except OSError as e:
                    return IoErrorRecord(
                        message="read failed", cause=str(e),
                    )
                if not line:
                    return IoErrorRecord(message="end of input")
                return line.rstrip("\n")

            stdio.add_func("read-line", stdio_read_line)
        stdio.close()

    def _register_panic(self, root: wc.LinkerInstance) -> None:
        """Register the ``capa:host/panic`` interface backing the
        ``panic`` builtin. Same contract as the core host: write
        the canonical ``panic: <message>`` line to stderr (stdout
        flushed first) and return; the guest then traps via
        ``unreachable``, which surfaces as the run_main exception
        the CLI translates to a non-zero exit."""
        def do_panic(_store, msg: str) -> None:
            try:
                sys.stdout.flush()
            except Exception:
                pass
            _write_safe(sys.stderr, "panic: " + msg + "\n")
            sys.stderr.flush()
            self.panicked = True

        panic_ifc = root.add_instance("capa:host/panic")
        panic_ifc.add_func("panic", do_panic)
        panic_ifc.close()

    # ---- handle-lookup helpers ---------------------------------

    def _lookup_or(self, handle: int, expected_cls, default=None):
        """Resolve ``handle`` in the local cap table, returning
        ``default`` (``None``) on any failure. The core host has
        per-cap variants; the CM host uses one shared helper because
        the indirect-return canonical-ABI plumbing isn't needed
        here (errors are surfaced through Python type dispatch)."""
        try:
            return self._cap_handles.lookup(handle, expected_cls)
        except CapHandleError:
            return default

    def _register_clock(self, root: wc.LinkerInstance) -> None:
        """Register the ``capa:host/clock`` interface.

        Slice 25.8 (2026-05-30): every op takes ``handle: u32``
        first, mirroring the core host. ``now-secs`` /
        ``now-monotonic`` are pure queries (anyone with a wall
        clock can read it); ``sleep`` and ``allows`` enforce the
        looked-up cap's ``allows()`` deadline.
        ``restrict-to-after(parent, t) -> u32`` allocates a fresh
        child handle with the max-merged deadline."""
        clock = root.add_instance("capa:host/clock")
        import time

        def now_secs(_store, handle: int) -> float:
            # Cap looked up for wire uniformity; the now_* family
            # is a pure query that ignores the cap's deadline.
            self._lookup_or(handle, Clock)
            return time.time()

        def now_monotonic(_store, handle: int) -> float:
            self._lookup_or(handle, Clock)
            return time.monotonic()

        def clock_sleep(_store, handle: int, secs: float):
            clock_cap = self._lookup_or(handle, Clock)
            if clock_cap is None or not clock_cap.allows():
                return None
            if secs < 0:
                return None
            time.sleep(secs)
            return None

        def clock_allows(_store, handle: int) -> bool:
            clock_cap = self._lookup_or(handle, Clock)
            if clock_cap is None:
                return False
            return bool(clock_cap.allows())

        def clock_restrict_to_after(_store, parent: int, t: float) -> int:
            try:
                return self._cap_handles.restrict_clock_after(parent, t)
            except CapHandleError:
                return 0

        clock.add_func("now-secs",          now_secs)
        clock.add_func("now-monotonic",     now_monotonic)
        clock.add_func("sleep",             clock_sleep)
        clock.add_func("allows",            clock_allows)
        clock.add_func("restrict-to-after", clock_restrict_to_after)
        clock.close()

    def _register_env(self, root: wc.LinkerInstance) -> None:
        """Register the ``capa:host/env`` interface.

        Slice 25.8 (2026-05-30): every op takes ``handle: u32`` first
        and routes through the looked-up Env cap, which enforces
        ``env.allows(name)`` before reading ``os.environ`` (same
        contract as the core host).

        Audit M1 (2026-05): an unrestricted Env cap leaks the full
        host environment to the guest; the attenuation system is the
        trust boundary. See ``_wasm_host.py``'s ``_register_env``
        docstring for the full discussion."""
        env_ifc = root.add_instance("capa:host/env")

        def env_args(_store, handle: int):
            # Cap looked up for wire uniformity; args themselves
            # don't depend on the cap's allow-list (matches the
            # Python runtime's Env.args()).
            self._lookup_or(handle, Env)
            return list(self._args)

        def env_get(_store, handle: int, name: str):
            env_cap = self._lookup_or(handle, Env)
            if env_cap is None or not env_cap.allows(name):
                # Denied / bad handle: looks identical to an unset
                # key. Matches the Python runtime's fail-closed
                # information-hiding policy.
                return None
            return os.environ.get(name)

        def env_restrict_to_keys(_store, parent: int, keys):
            try:
                return self._cap_handles.restrict_env(parent, list(keys))
            except CapHandleError:
                return 0

        def env_allows(_store, handle: int, key: str) -> bool:
            # GAP-2b (2026-06-21): authoritative ``env.allows(key)``
            # query, mirroring the core host. A dynamic
            # restrict_to_keys list now answers correctly (the old
            # guest-side inline check diverged silently to ``no``).
            env_cap = self._lookup_or(handle, Env)
            if env_cap is None:
                return False
            return bool(env_cap.allows(key))

        env_ifc.add_func("args",             env_args)
        env_ifc.add_func("get",              env_get)
        env_ifc.add_func("restrict-to-keys", env_restrict_to_keys)
        env_ifc.add_func("allows",           env_allows)
        env_ifc.close()

    def _register_fs(self, root: wc.LinkerInstance) -> None:
        """Register the ``capa:host/fs`` interface.

        Slice 25.8 (2026-05-30): every op takes ``handle: u32`` first
        and routes through the looked-up Fs cap, which enforces
        ``fs.allows(path)`` before the syscall. ``restrict-to``
        allocates a fresh child handle bound to the narrower prefix
        (intersection with the parent). Closes the cross-function
        attenuation gap (audit slice 25 F1) on the CM path."""
        fs_ifc = root.add_instance("capa:host/fs")

        def fs_read(_store, handle: int, path: str):
            # result<string, io-error>: untagged, dispatch by
            # Python type. Return a str on success, an
            # IoErrorRecord on failure.
            fs = self._lookup_or(handle, Fs)
            if fs is None:
                return IoErrorRecord(
                    message="invalid Fs capability handle",
                    cause=str(handle),
                )
            if not fs.allows(path):
                return _deny_record(fs._deny("read", path))
            # TOCTOU hardening (2026-06-10): same shared Fs._open_read
            # as the Python backend and the core-Wasm host; on a
            # restricted cap the open handle's true path is
            # re-validated before any byte is read.
            try:
                with fs._open_read(path) as f:
                    return f.read()
            except PostOpenDenied:
                return _deny_record(fs._deny("read", path))
            except OSError as e:
                return IoErrorRecord(
                    message=f"failed to read {path!r}", cause=str(e),
                )

        def fs_write(_store, handle: int, path: str, content: str):
            # result<_, io-error>: Ok carries unit -> return None;
            # Err carries io-error -> return IoErrorRecord.
            fs = self._lookup_or(handle, Fs)
            if fs is None:
                return IoErrorRecord(
                    message="invalid Fs capability handle",
                    cause=str(handle),
                )
            if not fs.allows(path):
                return _deny_record(fs._deny("write", path))
            # TOCTOU hardening: no truncation until the handle's true
            # path passes verification (shared Fs._open_write).
            try:
                with fs._open_write(path) as f:
                    f.write(content)
                return None
            except PostOpenDenied:
                return _deny_record(fs._deny("write", path))
            except OSError as e:
                return IoErrorRecord(
                    message=f"failed to write {path!r}", cause=str(e),
                )

        def fs_restrict_to(_store, parent: int, prefix: str) -> int:
            try:
                return self._cap_handles.restrict_fs(parent, prefix)
            except CapHandleError:
                return 0

        def fs_exists(_store, handle: int, path: str) -> bool:
            fs = self._lookup_or(handle, Fs)
            if fs is None or not fs.allows(path):
                return False
            return os.path.exists(path)

        def fs_is_dir(_store, handle: int, path: str) -> bool:
            fs = self._lookup_or(handle, Fs)
            if fs is None or not fs.allows(path):
                return False
            return os.path.isdir(path)

        def fs_mkdir(_store, handle: int, path: str):
            fs = self._lookup_or(handle, Fs)
            if fs is None:
                return IoErrorRecord(
                    message="invalid Fs capability handle",
                    cause=str(handle),
                )
            if not fs.allows(path):
                return _deny_record(fs._deny("mkdir", path))
            try:
                os.makedirs(path, exist_ok=True)
                return None
            except OSError as e:
                return IoErrorRecord(
                    message=f"failed to mkdir {path!r}", cause=str(e),
                )

        def fs_list_dir(_store, handle: int, path: str):
            # result<list<string>, io-error>: dispatch by Python type.
            # Return a list[str] on Ok (sorted to match the Python
            # runtime), IoErrorRecord on Err.
            fs = self._lookup_or(handle, Fs)
            if fs is None:
                return IoErrorRecord(
                    message="invalid Fs capability handle",
                    cause=str(handle),
                )
            if not fs.allows(path):
                return _deny_record(fs._deny("list_dir", path))
            try:
                return sorted(os.listdir(path))
            except OSError as e:
                return IoErrorRecord(
                    message=f"failed to list {path!r}", cause=str(e),
                )

        def fs_allows(_store, handle: int, path: str) -> bool:
            # GAP-2b (2026-06-21): authoritative ``fs.allows(path)``
            # query (realpath prefix containment) - same method the
            # privileged ops enforce, so query == enforcement.
            fs = self._lookup_or(handle, Fs)
            if fs is None:
                return False
            return bool(fs.allows(path))

        fs_ifc.add_func("read",         fs_read)
        fs_ifc.add_func("write",        fs_write)
        fs_ifc.add_func("restrict-to",  fs_restrict_to)
        fs_ifc.add_func("exists",       fs_exists)
        fs_ifc.add_func("is-dir",       fs_is_dir)
        fs_ifc.add_func("mkdir",        fs_mkdir)
        fs_ifc.add_func("list-dir",     fs_list_dir)
        fs_ifc.add_func("allows",       fs_allows)
        fs_ifc.close()

    def _register_random(self, root: wc.LinkerInstance) -> None:
        """Register the ``capa:host/random`` interface.

        Only ``system-seed`` crosses the boundary, returning 8 bytes
        of OS entropy as a u64 the guest uses to lazy-init its
        SplitMix64 state on an unseeded ``Random()``. Mirrors the
        core-host bridge byte-for-byte so seeded sequences are
        identical between ``--wasm --run`` and
        ``--wasm --component --run``."""
        random_ifc = root.add_instance("capa:host/random")
        random_ifc.add_func(
            "system-seed",
            lambda _store: int.from_bytes(
                os.urandom(8), "little", signed=False,
            ),
        )
        random_ifc.close()

    def _register_net(self, root: wc.LinkerInstance) -> None:
        """Register the ``capa:host/net`` interface.

        Slice 25.8 (2026-05-30): every op takes ``handle: u32`` first
        and routes through the looked-up Net cap. The Net class's
        own ``get`` / ``post`` methods do the
        ``urlparse(url).hostname`` + ``allows()`` check (which also
        fixes the audit slice 25 F2 substring-attack bug for free),
        so we delegate to them and surface the resulting Ok/Err."""
        net_ifc = root.add_instance("capa:host/net")

        def net_get(_store, handle: int, url: str):
            net = self._lookup_or(handle, Net)
            if net is None:
                return IoErrorRecord(
                    message="invalid Net capability handle",
                    cause=str(handle),
                )
            result = net.get(url)
            if isinstance(result, Ok):
                return result.value
            err = result.error
            return IoErrorRecord(
                message=getattr(err, "message", str(err)),
                cause=getattr(err, "cause", ""),
            )

        def net_post(_store, handle: int, url: str, body: str):
            net = self._lookup_or(handle, Net)
            if net is None:
                return IoErrorRecord(
                    message="invalid Net capability handle",
                    cause=str(handle),
                )
            result = net.post(url, body)
            if isinstance(result, Ok):
                return result.value
            err = result.error
            return IoErrorRecord(
                message=getattr(err, "message", str(err)),
                cause=getattr(err, "cause", ""),
            )

        def net_restrict_to(_store, parent: int, host: str) -> int:
            try:
                return self._cap_handles.restrict_net(parent, host)
            except CapHandleError:
                return 0

        def net_allows(_store, handle: int, host: str) -> bool:
            # GAP-2b (2026-06-21): authoritative ``net.allows(host)``
            # query (exact host-set membership).
            net = self._lookup_or(handle, Net)
            if net is None:
                return False
            return bool(net.allows(host))

        net_ifc.add_func("get",         net_get)
        net_ifc.add_func("post",        net_post)
        net_ifc.add_func("restrict-to", net_restrict_to)
        net_ifc.add_func("allows",      net_allows)
        net_ifc.close()

    def _register_db(self, root: wc.LinkerInstance) -> None:
        """Register the ``capa:host/db`` interface (slice 11).

        Slice 25.8 (2026-05-30): every op takes ``handle: u32`` first
        and routes through the looked-up Db cap, which enforces
        ``db.allows(path)`` before opening the SQLite connection.
        Mirrors the core host's exec / query / restrict-to. The
        result wire shape stays a JSON-encoded
        ``[[col, col, ...], ...]`` string with every cell
        stringified."""
        import sqlite3
        db_ifc = root.add_instance("capa:host/db")

        from ._fs_guard import PostOpenDenied

        def db_exec(_store, handle: int, path: str, sql: str):
            db = self._lookup_or(handle, Db)
            if db is None:
                return IoErrorRecord(
                    message="invalid Db capability handle",
                    cause=str(handle),
                )
            if not db.allows(path):
                return _deny_record(db._deny(path, "exec"))
            try:
                # _connect_verified applies the post-open symlink-swap
                # guard (audit 2026-06-17) and installs the
                # ATTACH/DETACH authorizer; the Component Model backend
                # closes the same TOCTOU window as the Python runtime.
                conn = db._connect_verified(path)
                try:
                    conn.executescript(sql)
                    conn.commit()
                finally:
                    conn.close()
                return None
            except PostOpenDenied:
                return _deny_record(db._deny(path, "exec"))
            except (sqlite3.Error, OSError, ValueError) as e:
                return IoErrorRecord(
                    message="SQLite exec failed", cause=str(e),
                )

        def db_query(_store, handle: int, path: str, sql: str):
            db = self._lookup_or(handle, Db)
            if db is None:
                return IoErrorRecord(
                    message="invalid Db capability handle",
                    cause=str(handle),
                )
            if not db.allows(path):
                return _deny_record(db._deny(path, "query"))
            try:
                conn = db._connect_verified(path)
                try:
                    cur = conn.execute(sql)
                    rows = cur.fetchall()
                finally:
                    conn.close()
                stringified = [
                    [
                        "null" if v is None else
                        v if isinstance(v, str) else str(v)
                        for v in row
                    ]
                    for row in rows
                ]
                return _stdlib_json.dumps(stringified)
            except PostOpenDenied:
                return _deny_record(db._deny(path, "query"))
            except (sqlite3.Error, OSError, ValueError) as e:
                return IoErrorRecord(
                    message="SQLite query failed", cause=str(e),
                )

        def db_restrict_to(_store, parent: int, prefix: str) -> int:
            try:
                return self._cap_handles.restrict_db(parent, prefix)
            except CapHandleError:
                return 0

        def db_allows(_store, handle: int, path: str) -> bool:
            # GAP-2b (2026-06-21): authoritative ``db.allows(path)``
            # query (realpath prefix containment, same as Fs.allows).
            db = self._lookup_or(handle, Db)
            if db is None:
                return False
            return bool(db.allows(path))

        db_ifc.add_func("exec",        db_exec)
        db_ifc.add_func("query",       db_query)
        db_ifc.add_func("restrict-to", db_restrict_to)
        db_ifc.add_func("allows",      db_allows)
        db_ifc.close()

    def _register_proc(self, root: wc.LinkerInstance) -> None:
        """Register the ``capa:host/proc`` interface (slice 15).

        Slice 25.8 (2026-05-30): every op takes ``handle: u32`` first
        and routes through the looked-up Proc cap, which enforces
        ``proc.allows(cmd)`` (basename + suffix-boundary) before
        spawning the subprocess. Mirrors the core host exactly."""
        import json as _stdlib_json_proc
        import subprocess
        proc_ifc = root.add_instance("capa:host/proc")

        def proc_exec(_store, handle: int, cmd: str, args_json: str):
            proc = self._lookup_or(handle, Proc)
            if proc is None:
                return IoErrorRecord(
                    message="invalid Proc capability handle",
                    cause=str(handle),
                )
            if not proc.allows(cmd):
                return _deny_record(proc._deny(cmd))
            try:
                tail = _stdlib_json_proc.loads(args_json)
            except (ValueError, TypeError) as e:
                return IoErrorRecord(
                    message="Proc.exec args_json parse failed",
                    cause=str(e),
                )
            if not isinstance(tail, list) or not all(
                    isinstance(x, str) for x in tail):
                return IoErrorRecord(
                    message="Proc.exec args_json parse failed",
                    cause="expected a JSON array of strings",
                )
            argv = [cmd, *tail]
            try:
                completed = subprocess.run(
                    argv,
                    capture_output=True,
                    timeout=30,
                    shell=False,
                )
            except subprocess.TimeoutExpired:
                return IoErrorRecord(
                    message="timed out", cause="30s elapsed",
                )
            except (OSError, ValueError) as e:
                return IoErrorRecord(
                    message="Proc.exec spawn failed", cause=str(e),
                )
            if completed.returncode != 0:
                stderr = completed.stderr.decode("utf-8", errors="replace")
                return IoErrorRecord(
                    message="non-zero exit",
                    cause=f"code={completed.returncode} stderr={stderr!r}",
                )
            return completed.stdout.decode("utf-8", errors="replace")

        def proc_restrict_to(_store, parent: int, prefix: str) -> int:
            try:
                return self._cap_handles.restrict_proc(parent, prefix)
            except CapHandleError:
                return 0

        def proc_allows(_store, handle: int, cmd: str) -> bool:
            # GAP-2b (2026-06-21): authoritative ``proc.allows(cmd)``
            # query (identity basename + suffix-boundary rule).
            proc = self._lookup_or(handle, Proc)
            if proc is None:
                return False
            return bool(proc.allows(cmd))

        proc_ifc.add_func("exec",        proc_exec)
        proc_ifc.add_func("restrict-to", proc_restrict_to)
        proc_ifc.add_func("allows",      proc_allows)
        proc_ifc.close()

    def _register_json(self, root: wc.LinkerInstance) -> None:
        json_ifc = root.add_instance("capa:host/json")

        # JsonValue crosses the boundary as an opaque u32 handle:
        # the host owns a side table mapping u32 -> Python value
        # so to-string can recover the value parse handed back.
        # In the core-wasm path the handle is a real linear-memory
        # pointer; here it stays Python-side because lifted host
        # functions never see the component's memory.
        self._jv_table: dict[int, Any] = {}
        self._jv_next_id = 1

        def alloc_handle(py_val: Any) -> int:
            nonlocal_id = self._jv_next_id
            self._jv_table[nonlocal_id] = py_val
            self._jv_next_id += 1
            return nonlocal_id

        def json_parse(_store, s: str):
            # result<u32, string>: untagged (int vs str). Return
            # int for Ok, str for Err.
            try:
                return alloc_handle(_stdlib_json.loads(s))
            except (ValueError, _stdlib_json.JSONDecodeError) as e:
                return str(e)

        def json_to_string(_store, jv: int):
            return _stdlib_json.dumps(self._jv_table[jv])

        json_ifc.add_func("parse",     json_parse)
        json_ifc.add_func("to-string", json_to_string)
        json_ifc.close()

    # ---- public surface ----------------------------------------

    def _bootstrap_root_handles(self) -> dict[str, int]:
        """Lazy-allocate the root caps the host will hand to
        ``main``. Returns a name -> handle dict (lowercase cap-name
        keyed: ``fs`` / ``net`` / ``db`` / ``proc`` / ``env`` /
        ``clock`` / ``stdio``). Mirrors ``WasmHost.run_main``'s
        block of the same name so re-running the program reuses
        the same handle table entries."""
        if self._root_fs is None:
            self._root_fs = Fs()
        if self._root_net is None:
            self._root_net = Net()
        if self._root_db is None:
            self._root_db = Db()
        if self._root_proc is None:
            self._root_proc = Proc()
        if self._root_env is None:
            self._root_env = Env()
        if self._root_clock is None:
            self._root_clock = Clock()
        if self._root_stdio is None:
            self._root_stdio = Stdio()
        return bootstrap_root_handles(
            self._cap_handles,
            fs=self._root_fs,
            net=self._root_net,
            db=self._root_db,
            proc=self._root_proc,
            env=self._root_env,
            clock=self._root_clock,
            stdio=self._root_stdio,
        )

    def run_main(self, wasm_blob_or_path) -> None:
        """Load a Component artifact (bytes or filesystem path)
        and dispatch to the world's ``main`` export.

        Slice 25.8 (2026-05-30): inspect ``main``'s component
        function type to see which handle-bearing cap slots it
        declares, then pass the matching root handle for each.
        The WIT generator (``_emit_wit._main_handle_param_names``)
        emits the param names in source-level order with the
        lowercase cap-kind (``fs`` / ``net`` / ...); we map by
        name to the root-handle dict so out-of-order param lists
        thread the right cap to each slot. Pure ``fun main()``
        programs (no handle-bearing cap params) keep the trivial
        zero-arg dispatch."""
        # Clear the per-host panic latch at the start of every run so
        # a host reused across programs cannot let a deliberate panic
        # from one run silence a genuine trap in the next.
        self.panicked = False
        if isinstance(wasm_blob_or_path, (bytes, bytearray)):
            # wasmtime.Component has no from_bytes; round-trip
            # through a temp file so the same surface as
            # ``WasmHost.run_main`` works.
            import tempfile
            with tempfile.NamedTemporaryFile(
                suffix=".wasm", delete=False,
            ) as tmp:
                tmp.write(bytes(wasm_blob_or_path))
                tmp_path = tmp.name
            try:
                component = wc.Component.from_file(self._engine, tmp_path)
            finally:
                os.unlink(tmp_path)
        else:
            component = wc.Component.from_file(
                self._engine, str(wasm_blob_or_path),
            )
        instance = self._linker.instantiate(self._store, component)
        main = instance.get_func(self._store, "main")
        if main is None:
            raise RuntimeError(
                "component has no exported `main` function; "
                "the WIT world must declare ``export main: func(...);``"
            )
        # Inspect main's signature: ``params`` returns a list of
        # (name, ValType) tuples lifted from the component's WIT
        # world. The WIT generator names each handle slot by its
        # source-level cap-kind (``fs`` / ``net`` / ...), so we
        # map each declared slot to the matching root handle.
        # Unknown slot names fall back to the Fs root (defensive;
        # an analyzer-mismatched signature would already have been
        # rejected long before this point).
        ftype = main.type(self._store)
        params = ftype.params
        if not params:
            main(self._store)
            return
        roots = self._bootstrap_root_handles()
        # WIT-side names are kebab-case (``my-fs``); on the source
        # side a user could conceivably write ``fun main(my_fs:
        # Fs)``. The emitter rewrites ``_`` -> ``-`` on the way
        # out; we don't bother reversing because our examples
        # use plain ``fs`` / ``net`` / ... names. Match strictly
        # against the lowercase cap-kind keys.
        name_to_root: dict[str, int] = {
            "fs": roots.get("fs", 0),
            "net": roots.get("net", 0),
            "db": roots.get("db", 0),
            "proc": roots.get("proc", 0),
            "env": roots.get("env", 0),
            "clock": roots.get("clock", 0),
        }
        # WASI mode: Env attenuation is enforced GUEST-SIDE (Level 2 of
        # docs/design/wasi-attenuation.md). The guest reinterprets the
        # Env i32 value as 0 = unrestricted root, or a pointer to a
        # linear-memory allow-list produced by ``restrict_to_keys``.
        # The host therefore passes 0 (the unrestricted sentinel) for
        # the Env root rather than a capa:host handle-table handle,
        # which has no meaning on the wasi:cli/environment path. The
        # other handle-bearing caps (Fs / Net / Db / Proc / Clock) keep
        # their capa:host table handles in this hybrid mode.
        if self._wasi:
            name_to_root["env"] = 0
            # WASI Fs (2026-06-27): Fs metadata is enforced by the host
            # PREOPENS, not the capa:host handle table. The Fs i32 param
            # on ``main`` is vestigial in this mode (the guest metadata
            # wrappers address preopens by compile-time index, never the
            # receiver handle), so pass the 0 sentinel rather than a
            # capa:host table handle, matching the Env treatment.
            name_to_root["fs"] = 0
            # WASI Net (2026-06-28, Phase 1): Net.get is served by
            # wasi:http and gated GUEST-SIDE against the static ceiling
            # (codegen), not the capa:host handle table. The Net i32 param
            # on ``main`` is vestigial in this mode (the $Net_get wrapper
            # never consults the receiver handle for the ceiling), so pass
            # the 0 sentinel rather than a capa:host table handle, matching
            # the Env / Fs treatment.
            name_to_root["net"] = 0
        handle_args: list[int] = []
        for name, _vtype in params:
            handle_args.append(name_to_root.get(name, roots.get("fs", 0)))
        main(self._store, *handle_args)
