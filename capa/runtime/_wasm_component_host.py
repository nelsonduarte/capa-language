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


class WasmComponentHost:
    """Wraps a Component Model ``.wasm`` artifact in a wasmtime
    linker pre-populated with Capa's ``capa:host/*`` interfaces.

    Construction takes the program ``argv`` (visible to the
    component via ``Env.args()``); ``run_main`` instantiates
    and dispatches to the world's ``main`` export with the right
    root capability handle threaded into each declared cap slot."""

    def __init__(self, args: Iterable[str] = ()):
        self._args = list(args)
        self._engine = wasmtime.Engine()
        self._store = wasmtime.Store(self._engine)
        self._linker = wc.Linker(self._engine)
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
        # Stdio has no handle threading (no attenuation surface);
        # signatures stay (msg) -> () like the core host.
        # Wrap each writer in ``_write_safe`` so a non-cp1252 char on a
        # Windows console falls back to replacement instead of crashing
        # the program. Same convention applied to the Python runtime
        # and the core Wasm host so the three backends print identical
        # bytes on a terminal that cannot encode the source character.
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

        env_ifc.add_func("args",             env_args)
        env_ifc.add_func("get",              env_get)
        env_ifc.add_func("restrict-to-keys", env_restrict_to_keys)
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
                return IoErrorRecord(
                    message=f"Fs capability does not permit read: {path}",
                )
            # TOCTOU hardening (2026-06-10): same shared Fs._open_read
            # as the Python backend and the core-Wasm host; on a
            # restricted cap the open handle's true path is
            # re-validated before any byte is read.
            try:
                with fs._open_read(path) as f:
                    return f.read()
            except PostOpenDenied:
                return IoErrorRecord(
                    message=f"Fs capability does not permit read: {path}",
                )
            except OSError as e:
                return IoErrorRecord(
                    message=str(e), cause=type(e).__name__,
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
                return IoErrorRecord(
                    message=f"Fs capability does not permit write: {path}",
                )
            # TOCTOU hardening: no truncation until the handle's true
            # path passes verification (shared Fs._open_write).
            try:
                with fs._open_write(path) as f:
                    f.write(content)
                return None
            except PostOpenDenied:
                return IoErrorRecord(
                    message=f"Fs capability does not permit write: {path}",
                )
            except OSError as e:
                return IoErrorRecord(
                    message=str(e), cause=type(e).__name__,
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
                return IoErrorRecord(
                    message=f"Fs capability does not permit mkdir: {path}",
                )
            try:
                os.makedirs(path, exist_ok=True)
                return None
            except OSError as e:
                return IoErrorRecord(
                    message=str(e), cause=type(e).__name__,
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
                return IoErrorRecord(
                    message=f"Fs capability does not permit list_dir: {path}",
                )
            try:
                return sorted(os.listdir(path))
            except OSError as e:
                return IoErrorRecord(
                    message=str(e), cause=type(e).__name__,
                )

        fs_ifc.add_func("read",         fs_read)
        fs_ifc.add_func("write",        fs_write)
        fs_ifc.add_func("restrict-to",  fs_restrict_to)
        fs_ifc.add_func("exists",       fs_exists)
        fs_ifc.add_func("is-dir",       fs_is_dir)
        fs_ifc.add_func("mkdir",        fs_mkdir)
        fs_ifc.add_func("list-dir",     fs_list_dir)
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

        net_ifc.add_func("get",         net_get)
        net_ifc.add_func("post",        net_post)
        net_ifc.add_func("restrict-to", net_restrict_to)
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

        from ._capabilities import _install_sqlite_authorizer

        def db_exec(_store, handle: int, path: str, sql: str):
            db = self._lookup_or(handle, Db)
            if db is None:
                return IoErrorRecord(
                    message="invalid Db capability handle",
                    cause=str(handle),
                )
            if not db.allows(path):
                return IoErrorRecord(
                    message=f"Db capability does not permit exec: {path}",
                )
            try:
                conn = sqlite3.connect(path)
                _install_sqlite_authorizer(conn)
                try:
                    conn.executescript(sql)
                    conn.commit()
                finally:
                    conn.close()
                return None
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
                return IoErrorRecord(
                    message=f"Db capability does not permit query: {path}",
                )
            try:
                conn = sqlite3.connect(path)
                _install_sqlite_authorizer(conn)
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
            except (sqlite3.Error, OSError, ValueError) as e:
                return IoErrorRecord(
                    message="SQLite query failed", cause=str(e),
                )

        def db_restrict_to(_store, parent: int, prefix: str) -> int:
            try:
                return self._cap_handles.restrict_db(parent, prefix)
            except CapHandleError:
                return 0

        db_ifc.add_func("exec",        db_exec)
        db_ifc.add_func("query",       db_query)
        db_ifc.add_func("restrict-to", db_restrict_to)
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
                return IoErrorRecord(
                    message=f"Proc capability does not permit exec: {cmd}",
                )
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

        proc_ifc.add_func("exec",        proc_exec)
        proc_ifc.add_func("restrict-to", proc_restrict_to)
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
        handle_args: list[int] = []
        for name, _vtype in params:
            handle_args.append(name_to_root.get(name, roots.get("fs", 0)))
        main(self._store, *handle_args)
