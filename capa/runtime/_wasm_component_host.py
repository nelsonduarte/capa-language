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

from ._capabilities import _write_safe


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
    and dispatches to the world's ``run`` export."""

    def __init__(self, args: Iterable[str] = ()):
        self._args = list(args)
        self._engine = wasmtime.Engine()
        self._store = wasmtime.Store(self._engine)
        self._linker = wc.Linker(self._engine)
        self._register_all()

    def _register_all(self) -> None:
        root = self._linker.root()
        self._register_stdio(root)
        self._register_clock(root)
        self._register_env(root)
        self._register_fs(root)
        self._register_json(root)
        self._register_random(root)
        self._register_net(root)
        self._register_db(root)
        root.close()

    # ---- per-interface registration ----------------------------

    def _register_stdio(self, root: wc.LinkerInstance) -> None:
        stdio = root.add_instance("capa:host/stdio")
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

    def _register_clock(self, root: wc.LinkerInstance) -> None:
        clock = root.add_instance("capa:host/clock")
        import time
        clock.add_func("now-secs",      lambda _store: time.time())
        clock.add_func("now-monotonic", lambda _store: time.monotonic())

        def clock_sleep(_store, secs: float):
            # Guard against negative durations same as the core
            # host (``time.sleep`` raises ValueError otherwise).
            if secs < 0:
                return None
            time.sleep(secs)
            return None

        def clock_allows(_store):
            # Wasm caps carry no ``not_before`` state at this layer;
            # mirror the unrestricted Python case (always true).
            return True

        clock.add_func("sleep",  clock_sleep)
        clock.add_func("allows", clock_allows)
        clock.close()

    def _register_env(self, root: wc.LinkerInstance) -> None:
        # Audit M1 (2026-05): leak-by-default. ``os.environ.get`` is
        # unfiltered on the host, so an unrestricted Env cap held by
        # the guest sees every host env var (including secrets).
        # Attenuation via ``env.restrict_to_keys([...])`` is enforced
        # inline by the Wasm emitter (audit C2) for literal allow-
        # lists; unrestricted caps still pass through. See
        # ``_wasm_host.py`` and ``capa.runtime._capabilities.Env``
        # for the full discussion.
        env = root.add_instance("capa:host/env")
        env.add_func("args", lambda _store: list(self._args))
        env.add_func(
            "get",
            lambda _store, name: os.environ.get(name),  # None -> WIT none
        )
        env.close()

    def _register_fs(self, root: wc.LinkerInstance) -> None:
        fs = root.add_instance("capa:host/fs")

        def fs_read(_store, path: str):
            # result<string, io-error>: untagged, dispatch by
            # Python type. Return a str on success, an
            # IoErrorRecord on failure.
            try:
                with open(path, encoding="utf-8") as f:
                    return f.read()
            except OSError as e:
                return IoErrorRecord(
                    message=str(e), cause=type(e).__name__,
                )

        def fs_write(_store, path: str, content: str):
            # result<_, io-error>: Ok carries unit -> return None;
            # Err carries io-error -> return IoErrorRecord.
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(content)
                return None
            except OSError as e:
                return IoErrorRecord(
                    message=str(e), cause=type(e).__name__,
                )

        def fs_restrict_to(_store, _prefix: str):
            # No-op at the Wasm/Component level. The analyzer's
            # static capability discipline is what enforces it;
            # the runtime accepts the call so attenuation chains
            # do not trap.
            return None

        def fs_exists(_store, path: str) -> bool:
            return os.path.exists(path)

        def fs_is_dir(_store, path: str) -> bool:
            return os.path.isdir(path)

        def fs_mkdir(_store, path: str):
            try:
                os.makedirs(path, exist_ok=True)
                return None
            except OSError as e:
                return IoErrorRecord(
                    message=str(e), cause=type(e).__name__,
                )

        def fs_list_dir(_store, path: str):
            # result<list<string>, io-error>: dispatch by Python type.
            # Return a list[str] on Ok (sorted to match the Python
            # runtime), IoErrorRecord on Err.
            try:
                return sorted(os.listdir(path))
            except OSError as e:
                return IoErrorRecord(
                    message=str(e), cause=type(e).__name__,
                )

        fs.add_func("read",         fs_read)
        fs.add_func("write",        fs_write)
        fs.add_func("restrict-to",  fs_restrict_to)
        fs.add_func("exists",       fs_exists)
        fs.add_func("is-dir",       fs_is_dir)
        fs.add_func("mkdir",        fs_mkdir)
        fs.add_func("list-dir",     fs_list_dir)
        fs.close()

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

        Mirrors the core-host bridge byte-for-byte: ``Net.get`` /
        ``Net.post`` run through ``urllib.request.urlopen`` with a
        10-second timeout and decode the body UTF-8 with
        ``errors="replace"`` for non-UTF-8 responses. Failures
        (URLError, OSError, ValueError) return an
        ``IoErrorRecord`` so the component-side
        ``result<string, io-error>`` lowers to Err with the same
        message shape the core host produces. ``net.restrict-to``
        is a no-op like ``fs.restrict-to``."""
        from urllib.request import Request, urlopen
        from urllib.error import URLError
        net_ifc = root.add_instance("capa:host/net")

        def net_get(_store, url: str):
            try:
                with urlopen(Request(url), timeout=10) as resp:
                    return resp.read().decode("utf-8", errors="replace")
            except (URLError, OSError, ValueError) as e:
                return IoErrorRecord(
                    message="HTTP GET failed", cause=str(e),
                )

        def net_post(_store, url: str, body: str):
            try:
                req = Request(
                    url, data=body.encode("utf-8"),
                    headers={"Content-Type": "application/octet-stream"},
                )
                with urlopen(req, timeout=10) as resp:
                    return resp.read().decode("utf-8", errors="replace")
            except (URLError, OSError, ValueError) as e:
                return IoErrorRecord(
                    message="HTTP POST failed", cause=str(e),
                )

        def net_restrict_to(_store, _host: str):
            return None

        net_ifc.add_func("get",         net_get)
        net_ifc.add_func("post",        net_post)
        net_ifc.add_func("restrict-to", net_restrict_to)
        net_ifc.close()

    def _register_db(self, root: wc.LinkerInstance) -> None:
        """Register the ``capa:host/db`` interface (slice 11).

        Mirrors the core-host bridge byte-for-byte: both ``exec``
        and ``query`` open a fresh ``sqlite3.connect`` per call;
        ``query`` returns a JSON-encoded ``[[col, col, ...], ...]``
        string with every cell stringified, so the cross-backend
        wire format stays a single shape. ``db.restrict-to`` is a
        no-op like ``fs.restrict-to``."""
        import sqlite3
        db_ifc = root.add_instance("capa:host/db")

        from ._capabilities import _install_sqlite_authorizer

        def db_exec(_store, path: str, sql: str):
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

        def db_query(_store, path: str, sql: str):
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

        def db_restrict_to(_store, _prefix: str):
            return None

        db_ifc.add_func("exec",        db_exec)
        db_ifc.add_func("query",       db_query)
        db_ifc.add_func("restrict-to", db_restrict_to)
        db_ifc.close()

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

    def run_main(self, wasm_blob_or_path) -> None:
        """Load a Component artifact (bytes or filesystem path)
        and dispatch to the world's ``run`` export. Traps and
        exceptions inside the component bubble up unchanged."""
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
                "the WIT world must declare ``export main: func();``"
            )
        main(self._store)
