"""Sandboxed dispatch of a typed foreign-component call (feature #4,
F2a) -- the runtime teeth that make the declared capability bound SOUND.

When a Capa program on the Wasm backend invokes ``Bureau.submit(net, x)``
the parent core module calls a host import (``capa:foreign/Bureau`` /
``submit``). :class:`capa.runtime._wasm_host.WasmHost` routes that import
here. This module:

1. INSTANTIATES the external child ``.wasm`` component with a RESTRICTED
   Component-Model linker that registers ONLY the ``capa:host/<cap>``
   interfaces for the capabilities the call GRANTS (its declared
   capability params). A child that imports any other ``capa:host/<cap>``
   interface fails at ``instantiate`` -- a host-enforced STRUCTURAL deny
   of the capability SET, not a call-time check. This is the core
   sandbox win: "the types say at most {Net}, and the runtime physically
   permits at most {Net}".

2. BINDS each granted interface's host closures to the caller's
   PRE-ATTENUATED cap value, captured in the closure. The closures
   IGNORE any guest-supplied handle, so the child holds NO
   authority-bearing value it could forge or widen (the spike proved the
   handle-passing variant was forgeable to root; this host-bound variant
   is not). The child gets exactly the caller's attenuated authority and
   can never exceed it.

The child runs in its OWN fresh store; scalar arguments and the scalar
result marshal through this Python closure (Int/Bool/Float), so no
cross-store value lifting is needed (that trampoline is only required
for aggregate crossing types -- feature #4 F2b). The ABI contract a
foreign component must conform to is: capabilities arrive as
``capa:host/<cap>`` IMPORTS (with the canonical Capa signatures), and the
callable method is EXPORTED taking only the scalar params. See
``docs/design/typed-ffi-abi.md``.
"""

from __future__ import annotations

import json as _stdlib_json
import os
from typing import Any

import wasmtime
import wasmtime.component as wc

from ._capabilities import Clock, Db, Env, Fs, Net, Proc, Random, Stdio, _write_safe
from ._fs_guard import PostOpenDenied
from ._result import Ok
from ._wasm_component_host import IoErrorRecord


class ForeignDenied(RuntimeError):
    """Raised when a foreign sub-component cannot be sandboxed as
    declared: the child imports a ``capa:host/<cap>`` interface the call
    did not grant (structural cap-set deny), or the child artifact is
    missing / malformed. The message is actionable and names the
    boundary."""


# Kebab-case a Capa method name for the child component's WIT export
# lookup (WIT identifiers are strict kebab-case; ``do_thing`` ->
# ``do-thing``). A plain lowercase name (``submit``) is unchanged.
def _wit_export_name(method: str) -> str:
    return method.replace("_", "-")


def dispatch_foreign_call(
    engine: wasmtime.Engine,
    artifact_path: str,
    method: str,
    granted: dict[str, Any],
    scalar_args: list,
    boundary_label: str,
):
    """Instantiate the child component at ``artifact_path`` with a
    restricted linker binding ONLY the ``granted`` caps, call its
    exported ``method`` with ``scalar_args``, and return the scalar
    result (or None for a Unit return).

    ``granted`` maps a capability class name (``"Net"`` / ``"Fs"`` /
    ...) to the caller's already-attenuated cap instance. A child that
    imports a cap NOT in ``granted`` fails at ``instantiate`` -- surfaced
    as :class:`ForeignDenied` with the boundary named."""
    if not os.path.isfile(artifact_path):
        raise ForeignDenied(
            f"foreign component {boundary_label}: artifact not found at "
            f"{artifact_path!r}"
        )
    try:
        component = wc.Component.from_file(engine, artifact_path)
    except Exception as e:  # malformed artifact
        raise ForeignDenied(
            f"foreign component {boundary_label}: could not load "
            f"artifact {artifact_path!r}: {e}"
        )
    store = wasmtime.Store(engine)
    linker = wc.Linker(engine)
    root = linker.root()
    _register_granted_caps(root, granted)
    root.close()
    try:
        instance = linker.instantiate(store, component)
    except wasmtime.WasmtimeError as e:
        # An un-granted capa:host/<cap> import fails here: the linker has
        # no matching interface. This is the STRUCTURAL host-enforced
        # cap-set deny -- the sandbox physically refuses to give the
        # child an interface the call did not declare.
        raise ForeignDenied(
            f"foreign component {boundary_label}: instantiation denied -- "
            f"the component imports a capability interface the call did "
            f"not grant (granted: {sorted(granted) or 'none'}). "
            f"Underlying: {e}"
        )
    export = _wit_export_name(method)
    fn = instance.get_func(store, export)
    if fn is None:
        raise ForeignDenied(
            f"foreign component {boundary_label}: the component exports no "
            f"method {export!r}"
        )
    result = fn(store, *scalar_args)
    # wasmtime-py returns a single value for a one-result func, a tuple
    # for multi-result, and None for no result. F2a scalars are always
    # single-value or none.
    if isinstance(result, (list, tuple)):
        return result[0] if result else None
    return result


def _register_granted_caps(root: wc.LinkerInstance, granted: dict[str, Any]) -> None:
    """Register the ``capa:host/<cap>`` interface for each granted cap,
    bound to the caller's attenuated cap instance. Only these interfaces
    are linked, so a child importing any other one fails to instantiate."""
    for cap_name, cap in granted.items():
        binder = _CAP_BINDERS.get(cap_name)
        if binder is None:
            # A capability with no host interface to bind (e.g. Unsafe,
            # which F1 forbids as a foreign param, or an unknown name).
            # Leaving it unregistered means a child importing it is
            # denied -- fail closed.
            continue
        binder(root, cap)


# ---- per-cap bound registrations -------------------------------------
#
# Each binder registers the canonical ``capa:host/<cap>`` interface (the
# same signatures ``capa.ir._emit_wit._WIT_SIGNATURES`` advertises) with
# closures that CAPTURE ``cap`` and IGNORE the guest-supplied ``handle``.
# The ``restrict-*`` attenuators return 0 (a dummy handle the child never
# meaningfully uses): the child cannot widen past ``cap`` because every
# privileged op uses the captured ``cap`` regardless of the handle.


def _bind_net(root: wc.LinkerInstance, net: Net) -> None:
    ifc = root.add_instance("capa:host/net")

    def net_get(_s, _handle, url: str):
        result = net.get(url)
        if isinstance(result, Ok):
            return result.value
        err = result.error
        return IoErrorRecord(
            message=getattr(err, "message", str(err)),
            cause=getattr(err, "cause", ""),
        )

    def net_post(_s, _handle, url: str, body: str):
        result = net.post(url, body)
        if isinstance(result, Ok):
            return result.value
        err = result.error
        return IoErrorRecord(
            message=getattr(err, "message", str(err)),
            cause=getattr(err, "cause", ""),
        )

    ifc.add_func("get", net_get)
    ifc.add_func("post", net_post)
    ifc.add_func("restrict-to", lambda _s, _h, _host: 0)
    ifc.add_func("allows", lambda _s, _h, host: bool(net.allows(host)))
    ifc.close()


def _bind_fs(root: wc.LinkerInstance, fs: Fs) -> None:
    ifc = root.add_instance("capa:host/fs")

    def fs_read(_s, _h, path: str):
        if not fs.allows(path):
            return IoErrorRecord(
                message=f"Fs capability does not permit read: {path}"
            )
        try:
            with fs._open_read(path) as f:
                return f.read()
        except PostOpenDenied:
            return IoErrorRecord(
                message=f"Fs capability does not permit read: {path}"
            )
        except OSError as e:
            return IoErrorRecord(message=str(e), cause=type(e).__name__)

    def fs_write(_s, _h, path: str, content: str):
        if not fs.allows(path):
            return IoErrorRecord(
                message=f"Fs capability does not permit write: {path}"
            )
        try:
            with fs._open_write(path) as f:
                f.write(content)
            return None
        except PostOpenDenied:
            return IoErrorRecord(
                message=f"Fs capability does not permit write: {path}"
            )
        except OSError as e:
            return IoErrorRecord(message=str(e), cause=type(e).__name__)

    def fs_mkdir(_s, _h, path: str):
        if not fs.allows(path):
            return IoErrorRecord(
                message=f"Fs capability does not permit mkdir: {path}"
            )
        try:
            os.makedirs(path, exist_ok=True)
            return None
        except OSError as e:
            return IoErrorRecord(message=str(e), cause=type(e).__name__)

    def fs_list_dir(_s, _h, path: str):
        if not fs.allows(path):
            return IoErrorRecord(
                message=f"Fs capability does not permit list_dir: {path}"
            )
        try:
            return sorted(os.listdir(path))
        except OSError as e:
            return IoErrorRecord(message=str(e), cause=type(e).__name__)

    ifc.add_func("read", fs_read)
    ifc.add_func("write", fs_write)
    ifc.add_func("mkdir", fs_mkdir)
    ifc.add_func("list-dir", fs_list_dir)
    ifc.add_func("exists", lambda _s, _h, p: fs.allows(p) and os.path.exists(p))
    ifc.add_func("is-dir", lambda _s, _h, p: fs.allows(p) and os.path.isdir(p))
    ifc.add_func("restrict-to", lambda _s, _h, _p: 0)
    ifc.add_func("allows", lambda _s, _h, p: bool(fs.allows(p)))
    ifc.close()


def _bind_env(root: wc.LinkerInstance, env: Env) -> None:
    ifc = root.add_instance("capa:host/env")

    def env_get(_s, _h, name: str):
        if not env.allows(name):
            return None
        return os.environ.get(name)

    ifc.add_func("args", lambda _s, _h: [])
    ifc.add_func("get", env_get)
    ifc.add_func("restrict-to-keys", lambda _s, _h, _keys: 0)
    ifc.add_func("allows", lambda _s, _h, key: bool(env.allows(key)))
    ifc.close()


def _bind_clock(root: wc.LinkerInstance, clock: Clock) -> None:
    import time

    ifc = root.add_instance("capa:host/clock")

    def clock_sleep(_s, _h, secs: float):
        if not clock.allows() or secs < 0:
            return None
        time.sleep(secs)
        return None

    ifc.add_func("now-secs", lambda _s, _h: time.time())
    ifc.add_func("now-monotonic", lambda _s, _h: time.monotonic())
    ifc.add_func("sleep", clock_sleep)
    ifc.add_func("allows", lambda _s, _h: bool(clock.allows()))
    ifc.add_func("restrict-to-after", lambda _s, _h, _t: 0)
    ifc.close()


def _bind_db(root: wc.LinkerInstance, db: Db) -> None:
    import sqlite3

    ifc = root.add_instance("capa:host/db")

    def db_exec(_s, _h, path: str, sql: str):
        if not db.allows(path):
            return IoErrorRecord(
                message=f"Db capability does not permit exec: {path}"
            )
        try:
            conn = db._connect_verified(path)
            try:
                conn.executescript(sql)
                conn.commit()
            finally:
                conn.close()
            return None
        except PostOpenDenied:
            return IoErrorRecord(
                message=f"Db capability does not permit exec: {path}"
            )
        except (sqlite3.Error, OSError, ValueError) as e:
            return IoErrorRecord(message="SQLite exec failed", cause=str(e))

    def db_query(_s, _h, path: str, sql: str):
        if not db.allows(path):
            return IoErrorRecord(
                message=f"Db capability does not permit query: {path}"
            )
        try:
            conn = db._connect_verified(path)
            try:
                cur = conn.execute(sql)
                rows = cur.fetchall()
            finally:
                conn.close()
            stringified = [
                [
                    "null" if v is None else v if isinstance(v, str) else str(v)
                    for v in row
                ]
                for row in rows
            ]
            return _stdlib_json.dumps(stringified)
        except PostOpenDenied:
            return IoErrorRecord(
                message=f"Db capability does not permit query: {path}"
            )
        except (sqlite3.Error, OSError, ValueError) as e:
            return IoErrorRecord(message="SQLite query failed", cause=str(e))

    ifc.add_func("exec", db_exec)
    ifc.add_func("query", db_query)
    ifc.add_func("restrict-to", lambda _s, _h, _p: 0)
    ifc.add_func("allows", lambda _s, _h, p: bool(db.allows(p)))
    ifc.close()


def _bind_proc(root: wc.LinkerInstance, proc: Proc) -> None:
    import subprocess

    ifc = root.add_instance("capa:host/proc")

    def proc_exec(_s, _h, cmd: str, args_json: str):
        if not proc.allows(cmd):
            return IoErrorRecord(
                message=f"Proc capability does not permit exec: {cmd}"
            )
        try:
            tail = _stdlib_json.loads(args_json)
        except (ValueError, TypeError) as e:
            return IoErrorRecord(
                message="Proc.exec args_json parse failed", cause=str(e)
            )
        if not isinstance(tail, list) or not all(isinstance(x, str) for x in tail):
            return IoErrorRecord(
                message="Proc.exec args_json parse failed",
                cause="expected a JSON array of strings",
            )
        argv = [cmd, *tail]
        try:
            completed = subprocess.run(
                argv, capture_output=True, timeout=30, shell=False,
            )
        except subprocess.TimeoutExpired:
            return IoErrorRecord(message="timed out", cause="30s elapsed")
        except (OSError, ValueError) as e:
            return IoErrorRecord(message="Proc.exec spawn failed", cause=str(e))
        if completed.returncode != 0:
            stderr = completed.stderr.decode("utf-8", errors="replace")
            return IoErrorRecord(
                message="non-zero exit",
                cause=f"code={completed.returncode} stderr={stderr!r}",
            )
        return completed.stdout.decode("utf-8", errors="replace")

    ifc.add_func("exec", proc_exec)
    ifc.add_func("restrict-to", lambda _s, _h, _p: 0)
    ifc.add_func("allows", lambda _s, _h, cmd: bool(proc.allows(cmd)))
    ifc.close()


def _bind_stdio(root: wc.LinkerInstance, _stdio: Stdio) -> None:
    import sys

    ifc = root.add_instance("capa:host/stdio")
    ifc.add_func("print", lambda _s, msg: _write_safe(sys.stdout, msg))
    ifc.add_func("println", lambda _s, msg: _write_safe(sys.stdout, msg + "\n"))
    ifc.add_func("eprintln", lambda _s, msg: _write_safe(sys.stderr, msg + "\n"))

    def stdio_read_line(_s):
        try:
            line = sys.stdin.readline()
        except OSError as e:
            return IoErrorRecord(message="read failed", cause=str(e))
        if not line:
            return IoErrorRecord(message="end of input")
        return line.rstrip("\n")

    ifc.add_func("read-line", stdio_read_line)
    ifc.close()


def _bind_random(root: wc.LinkerInstance, _random: Random) -> None:
    ifc = root.add_instance("capa:host/random")
    ifc.add_func(
        "system-seed",
        lambda _s: int.from_bytes(os.urandom(8), "little", signed=False),
    )
    ifc.close()


_CAP_BINDERS = {
    "Net": _bind_net,
    "Fs": _bind_fs,
    "Env": _bind_env,
    "Clock": _bind_clock,
    "Db": _bind_db,
    "Proc": _bind_proc,
    "Stdio": _bind_stdio,
    "Random": _bind_random,
}
