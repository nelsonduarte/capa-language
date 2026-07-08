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


class ForeignResourceExceeded(ForeignDenied):
    """Raised when a foreign sub-component runs INSIDE its granted
    capability set but breaches its RESOURCE CEILING: it exhausted the
    bounded CPU/fuel budget (an infinite loop / CPU spin) or tried to
    grow / claim a store resource (linear memory, a funcref table, ...)
    past its bound. This is an availability bound, not a confinement
    bypass -- the child is still confined to its granted caps; it is now
    also resource-bounded on three axes: CPU (fuel), host wall-time in the
    guest-controllable blocking closures (``clock.sleep`` clamp,
    ``db.exec`` / ``db.query`` deadline; ``net`` / ``proc`` carry their own
    timeouts), and store growth (linear memory + table + object counts).
    So a malicious or buggy child cannot DoS the host by a CPU spin, an
    unbounded sleep / runaway query, or a runaway wasm allocation. It can
    still do work PROPORTIONAL to a granted capability (read a granted
    file, fetch an allowlisted URL) exactly as the direct caller could --
    that is the capability model, bounded by each cap's own semantics, not
    a sandbox gap.

    Subclasses :class:`ForeignDenied` so the CLI surfaces it as the same
    clean, actionable, exit-1 diagnostic (no host hang, no OOM, no raw
    traceback)."""


# Resource ceiling applied to EVERY untrusted foreign-component child
# store (feature #4 hardening). Generous enough that the legitimate
# fixtures (scalar / String / aggregate crossing) run unaffected, but
# bounded so a pathological child TRAPS instead of DoS-ing the host.
#
# - Fuel bounds CPU: wasmtime charges ~1 fuel per executed wasm
#   instruction, so ~1e9 lets a legitimate foreign call do a great deal
#   of honest work while an infinite loop traps in well under a second.
# - Memory bounds linear-memory growth: 256 MiB dwarfs what any honest
#   crossing needs (the fixtures use a single 64 KiB page) yet is far
#   below the ~4 GiB a malicious self-allocation would reach.
DEFAULT_FOREIGN_FUEL = 1_000_000_000
DEFAULT_FOREIGN_MEMORY_CAP_BYTES = 256 * 1024 * 1024

# Store growable-resource caps (feature #4 hardening, review C2). Fuel and
# the linear-memory ceiling do NOT bound table growth or object counts, so
# a child could ``table.grow`` a huge funcref table (~8 bytes/element) or
# declare many memories / core instances and allocate far past the
# linear-memory cap. These bound every OTHER growable store resource so no
# runaway allocation escapes the ceiling. Applied together with the
# linear-memory cap (governed by the same on/off switch).
DEFAULT_FOREIGN_TABLE_ELEMENTS = 1_000_000  # ~8 MiB of funcref table
_FOREIGN_MAX_MEMORIES = 1     # a core module has a single linear memory
_FOREIGN_MAX_TABLES = 64      # generous vs the 1-2 a real component uses
_FOREIGN_MAX_INSTANCES = 64   # bounds nested core-instance explosion

# Wall-clock bound (seconds) on any single blocking granted host closure
# the untrusted child can reach (feature #4 hardening, review C1). Fuel
# meters wasm INSTRUCTIONS, not time spent inside a host Python call, so a
# blocking closure (``clock.sleep``, a long-running SQL query) would hang
# the host indefinitely despite the fuel ceiling unless bounded here.
# Generous for legitimate use, bounded so no guest- or external-controlled
# UNBOUNDED blocking is possible. ``net.get`` / ``net.post`` (urllib
# ``timeout=10``) and ``proc.exec`` (``timeout=30``) are already bounded in
# ``capa.runtime._capabilities``.
MAX_FOREIGN_BLOCKING_SECS = 5.0


def new_foreign_engine() -> wasmtime.Engine:
    """Build a wasmtime engine for untrusted foreign-component children
    with fuel consumption ENABLED, so a per-store fuel budget can bound
    the child's CPU. Kept separate from the parent module's engine: the
    parent runs unmetered, only the untrusted child is fuel-metered."""
    config = wasmtime.Config()
    config.consume_fuel = True
    return wasmtime.Engine(config)


def _is_store_limit_error(exc: Exception) -> bool:
    """True when a wasmtime error is the child breaching a STORE RESOURCE
    LIMIT (linear memory, table growth, or an object-count cap the child
    store was configured with), as opposed to the structural
    capability-import deny that also surfaces as a ``WasmtimeError`` at
    instantiation.

    NOTE (wasmtime 44 coupling): wasmtime-py exposes no typed limit error
    and a component instance hides its inner memory, so this matches the
    error TEXT. The capability-import deny reads "component imports
    instance ..., but a matching implementation was not found" -- neither
    "exceed" nor "limit" -- so the two are cleanly separable.
    ``test_store_limit_error_message_shape`` pins the current wasmtime
    phrasing so a future message change is caught rather than silently
    misclassifying a real error as a resource breach."""
    text = str(exc).lower()
    return "exceed" in text and "limit" in text


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
    *,
    aggregate_result: bool = False,
    fuel: int | None = DEFAULT_FOREIGN_FUEL,
    memory_cap_bytes: int | None = DEFAULT_FOREIGN_MEMORY_CAP_BYTES,
):
    """Instantiate the child component at ``artifact_path`` with a
    restricted linker binding ONLY the ``granted`` caps, call its
    exported ``method`` with ``scalar_args``, and return the scalar
    result (or None for a Unit return).

    ``granted`` maps a capability class name (``"Net"`` / ``"Fs"`` /
    ...) to the caller's already-attenuated cap instance. A child that
    imports a cap NOT in ``granted`` fails at ``instantiate`` -- surfaced
    as :class:`ForeignDenied` with the boundary named.

    The child store is bounded by a RESOURCE CEILING (feature #4
    hardening): ``fuel`` fuel units cap its CPU (an infinite loop TRAPS
    on fuel exhaustion instead of hanging the host) and
    ``memory_cap_bytes`` caps its linear-memory growth (a runaway
    self-allocation is refused instead of OOM-ing the host). Either
    breach surfaces as :class:`ForeignResourceExceeded`. Pass ``None``
    (or a non-positive value) for either to skip that bound. ``engine``
    MUST come from :func:`new_foreign_engine` for the fuel bound to
    apply; the confinement (restricted linker, granted caps, host-bound
    closures) is UNCHANGED -- this only adds the store ceiling."""
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
    # Resource ceiling on the untrusted child store (feature #4
    # hardening): fuel bounds CPU; the store limits bound EVERY growable
    # resource -- linear memory, funcref table growth, and the memory /
    # table / instance object counts -- so neither a runaway
    # ``memory.grow`` nor a runaway ``table.grow`` (review C2) can escape
    # the ceiling. Applied BEFORE instantiation so a child declaring an
    # over-cap minimum is refused up front, not after an OOM.
    fuel_enabled = fuel is not None and fuel > 0
    if fuel_enabled:
        store.set_fuel(fuel)
    if memory_cap_bytes is not None and memory_cap_bytes > 0:
        store.set_limits(
            memory_size=memory_cap_bytes,
            table_elements=DEFAULT_FOREIGN_TABLE_ELEMENTS,
            memories=_FOREIGN_MAX_MEMORIES,
            tables=_FOREIGN_MAX_TABLES,
            instances=_FOREIGN_MAX_INSTANCES,
        )
    linker = wc.Linker(engine)
    root = linker.root()
    _register_granted_caps(root, granted)
    root.close()
    try:
        instance = linker.instantiate(store, component)
    except wasmtime.WasmtimeError as e:
        # A child whose linear memory / table minimum already exceeds a
        # store limit is refused here (availability bound), distinct from
        # the capability-import deny below.
        if _is_store_limit_error(e):
            raise ForeignResourceExceeded(
                f"foreign component {boundary_label}: exceeded its memory / "
                f"resource limit (memory cap {memory_cap_bytes} bytes) -- the "
                f"child's declared store resources do not fit the sandbox "
                f"ceiling. Underlying: {e}"
            )
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
    try:
        result = fn(store, *scalar_args)
    except wasmtime.WasmtimeError as e:
        # The child trapped. If it drained its fuel budget (an infinite
        # loop / CPU spin), surface the bounded CPU diagnostic instead of
        # letting the host hang; ``get_fuel() == 0`` is the robust signal
        # (the component path reports fuel exhaustion as a plain
        # WasmtimeError, so the message alone is not reliable). Any other
        # trap (a genuine guest ``unreachable`` / out-of-bounds, including
        # a child that grew to its memory ceiling and then trapped on its
        # own -1-handling) propagates unchanged.
        if fuel_enabled:
            try:
                remaining = store.get_fuel()
            except wasmtime.WasmtimeError:
                remaining = None
            if remaining == 0:
                raise ForeignResourceExceeded(
                    f"foreign component {boundary_label}: exceeded its "
                    f"CPU/fuel budget ({fuel} fuel units) -- the child ran "
                    f"too long (possible infinite loop) and was stopped "
                    f"before it could hang the host"
                ) from e
        raise
    # wasmtime-py returns a single value for a one-result func, a tuple
    # for multi-result, and None for no result. F2a scalars are always
    # single-value or none, so a bare ``list`` / ``tuple`` there is a
    # multi-result flatten to unwrap. A FLAT aggregate return (F2c-1),
    # however, IS a single ``list`` / ``tuple`` VALUE -- return it whole.
    if aggregate_result:
        return result
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
        # Review C1: fuel meters wasm instructions, not host wall time, so
        # an unbounded ``time.sleep(secs)`` with a guest-controlled ``secs``
        # would hang the host indefinitely despite the fuel ceiling. Clamp
        # to a bounded maximum so a foreign child can never block the host
        # for longer than one bounded interval per call.
        time.sleep(min(secs, MAX_FOREIGN_BLOCKING_SECS))
        return None

    ifc.add_func("now-secs", lambda _s, _h: time.time())
    ifc.add_func("now-monotonic", lambda _s, _h: time.monotonic())
    ifc.add_func("sleep", clock_sleep)
    ifc.add_func("allows", lambda _s, _h: bool(clock.allows()))
    ifc.add_func("restrict-to-after", lambda _s, _h, _t: 0)
    ifc.close()


def _bind_db(root: wc.LinkerInstance, db: Db) -> None:
    import sqlite3
    import time

    ifc = root.add_instance("capa:host/db")

    def _install_deadline(conn) -> None:
        # Review C1: guest-supplied SQL can loop unboundedly (e.g. a
        # ``WITH RECURSIVE`` with no terminating condition), blocking the
        # host thread past any fuel bound. Install a progress handler that
        # aborts the statement once a bounded wall-clock deadline passes;
        # sqlite then raises ``OperationalError`` (a ``sqlite3.Error``),
        # caught below and surfaced as a clean IoError to the child.
        deadline = time.monotonic() + MAX_FOREIGN_BLOCKING_SECS

        def _guard():
            return 1 if time.monotonic() > deadline else 0

        # Fire the guard every ~100k VM instructions (cheap; frequent
        # enough that a tight query loop is stopped promptly).
        conn.set_progress_handler(_guard, 100_000)

    def db_exec(_s, _h, path: str, sql: str):
        if not db.allows(path):
            return IoErrorRecord(
                message=f"Db capability does not permit exec: {path}"
            )
        try:
            conn = db._connect_verified(path)
            try:
                _install_deadline(conn)
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
                _install_deadline(conn)
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
