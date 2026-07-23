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
import sqlite3 as _sqlite3
from typing import Any

import wasmtime
import wasmtime.component as wc

from ._capabilities import (
    Clock,
    Db,
    Env,
    Fs,
    Net,
    Proc,
    Random,
    ResultCapExceeded,
    Stdio,
    _write_safe,
)
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

# Result-size ceiling (bytes) on the value a host-mediated ``capa:host/<cap>``
# closure materialises for an untrusted foreign child (feature #4 hardening,
# the last DoS gap in the foreign resource ceiling). The fuel / memory caps
# bound the CHILD store; they do NOT bound the HOST-side buffer a granted,
# host-mediated read allocates. A single ``fs.read`` of a multi-GiB in-prefix
# file, a giant HTTP body, or a huge ``db.query`` result set runs in the HOST
# Python process and materialises the WHOLE result before lifting it to the
# child -- charging ~no child fuel -- so an untrusted child could OOM the host
# regardless of ``--foreign-memory-cap``. This bound caps the VALUE THAT
# CROSSES to the child: a read whose crossing value would exceed it aborts
# EARLY (for ``db.query`` the crossing value is the ``json.dumps`` result, and
# ``total`` is charged in its escaped size so the returned dump is ``<= cap``;
# for ``fs.read`` / ``net`` it is the raw byte count) and surfaces as
# :class:`ForeignResourceExceeded`. The retained host intermediate is ``<= cap``
# in raw terms too, so the peak host allocation is ~2x cap (intermediate +
# crossing value both live during the final serialise), never the whole result.
# 256 MiB matches the child memory cap -- the result must fit the child anyway,
# so this is the natural ceiling. ``0`` / ``None`` opts out (unbounded).
DEFAULT_FOREIGN_RESULT_CAP_BYTES = 256 * 1024 * 1024

# Chunk size (characters) for a bounded host-side text read (``fs.read``).
_FOREIGN_TEXT_READ_CHUNK = 65536

# Result-ROW bound for a capped host-side ``db.query`` fetch. A single result
# row = (number of result columns) x (per-value size). A per-value SOURCE
# guard plus a POST-materialisation accumulator cannot bound an ATOMIC C-layer
# fetch whose row width (columns) or batch size (rows) the untrusted child
# controls -- it drives host peak far above the cap two ways: a wide single
# row (``select zeroblob(900k), ... x 500``) and a big fetch batch (256 rows
# x ~cap). We bound BOTH terms of a single row at the sqlite SOURCE, before
# fetching, then fetch ONE row at a time (below), so the peak host allocation
# for a capped ``db.query`` is a small constant multiple of the cap (~2x),
# independent of the attacker's column count, value sizes, or row count:
#
# - ``MAX_RESULT_COLUMNS`` caps the result-set column count via
#   ``SQLITE_LIMIT_COLUMN`` (verified: this limits a SELECT RESULT width, not
#   only a table definition). A query with more columns is REFUSED by sqlite
#   ("too many columns in result set") before any row materialises -- this
#   kills the arbitrary-width attack. 100 is generous for real queries.
# - ``_FOREIGN_DB_VALUE_FLOOR`` is the minimum per-value length limit so small
#   legitimate values are never broken even at a tiny cap. The per-value
#   ``SQLITE_LIMIT_LENGTH`` is ``max(cap // MAX_RESULT_COLUMNS, FLOOR)``, so a
#   single row is bounded to about ``cap`` (cap binding) or
#   ``MAX_RESULT_COLUMNS * FLOOR`` = ~6.4 MiB (floor binding) -- a small fixed
#   constant either way, NOT attacker-scalable. 64 KiB floor.
MAX_RESULT_COLUMNS = 100
_FOREIGN_DB_VALUE_FLOOR = 65536

# The per-row accumulator (below) must be a SOUND OVER-ESTIMATE of
# ``len(_stdlib_json.dumps(stringified))`` -- the JSON string that ACTUALLY
# CROSSES to the child -- so that aborting the moment ``total > cap`` guarantees
# the crossing dump is ``<= cap`` for ANY attacker choice of value sizes, column
# count, row count AND escape content. Counting the raw UTF-8 payload bytes is
# unsound TWO ways. (1) Escape expansion: ``json.dumps`` with ``ensure_ascii``
# expands a control char to ``\uXXXX`` (6x), a quote / backslash to 2x, so an
# escape-heavy result whose RAW payload is just under the cap serialises to a
# dump ~6x it -- the value that crosses the boundary blows the cap. We therefore
# charge each VALUE its JSON-ESCAPED size ``len(_stdlib_json.dumps(s))`` -- its
# EXACT contribution to the dump -- or ``_FOREIGN_DB_PER_VALUE_COST``, whichever
# is larger. (2) Tiny / empty value flood: an attacker emitting millions of
# ``''`` values (``with recursive c(x) as (select '' ... limit 1000000) select
# x from c``) grows the retained ``list``-of-``list`` while a size-only ``total``
# barely moves. The per-value floor and the per-row charge close it: per
# accumulated ROW we charge a constant covering the row's STRUCTURAL dump bytes
# plus the retained ``list`` object; per accumulated VALUE the floor covers the
# retained ``str`` object (so an empty / tiny value still consumes budget).
#
# The per-row STRUCTURAL charge must cover the real dump separators. Note that
# ``json.dumps`` default separators are TWO bytes (``", "`` between items,
# ``": "`` in objects), NOT one: so a row's structural dump bytes are at most
# ``2 * MAX_RESULT_COLUMNS + 2`` -- the row's ``[`` ``]`` (2), up to
# ``MAX_RESULT_COLUMNS`` - 1 two-byte inter-value separators, and the two-byte
# inter-row separator (max 2*100 + 2 = 202 at ``MAX_RESULT_COLUMNS`` = 100).
# ``_FOREIGN_DB_ROW_STRUCTURAL`` is DERIVED from ``MAX_RESULT_COLUMNS`` so it
# cannot silently under-charge if that limit changes; ``_FOREIGN_DB_PER_ROW_COST``
# adds a 64-byte margin for the retained ``list`` object overhead. (On CPython
# an empty ``str`` is ~49 bytes <= 64, the per-value floor.) Because ``total``
# >= ``len(_stdlib_json.dumps(stringified))`` at every step, the abort fires
# early and the crossing dump stays ``<= cap``; the retained intermediate (raw
# payload <= its JSON size) stays ``<= cap`` in raw terms too, so the host peak
# is ~2x cap.
_FOREIGN_DB_PER_VALUE_COST = 64
_FOREIGN_DB_ROW_STRUCTURAL = 2 * MAX_RESULT_COLUMNS + 2
_FOREIGN_DB_PER_ROW_COST = _FOREIGN_DB_ROW_STRUCTURAL + 64

# sqlite ``SQLITE_TOOBIG`` (18): the extended-result-code sqlite raises when a
# string / blob exceeds ``SQLITE_LIMIT_LENGTH``. Resolved via ``getattr`` so a
# 3.10 interpreter (where the named constant is absent) still has the numeric
# fallback -- though that path fails closed before it is reached (no
# ``setlimit``). Named on the module so the too-big translation matches the
# length limit precisely, never a blanket ``except``.
_SQLITE_TOOBIG = getattr(_sqlite3, "SQLITE_TOOBIG", 18)


def _is_sqlite_length_limit_error(exc: Exception) -> bool:
    """True when ``exc`` is a sqlite RESULT-CAP breach we translate to
    :class:`ForeignResourceExceeded`: either the ``SQLITE_LIMIT_LENGTH`` breach
    (``SQLITE_TOOBIG``, "string or blob too big") or the ``SQLITE_LIMIT_COLUMN``
    breach ("too many columns in result set"), as opposed to a genuine SQL / IO
    error. The length breach keys off the extended result code when available
    (3.11+, where ``setlimit`` also lives) and falls back to the stable message
    text; the column breach surfaces as a generic ``SQLITE_ERROR`` (code 1) so
    it is matched by its stable message text. A normal ``sqlite3.Error`` (a
    missing table, a syntax error) is NEVER misclassified as the result-cap
    breach."""
    if not isinstance(exc, _sqlite3.Error):
        return False
    if getattr(exc, "sqlite_errorcode", None) == _SQLITE_TOOBIG:
        return True
    text = str(exc).lower()
    return (
        "string or blob too big" in text
        or "too many columns in result set" in text
    )

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
# UNBOUNDED blocking is possible. ``net.get`` / ``net.post`` (a 10s
# WALL-CLOCK deadline over the whole request, redirect hops and body read
# included) and ``proc.exec`` (``timeout=30``) are already bounded in
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


def _raise_if_resource_trap(
    exc: wasmtime.WasmtimeError,
    store: wasmtime.Store,
    *,
    fuel_enabled: bool,
    fuel: int | None,
    memory_cap_bytes: int | None,
    boundary_label: str,
) -> None:
    """Classify a wasmtime error by its UNDERLYING CAUSE and, if it is a
    RESOURCE trap, raise :class:`ForeignResourceExceeded`. Returns without
    raising when ``exc`` is NOT a resource trap, so the caller handles it
    (a genuine missing-import LINK deny at instantiation, or a genuine
    guest trap at execution).

    Uniform across instantiation AND the call: fuel can be drained either
    while instantiating the child (its start / init runs) or during the
    exported call, so classification MUST key off the cause, never off
    which wasmtime call raised. Order matters -- a resource trap is
    checked FIRST so it can never be mislabelled as a confinement (cap-set
    deny) event:

    - Fuel exhaustion is detected by ``store.get_fuel() == 0`` (the robust
      signal; the component path reports fuel exhaustion as a plain
      ``WasmtimeError`` whose text is not reliable). A genuine missing
      import fails at LINK time before any wasm runs, so it consumes NO
      fuel and leaves ``get_fuel()`` at the full budget -- cleanly
      distinct from a fuel trap.
    - A store-limit breach (linear memory / table / object-count) is
      detected by :func:`_is_store_limit_error`.
    """
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
            ) from exc
    if _is_store_limit_error(exc):
        raise ForeignResourceExceeded(
            f"foreign component {boundary_label}: exceeded its memory / "
            f"resource limit (memory cap {memory_cap_bytes} bytes) -- the "
            f"child's declared store resources do not fit the sandbox "
            f"ceiling. Underlying: {exc}"
        ) from exc


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
    result_cap_bytes: int | None = DEFAULT_FOREIGN_RESULT_CAP_BYTES,
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
    closures) is UNCHANGED -- this only adds the store ceiling.

    ``result_cap_bytes`` bounds the HOST-side buffer a granted,
    host-mediated closure materialises (``fs.read`` file bytes, a
    ``net.get`` / ``net.post`` body, a ``db.query`` result set). The fuel
    / memory caps bound the CHILD store; they do NOT bound this host-side
    allocation, so this is the last DoS axis of the foreign resource
    ceiling: a read that would exceed the cap aborts EARLY (peak host
    allocation stays ~cap, never the whole result) and surfaces as
    :class:`ForeignResourceExceeded`. ``None`` / a non-positive value
    opts out (unbounded)."""
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
    # Normalise the result cap once: a non-positive value opts out
    # (unbounded), mirroring the fuel / memory-cap on/off convention.
    result_cap = (
        result_cap_bytes
        if (result_cap_bytes is not None and result_cap_bytes > 0)
        else None
    )
    linker = wc.Linker(engine)
    root = linker.root()
    _register_granted_caps(root, granted, result_cap)
    root.close()
    try:
        instance = linker.instantiate(store, component)
    except wasmtime.WasmtimeError as e:
        # Classify by UNDERLYING CAUSE first: instantiating the child runs
        # its start / init, which can DRAIN the fuel budget (or hit a store
        # limit), so a resource trap can land HERE, not only in the call.
        # This must surface as the resource diagnostic, never mislabelled
        # as the cap-set deny below.
        _raise_if_resource_trap(
            e, store, fuel_enabled=fuel_enabled, fuel=fuel,
            memory_cap_bytes=memory_cap_bytes, boundary_label=boundary_label,
        )
        # Not a resource trap: a genuine missing-import LINK failure (the
        # linker has no matching interface; it fails before any wasm runs
        # and consumes no fuel). This is the STRUCTURAL host-enforced
        # cap-set deny -- the sandbox physically refuses to give the child
        # an interface the call did not declare.
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
        # The child trapped during execution. Classify by cause with the
        # SAME logic as instantiation: a drained fuel budget (an infinite
        # loop / CPU spin) or a store-limit breach surfaces as the resource
        # diagnostic. Any other trap (a genuine guest ``unreachable`` /
        # out-of-bounds, including a child that grew to its memory ceiling
        # and then trapped on its own -1-handling) propagates unchanged.
        _raise_if_resource_trap(
            e, store, fuel_enabled=fuel_enabled, fuel=fuel,
            memory_cap_bytes=memory_cap_bytes, boundary_label=boundary_label,
        )
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


def _register_granted_caps(
    root: wc.LinkerInstance,
    granted: dict[str, Any],
    result_cap: int | None,
) -> None:
    """Register the ``capa:host/<cap>`` interface for each granted cap,
    bound to the caller's attenuated cap instance. Only these interfaces
    are linked, so a child importing any other one fails to instantiate.

    ``result_cap`` (bytes, or ``None`` for unbounded) is the host-side
    result-size ceiling threaded to every result-returning binder
    (``fs.read`` / ``net.get`` / ``net.post`` / ``db.query``); binders
    that materialise no unbounded host buffer ignore it."""
    for cap_name, cap in granted.items():
        binder = _CAP_BINDERS.get(cap_name)
        if binder is None:
            # A capability with no host interface to bind (e.g. Unsafe,
            # which F1 forbids as a foreign param, or an unknown name).
            # Leaving it unregistered means a child importing it is
            # denied -- fail closed.
            continue
        binder(root, cap, result_cap)


def _read_text_capped(f, cap: int, label: str) -> str:
    """Read a text stream in bounded chunks, aborting the moment the
    UTF-8 byte size would exceed ``cap`` so PEAK host allocation stays
    ~``cap`` bytes (never the whole, possibly multi-GiB, file). A stream
    whose bytes total EXACTLY ``cap`` is allowed; ``cap + 1`` raises."""
    parts: list[str] = []
    total = 0
    while True:
        chunk = f.read(_FOREIGN_TEXT_READ_CHUNK)
        if not chunk:
            break
        total += len(chunk.encode("utf-8"))
        if total > cap:
            raise ForeignResourceExceeded(
                f"{label} result exceeded the foreign result cap "
                f"({cap} bytes) -- the host aborted the read before "
                f"buffering the whole result"
            )
        parts.append(chunk)
    return "".join(parts)


# ---- per-cap bound registrations -------------------------------------
#
# Each binder registers the canonical ``capa:host/<cap>`` interface (the
# same signatures ``capa.ir._emit_wit._WIT_SIGNATURES`` advertises) with
# closures that CAPTURE ``cap`` and IGNORE the guest-supplied ``handle``.
# The ``restrict-*`` attenuators return 0 (a dummy handle the child never
# meaningfully uses): the child cannot widen past ``cap`` because every
# privileged op uses the captured ``cap`` regardless of the handle.


def _bind_net(root: wc.LinkerInstance, net: Net, result_cap: int | None) -> None:
    ifc = root.add_instance("capa:host/net")

    def net_get(_s, _handle, url: str):
        try:
            result = net.get(url, max_bytes=result_cap)
        except ResultCapExceeded as e:
            raise ForeignResourceExceeded(
                f"Net.get result exceeded the foreign result cap "
                f"({result_cap} bytes) -- the host aborted the read before "
                f"buffering the whole response body"
            ) from e
        if isinstance(result, Ok):
            return result.value
        err = result.error
        return IoErrorRecord(
            message=getattr(err, "message", str(err)),
            cause=getattr(err, "cause", ""),
        )

    def net_post(_s, _handle, url: str, body: str):
        try:
            result = net.post(url, body, max_bytes=result_cap)
        except ResultCapExceeded as e:
            raise ForeignResourceExceeded(
                f"Net.post result exceeded the foreign result cap "
                f"({result_cap} bytes) -- the host aborted the read before "
                f"buffering the whole response body"
            ) from e
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


def _bind_fs(root: wc.LinkerInstance, fs: Fs, result_cap: int | None) -> None:
    ifc = root.add_instance("capa:host/fs")

    def fs_read(_s, _h, path: str):
        if not fs.allows(path):
            return IoErrorRecord(
                message=f"Fs capability does not permit read: {path}"
            )
        try:
            with fs._open_read(path) as f:
                # Bound the HOST-side buffer: an unbounded ``f.read()`` of
                # a multi-GiB in-prefix file would OOM the host regardless
                # of the child fuel / memory cap. The bounded read aborts
                # early (peak host allocation ~cap), raising
                # ForeignResourceExceeded past the ``except`` funnel below.
                if result_cap is None:
                    return f.read()
                return _read_text_capped(f, result_cap, "Fs.read")
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


def _bind_env(root: wc.LinkerInstance, env: Env, _result_cap: int | None) -> None:
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


def _bind_clock(root: wc.LinkerInstance, clock: Clock, _result_cap: int | None) -> None:
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


def _bind_db(root: wc.LinkerInstance, db: Db, result_cap: int | None) -> None:
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
            prev_len = None
            prev_col = None
            limit_scoped = False
            try:
                _install_deadline(conn)
                if result_cap is not None:
                    # Bound the ATOMIC fetch unit at the SOURCE. The untrusted
                    # child controls the SQL and drives host peak far above the
                    # cap two ways a per-value SOURCE guard + a POST-fetch
                    # accumulator cannot stop, because sqlite materialises a
                    # whole ROW (all columns) in one C-layer fetch BEFORE any
                    # host check fires:
                    #  - Vector A (wide row): ``select zeroblob(900k), ... x
                    #    500`` -> ~N x 900 KiB in one fetch, linear in the
                    #    attacker's column count.
                    #  - Vector B (fetch batch): pulling many rows atomically.
                    # We bound BOTH terms of a single row here, then fetch ONE
                    # row at a time (below) to remove the batch multiplier:
                    #  - ``SQLITE_LIMIT_COLUMN`` = ``MAX_RESULT_COLUMNS`` refuses
                    #    a wider result set outright (Vector A cannot use 500 /
                    #    2000 columns).
                    #  - ``SQLITE_LIMIT_LENGTH`` = ``per_value_limit`` refuses to
                    #    build any single string / blob past that bound.
                    # A single row is then bounded to ~``MAX_RESULT_COLUMNS *
                    # per_value_limit``: about the cap when the cap binds, or a
                    # small fixed constant (~6.4 MiB) when the floor binds --
                    # NOT attacker-scalable. TRADE-OFF (intended, the price of
                    # the single-row bound): a single db value larger than
                    # ``per_value_limit`` = ``max(cap // MAX_RESULT_COLUMNS,
                    # FLOOR)`` is refused; raise ``--foreign-result-cap`` to
                    # allow larger single values. Both limits are scoped to THIS
                    # foreign query and restored in the ``finally`` (``setlimit``
                    # mutates the connection and returns the prior value), so the
                    # normal / trusted ``Db.query`` path is untouched.
                    if not hasattr(conn, "setlimit"):
                        # Fail closed: without ``setlimit`` (sqlite ``setlimit``
                        # is Python 3.11+; the project floor is 3.10) the
                        # per-row accumulator cannot bound a single value, so a
                        # capped foreign db query could OOM the host. Refuse it
                        # rather than silently allow the OOM.
                        raise ForeignResourceExceeded(
                            f"Db.query cannot enforce the foreign result cap "
                            f"({result_cap} bytes) on this interpreter -- the "
                            f"sqlite result-length limit is unavailable "
                            f"(Python < 3.11); refusing the capped query "
                            f"rather than risk unbounded host allocation"
                        )
                    per_value_limit = max(
                        result_cap // MAX_RESULT_COLUMNS, _FOREIGN_DB_VALUE_FLOOR
                    )
                    prev_len = conn.setlimit(
                        sqlite3.SQLITE_LIMIT_LENGTH, per_value_limit
                    )
                    prev_col = conn.setlimit(
                        sqlite3.SQLITE_LIMIT_COLUMN, MAX_RESULT_COLUMNS
                    )
                    limit_scoped = True
                cur = conn.execute(sql)
                # Bound the HOST-side buffer: fetch ONE row at a time (never a
                # ``fetchall`` / ``fetchmany`` batch) so only a single, bounded
                # row is ever materialised by a fetch. The accumulator ``total``
                # is a SOUND OVER-ESTIMATE of ``len(_stdlib_json.dumps(
                # stringified))`` -- the JSON string that ACTUALLY CROSSES to the
                # child. We charge each value its JSON-ESCAPED size
                # ``len(_stdlib_json.dumps(s))`` (its EXACT contribution to the
                # final dump, since ``ensure_ascii`` escaping only EXPANDS: a
                # control char -> ``\uXXXX`` is 6x, a quote / backslash 2x), or
                # ``_FOREIGN_DB_PER_VALUE_COST``, whichever is larger (the floor
                # covers the retained ``str`` overhead of a tiny value so an
                # empty / tiny value still consumes budget). Per row we charge
                # ``_FOREIGN_DB_PER_ROW_COST`` (>= the row's STRUCTURAL dump bytes
                # -- its ``[`` ``]`` plus its two-byte inter-value separators, at
                # most ``2 * MAX_RESULT_COLUMNS + 2`` = 202 at MAX=100 since
                # ``json.dumps`` separators are two bytes -- plus the retained
                # ``list``), and seed ``total`` with the outer list's ``[`` ``]``.
                # So ``total`` >=
                # ``len(dumps(stringified))`` at every step: aborting the moment
                # ``total > cap`` guarantees the crossing dump is ``<= cap`` for
                # ANY attacker choice of value sizes, column count, row count AND
                # escape content -- closing the escape-expansion vector (an
                # escape-heavy result whose RAW payload is under the cap but whose
                # dump is ~6x it) and the tiny / empty value flood alike. Each
                # value's raw payload is <= its JSON size (escaping only expands),
                # so the retained intermediate is <= cap in raw terms too; both
                # the intermediate and the crossing dump are ``<= cap``, so the
                # host peak (both live during the final serialise) is ~2x cap.
                # The charge drives ONLY the abort; returned data is exact for an
                # under-cap query.
                stringified: list = []
                total = 2 if result_cap is not None else 0  # outer '[' and ']'
                while True:
                    row = cur.fetchone()
                    if row is None:
                        break
                    srow = []
                    if result_cap is not None:
                        total += _FOREIGN_DB_PER_ROW_COST
                    for v in row:
                        s = (
                            "null" if v is None
                            else v if isinstance(v, str) else str(v)
                        )
                        srow.append(s)
                        if result_cap is not None:
                            total += max(
                                len(_stdlib_json.dumps(s)),
                                _FOREIGN_DB_PER_VALUE_COST,
                            )
                            if total > result_cap:
                                raise ForeignResourceExceeded(
                                    f"Db.query result exceeded the foreign "
                                    f"result cap ({result_cap} bytes) -- "
                                    f"the host aborted the fetch before "
                                    f"buffering the whole result set"
                                )
                    stringified.append(srow)
            finally:
                if limit_scoped:
                    # Restore the prior limits before close so a shared /
                    # reused connection never inherits the foreign-query caps.
                    conn.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, prev_len)
                    conn.setlimit(sqlite3.SQLITE_LIMIT_COLUMN, prev_col)
                conn.close()
            return _stdlib_json.dumps(stringified)
        except PostOpenDenied:
            return IoErrorRecord(
                message=f"Db capability does not permit query: {path}"
            )
        except (sqlite3.Error, OSError, ValueError) as e:
            # A single value / row that overran ``SQLITE_LIMIT_LENGTH``
            # (``SQLITE_TOOBIG``) OR a result set wider than
            # ``SQLITE_LIMIT_COLUMN`` ("too many columns in result set")
            # surfaces here; translate ONLY those into the same clean
            # result-cap diagnostic. A genuine SQL / IO error (missing table,
            # syntax error) still surfaces as the existing db error, unswallowed.
            if _is_sqlite_length_limit_error(e):
                raise ForeignResourceExceeded(
                    f"Db.query result exceeded the foreign result cap "
                    f"({result_cap} bytes) -- a single value / row overran the "
                    f"per-value or column bound and sqlite refused to "
                    f"materialise it in host memory"
                ) from e
            return IoErrorRecord(message="SQLite query failed", cause=str(e))

    ifc.add_func("exec", db_exec)
    ifc.add_func("query", db_query)
    ifc.add_func("restrict-to", lambda _s, _h, _p: 0)
    ifc.add_func("allows", lambda _s, _h, p: bool(db.allows(p)))
    ifc.close()


def _bind_proc(root: wc.LinkerInstance, proc: Proc, _result_cap: int | None) -> None:
    import subprocess

    # NOTE: ``proc.exec`` stdout is NOT result-capped here. Bounding it
    # needs a STREAMING subprocess read (``subprocess.run`` already
    # buffers the whole ``capture_output`` before this closure sees it),
    # a distinct axis from the fs / net / db host buffers this change
    # bounds. Left out of scope deliberately; proc keeps its 30s timeout.
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


def _bind_stdio(root: wc.LinkerInstance, _stdio: Stdio, _result_cap: int | None) -> None:
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


def _bind_random(root: wc.LinkerInstance, _random: Random, _result_cap: int | None) -> None:
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
