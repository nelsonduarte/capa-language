"""Capability handle table for the Wasm runtime.

The Wasm backend has no native value representation for capabilities
(the analyzer enforces cap discipline at compile time, and the
emitter currently inlines ``restrict_to(...)`` checks at the literal
call site in the same function). Audit slice 25 (2026-05-30) found
that this inline approach loses all enforcement the moment a
restricted cap crosses any function boundary on Wasm; the Python
backend is sound because caps are first-class objects whose
restriction state travels with the value.

The fix (designed in ``docs/design/wasm-cap-handles.md``) makes cap
values on Wasm into i32 handles into a host-side table. Every
privileged host import looks up the handle, enforces the
restriction, then performs the syscall. This module is the
foundation: the table data structure + per-cap allocation helpers +
the root-handle bootstrap the host uses when invoking ``main``.

Slices 25.2 - 25.8 will wire this into the Wasm emitter and the
host bridges. Slice 25.1 (this slice) lands the foundation alone so
the wiring slices have a stable target.

Lifecycle
---------
- Handles are immutable. ``restrict_to(...)`` never mutates the
  source handle; it allocates a fresh one bound to a new
  restriction object.
- Handle ``0`` is reserved as a "no cap" sentinel; valid root
  handles start at ``1``.
- The table grows monotonically per Wasm instance. Wasm program
  lifetime in the common case is a single CLI invocation, so
  sticky handles are fine; long-running deployments would need
  GC, tracked as a future P3.
- One table per ``WasmHost`` / ``WasmComponentHost`` instance. The
  table is reset on instance teardown by simply dropping the host
  object (Python GC takes care of the entries).
"""

from __future__ import annotations

from typing import Optional, TypeVar

from ..ir._capa_types import HANDLE_BEARING_CAPS
from ..ir._cap_binding import CapBindingError
from ._capabilities import (
    Clock,
    Db,
    Env,
    Fs,
    Net,
    Proc,
    Random,
    Stdio,
    Unsafe,
)


# Union of every restriction-bearing cap object the table holds. The
# table's values are exactly the Python-side capability instances
# the existing runtime already carries; the table just maps a stable
# i32 handle to that object so the Wasm side can pass the handle
# across function boundaries.
CapValue = Clock | Db | Env | Fs | Net | Proc | Random | Stdio | Unsafe

T = TypeVar("T", bound=CapValue)


class CapHandleTable:
    """Maps i32 handles to the capability objects they represent.

    Per-instance. The host creates one of these per Wasm instance,
    populates it with root handles (the unrestricted caps the host
    holds for that program), and exposes the relevant ones through
    the cap-allocation imports.

    The Python-side capability classes
    (``capa.runtime._capabilities``) are reused verbatim - the table
    holds references; allocation helpers delegate restriction to the
    cap's own ``restrict_to`` / ``restrict_to_keys`` / etc. methods,
    which means restriction monotonicity and intersection semantics
    are inherited from the existing classes (no duplication).
    """

    __slots__ = ("_entries", "_next")

    def __init__(self) -> None:
        # Handle 0 is reserved as a "no cap" sentinel so a zero
        # handle from a buggy emitter immediately fails lookup
        # rather than silently aliasing a real cap. Real handles
        # start at 1.
        self._entries: dict[int, CapValue] = {}
        self._next: int = 1

    def alloc(self, cap: CapValue) -> int:
        """Insert ``cap`` and return its fresh handle.

        Used by both root-handle bootstrap (called once per cap at
        instance init) and per-call cap-allocation imports
        (``capa:host/fs.restrict-to`` etc., which allocate a fresh
        restricted cap on each invocation)."""
        h = self._next
        self._next += 1
        self._entries[h] = cap
        return h

    def lookup(self, handle: int, expected: type[T]) -> T:
        """Return the cap object for ``handle``, type-checked
        against ``expected``.

        Raises ``CapHandleError`` if the handle is unknown or the
        cap object isn't of the expected type. The type check
        defends against an emitter bug that passed an Fs handle
        where a Net handle was expected: better a loud failure at
        the host bridge than a silent cross-cap escalation."""
        cap = self._entries.get(handle)
        if cap is None:
            raise CapHandleError(
                f"unknown capability handle {handle}; either it "
                f"was never allocated for this instance, or it is "
                f"the reserved zero sentinel"
            )
        if not isinstance(cap, expected):
            raise CapHandleError(
                f"capability handle {handle} resolves to "
                f"{type(cap).__name__}, expected "
                f"{expected.__name__}: emitter / host bridge "
                f"mismatch"
            )
        return cap

    def restrict_fs(self, handle: int, prefix: str) -> int:
        """Allocate a new Fs handle representing
        ``handle.restrict_to(prefix)``. Mirrored signature for the
        other ``restrict_*`` helpers, one per cap. Each delegates
        to the underlying cap class's restriction logic so
        monotonicity + intersection semantics are inherited."""
        fs = self.lookup(handle, Fs)
        return self.alloc(fs.restrict_to(prefix))

    def restrict_net(self, handle: int, host: str) -> int:
        net = self.lookup(handle, Net)
        return self.alloc(net.restrict_to(host))

    def restrict_db(self, handle: int, prefix: str) -> int:
        db = self.lookup(handle, Db)
        return self.alloc(db.restrict_to(prefix))

    def restrict_proc(self, handle: int, name: str) -> int:
        proc = self.lookup(handle, Proc)
        return self.alloc(proc.restrict_to(name))

    def restrict_env(self, handle: int, keys: list[str]) -> int:
        env = self.lookup(handle, Env)
        return self.alloc(env.restrict_to_keys(keys))

    def restrict_clock_after(self, handle: int, ts: int) -> int:
        clock = self.lookup(handle, Clock)
        return self.alloc(clock.restrict_to_after(ts))

    def __len__(self) -> int:
        return len(self._entries)


class CapHandleError(RuntimeError):
    """Raised by the host bridge when a Wasm program passes a
    capability handle the table doesn't know, or a handle pointing
    to the wrong cap type. Either signals an emitter bug or a
    corrupted / forged Wasm module; the host fails loud rather
    than silently performing the syscall."""


def bootstrap_root_handles(
    table: CapHandleTable,
    *,
    stdio: Optional[Stdio] = None,
    fs: Optional[Fs] = None,
    net: Optional[Net] = None,
    env: Optional[Env] = None,
    clock: Optional[Clock] = None,
    random: Optional[Random] = None,
    db: Optional[Db] = None,
    proc: Optional[Proc] = None,
    unsafe: Optional[Unsafe] = None,
) -> dict[str, int]:
    """Allocate root handles for every cap the host will pass to
    ``main``. Returns a name -> handle dict the host bridge uses
    when invoking the program's entry point.

    Caps not passed are simply absent from the result dict; ``main``
    declarations that ask for them will fail at link time (the
    discovery walker already enforces this independently)."""
    out: dict[str, int] = {}
    for name, cap in (
        ("stdio", stdio),
        ("fs", fs),
        ("net", net),
        ("env", env),
        ("clock", clock),
        ("random", random),
        ("db", db),
        ("proc", proc),
        ("unsafe", unsafe),
    ):
        if cap is not None:
            out[name] = table.alloc(cap)
    return out


def root_handle_map(roots: dict) -> dict[str, int]:
    """Map a capability KIND (``fs`` / ``net`` / ...) to the root
    handle a ``main`` slot of that declared type receives.

    DERIVED from ``HANDLE_BEARING_CAPS`` rather than hand-listed, so
    reclassifying a capability as handle-bearing cannot leave this map
    behind. It was a hardcoded six-entry literal in ``_wasm_host`` until
    2026-07-18, and duplicated a second time in
    ``_wasm_component_host``.

    Keyed by cap kind since 2026-07-23. Both hosts used to key it by
    ``main``'s source PARAM NAME, which is what let ``fun main(conn:
    Net, ...)`` miss every key and take their Fs fallback.

    A handle-bearing cap with no root in ``roots`` raises rather than
    yielding the ``0`` sentinel: a slot silently bound to 0 would fail
    only at the first privileged call, and only for the ops that check.

    Lives here rather than in either host so the two cannot drift, and
    so the registry guard in ``tests/test_cap_handles.py`` can assert
    against the real map without importing wasmtime. Deliberately NOT
    ``bootstrap_root_handles``' output, which is a strictly larger dict
    (it also serves the erased caps).
    """
    out: dict[str, int] = {}
    for cap in HANDLE_BEARING_CAPS:
        kind = cap.lower()
        handle = roots.get(kind)
        if not handle:
            raise CapBindingError(
                f"the host bootstrapped no root handle for the "
                f"{cap!r} capability, so a `main` slot declaring it "
                f"cannot be bound; no capability is granted"
            )
        out[kind] = handle
    return out
