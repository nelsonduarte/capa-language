"""Shared capability-method classification for the Wasm backends.

A Capa program's used capabilities are classified once per artifact
the Wasm backend produces: the core-wasm discovery pass
(``capa.ir._emit_wasm._discovery``) turns them into host imports, and
the WIT collector (``capa.ir._emit_wit.collect_used_capabilities``)
turns them into interface signatures. Both drive the shared
``capa.ir._walk`` traversal, and both used to re-derive the SAME base
classification: resolve the receiver's capability (the lowerer's
``cap_used``, else a built-in receiver type) and split the pure
attenuators (``restrict_to`` / ``restrict_to_keys`` /
``restrict_to_after``) that are elided at emit time from the graduated
ones that cross the host bridge with the parent handle. That mirrored
derivation drifted (the M2b agreement test now guards it), so it lives
here once.

:func:`classify_cap_method` is that single source. Each backend
PROJECTS its result to its own shape (``(cap, method)`` tuples for the
core-wasm imports, a ``cap -> {method}`` map for the WIT interfaces)
and layers its own downstream steps on top: the discovery pass
validates against ``_WIT_SIGNATURES`` and collapses the guest-side
``Random`` methods to ``system_seed``; the WIT collector synthesises
the attenuated-``Clock.sleep`` ``now_secs`` gate and the post-pass
``Random.system_seed`` import. Those syntheses differ between the two
(the documented ``_KNOWN_ASYMMETRIES`` in the agreement test) and so
stay at each projection; only the base classification is shared here.

Kept deliberately thin, like ``_capa_types``: it imports only
``_nodes`` and the capability-set constants, so the WIT generator and
the Wasm discovery pass can both consume it without an import cycle.
"""

from __future__ import annotations

from typing import Optional

from ._nodes import Instr, MethodCall
from ._capa_types import BUILTIN_CAPS


# The pure-attenuator method names. A call to one of these is elided at
# emit time UNLESS it is one of the graduated ``(cap, method)`` combos
# below.
_ATTENUATOR_METHODS: frozenset[str] = frozenset({
    "restrict_to", "restrict_to_keys", "restrict_to_after",
})

# The attenuator ``(cap, method)`` combos that graduated to real host
# calls (audit slices 25.2 - 25.6, 2026-05-30): they take the parent
# handle + the attenuation arg and return a fresh, narrower child
# handle, so they are KEPT rather than elided. The split is by
# attenuator method name, not cap class: Env narrows via
# ``restrict_to_keys`` and Clock via ``restrict_to_after``, so only the
# remaining four share the ``restrict_to`` spelling.
_GRADUATED_ATTENUATORS: frozenset[tuple[str, str]] = frozenset({
    ("Fs", "restrict_to"),
    ("Net", "restrict_to"),
    ("Db", "restrict_to"),
    ("Proc", "restrict_to"),
    ("Env", "restrict_to_keys"),
    ("Clock", "restrict_to_after"),
})


def classify_cap_method(instr: Instr) -> Optional[tuple[str, str]]:
    """Classify one instruction as a KEPT capability method call.

    Returns ``(cap, method)`` when ``instr`` is a ``MethodCall`` whose
    receiver resolves to a capability -- via the lowerer's ``cap_used``,
    else a built-in receiver type -- and whose method is not a pure
    attenuator elided at emit time. Returns ``None`` otherwise: not a
    ``MethodCall``, no resolvable capability, or an elided attenuator
    (``restrict_to`` / ``restrict_to_keys`` / ``restrict_to_after`` on a
    cap that does not graduate that spelling to a host call).

    This is the base classification the core-wasm discovery pass and the
    WIT collector share; each layers its own projection + synthesis on
    the pair returned here.
    """
    if not isinstance(instr, MethodCall):
        return None
    # Prefer the lowerer's ``cap_used``; fall back to the receiver type
    # for impl-method-internal calls where the analyzer does not
    # propagate ``cap_used`` through. This mirrors the emit-side
    # dispatch in the Wasm backend's ``_emit_instr``.
    cap = instr.cap_used
    if not cap:
        rty = instr.receiver.ty or ""
        if rty not in BUILTIN_CAPS:
            return None
        cap = rty
    method = instr.method
    if (method in _ATTENUATOR_METHODS
            and (cap, method) not in _GRADUATED_ATTENUATORS):
        return None
    return (cap, method)
