"""Shared type-level constants used by the IR backends.

Both the lowerer and the two emitters (Python + Wasm) need the
same view of "what is a built-in capability". Before this module
existed the set was duplicated across [`capa/ir/_lower.py`](_lower.py),
[`capa/ir/_emit_wit.py`](_emit_wit.py), and
[`capa/ir/_emit_wasm/_layout.py`](_emit_wasm/_layout.py); the
duplication was load-bearing because each file produced WAT or
WIT against its own copy of the set, so drift would silently
diverge backend output. Audit 2026-05-25 (item #7) called the
copies out as the single biggest correctness lever after the
inline helper duplication.

This module deliberately contains nothing except the constants
the three call sites need. Anything that ships logic alongside
the data belongs in the calling module so the dependency graph
stays shallow.
"""

from __future__ import annotations


# Built-in capability type names. Receivers of these types route
# their method calls to host imports (Wasm) or to capability
# classes from ``capa.runtime`` (Python). The set must match
# ``capa.typesys.CAPABILITY_NAMES`` and ``capa.builtins``'s
# registered capability classes; the cross-check that keeps the
# copies in lockstep is ``TestCapabilityRegistry`` in
# [`tests/test_cap_handles.py`](../../tests/test_cap_handles.py).
# (This comment used to promise ``tests/test_properties.py``, but
# that module skips wholesale when Hypothesis is absent and a
# registry guard must never be skippable.)
BUILTIN_CAPS: frozenset[str] = frozenset({
    "Stdio", "Fs", "Net", "Env", "Clock", "Random", "Proc", "Db",
    "Serve", "Unsafe",
})


# The built-in caps the Wasm backends cannot implement at all. A
# program whose signatures reach one of these is rejected up front
# with a diagnostic naming the offending sites, so it never reaches
# lowering or the host bridges.
#
# TWO independent paths must reject, because each is reachable on
# its own: the Wasm emitter's discovery pass (``capa --wasm``) and
# WIT generation (``capa --wit``, which never runs the emitter). The
# shared reachability scan they both call lives in
# [`_python_only_caps.py`](_python_only_caps.py).
#
# These are PERMANENT stances, not backlog items:
#
# - ``Unsafe`` grants raw pointer / FFI / mmap-class primitives that
#   have no sandboxed Wasm equivalent (slice 7 / D5, 2026-05).
# - ``Serve`` needs ``wasi:sockets`` to bind a listening socket. That
#   world is not vendored in ``capa/wasi_wit`` and is not reachable
#   from the wasmtime-py 44 bindings the hosts are built on, so there
#   is no inbound socket for the guest to be handed (2026-07).
PYTHON_ONLY_CAPS: frozenset[str] = frozenset({
    "Unsafe", "Serve",
})


# The built-in caps that are UN-ERASED on the Wasm side: each one
# lowers to a real i32 handle into the host's per-instance cap
# table, so a restricted cap keeps its restriction across function
# boundaries (audit slices 25.2 - 25.6, 2026-05-30). A handle
# occupies a Wasm slot everywhere a value can live: params, locals,
# struct fields, closure environments, call args, return values,
# and ``main``'s exported signature.
#
# The complement (``ERASED_CAPS`` below) pushes no Wasm value at
# all: those caps have no attenuation surface to thread.
#
# Every built-in capability MUST appear in exactly one of the two
# sets; ``TestCapabilityRegistry`` in
# [`tests/test_cap_handles.py`](../../tests/test_cap_handles.py)
# fails if a new name lands in ``BUILTIN_CAPS`` without that
# decision being recorded here.
HANDLE_BEARING_CAPS: frozenset[str] = frozenset({
    "Fs", "Net", "Db", "Proc", "Env", "Clock",
})


# The deliberately-erased complement. Spelled out rather than
# derived from ``BUILTIN_CAPS - HANDLE_BEARING_CAPS`` so that adding
# a capability forces an explicit choice instead of silently
# defaulting to "erased".
#
# ``Unsafe`` and ``Serve`` are here because they are members of
# ``PYTHON_ONLY_CAPS``: the Wasm backends reject them before lowering,
# so neither ever reaches a Wasm slot and "handle-bearing" would be a
# claim about codegen that never runs. Erased is also the SAFER
# classification for a rejected cap. If the rejection ever developed a
# hole, an erased cap pushes no value and the module fails to link
# against a host import nobody defined (loud); a handle-bearing cap
# would occupy an i32 slot with no entry in the host's root-handle
# map and silently fall back to the ``Fs`` root, which is exactly the
# quiet cross-cap substitution
# ``test_host_root_handle_map_covers_every_handle_bearing_cap``
# exists to prevent.
ERASED_CAPS: frozenset[str] = frozenset({
    "Stdio", "Random", "Unsafe", "Serve",
})
