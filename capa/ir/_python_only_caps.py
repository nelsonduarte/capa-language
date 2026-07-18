"""Rejection of capabilities that only work on the Python backend.

``PYTHON_ONLY_CAPS`` (see [`_capa_types.py`](_capa_types.py)) names the
built-in capabilities no Wasm backend can implement. Two independent
emit paths must refuse a program that reaches one:

- the Wasm emitter's discovery pass
  ([`_emit_wasm/_discovery.py`](_emit_wasm/_discovery.py)), and
- WIT generation ([`_emit_wit.py`](_emit_wit.py)), which is reachable
  on its own via ``capa --wit`` WITHOUT going through the Wasm
  emitter.

The reachability scan lives here, once, rather than in either caller.
Duplicating it is exactly the failure mode ``_capa_types``' own
docstring warns about: two copies of a security-relevant predicate
drift, and the drift is silent. Keeping the reason strings next to the
scan also means a new Python-only capability is explained identically
on every path that rejects it.

This module deliberately raises nothing itself. The two callers have
different exception types (``WasmEmissionError`` vs
``UnsupportedCapability``) and both are meaningful to their own users,
so the shared code produces the offender list and the message text and
lets each caller raise in its own vocabulary.
"""

from __future__ import annotations

import re

from ._capa_types import PYTHON_ONLY_CAPS


# Why each ``PYTHON_ONLY_CAPS`` member cannot work on Wasm, phrased to
# sit inside "the X capability is intentionally not supported on the
# Wasm backend (...)". These are permanent stances, not backlog items,
# and the wording says so: someone who reads "not supported" should not
# go looking for the tracking issue.
PYTHON_ONLY_CAP_REASONS: dict[str, str] = {
    "Unsafe": (
        "it grants raw pointer / FFI / memory-map primitives that "
        "have no sandboxed Wasm equivalent"
    ),
    "Serve": (
        "binding a listening socket needs wasi:sockets, which is "
        "neither vendored in capa/wasi_wit nor reachable from the "
        "wasmtime-py bindings the Wasm hosts are built on, so a "
        "guest can never be handed an inbound connection"
    ),
}


def _type_name_tokens(ty: str) -> set[str]:
    """Every type-name identifier appearing in a CIR type string,
    including generic args and tuple elements. A simple word scan is
    sound for the reachability check: the only false positives would be
    a user type whose name happens to be a substring of another, which
    the ``\\b`` boundaries rule out."""
    if not ty:
        return set()
    return set(re.findall(r"[A-Za-z_]\w*", ty))


def _cap_bearing_type_names(module, cap: str) -> set[str]:
    """Fixpoint set of struct / sum type names that transitively reach
    ``cap`` through a field or variant payload, so a parameter of such
    a type is caught even when ``cap`` never appears literally in the
    signature (audit 2026-06-17 C5(b))."""
    field_tys: dict[str, list[str]] = {}
    for decl in module.types:
        fields = getattr(decl, "fields", None)
        if fields is not None:
            field_tys[decl.name] = [f.ty for f in fields]
            continue
        variants = getattr(decl, "variants", None)
        if variants is not None:
            field_tys[decl.name] = [
                pty for v in variants for pty in v.payload_tys
            ]
    bearing: set[str] = set()
    changed = True
    while changed:
        changed = False
        for name, tys in field_tys.items():
            if name in bearing:
                continue
            for ty in tys:
                toks = _type_name_tokens(ty)
                if cap in toks or toks & bearing:
                    bearing.add(name)
                    changed = True
                    break
    return bearing


def find_offending_sites(module, cap: str) -> list[str]:
    """Every parameter in ``module`` whose type reaches ``cap``,
    rendered as a human-readable site label.

    Covers top-level functions and impl methods. The walk goes
    RECURSIVELY through named struct fields, sum-variant payloads, and
    generic arguments, so a parameter of a type that merely *contains*
    the capability (``type Wrapper { u: Unsafe }``) is caught rather
    than slipping through to emit an invalid call.

    Known limit: a capability reached ONLY through ``self`` inside an
    impl method is not listed as its own site. Such a module is still
    rejected, because constructing the receiver struct requires a
    parameter of the capability's type somewhere, and THAT parameter is
    listed. So the rejection is not missed; only the site list is less
    complete than it could be.
    """
    bearing = _cap_bearing_type_names(module, cap)

    def reaches(ty: str) -> bool:
        for name in _type_name_tokens(ty):
            if name == cap or name in bearing:
                return True
        return False

    sites: list[str] = []
    for fn in module.functions:
        for p in fn.params:
            if reaches(p.ty):
                sites.append(f"{fn.name}({p.name}: {p.ty})")
    for impl in module.impls:
        impl_label = (
            f"impl {impl.trait_name} for {impl.type_name}"
            if impl.trait_name else f"impl {impl.type_name}"
        )
        for method in impl.methods:
            for p in method.params:
                if reaches(p.ty):
                    sites.append(
                        f"{impl_label}::{method.name}({p.name}: {p.ty})"
                    )
    return sites


def format_rejection(cap: str, sites: list[str], *, note: str = "") -> str:
    """The diagnostic text for a rejected capability: what, why, what
    to do instead, and where.

    The subject is always "the Wasm backend", on every path, because
    WIT generation exists only to describe a Wasm component -- a
    program that cannot run on Wasm has no meaningful WIT either. The
    caller's own prefix (``capa: --wasm:`` / ``capa: --wit:``) already
    tells the user which command they ran. ``note`` appends a
    path-specific sentence where one genuinely adds information."""
    listed = "\n  - ".join(sites)
    extra = f" {note}" if note else ""
    return (
        f"the {cap} capability is intentionally not supported "
        f"on the Wasm backend ({PYTHON_ONLY_CAP_REASONS[cap]}). "
        f"Use the Python backend for these functions, or "
        f"refactor to remove the {cap} parameter.{extra}\n  - "
        f"{listed}"
    )


def find_rejection(module, *, note: str = ""):
    """Return ``(cap, message)`` for the first Python-only capability
    ``module`` reaches, or ``None`` if it reaches none.

    Per-capability rather than aggregated on purpose: the members have
    entirely different reasons and entirely different "what to do
    instead", so one raise naming one capability is more useful than a
    combined message. Iteration is sorted for a deterministic
    diagnostic when a program somehow reaches two.
    """
    for cap in sorted(PYTHON_ONLY_CAPS):
        sites = find_offending_sites(module, cap)
        if sites:
            return cap, format_rejection(cap, sites, note=note)
    return None
