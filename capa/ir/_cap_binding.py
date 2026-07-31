"""How ``main``'s capability parameters are bound to root handles.

The Wasm hosts must hand each of ``main``'s handle slots the root
capability of the DECLARED type. Until 2026-07-23 they decided that by
matching the parameter's NAME: ``_wasm_host`` read the source-level
identifiers out of the WebAssembly debug ``name`` custom section, the
Component host read the WIT parameter labels, and both fell back to the
``Fs`` root when the name was not one of ``fs`` / ``net`` / ``db`` /
``proc`` / ``env`` / ``clock``. Three consequences, all measured:

* ``fun main(conn: Net, stdio: Stdio)`` got the ``Fs`` root on Wasm, so
  ``conn.allows("example.com")`` answered the opposite of the Python
  backend for the same source.
* ``fun main(net: Fs, ...)`` got the ``Net`` root because of how the
  parameter was SPELLED, and the type mismatch surfaced as an ordinary
  ``Err`` the program could swallow.
* ``wasm-tools strip --all`` removes the ``name`` section, after which
  EVERY slot fell to the ``Fs`` root. A release step changed behaviour.

That contradicts Capa's own claim that the type is the contract. So the
binding is now driven by the declared capability TYPE, carried in
structure that ordinary Wasm tooling cannot strip:

* **Core modules** (``capa --wasm``, run by ``WasmHost``) carry an
  exported global whose EXPORT NAME is
  ``capa:main-cap-types=<kind>,<kind>,...`` in ``main``'s slot order.
  Export names are part of the module's structure, not a custom
  section, so ``wasm-tools strip --all`` leaves them alone.
* **Components** (``capa --component`` / ``--wasi``, run by
  ``WasmComponentHost``) name each handle slot ``cap<N>-<kind>`` in the
  exported WIT world. Those labels are part of the component type.

Both carriers are chosen to be OUT OF REACH of the running program, not
merely strip-proof. Lehmann, Kinder and Pradel ("Everything Old is New
Again: Binary Security of WebAssembly", USENIX Security 2020, section
4.2.3 "Overwriting 'Constant' Data") show that what a compiler treats as
constant is, once it lands in WebAssembly's linear memory, routinely
writable. So the binding lives in NO data segment and NO linear memory:

* the core-module binding is an EXPORT NAME in the export section
  (section id 7), which the host parses out of the module bytes before
  the guest runs and which no Wasm instruction can address;
* the exported global it hangs off is immutable and its value is never
  consulted, so even a ``global.set`` primitive would buy nothing;
* the component binding is part of the component TYPE, which the
  Component Model fixes at instantiation.

Capa itself is memory-safe, so this is not a threat from Capa code. It
matters at the foreign-component boundary, where a module Capa did not
compile shares the address space.

Neither host falls back. A module that carries no binding is refused
with :class:`CapBindingError`; there is no name-matching compatibility
mode, because that path IS the vulnerability.

What this DOES and DOES NOT claim
---------------------------------

Exactly three properties, all of them mechanically checked in
``tests/test_wasm_cap_binding.py``:

1. Which root capability a ``main`` slot receives is decided by the
   parameter's DECLARED TYPE, never by its name.
2. The information that drives that decision is not in a section
   ordinary tooling strips, and not in memory the guest can write.
3. It can never be silently defaulted: an artifact the host cannot
   read a binding out of grants nothing and does not run.

It does NOT deliver WASI's "handles are unforgeable, no ambient
authorities": root handles are small sequential integers, so a guest
can name a handle by writing the integer down. That predates this
module and still holds; what an attacker gains from it changed on
2026-07-31 and now splits in two:

* Cross-capability forgery is CLOSED. Until then the per-instance
  handle table was bootstrapped with a root for EVERY handle-bearing
  cap, so a hand-written module that declared only ``net`` could forge
  the small integer the ``Fs`` root was deterministically assigned,
  call ``capa:host/fs.*`` and read the filesystem.
  ``bootstrap_root_handles`` now allocates a root ONLY for a cap the
  artifact declares, so a forged integer for an UNDECLARED cap resolves
  to no entry (or the wrong-type entry a declared cap occupies) at the
  typed lookup and the op denies. The declared cap set is therefore a
  runtime-enforced upper bound on all three hosts (core, AOT
  ``run-aot``, Component). The linker is unchanged: it still defines
  every ``capa:host/*`` import; the gate is the missing root, not a
  missing import. This restores the honesty of the declared cap set; it
  does NOT make ``run-aot`` a sandbox, since the binding is the
  artifact's own self-declaration and a malicious artifact may declare
  all six caps and receive all six roots.
* Intra-capability widening is still OPEN. Within a cap it DECLARED, a
  guest can still name the unrestricted root instead of a
  ``restrict_to`` child, because those handles are predictable
  integers. This is not a cross-cap escalation, it is authority the
  artifact already holds by declaring the cap, and full handle
  unforgeability (unguessable tokens, or a resource-type migration)
  remains separate, deferred work.

The handle TABLE's typed lookup is what actually contains a forged or
rewritten binding: a slot handed the wrong root fails
``lookup(handle, Fs)`` and the op denies. That containment is only as
good as its coverage, which is why every host bridge must CONSULT the
lookup rather than merely perform it. Three bridges (``now_secs``,
``now_monotonic``, ``env_args``, on both hosts) called it and threw the
result away, so a forged binding was honoured there; they now require
it, and ``TestEveryBridgeRequiresItsReceiver`` fails if a fourth
appears.

This module owns nothing but the encoding and its inverse, so the
emitters and the two hosts cannot drift apart on the wire format.
"""

from __future__ import annotations

from ._capa_types import HANDLE_BEARING_CAPS


# Prefix of the core-module export name that carries the binding. The
# comma-separated cap kinds follow it directly, so the whole export name
# for ``fun main(conn: Net, stdio: Stdio, out: Fs)`` is
# ``capa:main-cap-types=net,fs`` (Stdio is erased on the Wasm side and
# occupies no slot).
MAIN_CAP_TYPES_EXPORT_PREFIX = "capa:main-cap-types="


# Name of the WAT global the export above is attached to. Declared
# IMMUTABLE (``(global $g i32 (i32.const N))``, no ``mut``): the binding
# must not be reachable by anything the module executes, and an
# immutable global cannot be the target of ``global.set`` even from a
# foreign component sharing the instance. The value is the slot count;
# nothing reads it, but a mismatch against the name is an obvious
# tampering tell in a ``wasm-tools dump``.
MAIN_CAP_TYPES_GLOBAL = "__capa_main_cap_types"


# Where each artifact shape is supposed to carry the binding, phrased
# for a diagnostic. A ``.wasm`` has an export name; the AOT container
# is a JSON header and has no sections at all, so pointing its operator
# at an export name sends them looking for something that cannot exist.
CARRIER_WASM_EXPORT = f"no `{MAIN_CAP_TYPES_EXPORT_PREFIX}` export"
CARRIER_AOT_HEADER = "no `main_cap_types` key in the container header"


# The lowercase spellings the wire format accepts, derived from the
# capability registry so a cap reclassified as handle-bearing cannot
# leave this behind.
CAP_KINDS: frozenset[str] = frozenset(
    cap.lower() for cap in HANDLE_BEARING_CAPS
)


class CapBindingError(Exception):
    """A Wasm artifact does not carry a usable capability binding for
    ``main``, so the host cannot tell which root capability each slot
    is entitled to. Never recovered from: the host refuses to run
    rather than hand out an authority the program did not declare."""


# The diagnostic every refusal ends with. Kept in one place so both
# hosts tell the operator the same thing.
#
# Deliberately does NOT say "built by 1.19.0 or earlier". The binding
# landed after the 1.19.0 RELEASE, so a toolchain reporting 1.19.0 is
# either that release (no binding) or a development build past this
# commit (binding present), and naming the version tells half of those
# operators that the version they are running is the broken one.
REBUILD_HINT = (
    "rebuild the artifact with this Capa toolchain (`capa --wasm` / "
    "`capa build`) and re-run. The artifact predates the capability "
    "binding, which was introduced after the 1.19.0 release. There is "
    "deliberately no compatibility mode: the older host inferred the "
    "binding from parameter names in the strippable debug `name` "
    "section, and honouring that inference is the defect"
)


def main_handle_cap_types(module) -> list[str]:
    """The lowercase cap kinds of ``main``'s handle-bearing parameters,
    in declaration order. ``[]`` when ``main`` is absent or declares no
    handle-bearing capability (a ``fun main()`` or Stdio-only program).

    ``module`` is a CIR ``Module``; only ``.functions`` and each
    function's ``.params`` are touched, so both emitters can call this
    without importing anything heavier."""
    for fn in module.functions:
        if fn.name != "main":
            continue
        return [
            p.ty.lower() for p in fn.params if p.ty in HANDLE_BEARING_CAPS
        ]
    return []


def main_cap_types_export_name(cap_types: list[str]) -> str:
    """The core-module export name carrying ``cap_types``. Emitted even
    for the empty list (``capa:main-cap-types=``) so its ABSENCE is an
    unambiguous "built by an older toolchain" signal rather than an
    ambiguous "maybe this program has no cap params"."""
    return MAIN_CAP_TYPES_EXPORT_PREFIX + ",".join(cap_types)


def parse_main_cap_types_export_name(name: str) -> list[str] | None:
    """Inverse of :func:`main_cap_types_export_name`. ``None`` when
    ``name`` is not the binding export at all; the caller distinguishes
    "wrong export" from "no cap params" (which yields ``[]``)."""
    if not name.startswith(MAIN_CAP_TYPES_EXPORT_PREFIX):
        return None
    rest = name[len(MAIN_CAP_TYPES_EXPORT_PREFIX):]
    if not rest:
        return []
    return rest.split(",")


def wit_cap_slot_name(index: int, cap: str) -> str:
    """The WIT label for ``main``'s handle slot ``index`` holding
    capability ``cap`` (a ``HANDLE_BEARING_CAPS`` member).

    ``cap0-net``. WIT labels are strict kebab-case (each dash-separated
    word starts with a lowercase letter), which is why the index rides
    inside the ``cap`` word rather than standing alone. The index is
    redundant with the parameter position and is checked against it, so
    a component whose labels were rewritten out of order is refused
    instead of silently permuting authorities."""
    return f"cap{index}-{cap.lower()}"


def parse_wit_cap_slot_name(name: str) -> tuple[int, str] | None:
    """Inverse of :func:`wit_cap_slot_name`, returning ``(index, kind)``
    or ``None`` when ``name`` is not a slot label this toolchain emits
    (an older component's plain ``fs`` / ``net`` labels land here)."""
    head, sep, kind = name.partition("-")
    if not sep or not head.startswith("cap"):
        return None
    digits = head[len("cap"):]
    if not digits.isdigit():
        return None
    return int(digits), kind


def resolve_cap_types(
    cap_types: list[str] | None,
    n_slots: int,
    *,
    artifact: str,
    carrier: str,
) -> list[str]:
    """Validate a decoded binding against the arity ``main`` actually
    declares, raising :class:`CapBindingError` with a diagnostic naming
    the problem. Returns ``cap_types`` unchanged when it is usable.

    ``artifact`` describes what was loaded (``"module"`` / ``"AOT
    artifact"``), so the message tells the operator which file to
    rebuild. ``carrier`` names where the binding SHOULD have been, and
    differs per artifact: the ``.wasm`` carries an export name, the AOT
    container a JSON key. Naming the export in an AOT diagnostic sent
    the operator looking for a section its format does not have."""
    if cap_types is None:
        raise CapBindingError(
            f"this {artifact} declares no capability binding for `main` "
            f"({carrier}), so the host cannot tell which root capability "
            f"each of `main`'s handle slots is entitled to; {REBUILD_HINT}"
        )
    if len(cap_types) != n_slots:
        raise CapBindingError(
            f"this {artifact} declares a capability binding for "
            f"{len(cap_types)} slot(s) ({', '.join(cap_types) or 'none'}) "
            f"but its `main` export takes {n_slots}; the binding does not "
            f"describe the module it travels with, so no capability is "
            f"granted. {REBUILD_HINT}"
        )
    unknown = [k for k in cap_types if k not in CAP_KINDS]
    if unknown:
        raise CapBindingError(
            f"this {artifact} binds `main` to unknown capability "
            f"kind(s) {', '.join(repr(k) for k in unknown)}; known kinds "
            f"are {', '.join(sorted(CAP_KINDS))}. No capability is "
            f"granted. {REBUILD_HINT}"
        )
    return cap_types
