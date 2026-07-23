"""Ahead-of-time (AOT) Capa artifacts: ``capa build --release``.

The Wasm pipeline (``capa.ir.compile_wasm``) already produces a binary
``.wasm`` module that ``WasmHost`` JIT-compiles and runs on every
invocation. ``--run`` therefore pays the Cranelift compile cost each
time. This module adds the "compile once, run many" path: serialise the
wasmtime ``Module`` (Cranelift-compiled machine code) to a ``.cwasm``
blob via ``Module.serialize()`` and load it back with
``Module.deserialize()`` -- near-native execution with no recompile and
no new backend (roadmap P1, see docs/design/roadmap-technical-detail.md).

Two problems the raw serialized blob does not solve, handled by the
container format below:

1. **The capability binding is lost.** ``WasmHost.run_main`` reads
   which capability TYPE each of ``main``'s i32 slots is entitled to
   from the ``capa:main-cap-types=`` export name of the ``.wasm``
   (see :mod:`capa.ir._cap_binding`). The serialized ``.cwasm`` is
   wasmtime's internal machine-code format, not a ``.wasm``; it has no
   export names to read back. We therefore extract the binding from
   the ``.wasm`` BEFORE serialising and store it in the container
   header.

2. **Non-portability.** A ``.cwasm`` is specific to the exact wasmtime
   version (and target) that produced it; ``Module.deserialize`` of a
   mismatched blob is undefined/erroring. We stamp the wasmtime version
   into the header and refuse a mismatch with a clean error rather than
   a crash.

Container layout (all integers little-endian)::

    magic        4 bytes   b"CPAO"   (CaPa Aot)
    format_ver   u32       container format version (1)
    header_len   u32       length of the JSON header that follows
    header       header_len bytes, UTF-8 JSON:
                   {"capa_version": str,
                    "wasmtime_version": str,
                    "main_cap_types": [str, ...]}
    cwasm        the rest of the file: Module.serialize() bytes
"""

from __future__ import annotations

import json
import struct
from typing import Optional

from ..ir._cap_binding import resolve_cap_types

_MAGIC = b"CPAO"
# Bumped to 2 on 2026-07-23: the header carries ``main_cap_types``
# (the declared capability TYPE of each of ``main``'s slots) where it
# used to carry ``main_param_names``. A version-1 container is refused
# by :func:`parse_aot` rather than read with the old key, because the
# old key drove a name-matching binding that fell back to the Fs root
# for any unrecognised name.
_FORMAT_VERSION = 2


def _wasmtime_version() -> str:
    import importlib.metadata as md
    try:
        return md.version("wasmtime")
    except Exception:  # pragma: no cover - metadata always present in practice
        return "unknown"


def build_aot(wasm_blob: bytes, *, capa_version: str) -> bytes:
    """Compile ``wasm_blob`` (a binary ``.wasm``) to a portable AOT
    container.

    Extracts ``main``'s capability binding from the ``.wasm`` export
    section (so the loader can still map cap handles), serialises the
    module via wasmtime/Cranelift, and wraps both in the container
    described in the module docstring. Raises ``RuntimeError`` with a
    clear message if wasmtime is unavailable, or ``CapBindingError`` if
    the source module carries no binding to copy forward."""
    try:
        import wasmtime
    except ImportError as e:  # pragma: no cover - exercised without the dep
        raise RuntimeError(
            "AOT build needs the 'wasmtime' package; install it with "
            "`pip install wasmtime`"
        ) from e

    # Recover the capability binding from the source .wasm BEFORE
    # serialising -- the serialized form has no export names.
    from ._wasm_host import _read_main_cap_types

    # n_params: ask the module's main export how many params it takes.
    engine = wasmtime.Engine()
    module = wasmtime.Module(engine, wasm_blob)
    n_params = _main_param_count(module)
    cap_types = resolve_cap_types(
        _read_main_cap_types(wasm_blob), n_params, artifact="module",
    )

    cwasm = module.serialize()

    header = {
        "capa_version": capa_version,
        "wasmtime_version": _wasmtime_version(),
        "main_cap_types": list(cap_types),
    }
    header_bytes = json.dumps(header).encode("utf-8")

    return b"".join([
        _MAGIC,
        struct.pack("<I", _FORMAT_VERSION),
        struct.pack("<I", len(header_bytes)),
        header_bytes,
        cwasm,
    ])


def _main_param_count(module) -> int:
    """Number of params the module's ``main`` export takes. Returns 0
    if main is absent or has no params (the legacy no-cap shape)."""
    for exp in module.exports:
        if exp.name == "main":
            try:
                return len(list(exp.type.params))
            except Exception:
                return 0
    return 0


class AotError(RuntimeError):
    """Raised when an AOT container cannot be loaded: bad magic,
    unknown format version, or a wasmtime-version mismatch that makes
    the embedded ``.cwasm`` unsafe to deserialize."""


def parse_aot(blob: bytes) -> tuple[dict, bytes]:
    """Split an AOT container into ``(header_dict, cwasm_bytes)``.

    Raises ``AotError`` on a bad magic or an unknown container format
    version. Does NOT check the wasmtime version (that is the loader's
    job, in :func:`load_aot`, so a tool that only wants the header can
    read it without a wasmtime install)."""
    if len(blob) < 12 or blob[:4] != _MAGIC:
        raise AotError(
            "not a Capa AOT artifact (bad magic); expected a file "
            "produced by `capa build --release`"
        )
    fmt_ver, header_len = struct.unpack("<II", blob[4:12])
    if fmt_ver != _FORMAT_VERSION:
        raise AotError(
            f"AOT container format version {fmt_ver} is not supported "
            f"by this toolchain (expected {_FORMAT_VERSION}); rebuild "
            f"with `capa build --release`"
        )
    header_end = 12 + header_len
    if len(blob) < header_end:
        raise AotError("AOT container is truncated (header runs past EOF)")
    header = json.loads(blob[12:header_end].decode("utf-8"))
    cwasm = blob[header_end:]
    return header, cwasm


def load_aot(blob: bytes, engine=None):
    """Load an AOT container, returning ``(module, header)`` where
    ``module`` is a deserialized ``wasmtime.Module`` ready to
    instantiate.

    ``engine`` MUST be the same ``wasmtime.Engine`` the module will be
    instantiated against -- wasmtime refuses cross-Engine
    instantiation, so the host passes its own engine here. When
    ``None`` a fresh engine is created (useful for header inspection /
    tests that don't instantiate).

    Raises ``AotError`` if the embedded ``.cwasm`` was produced by a
    different wasmtime version than the one running now (deserializing a
    mismatched blob is unsafe), or on any container-format problem."""
    try:
        import wasmtime
    except ImportError as e:  # pragma: no cover
        raise AotError(
            "loading an AOT artifact needs the 'wasmtime' package"
        ) from e

    header, cwasm = parse_aot(blob)
    built_with = header.get("wasmtime_version")
    running = _wasmtime_version()
    if built_with != running:
        raise AotError(
            f"this AOT artifact was built with wasmtime {built_with} but "
            f"this toolchain runs wasmtime {running}; a serialized module "
            f"is only valid for the exact wasmtime version that produced "
            f"it. Rebuild with `capa build --release`."
        )

    if engine is None:
        engine = wasmtime.Engine()
    module = wasmtime.Module.deserialize(engine, cwasm)
    return module, header


def aot_main_cap_types(header: dict) -> list[str] | None:
    """The declared capability type of each of ``main``'s handle slots,
    recorded at build time. Used by the host loader to map each i32
    slot to a root capability handle, since the serialized module has
    no export names to recover them from.

    ``None`` when the header carries no usable binding; the host then
    refuses to run rather than granting a default authority."""
    kinds = header.get("main_cap_types")
    if not isinstance(kinds, list):
        return None
    if not all(isinstance(k, str) for k in kinds):
        return None
    return list(kinds)
