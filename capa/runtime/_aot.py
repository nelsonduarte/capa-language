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

1. **Param names are lost.** ``WasmHost.run_main`` recovers ``main``'s
   capability parameter names from the ``name`` custom section of the
   ``.wasm`` (to hand each i32 slot the right root handle). The
   serialized ``.cwasm`` is wasmtime's internal machine-code format,
   not a ``.wasm``; it does not carry a readable name section. We
   therefore extract the param names from the ``.wasm`` BEFORE
   serialising and store them in the container header.

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
                    "main_param_names": [str, ...]}
    cwasm        the rest of the file: Module.serialize() bytes
"""

from __future__ import annotations

import json
import struct
from typing import Optional

_MAGIC = b"CPAO"
_FORMAT_VERSION = 1


def _wasmtime_version() -> str:
    import importlib.metadata as md
    try:
        return md.version("wasmtime")
    except Exception:  # pragma: no cover - metadata always present in practice
        return "unknown"


def build_aot(wasm_blob: bytes, *, capa_version: str) -> bytes:
    """Compile ``wasm_blob`` (a binary ``.wasm``) to a portable AOT
    container.

    Extracts ``main``'s parameter names from the ``.wasm`` name section
    (so the loader can still map cap handles), serialises the module
    via wasmtime/Cranelift, and wraps both in the container described in
    the module docstring. Raises ``RuntimeError`` with a clear message
    if wasmtime is unavailable."""
    try:
        import wasmtime
    except ImportError as e:  # pragma: no cover - exercised without the dep
        raise RuntimeError(
            "AOT build needs the 'wasmtime' package; install it with "
            "`pip install wasmtime`"
        ) from e

    # Recover the param names from the source .wasm BEFORE serialising
    # -- the serialized form drops the name section.
    from ._wasm_host import _read_main_param_names

    # n_params: ask the module's main export how many params it takes.
    engine = wasmtime.Engine()
    module = wasmtime.Module(engine, wasm_blob)
    n_params = _main_param_count(module)
    param_names = _read_main_param_names(wasm_blob, n_params)

    cwasm = module.serialize()

    header = {
        "capa_version": capa_version,
        "wasmtime_version": _wasmtime_version(),
        "main_param_names": list(param_names),
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


def aot_main_param_names(header: dict) -> list[str]:
    """The ``main`` parameter names recorded at build time. Used by the
    host loader to map each i32 slot to a root capability handle, since
    the serialized module has no name section to recover them from."""
    names = header.get("main_param_names")
    return list(names) if isinstance(names, list) else []
