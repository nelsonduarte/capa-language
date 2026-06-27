"""Capa IR (CIR): intermediate representation between the typed AST
and the emit-target backends.

Goals:

- Decouple the language semantics (lowered into IR instructions) from
  the emission of any specific target (currently Python source; in the
  future, WebAssembly Component Model bytecode + WIT, or LLVM IR, or
  Cranelift IR).
- Preserve capability annotations at every function boundary and at
  every capability-method-call site, so backends targeting capability-
  aware platforms (Wasm CM via WIT) can emit them verbatim.
- Carry per-value type information so type-aware lowering decisions
  (method dispatch, manifest extraction) stay possible after the AST
  is gone.

Phase 1 scope (this commit): the IR data classes, an AST -> IR lowering
pass for a small subset of the language (function declarations with
literal / identifier / binary-op / call / method-call expressions, plus
let / return / expression statements), and a Python emitter from IR.
The legacy direct AST -> Python transpiler remains the default; the
IR path is opt-in via the ``compile()`` entrypoint below, used by the
IR tests until coverage is complete.

The IR is intentionally three-address / ANF-flavoured: every operation
binds its result to a fresh local. This is what Wasm and LLVM-class
backends prefer; the alternative (tree-structured expressions) would
work for Python emission but force re-flattening on every other
backend.
"""

from __future__ import annotations

from .. import capa_ast as A
from ._nodes import Module, Function, Param, Local, Value, Instr
from ._lower import Lowerer, UnsupportedInIR
from ._emit_python import PythonEmitter
from ._emit_wasm import WasmEmitter, WasmEmissionError
from ._emit_wit import (
    emit_wit, collect_used_capabilities, UnsupportedCapabilityMethod,
)
from ._env_ceiling import (
    EnvCeiling, compute_env_ceiling, compute_env_ceiling_from_cir,
)
from ._fs_ceiling import (
    FsCeiling, FsPreopen, compute_fs_ceiling,
    compute_fs_ceiling_from_cir, mkdir_prefixes, resolve_fs_call,
)

__all__ = [
    "Module",
    "Function",
    "Param",
    "Local",
    "Value",
    "Instr",
    "Lowerer",
    "UnsupportedInIR",
    "PythonEmitter",
    "WasmEmitter",
    "WasmEmissionError",
    "UnsupportedCapabilityMethod",
    "lower",
    "emit_python",
    "emit_wat",
    "emit_wit",
    "collect_used_capabilities",
    "EnvCeiling",
    "compute_env_ceiling",
    "compute_env_ceiling_from_cir",
    "FsCeiling",
    "FsPreopen",
    "compute_fs_ceiling",
    "compute_fs_ceiling_from_cir",
    "mkdir_prefixes",
    "resolve_fs_call",
    "compile",
    "compile_program",
    "compile_wat",
    "compile_wasm",
    "compile_wit",
    "read_wasm_manifest",
]


def lower(module: A.Module, types: dict | None = None) -> Module:
    """Lower a typed AST module to CIR.

    Raises ``UnsupportedInIR`` if the module contains constructs the
    Phase 1 lowering does not yet handle. Caller is expected to catch
    and fall back to the legacy transpiler in that case.
    """
    return Lowerer(types=types or {}).lower_module(module)


def emit_python(ir_module: Module) -> str:
    """Emit Python source from a CIR module."""
    return PythonEmitter().emit(ir_module)


def compile(module: A.Module, types: dict | None = None) -> str:
    """End-to-end AST -> CIR -> Python convenience helper."""
    return emit_python(lower(module, types=types))


def compile_program(
    module: A.Module,
    filename: str = "<input>",
    types: dict | None = None,
) -> str:
    """End-to-end AST -> CIR -> runnable Python program.

    Unlike :func:`compile`, this prepends the runtime prelude (the
    same one the legacy transpiler emits) and appends the
    ``if __name__ == "__main__":`` bootstrap when a ``main`` function
    is present. The result is directly ``exec``-runnable in a bare
    namespace and matches the legacy transpiler's emission shape for
    the subset the IR covers.

    Reuses the legacy ``_PRELUDE`` constant rather than duplicating
    the runtime-import list so the two paths stay in lockstep on
    runtime-API changes. The legacy's ``_TRY_HELPER`` (the
    ``_capa_try`` / ``_CapaTryEarlyReturn`` block) is intentionally
    omitted: the IR expands ``?`` inline via TryUnwrap, so the
    exception path is never reached.
    """
    from ..transpiler import _PRELUDE
    ir_mod = lower(module, types=types)
    body = emit_python(ir_mod)
    # Identify the main function from the IR so the bootstrap
    # instantiates its capability params correctly.
    main_fn = next((f for f in ir_mod.functions if f.name == "main"), None)
    parts: list[str] = [_PRELUDE.format(filename=filename).rstrip(), ""]
    parts.append(body.rstrip())
    if main_fn is not None:
        parts.append("")
        parts.append(_emit_main_bootstrap(main_fn))
    return "\n".join(parts).rstrip() + "\n"


def emit_wat(
    ir_module: Module,
    *,
    memory_cap_pages: int | None = ...,  # type: ignore[assignment]
    manifest_json: str | None = None,
    wasi: bool = False,
) -> str:
    """Emit WebAssembly text format (WAT) from a CIR module.

    Phase 6A scope: integer / boolean functions only. Any CIR
    construct outside this subset raises ``WasmEmissionError`` with
    a precise reason. The output is valid WAT that ``wasm-tools
    parse`` accepts; see :func:`compile_wasm` for an assemble-to-
    bytes convenience wrapper.

    ``memory_cap_pages`` (audit H1, 2026-05): caps the emitted
    ``(memory ...)`` declaration at the given page count (1 page =
    64 KiB). Defaults to ``MEMORY_CAP_DEFAULT_PAGES`` (256 pages =
    16 MiB). Pass ``None`` to skip the cap (host decides).

    ``manifest_json`` (audit M4, 2026-05): when non-None, embeds the
    string into a ``capa-manifest`` Wasm custom section so per-
    function capability declarations travel with the artefact.
    Runtimes ignore custom sections; ``wasm-tools dump`` and any
    Wasm parser can read them."""
    from ._emit_wasm import MEMORY_CAP_DEFAULT_PAGES
    if memory_cap_pages is ...:
        memory_cap_pages = MEMORY_CAP_DEFAULT_PAGES
    return WasmEmitter(
        memory_cap_pages=memory_cap_pages,
        manifest_json=manifest_json,
        wasi=wasi,
    ).emit(ir_module)


def compile_wat(
    module: A.Module,
    types: dict | None = None,
    *,
    memory_cap_pages: int | None = ...,  # type: ignore[assignment]
    filename: str = "<input>",
    embed_manifest: bool = True,
    wasi: bool = False,
) -> str:
    """End-to-end AST -> CIR -> WAT convenience helper. Mirrors
    :func:`compile` but targets the Wasm Component Model text form
    instead of Python source.

    Programs that touch ``parse_json`` / ``to_json`` get the
    bundled Capa-source JSON parser spliced in via
    ``_builtin_json.inject_into``; the Wasm emitter then routes
    ``parse_json`` / ``to_json`` calls into the bundled functions
    instead of importing ``capa:host/json``. That keeps the
    JsonValue tree inside the component's own linear memory so
    ``--component --run`` works without any host-side memory
    access.

    ``memory_cap_pages`` (audit H1): forwarded to :func:`emit_wat`.

    ``embed_manifest`` (audit M4): when True (default), builds a
    capability manifest from ``module`` and embeds it into a
    ``capa-manifest`` custom section. Off only for tests where the
    extra section would noisily change byte-level snapshots."""
    from ._builtin_json import inject_into
    from ._monomorphise import monomorphise
    from ._normalize_char import normalize_char_to_string
    from ._emit_wasm import MEMORY_CAP_DEFAULT_PAGES
    if memory_cap_pages is ...:
        memory_cap_pages = MEMORY_CAP_DEFAULT_PAGES
    ir_mod = lower(module, types=types)
    inject_into(ir_mod)
    # Specialise every generic free function per concrete
    # instantiation reached from a non-generic caller. The Wasm
    # backend's layout machinery cannot encode type variables
    # like ``T``; after this pass the module has no
    # ``type_params`` left to confuse it. Pass is a no-op on
    # programs without generics.
    monomorphise(ir_mod)
    # Normalize the Capa type token ``Char`` -> ``String`` across
    # every type-string-bearing field of the module. A Char is a
    # single-codepoint String and is laid out exactly like a String
    # at the Wasm level; this pass lets the emitter's String
    # machinery carry it without a dedicated Char encoding. Wasm path
    # only -- the Python transpiler and the AST-derived manifest are
    # untouched. No-op on programs without any Char. Runs after
    # monomorphise so specialised clones (e.g. ``first<Char>``) are
    # normalized too.
    normalize_char_to_string(ir_mod)
    manifest_json: str | None = None
    if embed_manifest:
        manifest_json = _build_wasm_capa_manifest_json(
            module, filename=filename,
        )
    return emit_wat(
        ir_mod,
        memory_cap_pages=memory_cap_pages,
        manifest_json=manifest_json,
        wasi=wasi,
    )


def _build_wasm_capa_manifest_json(
    module: A.Module,
    *,
    filename: str = "<input>",
) -> str:
    """Build the JSON payload for the ``capa-manifest`` custom
    section (audit M4, 2026-05).

    Reuses :func:`capa.manifest.build_manifest` so per-function
    ``declared_capabilities`` are computed in exactly one place,
    then projects the relevant subset (name + declared caps) so
    the artefact stays compact. Format v1::

        {
          "capa_manifest_version": 1,
          "capa_version": "<rc version>",
          "functions": [
            {"name": "main",    "declared_capabilities": ["Stdio"]},
            {"name": "compute", "declared_capabilities": []},
            ...
          ]
        }
    """
    import json
    from .. import __version__ as _capa_version
    from ..manifest._funrec import build_manifest
    from ._emit_wasm import CAPA_MANIFEST_SCHEMA_VERSION

    full = build_manifest(
        module, filename=filename, capa_version=_capa_version,
    )
    functions = [
        {
            "name": f["name"],
            "declared_capabilities": list(f["declared_capabilities"]),
        }
        for f in full["functions"]
    ]
    payload = {
        "capa_manifest_version": CAPA_MANIFEST_SCHEMA_VERSION,
        "capa_version": _capa_version,
        "functions": functions,
    }
    # Compact separators keep the custom-section payload as small as
    # we can without losing JSON readability; consumers can re-pretty
    # the output if they want.
    return json.dumps(payload, separators=(",", ":"), sort_keys=False)


def compile_wit(
    module: A.Module,
    types: dict | None = None,
    world_name: str = "program",
    *,
    wasi: bool = False,
) -> str:
    """End-to-end AST -> CIR -> WIT spec.

    Returns a WIT document declaring an interface per built-in
    capability the program touches plus a ``world`` that imports
    them. Pair with :func:`compile_wasm` and a host that provides
    the interfaces to obtain a runnable component.

    ``wasi`` (experimental, 2026-06-27): when True, the world imports
    the canonical ``wasi:random`` / ``wasi:clocks`` interfaces for the
    migrated Random / Clock touch-points instead of the matching
    ``capa:host`` interfaces; every other capability stays
    ``capa:host`` (hybrid). See ``docs/design/wasi_mode.md``."""
    return emit_wit(
        lower(module, types=types), world_name=world_name, wasi=wasi,
    )


def compile_wasm(
    module: A.Module,
    types: dict | None = None,
    wasm_tools_path: str = "wasm-tools",
    *,
    memory_cap_pages: int | None = ...,  # type: ignore[assignment]
    filename: str = "<input>",
    embed_manifest: bool = True,
    wasi: bool = False,
) -> bytes:
    """End-to-end AST -> CIR -> WAT -> binary Wasm assembly.

    Shells out to ``wasm-tools parse`` to assemble the WAT into
    binary ``.wasm`` bytes. Returns the binary content so callers
    can write it to disk, load it into a runtime, or sign it
    without intermediate file shuffling. Raises
    ``FileNotFoundError`` if ``wasm-tools`` is not on PATH, and
    ``subprocess.CalledProcessError`` if the assembly itself fails
    (the WAT it complained about is in ``.stderr``).

    ``memory_cap_pages`` (audit H1) and ``embed_manifest`` /
    ``filename`` (audit M4) are forwarded to :func:`compile_wat`.
    """
    import subprocess
    wat = compile_wat(
        module, types=types,
        memory_cap_pages=memory_cap_pages,
        filename=filename,
        embed_manifest=embed_manifest,
        wasi=wasi,
    )
    proc = subprocess.run(
        [wasm_tools_path, "parse", "-"],
        input=wat.encode("utf-8"),
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"wasm-tools parse failed (exit {proc.returncode}):\n"
            f"{proc.stderr.decode('utf-8', errors='replace')}\n"
            f"--- WAT input ---\n{wat}"
        )
    return proc.stdout


def read_wasm_manifest(blob: bytes) -> dict | None:
    """Read the embedded ``capa-manifest`` custom section from a
    Wasm binary (audit M4, 2026-05).

    Returns the decoded JSON dict, or ``None`` when the binary
    carries no ``capa-manifest`` section. Raises ``ValueError`` on
    a malformed Wasm header.

    Implemented as a tiny custom-section parser so callers do not
    need to pull in ``wasmtime`` or shell out to ``wasm-tools``:
    every Wasm module starts with the 8-byte preamble (magic +
    version) followed by sections of the form ``(section_id: u8,
    size: leb128, payload: bytes)``. Custom sections have id 0 and
    their payload starts with a ``(name_len: leb128, name: utf-8)``
    pair, followed by the section's data.
    """
    import json
    if len(blob) < 8 or blob[:4] != b"\x00asm":
        raise ValueError("not a Wasm binary (bad preamble)")
    i = 8
    while i < len(blob):
        section_id = blob[i]
        i += 1
        size, i = _read_uleb128(blob, i)
        end = i + size
        if section_id == 0:
            name_len, name_start = _read_uleb128(blob, i)
            name_end = name_start + name_len
            name = blob[name_start:name_end].decode("utf-8", errors="replace")
            if name == "capa-manifest":
                payload = blob[name_end:end]
                return json.loads(payload.decode("utf-8"))
        i = end
    return None


def _read_uleb128(buf: bytes, start: int) -> tuple[int, int]:
    """Read an unsigned LEB128 integer at ``buf[start:]``. Returns
    ``(value, next_index)``. Internal helper for
    :func:`read_wasm_manifest`."""
    result = 0
    shift = 0
    i = start
    while True:
        byte = buf[i]
        i += 1
        result |= (byte & 0x7F) << shift
        if (byte & 0x80) == 0:
            break
        shift += 7
    return result, i


def _emit_main_bootstrap(main_fn) -> str:
    """Emit the ``if __name__ == "__main__":`` block that instantiates
    each capability param and calls ``main(...)``. Mirrors the legacy
    transpiler's :meth:`_emit_main_bootstrap` so behaviour is
    identical for the same input."""
    args: list[str] = []
    for p in main_fn.params:
        # The IR's Param carries the source-level type name as a
        # string in ``p.ty``; for built-in capability params that is
        # the class name we need to instantiate (e.g. "Stdio").
        cap_name = p.ty if p.ty else "Stdio"
        args.append(f"{cap_name}()")
    call = f"main({', '.join(args)})" if args else "main()"
    return (
        'if __name__ == "__main__":\n'
        f"    {call}\n"
    )
