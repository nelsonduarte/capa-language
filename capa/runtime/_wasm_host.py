"""Host-side bridge that implements Capa's built-in capability
interfaces for Wasm-compiled programs.

A Capa program compiled to Wasm with ``capa.ir.compile_wasm`` imports
its capability methods by WIT-aligned names (e.g.
``capa:stdio.println``). The host provides those imports via
``wasmtime.Linker``; this module wraps the wiring so a test or
runtime entry point can do:

    from capa.runtime._wasm_host import WasmHost
    host = WasmHost()
    host.run_main(wasm_blob)

and the program's ``main`` export executes with the host's
capabilities live (stdio printing to real stdout, etc.).

Phase 6B scope: ``capa:stdio`` interface (print / println / eprintln)
only. Subsequent phases add Fs / Env / Clock / Net via the same
pattern.

Trust-boundary notes (audit items M1 / H1, 2026-05):

- ``env.get`` is leak-by-default. An unrestricted ``Env`` cap reads
  ``os.environ`` verbatim, so a Capa program with the cap sees every
  environment variable on the host (including secrets). The
  attenuation system narrows it: a program that calls
  ``env.restrict_to_keys([...])`` on a literal allow-list is enforced
  inline by the Wasm emitter (audit C2). Production hosts handing a
  ``.wasm`` blob to untrusted code must restrict first.
- The bump allocator's ``memory.grow`` call is bounded by the
  module's declared ``(memory ... <max>)`` upper-page limit. The
  Wasm emitter ships a sane default (see
  ``capa.ir._emit_wasm.MEMORY_CAP_DEFAULT_PAGES`` = 256 pages = 16
  MiB) so a runaway allocator traps predictably rather than at some
  host-dependent OOM point. Override on the CLI with
  ``--wasm-memory-cap <pages>`` (1 page = 64 KiB).
"""

from __future__ import annotations

import struct as _struct
import sys
from typing import Optional

import wasmtime
import wasmtime.component as wc

from ._capabilities import Clock, Db, Env, Fs, Net, Proc, Stdio, _write_safe
from ._fs_guard import PostOpenDenied
from ._cap_handles import (
    CapHandleError,
    CapHandleTable,
    bootstrap_root_handles,
)


class WasmHostError(RuntimeError):
    """A host-side failure while servicing a guest import.

    Raised when the host cannot honour a guest request through no
    fault of the guest's bytecode - e.g. the module's exported
    ``$alloc`` returns 0 (out of memory in the bump allocator) for a
    non-empty allocation. Surfacing this as a clean host error (rather
    than writing the buffer at address 0 and scribbling the data
    segment) keeps the OOM diagnostic intact. Audit 2026-05-25 L1.
    """


class _ForeignRecord(wc.Record):
    """A crossing struct value (feature #4 F2c). Subclasses
    ``wasmtime.component``'s ``Record`` so it passes the ``isinstance(val,
    Record)`` test wasmtime uses to discriminate an UNTAGGED variant arm
    whose case is a record (e.g. the ``some`` arm of ``Option<struct>`` or
    the ``ok`` arm of ``Result<struct, String>``); ``RecordType`` reads
    each field with ``getattr(val, wit_field_name)``. Carries no
    authority, only plain leaf / nested-aggregate data."""


# Maximum aggregate nesting depth the host will marshal in either
# direction. A crossing schema is built at compile time from a finite,
# non-self-referential declared type, so its depth is already bounded; the
# WIT canonical ABI likewise bounds the depth of any value the untrusted
# child can return. This constant is a defensive backstop so an unexpected
# schema / value cycle surfaces as a clean WasmHostError rather than a
# Python ``RecursionError`` (like the F2b/F2c memory-cap bound on size).
_MAX_MARSHAL_DEPTH = 64

# Schema class-set sentinel (from ``capa.foreign_schema._node_classes``)
# -> the real Python class, used to discriminate an untagged variant arm
# exactly as ``wasmtime.component`` does.
_SENTINEL_CLASS = {
    "int": int, "bool": bool, "float": float, "str": str,
    "Record": wc.Record, "list": list, "tuple": tuple,
    "Variant": wc.Variant, "object": object,
}


def _node_real_classes(node: dict) -> tuple:
    """The real Python classes an untagged variant arm ``node`` accepts,
    for an ``isinstance`` discrimination that mirrors wasmtime's."""
    from capa.foreign_schema import _node_classes
    return tuple(_SENTINEL_CLASS[c] for c in _node_classes(node))


def _discriminate(value, case_nodes: list) -> int:
    """Return the index of the first case ``value`` matches, mirroring
    ``wasmtime.component.VariantLikeType._lower``: a ``None`` case matches
    ``value is None``; a payload case matches ``isinstance(value,
    classes)``. Case order MUST match the WIT declaration order (none
    before some; ok before err; sum variants in declaration order)."""
    for i, node in enumerate(case_nodes):
        if node is None:
            if value is None:
                return i
        elif isinstance(value, _node_real_classes(node)):
            return i
    raise WasmHostError(
        "foreign aggregate: returned value matches no variant case"
    )


class WasmHost:
    """A wasmtime-based host that wires Capa's built-in capabilities
    into a compiled Wasm module."""

    def __init__(self, args: Optional[list[str]] = None) -> None:
        self.engine = wasmtime.Engine()
        self.store = wasmtime.Store(self.engine)
        self.linker = wasmtime.Linker(self.engine)
        # Feature #4 hardening: untrusted foreign-component children run
        # in their OWN store on a SEPARATE fuel-metered engine, bounded
        # by a CPU (fuel) + memory ceiling so a malicious / buggy child
        # cannot hang or memory-exhaust the host. The parent module above
        # stays unmetered. Budgets default to the generous module
        # constants and can be tuned via :meth:`configure_foreign_limits`
        # (wired to the ``--foreign-fuel`` / ``--foreign-memory-cap``
        # flags). See ``capa.runtime._foreign``.
        from ._foreign import (
            DEFAULT_FOREIGN_FUEL,
            DEFAULT_FOREIGN_MEMORY_CAP_BYTES,
            new_foreign_engine,
        )
        self._foreign_engine = new_foreign_engine()
        self._foreign_fuel: Optional[int] = DEFAULT_FOREIGN_FUEL
        self._foreign_memory_cap_bytes: Optional[int] = (
            DEFAULT_FOREIGN_MEMORY_CAP_BYTES
        )
        # Holds the instance's exported memory after instantiation;
        # host callbacks read string arguments out of this memory.
        self._memory: Optional[wasmtime.Memory] = None
        # Cache the module's exported $alloc once we instantiate;
        # host functions like ``env.get`` need to allocate Option /
        # Result records back into wasm memory, which requires
        # calling ``$alloc`` from the host side.
        self._alloc_export: Optional[wasmtime.Func] = None
        # Program arguments handed to the wasm module via env.args.
        # Defaults to an empty list; callers (e.g. the CLI) pass the
        # real argv when they have it.
        self._args: list[str] = list(args) if args is not None else []
        # Slices 25.2 - 25.6 (2026-05-30): per-instance capability
        # handle table. Fs (25.2), Net (25.3), Db / Proc (25.4),
        # Env (25.5), Clock (25.6) have been migrated to handle-
        # passing so a restricted cap crossing a function boundary
        # keeps its restriction (the receiver's i32 handle is now
        # part of the cap-method call signature, looked up by the
        # host on every privileged op). The unrestricted root caps
        # the host holds are allocated into this table by ``run_main``
        # once it has inspected ``main``'s signature; child handles
        # come from ``capa:host/<cap>.restrict-{to|to-keys|to-after}``.
        self._cap_handles = CapHandleTable()
        # Root caps the host hands to programs that declare them on
        # main. Lazy-constructed in ``run_main`` so unit tests that
        # never invoke ``main`` don't get real cap instances
        # attached. Random / Unsafe stay erased indefinitely (no
        # restriction state to thread); Stdio stays erased too.
        self._root_fs: Optional[Fs] = None
        self._root_net: Optional[Net] = None
        self._root_db: Optional[Db] = None
        self._root_proc: Optional[Proc] = None
        self._root_env: Optional[Env] = None
        self._root_clock: Optional[Clock] = None
        self._root_stdio: Optional[Stdio] = None
        # Set True by the panic host import once it has written the
        # canonical ``panic: <message>`` line. The guest then traps
        # via ``unreachable``; the CLI uses this flag to tell a
        # deliberate panic abort (already reported, exit clean) apart
        # from a genuine runtime trap (out-of-bounds, integer
        # divide-by-zero, ...) that still warrants a host traceback.
        # Re-cleared at the start of every run (see ``_invoke_main``)
        # so a host reused across programs cannot carry a stale latch
        # from one run into the next.
        self.panicked = False
        self._register_stdio()
        self._register_panic()
        self._register_clock()
        self._register_env()
        self._register_fs()
        self._register_json()
        self._register_random()
        self._register_net()
        self._register_db()
        self._register_proc()

    # ---- typed foreign components (feature #4, F2a) -------------

    def _foreign_call_engine(self) -> wasmtime.Engine:
        """The engine an untrusted child runs on. When a CPU (fuel) bound
        is active, the fuel-metered engine; when the bound is opted out
        (``--foreign-fuel 0``), the plain unmetered engine -- a
        consume_fuel store starts at 0 fuel, so opting out MUST drop the
        metering entirely rather than leave the child instantly starved.
        The memory bound is a store limit and applies on either engine."""
        if self._foreign_fuel is not None:
            return self._foreign_engine
        return self.engine

    def configure_foreign_limits(
        self,
        fuel: Optional[int] = None,
        memory_cap_bytes: Optional[int] = None,
    ) -> None:
        """Override the untrusted-child resource ceiling (feature #4
        hardening). ``fuel`` bounds child CPU (``None`` keeps the default;
        a non-positive value skips the CPU bound); ``memory_cap_bytes``
        bounds child linear-memory growth likewise. Call BEFORE
        :meth:`register_foreign_methods` runs the program. Wired to the
        CLI's ``--foreign-fuel`` / ``--foreign-memory-cap`` flags."""
        if fuel is not None:
            self._foreign_fuel = fuel if fuel > 0 else None
        if memory_cap_bytes is not None:
            self._foreign_memory_cap_bytes = (
                memory_cap_bytes if memory_cap_bytes > 0 else None
            )

    def register_foreign_methods(self, methods: list) -> None:
        """Define the ``capa:foreign/<component>`` host imports for the
        typed foreign-component methods this program invokes (feature #4,
        F2a), BEFORE the module is instantiated.

        Each import closure resolves the caller's capability handles on
        this host's handle table into the caller's PRE-ATTENUATED cap
        instances, then dispatches into a sandboxed child sub-component
        (see ``capa.runtime._foreign.dispatch_foreign_call``): the child
        is instantiated with a restricted linker that binds ONLY those
        caps, so it physically cannot reach any capability the call did
        not grant. Scalar arguments and the scalar result marshal through
        this closure (Int / Bool / Float); the guest holds no
        authority-bearing value it could forge or widen.

        ``methods`` is the metadata list from
        ``capa.foreign.foreign_runtime_methods`` with the ``artifact``
        path already resolved to an absolute filesystem path by the
        caller (the CLI, relative to the source file)."""
        for meta in methods:
            self._define_foreign_import(meta)

    def _define_foreign_import(self, meta: dict) -> None:
        from ._foreign import dispatch_foreign_call, ForeignDenied

        _CAP_CLASSES = {
            "Fs": Fs, "Net": Net, "Db": Db, "Proc": Proc,
            "Env": Env, "Clock": Clock, "Stdio": Stdio,
        }
        _WASM_VALTYPE = {
            "i32": wasmtime.ValType.i32,
            "i64": wasmtime.ValType.i64,
            "f64": wasmtime.ValType.f64,
        }
        component = meta["component"]
        method = meta["method"]
        params = meta["params"]
        return_kind = meta.get("return_kind", "unit")
        return_wasm = meta["return_wasm"]
        label = f"{component}.{method}"

        # A String / aggregate param or a String / aggregate return needs
        # the host to touch the caller's linear memory + ``$alloc`` (a
        # String crosses as ptr/len, an aggregate as a single i32 heap
        # pointer read out of / written back into parent memory). When
        # none is present the method is F2a scalar-only and takes the
        # exact same fast path it always did (no caller access, direct
        # scalar closure).
        needs_memory = return_kind in ("string", "aggregate") or any(
            p["kind"] in ("string", "aggregate") for p in params
        )
        # Flatten each param to its core-wasm value type(s); a String
        # param contributes two i32s (ptr, len); an aggregate one i32.
        param_valtypes = [
            _WASM_VALTYPE[w]() for p in params for w in p["wasm"]
        ]
        if return_kind in ("string", "aggregate"):
            # Indirect return: trailing i32 ret-area pointer, no result.
            param_valtypes.append(wasmtime.ValType.i32())
            result_valtypes: list = []
        elif return_wasm:
            result_valtypes = [_WASM_VALTYPE[return_wasm]()]
        else:
            result_valtypes = []
        functype = wasmtime.FuncType(param_valtypes, result_valtypes)

        if not needs_memory:
            # ---- F2a scalar-only path (unchanged) ------------------
            def closure(*args, _meta=meta, _label=label):
                granted: dict = {}
                scalar_args: list = []
                for value, p in zip(args, _meta["params"]):
                    if p["kind"] == "cap":
                        cap_cls = _CAP_CLASSES.get(p["cap"])
                        if cap_cls is None:
                            raise ForeignDenied(
                                f"foreign component {_label}: capability "
                                f"{p['cap']!r} cannot be handed across the "
                                f"boundary"
                            )
                        try:
                            cap = self._cap_handles.lookup(
                                int(value), cap_cls,
                            )
                        except CapHandleError as e:
                            raise ForeignDenied(
                                f"foreign component {_label}: invalid "
                                f"{p['cap']} capability handle ({e})"
                            )
                        granted[p["cap"]] = cap
                    else:
                        # Scalar: convert the wasm i32 back to a Python
                        # bool for a Bool crossing param so the child's
                        # component func receives the WIT ``bool`` it
                        # expects; Int (i64) and Float (f64) pass through.
                        if p["root"] == "Bool":
                            scalar_args.append(bool(value))
                        else:
                            scalar_args.append(value)
                result = dispatch_foreign_call(
                    self._foreign_call_engine(), _meta["artifact"],
                    _meta["method"], granted, scalar_args, _label,
                    fuel=self._foreign_fuel,
                    memory_cap_bytes=self._foreign_memory_cap_bytes,
                )
                if _meta["return_wasm"] is None:
                    return None
                # A Bool return lowers to i32 (0/1); Int / Float pass
                # through.
                if _meta["return_root"] == "Bool":
                    return 1 if result else 0
                return result

            self.linker.define_func(
                f"capa:foreign/{component}", method, functype, closure,
            )
            return

        # ---- F2b String-marshalling path -------------------------
        # The closure resolves caps + scalars exactly as the scalar
        # path does, but a String argument is read out of the caller's
        # linear memory (its (ptr, len) pair) into a Python str, and a
        # String result is written back into the caller's memory via
        # ``$alloc`` with the (ptr, len) recorded in the trailing return
        # area. The security enforcement is byte-for-byte identical to
        # F2a: only the VALUE marshalling differs; a String is plain
        # data (F1-quarantine-clean) and carries no authority.
        def closure_mem(caller, *args, _meta=meta, _label=label):
            granted: dict = {}
            scalar_args: list = []
            idx = 0
            for p in _meta["params"]:
                kind = p["kind"]
                if kind == "cap":
                    value = args[idx]
                    idx += 1
                    cap_cls = _CAP_CLASSES.get(p["cap"])
                    if cap_cls is None:
                        raise ForeignDenied(
                            f"foreign component {_label}: capability "
                            f"{p['cap']!r} cannot be handed across the "
                            f"boundary"
                        )
                    try:
                        cap = self._cap_handles.lookup(int(value), cap_cls)
                    except CapHandleError as e:
                        raise ForeignDenied(
                            f"foreign component {_label}: invalid "
                            f"{p['cap']} capability handle ({e})"
                        )
                    granted[p["cap"]] = cap
                elif kind == "string":
                    s_ptr, s_len = args[idx], args[idx + 1]
                    idx += 2
                    scalar_args.append(
                        self._read_wtf8(caller, s_ptr, s_len)
                    )
                elif kind == "aggregate":
                    # Feature #4 F2c-1: the arg is a single i32 pointer to
                    # a Capa heap record in the parent's memory. Read it
                    # into a plain Python value the child component's
                    # canonical ABI lowers (record / list / tuple /
                    # option / result of scalars).
                    agg_ptr = args[idx]
                    idx += 1
                    scalar_args.append(
                        self._read_capa_value(caller, agg_ptr, p["schema"])
                    )
                else:
                    value = args[idx]
                    idx += 1
                    if p["root"] == "Bool":
                        scalar_args.append(bool(value))
                    else:
                        scalar_args.append(value)
            ret_area = (
                args[idx]
                if _meta["return_kind"] in ("string", "aggregate")
                else None
            )
            result = dispatch_foreign_call(
                self._foreign_call_engine(), _meta["artifact"],
                _meta["method"], granted, scalar_args, _label,
                aggregate_result=_meta["return_kind"] == "aggregate",
                fuel=self._foreign_fuel,
                memory_cap_bytes=self._foreign_memory_cap_bytes,
            )
            if _meta["return_kind"] == "aggregate":
                # Write the child's returned value back into the parent's
                # memory as a Capa heap record and store its pointer in
                # the 4-byte ret area (bounded by $alloc / the memory cap,
                # exactly like the F2b String write-back).
                rec_ptr = self._write_capa_value(
                    caller, result, _meta["return_schema"],
                )
                self._memory.write(
                    caller, rec_ptr.to_bytes(4, "little"), ret_area,
                )
                return None
            if _meta["return_kind"] == "string":
                # Write the child's returned str into the parent's
                # memory and record (ptr, len) in the 8-byte ret area.
                s_ptr, s_len = self._write_wtf8(caller, result or "")
                self._memory.write(
                    caller, s_ptr.to_bytes(4, "little"), ret_area,
                )
                self._memory.write(
                    caller, s_len.to_bytes(4, "little"), ret_area + 4,
                )
                return None
            if _meta["return_wasm"] is None:
                return None
            if _meta["return_root"] == "Bool":
                return 1 if result else 0
            return result

        self.linker.define_func(
            f"capa:foreign/{component}", method, functype, closure_mem,
            access_caller=True,
        )

    def _read_wtf8(self, caller, ptr: int, length: int) -> str:
        """Read a Capa String's ``length`` UTF-8/WTF-8 bytes at ``ptr``
        out of the caller's linear memory into a Python str (feature #4
        F2b String marshalling). Uses ``surrogatepass`` so a lone
        surrogate carried in a Capa string survives the round trip
        (same convention as the stdio host bridge); genuinely invalid
        bytes degrade to the replacement char rather than crashing the
        store."""
        if self._memory is None:
            raise RuntimeError(
                "foreign String arg read before instance memory was set"
            )
        raw = bytes(self._memory.read(caller, ptr, ptr + length))
        try:
            return raw.decode("utf-8", errors="surrogatepass")
        except UnicodeDecodeError:
            return raw.decode("utf-8", errors="replace")

    def _write_wtf8(self, caller, text: str) -> tuple[int, int]:
        """Encode ``text`` and copy it into the caller's linear memory
        via the module's ``$alloc``, returning (ptr, len). An empty
        string allocates nothing and returns (0, 0). Uses
        ``surrogatepass`` to preserve lone surrogates symmetrically with
        :meth:`_read_wtf8`."""
        if self._memory is None or self._alloc_export is None:
            raise RuntimeError(
                "foreign String return written before memory + $alloc set"
            )
        encoded = text.encode("utf-8", errors="surrogatepass")
        if not encoded:
            return 0, 0
        ptr = self._host_alloc(caller, len(encoded))
        self._memory.write(caller, encoded, ptr)
        return ptr, len(encoded)

    def _host_alloc(self, caller, n: int) -> int:
        """Allocate ``n`` bytes in guest memory via the module's
        exported ``$alloc``, guarding against a failed allocation.

        Two OOM shapes surface here as a clean ``WasmHostError`` (rather
        than a scribble at address 0 or a raw host traceback):

        - the bump allocator returns 0. Address 0 is the start of the
          guest's data segment, so writing the buffer there would
          silently corrupt the module's static data. Audit 2026-05-25 L1.
        - the bump allocator TRAPS: the emitted ``$alloc`` executes
          ``unreachable`` when ``memory.grow`` is refused at the
          source-declared ceiling (``--wasm-memory-cap``). That is
          exactly what a HOST-driven allocation hits when a foreign call's
          returned aggregate (feature #4 F2c) is too large for the
          caller's memory cap; catch the trap and re-raise it as the same
          bounded diagnostic so a malformed / oversized child return is
          memory-safe, not a crash.

        A zero-length request legitimately returns 0 (no write follows).
        """
        if n == 0:
            return 0
        try:
            ptr = self._alloc_export(caller, n)
        except (wasmtime.Trap, wasmtime.WasmtimeError) as e:
            raise WasmHostError(
                f"guest $alloc trapped on a {n}-byte allocation (out of "
                "memory: exceeded the caller's --wasm-memory-cap); the "
                "foreign call's returned value does not fit the parent's "
                "linear-memory cap"
            ) from e
        if not ptr:
            raise WasmHostError(
                f"guest $alloc returned 0 for a {n}-byte allocation "
                "(out of memory); refusing to write at address 0"
            )
        return ptr

    # ---- typed foreign components: FLAT aggregate marshalling (F2c-1) --
    #
    # A crossing aggregate is F1-quarantine-clean PLAIN DATA (no Fun / cap
    # / Unsafe nested), so it carries no authority: these codecs only move
    # bytes, they never resolve a handle or bind a cap. The byte offsets
    # come from the serialised layout schema built by
    # ``capa.foreign_schema`` off the ``_layout.py`` authority, so the
    # host reproduces exactly what the core emitter writes rather than
    # re-deriving offsets. Every String leaf reuses ``_read_wtf8`` /
    # ``_write_wtf8``; every write-back is bounded by ``$alloc`` / the
    # memory cap, so a malformed child return is memory-safe (bounded like
    # the F2b String return).

    def _read_i32(self, caller, addr: int) -> int:
        return int.from_bytes(
            bytes(self._memory.read(caller, addr, addr + 4)), "little",
        )

    def _read_leaf(self, caller, addr: int, leaf: str):
        """Read one scalar leaf out of the parent's memory at ``addr``.
        The low bytes hold the value in every container context (a struct
        field, a List element, or an 8-byte tuple / Option / Result slot),
        so a single reader serves all of them: Bool's i32 low word is the
        same whether the leaf is a 4-byte field or an i64-extended slot."""
        if leaf == "Int":
            return int.from_bytes(
                bytes(self._memory.read(caller, addr, addr + 8)),
                "little", signed=True,
            )
        if leaf == "Bool":
            return self._read_i32(caller, addr) != 0
        if leaf == "Float":
            return _struct.unpack(
                "<d", bytes(self._memory.read(caller, addr, addr + 8)),
            )[0]
        if leaf == "String":
            s_ptr = self._read_i32(caller, addr)
            s_len = self._read_i32(caller, addr + 4)
            return self._read_wtf8(caller, s_ptr, s_len)
        raise WasmHostError(f"foreign aggregate: unknown scalar leaf {leaf!r}")

    def _read_slot(self, caller, addr: int, node: dict, depth: int):
        """Read one aggregate SLOT (a struct field / List element / tuple
        element / variant payload) at ``addr``. A scalar leaf is read
        inline; any nested aggregate is a 4-byte POINTER at ``addr`` to a
        separately-allocated sub-record, read recursively (the low 4 bytes
        hold the pointer in every slot context -- a 4-byte field / list
        element, or an i64-extended 8-byte tuple / Option / Result / sum
        slot)."""
        if node["kind"] == "scalar":
            return self._read_leaf(caller, addr, node["leaf"])
        child = self._read_i32(caller, addr)
        return self._read_capa_value(caller, child, node, depth + 1)

    def _read_capa_value(self, caller, ptr: int, schema: dict, depth: int = 0):
        """Read a Capa aggregate at ``ptr`` (of any finite nesting depth)
        into a plain Python value the child component's canonical ABI
        lowers (feature #4 F2c-2). Recurses through nested struct fields,
        List elements and variant payloads; each nested aggregate is a
        pointer to its own record."""
        if depth > _MAX_MARSHAL_DEPTH:
            raise WasmHostError(
                "foreign aggregate: nesting exceeded the marshalling depth "
                f"bound ({_MAX_MARSHAL_DEPTH})"
            )
        kind = schema["kind"]
        if kind == "struct":
            rec = _ForeignRecord()
            for f in schema["fields"]:
                setattr(
                    rec, f["wit"],
                    self._read_slot(caller, ptr + f["offset"], f["node"], depth),
                )
            return rec
        if kind == "list":
            # List<T> header: len @ 0, cap @ 4, data_ptr @ 8. Elements at
            # data + i * stride (stride = _size_of(elem): 8 for Int / Float
            # / String, 4 for Bool AND any pointer-shape nested element).
            n = self._read_i32(caller, ptr)
            data = self._read_i32(caller, ptr + 8)
            stride = schema["stride"]
            elem = schema["elem"]
            return [
                self._read_slot(caller, data + i * stride, elem, depth)
                for i in range(n)
            ]
        if kind == "tuple":
            # Uniform 8-byte slot per element at i * 8.
            return tuple(
                self._read_slot(caller, ptr + i * 8, node, depth)
                for i, node in enumerate(schema["elems"])
            )
        if kind == "option":
            # 16-byte sum record: tag @ 0 (Capa Some = 0, None = 1),
            # payload 8-byte slot @ 8. WIT inverts (none = 0, some = 1);
            # the wc.Variant carries the WIT case name.
            if self._read_i32(caller, ptr) == 0:  # Some
                payload = self._read_slot(
                    caller, ptr + 8, schema["payload"], depth,
                )
                return wc.Variant("some", payload) if schema["tagged"] else payload
            return wc.Variant("none") if schema["tagged"] else None
        if kind == "result":
            # 16-byte sum record: tag @ 0 (Capa Ok = 0, Err = 1), payload @ 8.
            is_ok = self._read_i32(caller, ptr) == 0
            node = schema["ok"] if is_ok else schema["err"]
            val = self._read_slot(caller, ptr + 8, node, depth)
            if schema["tagged"]:
                return wc.Variant("ok" if is_ok else "err", val)
            return val
        if kind == "sum":
            # User sum: tag @ 0, per-payload slots from compute_sum_layout.
            tag = self._read_i32(caller, ptr)
            var = next(
                (v for v in schema["variants"] if v["tag"] == tag), None,
            )
            if var is None:
                raise WasmHostError(
                    f"foreign aggregate: sum tag {tag} out of range "
                    "(no matching variant); refusing to marshal"
                )
            vals = [
                self._read_slot(caller, ptr + pl["offset"], pl["node"], depth)
                for pl in var["payloads"]
            ]
            if not vals:
                payload = None
            elif len(vals) == 1:
                payload = vals[0]
            else:
                payload = tuple(vals)  # multi-payload case -> WIT tuple
            return wc.Variant(var["wit"], payload) if schema["tagged"] else payload
        raise WasmHostError(
            f"foreign aggregate: unknown schema kind {kind!r}"
        )

    def _write_leaf(self, caller, addr: int, leaf: str, val, width: int) -> None:
        """Write one scalar leaf into the parent's memory at ``addr``.
        ``width`` is the leaf's byte footprint in this container (4 for a
        Bool struct field / List element, 8 in an i64-extended slot)."""
        if leaf == "Int":
            self._memory.write(
                caller, int(val).to_bytes(8, "little", signed=True), addr,
            )
            return
        if leaf == "Bool":
            self._memory.write(
                caller, (1 if val else 0).to_bytes(width, "little"), addr,
            )
            return
        if leaf == "Float":
            self._memory.write(caller, _struct.pack("<d", float(val)), addr)
            return
        if leaf == "String":
            s_ptr, s_len = self._write_wtf8(caller, val if val is not None else "")
            self._memory.write(caller, s_ptr.to_bytes(4, "little"), addr)
            self._memory.write(caller, s_len.to_bytes(4, "little"), addr + 4)
            return
        raise WasmHostError(f"foreign aggregate: unknown scalar leaf {leaf!r}")

    def _write_slot(
        self, caller, addr: int, node: dict, val, width: int, depth: int,
    ) -> None:
        """Write one aggregate SLOT at ``addr``. A scalar leaf is written
        inline; any nested aggregate allocates its CHILD record FIRST
        (recursively) and THEN stores the child pointer into this slot
        (allocation ordering). ``width`` is the pointer's footprint here:
        4 for a struct field / List element / sum payload, 8 for an
        i64-extended tuple / Option / Result slot (the extra bytes stay
        zero)."""
        if node["kind"] == "scalar":
            self._write_leaf(caller, addr, node["leaf"], val, width)
            return
        child = self._write_capa_value(caller, val, node, depth + 1)
        self._memory.write(caller, child.to_bytes(width, "little"), addr)

    def _write_capa_value(
        self, caller, value, schema: dict, depth: int = 0,
    ) -> int:
        """Write ``value`` (the child's returned Python value) back into
        the parent's memory as a Capa heap record of any finite nesting
        depth, returning its i32 pointer (feature #4 F2c-2). Every
        allocation is bounded by the guest ``$alloc`` / the memory cap, so
        a malformed or huge child return is memory-safe (surfaces as a
        clean WasmHostError, not a scribble)."""
        if depth > _MAX_MARSHAL_DEPTH:
            raise WasmHostError(
                "foreign aggregate: nesting exceeded the marshalling depth "
                f"bound ({_MAX_MARSHAL_DEPTH})"
            )
        kind = schema["kind"]
        if kind == "struct":
            ptr = self._host_alloc(caller, schema["size"])
            if schema.get("has_header"):
                # Multi-impl-trait dispatch type-id at offset 4 (the header
                # word), so downstream dynamic dispatch on the returned
                # value routes to the right concrete impl.
                self._memory.write(
                    caller,
                    int(schema.get("type_id", 0)).to_bytes(4, "little"),
                    ptr + 4,
                )
            for f in schema["fields"]:
                self._write_slot(
                    caller, ptr + f["offset"], f["node"],
                    getattr(value, f["wit"]), f["size"], depth,
                )
            return ptr
        if kind == "list":
            items = list(value)
            n = len(items)
            stride = schema["stride"]
            elem = schema["elem"]
            data = self._host_alloc(caller, n * stride) if n else 0
            for i, v in enumerate(items):
                self._write_slot(caller, data + i * stride, elem, v, stride, depth)
            hdr = self._host_alloc(caller, 16)
            self._memory.write(caller, n.to_bytes(4, "little"), hdr)
            self._memory.write(caller, n.to_bytes(4, "little"), hdr + 4)
            self._memory.write(caller, data.to_bytes(4, "little"), hdr + 8)
            self._memory.write(caller, (0).to_bytes(4, "little"), hdr + 12)
            return hdr
        if kind == "tuple":
            elems = schema["elems"]
            ptr = self._host_alloc(caller, 8 * len(elems))
            for i, (node, v) in enumerate(zip(elems, tuple(value))):
                self._write_slot(caller, ptr + i * 8, node, v, 8, depth)
            return ptr
        if kind == "option":
            ptr = self._host_alloc(caller, 16)
            some, payload = self._unwrap_option(value, schema)
            if some:
                self._memory.write(caller, (0).to_bytes(4, "little"), ptr)
                self._write_slot(caller, ptr + 8, schema["payload"], payload, 8, depth)
            else:
                self._memory.write(caller, (1).to_bytes(4, "little"), ptr)
                self._memory.write(caller, (0).to_bytes(8, "little"), ptr + 8)
            return ptr
        if kind == "result":
            ptr = self._host_alloc(caller, 16)
            is_ok, payload = self._unwrap_result(value, schema)
            self._memory.write(
                caller, (0 if is_ok else 1).to_bytes(4, "little"), ptr,
            )
            node = schema["ok"] if is_ok else schema["err"]
            self._write_slot(caller, ptr + 8, node, payload, 8, depth)
            return ptr
        if kind == "sum":
            ptr = self._host_alloc(caller, schema["size"])
            if schema.get("has_header"):
                self._memory.write(
                    caller,
                    int(schema.get("type_id", 0)).to_bytes(4, "little"),
                    ptr + 4,
                )
            var, values = self._resolve_sum_case(value, schema)
            self._memory.write(caller, int(var["tag"]).to_bytes(4, "little"), ptr)
            for pl, pv in zip(var["payloads"], values):
                self._write_slot(
                    caller, ptr + pl["offset"], pl["node"], pv, pl["size"], depth,
                )
            return ptr
        raise WasmHostError(
            f"foreign aggregate: unknown schema kind {kind!r}"
        )

    def _unwrap_option(self, value, schema: dict):
        """Normalise the child's returned ``option`` to ``(is_some,
        payload)``. A tagged option lifts to a ``wc.Variant``; an untagged
        one to the bare payload (or ``None``)."""
        if schema["tagged"]:
            return value.tag == "some", value.payload
        return value is not None, value

    def _unwrap_result(self, value, schema: dict):
        """Normalise the child's returned ``result`` to ``(is_ok,
        payload)``. A tagged result lifts to a ``wc.Variant``; an untagged
        one to the bare payload, discriminated by Python type in WIT case
        order (ok before err) exactly as wasmtime lowers it."""
        if schema["tagged"]:
            return value.tag == "ok", value.payload
        idx = _discriminate(value, [schema["ok"], schema["err"]])
        return idx == 0, value

    def _resolve_sum_case(self, value, schema: dict):
        """Map the child's returned sum value to ``(variant_meta,
        [payload_value, ...])``. A tagged sum lifts to a ``wc.Variant``
        whose ``.tag`` is the WIT case name; an untagged one to a bare
        payload (or ``None`` for a no-payload case), discriminated by
        Python type in declaration order. A multi-payload case carries a
        tuple, split back into its per-payload slots."""
        from capa.foreign_schema import _sum_case_payload_node
        variants = schema["variants"]
        if schema["tagged"]:
            var = next(v for v in variants if v["wit"] == value.tag)
            payload = value.payload
        else:
            idx = _discriminate(
                value, [_sum_case_payload_node(v) for v in variants],
            )
            var = variants[idx]
            payload = value
        n = len(var["payloads"])
        if n == 0:
            values: list = []
        elif n == 1:
            values = [payload]
        else:
            values = list(payload)
        return var, values

    def _register_stdio(self) -> None:
        """Register the ``capa:stdio`` interface methods. Each
        method takes (ptr, len) as i32s describing a UTF-8 byte
        slice in the module's exported memory; the host reads the
        slice and forwards to Python's stdio."""
        ft_string_to_unit = wasmtime.FuncType(
            [wasmtime.ValType.i32(), wasmtime.ValType.i32()], [],
        )

        # Stream lookups are deferred to call time (each invocation
        # consults the live ``sys.stdout`` / ``sys.stderr``) so tests
        # that ``contextlib.redirect_stdout`` AFTER instantiating
        # the host still capture output. Eager capture at host-
        # construction time would freeze the file objects to the
        # values they had then.
        # Stdio has no return value, so it cannot signal failure
        # back to the guest the way Fs / Env do. Audit fix H3: never
        # raise ``UnicodeDecodeError`` out of the host callback (which
        # would crash the whole wasmtime store); degrade malformed
        # bytes to the Unicode replacement character (U+FFFD) instead.
        # Choice rationale: silent corruption is unacceptable for a
        # security-oriented language, but trapping the guest would
        # propagate a purely cosmetic encoding bug into a hard crash.
        #
        # Capa strings are WTF-8 (UTF-8 plus lone surrogates), so the
        # decode uses ``errors="surrogatepass"`` to preserve unpaired
        # surrogates (e.g. a ``\uD800`` carried through from JSON) as
        # the same str the Python backend holds (``'\ud800'``). Both
        # backends then share ``_write_safe``, which handles the
        # terminal codec identically, so the two paths stay byte-
        # identical at the writer. Strict ``errors="replace"`` here
        # would mangle the three WTF-8 surrogate bytes into three
        # U+FFFD before ``_write_safe`` ever saw them, diverging from
        # the Python oracle. ``surrogatepass`` only handles surrogates;
        # genuinely invalid (non-WTF-8) bytes still raise, so the
        # ``except`` falls back to ``replace`` to keep audit fix H3's
        # no-crash guarantee for malformed input.
        def _decode_wtf8(data):
            raw = bytes(data)
            try:
                return raw.decode("utf-8", errors="surrogatepass")
            except UnicodeDecodeError:
                return raw.decode("utf-8", errors="replace")

        def stdio_print(caller, ptr, length):
            if self._memory is None:
                raise RuntimeError(
                    "stdio called before instance memory was set"
                )
            data = self._memory.read(caller, ptr, ptr + length)
            _write_safe(sys.stdout, _decode_wtf8(data))
            sys.stdout.flush()

        def stdio_println(caller, ptr, length):
            if self._memory is None:
                raise RuntimeError(
                    "stdio called before instance memory was set"
                )
            data = self._memory.read(caller, ptr, ptr + length)
            _write_safe(sys.stdout, _decode_wtf8(data) + "\n")
            sys.stdout.flush()

        def stdio_eprintln(caller, ptr, length):
            if self._memory is None:
                raise RuntimeError(
                    "stdio called before instance memory was set"
                )
            data = self._memory.read(caller, ptr, ptr + length)
            _write_safe(sys.stderr, _decode_wtf8(data) + "\n")
            sys.stderr.flush()

        self.linker.define_func(
            "capa:host/stdio", "print", ft_string_to_unit,
            stdio_print, access_caller=True,
        )
        self.linker.define_func(
            "capa:host/stdio", "println", ft_string_to_unit,
            stdio_println, access_caller=True,
        )
        self.linker.define_func(
            "capa:host/stdio", "eprintln", ft_string_to_unit,
            stdio_eprintln, access_caller=True,
        )

        # Stdio.read_line: canonical-ABI result<string, io-error>.
        # Same 20-byte indirect-return shape as Fs.read; the host
        # writes the tag + Ok (ptr, len) or Err (m_ptr, m_len, c_ptr,
        # c_len) into the caller-allocated area. Mirrors the Python
        # runtime: empty input (EOF) becomes Err("end of input");
        # invalid UTF-8 becomes Err with the decode exception in the
        # cause field (audit H3 convention).
        ft_read_line = wasmtime.FuncType(
            [wasmtime.ValType.i32()], [],
        )

        def _write_rsio_ok_string(caller, ret_area, ptr, length):
            self._memory.write(caller, (0).to_bytes(4, "little"), ret_area)
            self._memory.write(
                caller, ptr.to_bytes(4, "little"), ret_area + 4,
            )
            self._memory.write(
                caller, length.to_bytes(4, "little"), ret_area + 8,
            )
            self._memory.write(
                caller, (0).to_bytes(8, "little"), ret_area + 12,
            )

        def _alloc_utf8_local(caller, text: str) -> tuple[int, int]:
            encoded = text.encode("utf-8")
            if not encoded:
                return 0, 0
            ptr = self._host_alloc(caller, len(encoded))
            self._memory.write(caller, encoded, ptr)
            return ptr, len(encoded)

        def _write_rsio_err(caller, ret_area, message, cause=""):
            m_ptr, m_len = _alloc_utf8_local(caller, message)
            c_ptr, c_len = _alloc_utf8_local(caller, cause)
            self._memory.write(caller, (1).to_bytes(4, "little"), ret_area)
            self._memory.write(
                caller, m_ptr.to_bytes(4, "little"), ret_area + 4,
            )
            self._memory.write(
                caller, m_len.to_bytes(4, "little"), ret_area + 8,
            )
            self._memory.write(
                caller, c_ptr.to_bytes(4, "little"), ret_area + 12,
            )
            self._memory.write(
                caller, c_len.to_bytes(4, "little"), ret_area + 16,
            )

        def stdio_read_line(caller, ret_area):
            if self._memory is None or self._alloc_export is None:
                raise RuntimeError(
                    "stdio.read_line called before memory + $alloc set"
                )
            try:
                line = sys.stdin.readline()
            except OSError as e:
                _write_rsio_err(caller, ret_area, "read failed", str(e))
                return
            except UnicodeDecodeError as e:
                _write_rsio_err(
                    caller, ret_area, "invalid utf-8 on stdin", str(e),
                )
                return
            if not line:
                _write_rsio_err(caller, ret_area, "end of input")
                return
            stripped = line.rstrip("\n")
            s_ptr, s_len = _alloc_utf8_local(caller, stripped)
            _write_rsio_ok_string(caller, ret_area, s_ptr, s_len)

        self.linker.define_func(
            "capa:host/stdio", "read-line", ft_read_line,
            stdio_read_line, access_caller=True,
        )

    def _register_panic(self) -> None:
        """Register the ``capa:host/panic`` import backing the
        ``panic`` builtin. The guest passes the message as a
        (ptr, len) UTF-8 slice; the host writes the canonical
        ``panic: <message>`` line to stderr (flushing stdout first
        so prior program output is not reordered past it) and
        returns. The guest then executes ``unreachable``, so the
        trap that aborts execution is deterministic and guest-side;
        the host import is a pure write."""
        ft_string_to_unit = wasmtime.FuncType(
            [wasmtime.ValType.i32(), wasmtime.ValType.i32()], [],
        )

        def panic_write(caller, ptr, length):
            if self._memory is None:
                raise RuntimeError(
                    "panic called before instance memory was set"
                )
            data = self._memory.read(caller, ptr, ptr + length)
            try:
                sys.stdout.flush()
            except Exception:
                pass
            _write_safe(
                sys.stderr,
                "panic: "
                + bytes(data).decode("utf-8", errors="replace")
                + "\n",
            )
            sys.stderr.flush()
            # Mark the abort as a deliberate panic so the CLI can
            # exit cleanly on the trap the guest's ``unreachable``
            # is about to raise, instead of dumping a host traceback.
            self.panicked = True

        self.linker.define_func(
            "capa:host/panic", "panic", ft_string_to_unit,
            panic_write, access_caller=True,
        )

    def _register_clock(self) -> None:
        """Register the ``capa:host/clock`` interface methods.

        Slice 25.6 (2026-05-30): every Clock op now takes ``handle:
        u32`` as its first arg. The host looks up the receiver Clock
        in ``self._cap_handles`` and consults its real
        ``restrict_to_after`` deadline (``cap.allows()``) before any
        action. Closes the cross-function attenuation bug (audit
        slice 25 F1) for Clock: a Clock narrowed via
        ``restrict_to_after(t)`` threaded through a helper function
        on Wasm now keeps its deadline (pre-slice the host
        hard-coded ``return 1`` for ``allows`` regardless of
        attenuation, so a deny on a narrowed Clock crossing a
        function boundary was lost).

        ``now-secs(handle) -> f64`` / ``now-monotonic(handle) -> f64``:
        the now_* family is a pure query in the Python runtime
        (anyone with a wall clock can read it) so the host doesn't
        gate them on ``allows()``; the handle threads for wire
        uniformity. ``sleep(handle, secs)``: silent no-op on a
        denied cap (matches Python). ``allows(handle) -> bool``:
        queries the looked-up cap's ``allows()`` directly.
        ``restrict-to-after(handle, t) -> u32``: returns a fresh
        handle bound to the later of max(parent_threshold, t).
        """
        import time
        ft_handle_to_f64 = wasmtime.FuncType(
            [wasmtime.ValType.i32()], [wasmtime.ValType.f64()],
        )

        def _lookup_clock(handle):
            """Resolve the receiver Clock cap; return None on a bad
            handle (caller short-circuits to a sensible default
            rather than crashing the host)."""
            try:
                return self._cap_handles.lookup(handle, Clock)
            except CapHandleError:
                return None

        def now_secs(handle):
            # The cap is looked up for wire uniformity (and so a
            # bogus handle surfaces here rather than silently
            # returning a real clock reading). The now_* ops are
            # pure queries that ignore the cap's deadline.
            _lookup_clock(handle)
            return time.time()

        def now_monotonic(handle):
            _lookup_clock(handle)
            return time.monotonic()

        self.linker.define_func(
            "capa:host/clock", "now-secs", ft_handle_to_f64, now_secs,
        )
        self.linker.define_func(
            "capa:host/clock", "now-monotonic", ft_handle_to_f64,
            now_monotonic,
        )

        # Clock.sleep(handle, secs). Slice 25.6: the host enforces
        # the receiver Clock's ``allows()`` before calling
        # ``time.sleep``; on a denied cap the call is a silent
        # no-op (matches the Python runtime). Guard against
        # negative durations (``time.sleep`` raises ValueError) so
        # the guest can't crash the host with a bad literal.
        ft_sleep = wasmtime.FuncType(
            [wasmtime.ValType.i32(), wasmtime.ValType.f64()], [],
        )

        def clock_sleep(handle, secs):
            clock = _lookup_clock(handle)
            if clock is None or not clock.allows():
                return
            if secs < 0:
                return
            time.sleep(secs)

        self.linker.define_func(
            "capa:host/clock", "sleep", ft_sleep, clock_sleep,
        )

        # Clock.allows(handle) -> bool. Slice 25.6: the host looks
        # up the cap and consults its real not-before deadline
        # against the wall clock. Pre-slice the host hard-coded
        # ``return 1`` regardless of attenuation, so a deny on a
        # narrowed Clock crossing a function boundary was lost
        # (audit slice 25 F1 for Clock).
        ft_allows = wasmtime.FuncType(
            [wasmtime.ValType.i32()], [wasmtime.ValType.i32()],
        )

        def clock_allows(handle):
            clock = _lookup_clock(handle)
            if clock is None:
                # Unknown handle: fail-closed (matches Fs / Net
                # patterns where a bad handle never authorises a
                # syscall).
                return 0
            return 1 if clock.allows() else 0

        self.linker.define_func(
            "capa:host/clock", "allows", ft_allows, clock_allows,
        )

        # Clock.restrict_to_after(parent_handle, t) -> u32.
        # Slice 25.6: looks up the parent handle, allocates a child
        # Clock with the later (max-merged) deadline, returns the
        # child's i32 handle.
        ft_restrict_after = wasmtime.FuncType(
            [wasmtime.ValType.i32(), wasmtime.ValType.f64()],
            [wasmtime.ValType.i32()],
        )

        def clock_restrict_to_after(parent_handle, t):
            try:
                return self._cap_handles.restrict_clock_after(
                    parent_handle, t,
                )
            except CapHandleError:
                # Unknown parent handle = emitter bug; return 0
                # (sentinel) so the next Clock op fails loudly.
                return 0

        self.linker.define_func(
            "capa:host/clock", "restrict-to-after", ft_restrict_after,
            clock_restrict_to_after,
        )

    def _register_env(self) -> None:
        """Register the ``capa:host/env`` interface methods.

        Slice 25.5 (2026-05-30): every Env op now takes ``handle: u32``
        as its first arg. The host looks up the receiver Env in
        ``self._cap_handles`` and enforces ``env.allows(name)``
        before reading ``os.environ``. Closes the cross-function
        attenuation bug (audit slice 25 F1) for Env: a restricted
        Env handed off to a helper function on Wasm previously lost
        its allow-list because the emitter inlined the key check at
        the literal call site only.

        ``get(handle, name) -> option<string>``: looks up the cap,
        delegates to ``env.get(name)`` which already does
        ``allows()`` + ``os.environ.get`` + ``Some/None_`` wrapping.
        A denied key looks like an unset variable (returns None)
        matching the Python runtime's fail-closed information-
        hiding policy.

        **Trust boundary (audit M1, 2026-05).** This host bridge
        reads ``os.environ.get(name)`` without filtering: an
        unrestricted ``Env`` cap held by the wasm guest sees every
        host env var (including secrets like ``OPENAI_API_KEY``,
        ``AWS_*``, ``GITHUB_TOKEN``, ``PATH``). Capa's discipline is
        that the Env cap is itself the trust boundary; the
        attenuation system narrows it. Programs that statically call
        ``env.restrict_to_keys([...])`` now have the restriction
        enforced by the host (slice 25.5); unrestricted caps still
        see the full host environment. Hosts wrapping a third-party
        ``.wasm`` blob should refuse to grant an unrestricted Env
        cap unless they have audited the guest."""
        import os
        # Canonical ABI lowering: ``option<string>`` returns through
        # a 12-byte caller-allocated area (tag i32 @ 0, ptr i32 @ 4,
        # len i32 @ 8). The host writes the flat fields; the IR
        # materialiser repackages them into a Capa Option<String>
        # heap record.
        # Slice 25.5: handle + (name_ptr, name_len) + ret_area =
        # 4 i32s.
        ft_handle_string_indirect = wasmtime.FuncType(
            [
                wasmtime.ValType.i32(),
                wasmtime.ValType.i32(),
                wasmtime.ValType.i32(),
                wasmtime.ValType.i32(),
            ],
            [],
        )

        def _lookup_env(handle):
            """Resolve the receiver Env cap. Returns None on a bad
            handle; callers short-circuit to a "no such key" None
            value (matching the fail-closed convention)."""
            try:
                return self._cap_handles.lookup(handle, Env)
            except CapHandleError:
                return None

        def env_get(caller, handle, name_ptr, name_len, ret_area):
            if self._memory is None or self._alloc_export is None:
                raise RuntimeError(
                    "env.get called before instance memory + $alloc set"
                )
            data = self._memory.read(caller, name_ptr, name_ptr + name_len)
            # Audit fix H3: invalid UTF-8 in the lookup key cannot match
            # any real env var (env names are well-formed strings on every
            # OS we target); return None cleanly instead of bubbling
            # ``UnicodeDecodeError`` up through wasmtime and crashing the
            # store. The WIT shape (``option<string>``) already carries
            # the "no such key" path, so the guest sees the same value
            # it would for a typo.
            try:
                name = bytes(data).decode("utf-8")
            except UnicodeDecodeError:
                value = None
            else:
                # Slice 25.5: enforce via the looked-up Env cap.
                # ``Env.get`` already does ``allows(name)`` +
                # ``os.environ.get`` + ``Some/None_`` wrapping.
                env = _lookup_env(handle)
                if env is None or not env.allows(name):
                    value = None
                else:
                    value = os.environ.get(name)
            # Tag convention: write the WIT-canonical discriminant
            # (none=0, some=1). The materialiser XOR-flips to Capa's
            # internal Option layout (Some=0, None=1) on read, so
            # the core-host path and the Component Model path
            # produce identical Capa records. Pre-fix the core host
            # wrote Capa-convention tags here which happened to fake-
            # match the materialiser's then-naive copy; the bug
            # surfaced only on the component-wrapped path because
            # the CM adapter writes WIT-convention.
            if value is None:
                # tag = 0 (WIT none); ptr/len fields undefined per
                # WIT, write zeros so memory stays deterministic.
                self._memory.write(
                    caller, (0).to_bytes(4, "little"), ret_area,
                )
                self._memory.write(
                    caller, (0).to_bytes(4, "little"), ret_area + 4,
                )
                self._memory.write(
                    caller, (0).to_bytes(4, "little"), ret_area + 8,
                )
                return
            encoded = value.encode("utf-8")
            if encoded:
                s_ptr = self._host_alloc(caller, len(encoded))
                self._memory.write(caller, encoded, s_ptr)
            else:
                s_ptr = 0
            # tag = 1 (WIT some)
            self._memory.write(caller, (1).to_bytes(4, "little"), ret_area)
            self._memory.write(
                caller, s_ptr.to_bytes(4, "little"), ret_area + 4,
            )
            self._memory.write(
                caller,
                len(encoded).to_bytes(4, "little"),
                ret_area + 8,
            )

        self.linker.define_func(
            "capa:host/env", "get", ft_handle_string_indirect,
            env_get, access_caller=True,
        )

        # env.args(handle) -> list<string>. Slice 25.5: handle +
        # ret_area (canonical-ABI indirect). Builds a List<String> in
        # linear memory: 16-byte header (len, cap, data_ptr, pad)
        # + N*8-byte data array of packed (ptr, len) i64s. The
        # WasmHost stashes argv at construction time. The handle
        # is taken for wire uniformity; argv itself is not
        # restriction-bearing (mirrors the Python ``Env.args``).
        ft_handle_to_unit_indirect = wasmtime.FuncType(
            [wasmtime.ValType.i32(), wasmtime.ValType.i32()], [],
        )

        def env_args(caller, handle, ret_area):
            if self._memory is None or self._alloc_export is None:
                raise RuntimeError(
                    "env.args called before memory + $alloc set"
                )
            # Look up the cap (for wire uniformity / loud failure on
            # a bad handle); args themselves don't depend on the
            # cap's allow-list.
            _lookup_env(handle)
            n = len(self._args)
            # Allocate the data buffer (n * 8 bytes). Each slot
            # holds (str_ptr i32, str_len i32) which is the same
            # byte layout Capa's packed-i64 string convention
            # produces, so downstream List<String> iteration
            # works unchanged.
            data_ptr = self._host_alloc(caller, n * 8) if n else 0
            for i, arg in enumerate(self._args):
                encoded = arg.encode("utf-8")
                if encoded:
                    s_ptr = self._host_alloc(caller, len(encoded))
                    self._memory.write(caller, encoded, s_ptr)
                else:
                    # Empty string: a valid (0, 0) slot; pointer
                    # never read because length is zero.
                    s_ptr = 0
                slot = data_ptr + i * 8
                self._memory.write(
                    caller, s_ptr.to_bytes(4, "little"), slot,
                )
                self._memory.write(
                    caller, len(encoded).to_bytes(4, "little"), slot + 4,
                )
            # Write (data_ptr, len) into the return area.
            self._memory.write(
                caller, data_ptr.to_bytes(4, "little"), ret_area,
            )
            self._memory.write(
                caller, n.to_bytes(4, "little"), ret_area + 4,
            )

        self.linker.define_func(
            "capa:host/env", "args", ft_handle_to_unit_indirect,
            env_args, access_caller=True,
        )

        # env.restrict-to-keys(parent_handle, data_ptr, len) -> u32.
        # Slice 25.5 (2026-05-30): walks the keys list out of linear
        # memory and allocates a child Env with the narrowed allow-
        # list (intersection with the parent). The data array
        # stores N packed (str_ptr, str_len) i32 pairs - same
        # layout the host produces for ``env.args``.
        ft_restrict_keys = wasmtime.FuncType(
            [
                wasmtime.ValType.i32(),  # parent handle
                wasmtime.ValType.i32(),  # data_ptr
                wasmtime.ValType.i32(),  # len
            ],
            [wasmtime.ValType.i32()],
        )

        def env_restrict_to_keys(caller, parent_handle, data_ptr, n):
            if self._memory is None:
                raise RuntimeError(
                    "env.restrict_to_keys called before memory was set"
                )
            keys: list[str] = []
            for i in range(n):
                slot = data_ptr + i * 8
                k_ptr_b = bytes(self._memory.read(caller, slot, slot + 4))
                k_len_b = bytes(self._memory.read(caller, slot + 4, slot + 8))
                k_ptr = int.from_bytes(k_ptr_b, "little")
                k_len = int.from_bytes(k_len_b, "little")
                try:
                    key = bytes(
                        self._memory.read(caller, k_ptr, k_ptr + k_len)
                    ).decode("utf-8")
                except UnicodeDecodeError:
                    # An invalid-UTF-8 key cannot match any real env
                    # var; skip it rather than crashing the host.
                    continue
                keys.append(key)
            try:
                return self._cap_handles.restrict_env(parent_handle, keys)
            except CapHandleError:
                # Unknown parent handle = emitter bug; return 0 so
                # the next Env op fails loudly.
                return 0

        self.linker.define_func(
            "capa:host/env", "restrict-to-keys", ft_restrict_keys,
            env_restrict_to_keys, access_caller=True,
        )

        # Env.allows(handle, key_ptr, key_len) -> i32 (bool). GAP-2b
        # (2026-06-21): looks up the receiver Env cap and returns
        # ``env.allows(key)`` (canon-key allow-list membership). This
        # is the case that DIVERGED SILENTLY pre-route: the guest-side
        # key-list reconstruction returned [] for a dynamic
        # restrict_to_keys list, so the query answered ``no`` where
        # Python answered ``yes``. Routing it host-side restores
        # parity. Bad handle / invalid UTF-8 fail closed (0).
        ft_allows = wasmtime.FuncType(
            [
                wasmtime.ValType.i32(),  # handle
                wasmtime.ValType.i32(),  # key_ptr
                wasmtime.ValType.i32(),  # key_len
            ],
            [wasmtime.ValType.i32()],
        )

        def env_allows(caller, handle, key_ptr, key_len):
            if self._memory is None:
                raise RuntimeError(
                    "env.allows called before memory was set"
                )
            try:
                key = bytes(
                    self._memory.read(caller, key_ptr, key_ptr + key_len)
                ).decode("utf-8")
            except UnicodeDecodeError:
                return 0
            env = _lookup_env(handle)
            if env is None:
                return 0
            return 1 if env.allows(key) else 0

        self.linker.define_func(
            "capa:host/env", "allows", ft_allows,
            env_allows, access_caller=True,
        )

    def _register_fs(self) -> None:
        """Register ``capa:host/fs`` interface methods.

        Slice 25.2 (2026-05-30): every Fs op now takes ``handle: u32``
        as its first arg. The host looks up the receiver Fs in
        ``self._cap_handles`` and enforces the restriction
        (``fs.allows(path)``) before the syscall. This closes the
        cross-function attenuation bug (audit slice 25 F1): a
        restricted Fs threaded through a helper function on Wasm
        previously lost its restriction because the emitter inlined
        the prefix check at the literal call site only. Now the
        receiver carries an i32 handle through the Wasm value flow
        and the host enforces on every call.

        ``read(handle: u32, path: string) -> result<string, io-error>``:
        looks up the cap from the handle table, calls
        ``fs.allows(path)``; on deny, writes
        ``Err(IoError(\"permission denied: ...\"))`` to the ret area
        and skips the syscall. On allow, reads the file. ``write`` /
        ``mkdir`` / ``list_dir`` follow the same pattern.
        ``exists`` / ``is_dir`` fail-closed-as-absent on a denied
        path (returns false rather than leaking out-of-prefix
        existence; matches the Python runtime's behaviour).
        ``restrict-to`` returns a fresh handle bound to a child
        restriction (intersection with the parent)."""
        # Canonical ABI: result<T, io-error> returns indirectly via
        # a 20-byte caller area. Layout:
        #   tag i32  @ 0
        #   Ok arm (string): ptr @ 4, len @ 8 (Ok<unit> writes zeros)
        #   Err arm (io-error): m_ptr @ 4, m_len @ 8, c_ptr @ 12,
        #                       c_len @ 16
        ft_fs_read_indirect = wasmtime.FuncType(
            [
                wasmtime.ValType.i32(),  # handle (slice 25.2)
                wasmtime.ValType.i32(),  # path_ptr
                wasmtime.ValType.i32(),  # path_len
                wasmtime.ValType.i32(),  # ret_area
            ],
            [],
        )
        ft_fs_write_indirect = wasmtime.FuncType(
            [
                wasmtime.ValType.i32(),  # handle (slice 25.2)
                wasmtime.ValType.i32(),  # path_ptr
                wasmtime.ValType.i32(),  # path_len
                wasmtime.ValType.i32(),  # content_ptr
                wasmtime.ValType.i32(),  # content_len
                wasmtime.ValType.i32(),  # ret_area
            ],
            [],
        )

        def _alloc_utf8(caller, text: str) -> tuple[int, int]:
            encoded = text.encode("utf-8")
            if not encoded:
                return 0, 0
            ptr = self._host_alloc(caller, len(encoded))
            self._memory.write(caller, encoded, ptr)
            return ptr, len(encoded)

        def _write_result_ok_string(caller, ret_area, ptr, length):
            self._memory.write(caller, (0).to_bytes(4, "little"), ret_area)
            self._memory.write(
                caller, ptr.to_bytes(4, "little"), ret_area + 4,
            )
            self._memory.write(
                caller, length.to_bytes(4, "little"), ret_area + 8,
            )
            # Zero the remaining bytes of the Err union for tidiness.
            self._memory.write(
                caller, (0).to_bytes(8, "little"), ret_area + 12,
            )

        def _write_result_ok_unit(caller, ret_area):
            # Tag = 0, rest zeroed.
            self._memory.write(caller, (0).to_bytes(4, "little"), ret_area)
            self._memory.write(
                caller, (0).to_bytes(16, "little"), ret_area + 4,
            )

        def _write_result_err_ioerror(caller, ret_area, message, cause=""):
            m_ptr, m_len = _alloc_utf8(caller, message)
            c_ptr, c_len = _alloc_utf8(caller, cause)
            self._memory.write(caller, (1).to_bytes(4, "little"), ret_area)
            self._memory.write(
                caller, m_ptr.to_bytes(4, "little"), ret_area + 4,
            )
            self._memory.write(
                caller, m_len.to_bytes(4, "little"), ret_area + 8,
            )
            self._memory.write(
                caller, c_ptr.to_bytes(4, "little"), ret_area + 12,
            )
            self._memory.write(
                caller, c_len.to_bytes(4, "little"), ret_area + 16,
            )

        def _lookup_fs_or_err(caller, handle, ret_area):
            """Resolve the receiver Fs cap from the handle table.
            On failure (unknown handle / wrong type / zero sentinel)
            write an Err(IoError) into ``ret_area`` and return
            None; callers short-circuit and skip the syscall."""
            try:
                return self._cap_handles.lookup(handle, Fs)
            except CapHandleError as e:
                _write_result_err_ioerror(
                    caller, ret_area,
                    "invalid Fs capability handle", str(e),
                )
                return None

        def fs_read(caller, handle, path_ptr, path_len, ret_area):
            if self._memory is None or self._alloc_export is None:
                raise RuntimeError(
                    "fs.read called before memory + $alloc set"
                )
            # Audit fix H3: invalid UTF-8 in the path argument is
            # a guest-side bug, not a host-process crash. Surface it
            # through the WIT result<_, io-error> channel so the guest
            # can pattern-match on Err the same way it would for a
            # permission-denied or no-such-file failure.
            try:
                path = bytes(
                    self._memory.read(caller, path_ptr, path_ptr + path_len)
                ).decode("utf-8")
            except UnicodeDecodeError as e:
                _write_result_err_ioerror(
                    caller, ret_area, f"invalid utf-8 in path: {e}",
                )
                return
            # Slice 25.2: enforce the receiver cap's restriction here
            # rather than trusting an emitter-inlined prefix check. The
            # cross-function attenuation bug (audit slice 25 F1) fell
            # out of the inline approach losing the restriction at any
            # function boundary; routing through ``self.allows(path)``
            # is the single soundness chokepoint.
            fs = _lookup_fs_or_err(caller, handle, ret_area)
            if fs is None:
                return
            if not fs.allows(path):
                _write_result_err_ioerror(
                    caller, ret_area,
                    f"Fs capability does not permit read: {path}",
                )
                return
            # TOCTOU hardening (2026-06-10): route through the same
            # Fs._open_read used by the Python backend, which
            # re-validates the true path of the open handle on
            # restricted caps. A symlink swapped between allows()
            # and the open lands here as PostOpenDenied and surfaces
            # as the same deny message as the pre-check.
            try:
                with fs._open_read(path) as f:
                    content = f.read()
                s_ptr, s_len = _alloc_utf8(caller, content)
                _write_result_ok_string(caller, ret_area, s_ptr, s_len)
            except PostOpenDenied:
                _write_result_err_ioerror(
                    caller, ret_area,
                    f"Fs capability does not permit read: {path}",
                )
            except OSError as e:
                _write_result_err_ioerror(caller, ret_area, str(e))

        def fs_write(caller, handle, p_ptr, p_len, c_ptr, c_len, ret_area):
            if self._memory is None or self._alloc_export is None:
                raise RuntimeError(
                    "fs.write called before memory + $alloc set"
                )
            # Audit fix H3: same as fs.read, but two strings can each
            # be invalid; surface both in the Err message so the guest
            # can tell which arg was malformed.
            try:
                path = bytes(
                    self._memory.read(caller, p_ptr, p_ptr + p_len)
                ).decode("utf-8")
            except UnicodeDecodeError as e:
                _write_result_err_ioerror(
                    caller, ret_area, f"invalid utf-8 in path: {e}",
                )
                return
            try:
                content = bytes(
                    self._memory.read(caller, c_ptr, c_ptr + c_len)
                ).decode("utf-8")
            except UnicodeDecodeError as e:
                _write_result_err_ioerror(
                    caller, ret_area, f"invalid utf-8 in content: {e}",
                )
                return
            fs = _lookup_fs_or_err(caller, handle, ret_area)
            if fs is None:
                return
            if not fs.allows(path):
                _write_result_err_ioerror(
                    caller, ret_area,
                    f"Fs capability does not permit write: {path}",
                )
                return
            # TOCTOU hardening: same routing as fs_read; on a
            # restricted cap the open does NOT truncate until the
            # handle's true path passes verification, so a denied
            # write never destroys data outside the prefixes.
            try:
                with fs._open_write(path) as f:
                    f.write(content)
                _write_result_ok_unit(caller, ret_area)
            except PostOpenDenied:
                _write_result_err_ioerror(
                    caller, ret_area,
                    f"Fs capability does not permit write: {path}",
                )
            except OSError as e:
                _write_result_err_ioerror(caller, ret_area, str(e))

        self.linker.define_func(
            "capa:host/fs", "read", ft_fs_read_indirect,
            fs_read, access_caller=True,
        )
        self.linker.define_func(
            "capa:host/fs", "write", ft_fs_write_indirect,
            fs_write, access_caller=True,
        )

        # fs.restrict_to: slice 25.2 (2026-05-30). Looks up the parent
        # handle, allocates a child Fs with the narrowed prefix, and
        # returns the child's i32 handle. The Capa-side ``restrict_to``
        # expression now produces a non-erased i32 value the guest
        # threads as the receiver of subsequent Fs calls; passing it
        # across a function boundary preserves the restriction (the
        # bug fixed by this slice).
        ft_restrict_to = wasmtime.FuncType(
            [
                wasmtime.ValType.i32(),  # parent handle
                wasmtime.ValType.i32(),  # prefix_ptr
                wasmtime.ValType.i32(),  # prefix_len
            ],
            [wasmtime.ValType.i32()],
        )

        def fs_restrict_to(caller, parent_handle, prefix_ptr, prefix_len):
            if self._memory is None:
                raise RuntimeError(
                    "fs.restrict_to called before memory was set"
                )
            # Invalid UTF-8 in the prefix: surface as zero handle
            # (the lookup-zero-sentinel raise on next use is the
            # closest analogue to the Python runtime's failure mode
            # without breaking the WIT signature). Vanishingly rare
            # in practice (prefix is normally a literal interned at
            # emit time).
            try:
                prefix = bytes(
                    self._memory.read(
                        caller, prefix_ptr, prefix_ptr + prefix_len,
                    )
                ).decode("utf-8")
            except UnicodeDecodeError:
                return 0
            try:
                return self._cap_handles.restrict_fs(parent_handle, prefix)
            except CapHandleError:
                # Unknown parent handle = emitter bug; the guest
                # would crash on the next Fs op anyway. Return 0
                # (sentinel) so the failure is loud rather than
                # silently aliasing a real cap.
                return 0

        self.linker.define_func(
            "capa:host/fs", "restrict-to", ft_restrict_to,
            fs_restrict_to, access_caller=True,
        )

        # Fs.allows(handle, path_ptr, path_len) -> i32 (bool). GAP-2b
        # (2026-06-21): the authoritative guest-side query. Looks up
        # the receiver Fs cap and returns ``fs.allows(path)`` - the
        # same realpath-canonicalising containment check the
        # privileged ops enforce - so the query answer equals the
        # enforcement. Invalid UTF-8 or a bad handle fail closed (0).
        ft_allows = wasmtime.FuncType(
            [
                wasmtime.ValType.i32(),  # handle
                wasmtime.ValType.i32(),  # path_ptr
                wasmtime.ValType.i32(),  # path_len
            ],
            [wasmtime.ValType.i32()],
        )

        def fs_allows(caller, handle, path_ptr, path_len):
            if self._memory is None:
                raise RuntimeError(
                    "fs.allows called before memory was set"
                )
            try:
                path = bytes(
                    self._memory.read(caller, path_ptr, path_ptr + path_len)
                ).decode("utf-8")
            except UnicodeDecodeError:
                return 0
            fs = _lookup_fs_bool(caller, handle)
            if fs is None:
                return 0
            return 1 if fs.allows(path) else 0

        self.linker.define_func(
            "capa:host/fs", "allows", ft_allows,
            fs_allows, access_caller=True,
        )

        # Fs.exists / Fs.is_dir: (handle, path_ptr, path_len) -> i32 (bool).
        # Mirror the Python runtime's fail-closed-as-absent
        # convention: invalid UTF-8 in the path OR a denied path
        # returns 0 (the host can't even attempt the syscall /
        # the cap doesn't permit it). Routes through the handle
        # table so cross-function restrictions hold (slice 25.2).
        ft_path_to_bool = wasmtime.FuncType(
            [
                wasmtime.ValType.i32(),  # handle (slice 25.2)
                wasmtime.ValType.i32(),
                wasmtime.ValType.i32(),
            ],
            [wasmtime.ValType.i32()],
        )

        import os as _os_mod

        def _lookup_fs_bool(caller, handle):
            """Bool-returning variant of the lookup helper. Returns
            None when the handle is invalid; callers report 0."""
            try:
                return self._cap_handles.lookup(handle, Fs)
            except CapHandleError:
                return None

        def fs_exists(caller, handle, path_ptr, path_len):
            if self._memory is None:
                raise RuntimeError(
                    "fs.exists called before memory was set"
                )
            try:
                path = bytes(
                    self._memory.read(caller, path_ptr, path_ptr + path_len)
                ).decode("utf-8")
            except UnicodeDecodeError:
                return 0
            fs = _lookup_fs_bool(caller, handle)
            if fs is None or not fs.allows(path):
                return 0
            return 1 if _os_mod.path.exists(path) else 0

        def fs_is_dir(caller, handle, path_ptr, path_len):
            if self._memory is None:
                raise RuntimeError(
                    "fs.is_dir called before memory was set"
                )
            try:
                path = bytes(
                    self._memory.read(caller, path_ptr, path_ptr + path_len)
                ).decode("utf-8")
            except UnicodeDecodeError:
                return 0
            fs = _lookup_fs_bool(caller, handle)
            if fs is None or not fs.allows(path):
                return 0
            return 1 if _os_mod.path.isdir(path) else 0

        self.linker.define_func(
            "capa:host/fs", "exists", ft_path_to_bool,
            fs_exists, access_caller=True,
        )
        self.linker.define_func(
            "capa:host/fs", "is-dir", ft_path_to_bool,
            fs_is_dir, access_caller=True,
        )

        # Fs.mkdir: (handle, path_ptr, path_len, ret_area) -> ()
        # Same canonical-ABI shape as Fs.write Ok-Unit branch (20-byte
        # area). Idempotent via ``exist_ok=True`` to match the Python
        # runtime's contract; failures (e.g. EACCES, ENOTDIR on a
        # path component) become Err(IoError).
        ft_mkdir = wasmtime.FuncType(
            [
                wasmtime.ValType.i32(),  # handle (slice 25.2)
                wasmtime.ValType.i32(),
                wasmtime.ValType.i32(),
                wasmtime.ValType.i32(),
            ],
            [],
        )

        def fs_mkdir(caller, handle, path_ptr, path_len, ret_area):
            if self._memory is None or self._alloc_export is None:
                raise RuntimeError(
                    "fs.mkdir called before memory + $alloc set"
                )
            try:
                path = bytes(
                    self._memory.read(caller, path_ptr, path_ptr + path_len)
                ).decode("utf-8")
            except UnicodeDecodeError as e:
                _write_result_err_ioerror(
                    caller, ret_area, f"invalid utf-8 in path: {e}",
                )
                return
            fs = _lookup_fs_or_err(caller, handle, ret_area)
            if fs is None:
                return
            if not fs.allows(path):
                _write_result_err_ioerror(
                    caller, ret_area,
                    f"Fs capability does not permit mkdir: {path}",
                )
                return
            try:
                _os_mod.makedirs(path, exist_ok=True)
                _write_result_ok_unit(caller, ret_area)
            except OSError as e:
                _write_result_err_ioerror(caller, ret_area, str(e))

        self.linker.define_func(
            "capa:host/fs", "mkdir", ft_mkdir,
            fs_mkdir, access_caller=True,
        )

        # Fs.list_dir: (handle, path_ptr, path_len, ret_area) -> ()
        # Canonical-ABI result<list<string>, io-error>. ret_area is
        # 20 bytes: tag i32 @ 0; Ok arm (data_ptr i32 @ 4, len i32 @ 8);
        # Err arm (m_ptr @ 4, m_len @ 8, c_ptr @ 12, c_len @ 16).
        # Host allocates the list data buffer (n*8 packed (ptr, len)
        # slots, same layout as Env.args produces); the IR
        # materialiser wraps it in a List<String> header. Entries are
        # sorted to match the Python runtime's
        # ``sorted(os.listdir(path))``.
        def fs_list_dir(caller, handle, path_ptr, path_len, ret_area):
            if self._memory is None or self._alloc_export is None:
                raise RuntimeError(
                    "fs.list_dir called before memory + $alloc set"
                )
            try:
                path = bytes(
                    self._memory.read(caller, path_ptr, path_ptr + path_len)
                ).decode("utf-8")
            except UnicodeDecodeError as e:
                _write_result_err_ioerror(
                    caller, ret_area, f"invalid utf-8 in path: {e}",
                )
                return
            fs = _lookup_fs_or_err(caller, handle, ret_area)
            if fs is None:
                return
            if not fs.allows(path):
                _write_result_err_ioerror(
                    caller, ret_area,
                    f"Fs capability does not permit list_dir: {path}",
                )
                return
            try:
                entries = sorted(_os_mod.listdir(path))
            except OSError as e:
                _write_result_err_ioerror(caller, ret_area, str(e))
                return
            n = len(entries)
            data_ptr = self._host_alloc(caller, n * 8) if n else 0
            for i, entry in enumerate(entries):
                encoded = entry.encode("utf-8")
                if encoded:
                    s_ptr = self._host_alloc(caller, len(encoded))
                    self._memory.write(caller, encoded, s_ptr)
                else:
                    s_ptr = 0
                slot = data_ptr + i * 8
                self._memory.write(
                    caller, s_ptr.to_bytes(4, "little"), slot,
                )
                self._memory.write(
                    caller, len(encoded).to_bytes(4, "little"), slot + 4,
                )
            # Ok tag + (data_ptr, len) into the area; zero the unused
            # Err c_ptr / c_len bytes so the layout stays
            # deterministic.
            self._memory.write(caller, (0).to_bytes(4, "little"), ret_area)
            self._memory.write(
                caller, data_ptr.to_bytes(4, "little"), ret_area + 4,
            )
            self._memory.write(
                caller, n.to_bytes(4, "little"), ret_area + 8,
            )
            self._memory.write(
                caller, (0).to_bytes(8, "little"), ret_area + 12,
            )

        self.linker.define_func(
            "capa:host/fs", "list-dir", ft_mkdir,
            fs_list_dir, access_caller=True,
        )

    def _register_random(self) -> None:
        """Register the ``capa:host/random`` interface methods.

        Only one method crosses the host boundary: ``system-seed``
        returns 8 bytes of entropy (as a u64) at the moment an
        unseeded guest ``Random()`` lazy-initialises its PRNG state.
        Every subsequent draw runs guest-side in pure WAT (SplitMix64
        over a module-local i64), so seeded sequences are byte-
        identical with the Python backend.
        """
        import os
        ft_seed = wasmtime.FuncType([], [wasmtime.ValType.i64()])

        def random_system_seed():
            # ``os.urandom(8)`` -> little-endian unsigned u64. Matches
            # the Python ``Random.__init__`` entropy path exactly so
            # both backends seed off the same byte-shape on an
            # unseeded construction. Wasmtime's i64 type carries the
            # full 64 bits regardless of Python's signed-int rendering
            # at the binding boundary.
            return int.from_bytes(os.urandom(8), "little", signed=False)

        self.linker.define_func(
            "capa:host/random", "system-seed", ft_seed,
            random_system_seed,
        )

    def _register_net(self) -> None:
        """Register the ``capa:host/net`` interface methods.

        Slice 25.3 (2026-05-30): every Net op now takes ``handle: u32``
        as its first arg. The host looks up the receiver Net cap in
        ``self._cap_handles`` and enforces the restriction by calling
        the looked-up ``Net.get(url)`` / ``Net.post(url, body)``
        directly (the existing Python ``Net.get`` / ``Net.post``
        already do ``urlparse(url).hostname`` + ``allows()``, which
        also fixes audit slice 25 F2 - the inline
        ``$str_contains(url, host)`` accepted lookalikes like
        ``https://attacker.invalid/?redir=api.example.com``).

        Methods:
        - ``get(handle, url) -> Result<String, IoError>``
        - ``post(handle, url, body) -> Result<String, IoError>``
        - ``restrict-to(handle, host) -> u32``

        Cross-function attenuation soundness (audit slice 25 F1):
        a restricted Net cap threaded through a helper function on
        Wasm now keeps its restriction because the receiver carries
        its i32 handle through every call; the host enforces on
        every privileged op rather than at the literal call site
        only."""
        # Canonical ABI: result<string, io-error> returns indirectly
        # via a 20-byte caller area. Same shape as Fs.read. Layout:
        #   tag i32  @ 0
        #   Ok arm (string): ptr @ 4, len @ 8
        #   Err arm (io-error): m_ptr @ 4, m_len @ 8, c_ptr @ 12,
        #                       c_len @ 16
        ft_net_get_indirect = wasmtime.FuncType(
            [
                wasmtime.ValType.i32(),  # handle (slice 25.3)
                wasmtime.ValType.i32(),  # url_ptr
                wasmtime.ValType.i32(),  # url_len
                wasmtime.ValType.i32(),  # ret_area
            ],
            [],
        )

        def _alloc_utf8(caller, text: str) -> tuple[int, int]:
            encoded = text.encode("utf-8")
            if not encoded:
                return 0, 0
            ptr = self._host_alloc(caller, len(encoded))
            self._memory.write(caller, encoded, ptr)
            return ptr, len(encoded)

        def _write_result_ok_string(caller, ret_area, ptr, length):
            self._memory.write(caller, (0).to_bytes(4, "little"), ret_area)
            self._memory.write(
                caller, ptr.to_bytes(4, "little"), ret_area + 4,
            )
            self._memory.write(
                caller, length.to_bytes(4, "little"), ret_area + 8,
            )
            self._memory.write(
                caller, (0).to_bytes(8, "little"), ret_area + 12,
            )

        def _write_result_err_ioerror(caller, ret_area, message, cause=""):
            m_ptr, m_len = _alloc_utf8(caller, message)
            c_ptr, c_len = _alloc_utf8(caller, cause)
            self._memory.write(caller, (1).to_bytes(4, "little"), ret_area)
            self._memory.write(
                caller, m_ptr.to_bytes(4, "little"), ret_area + 4,
            )
            self._memory.write(
                caller, m_len.to_bytes(4, "little"), ret_area + 8,
            )
            self._memory.write(
                caller, c_ptr.to_bytes(4, "little"), ret_area + 12,
            )
            self._memory.write(
                caller, c_len.to_bytes(4, "little"), ret_area + 16,
            )

        def _lookup_net_or_err(caller, handle, ret_area):
            """Resolve the receiver Net cap from the handle table.
            On failure (unknown handle / wrong type / zero sentinel)
            write an Err(IoError) into ``ret_area`` and return
            None; callers short-circuit and skip the syscall."""
            try:
                return self._cap_handles.lookup(handle, Net)
            except CapHandleError as e:
                _write_result_err_ioerror(
                    caller, ret_area,
                    "invalid Net capability handle", str(e),
                )
                return None

        def net_get(caller, handle, url_ptr, url_len, ret_area):
            if self._memory is None or self._alloc_export is None:
                raise RuntimeError(
                    "net.get called before memory + $alloc set"
                )
            # Audit H3 convention: invalid UTF-8 in the URL bytes
            # is a guest-side bug; route it through the WIT
            # result<_, io-error> Err arm so the guest pattern-
            # matches it the same way it would a real network
            # failure, instead of trapping the host.
            try:
                url = bytes(
                    self._memory.read(caller, url_ptr, url_ptr + url_len)
                ).decode("utf-8")
            except UnicodeDecodeError as e:
                _write_result_err_ioerror(
                    caller, ret_area, "invalid URL", str(e),
                )
                return
            # Slice 25.3: enforce via the looked-up Net cap directly.
            # ``Net.get`` already does ``urlparse(url).hostname`` +
            # ``allows()`` + the urlopen call + the same OSError /
            # URLError fall-through to a Capa-side IoError. Routing
            # through it gives us the F2 substring-attack fix for
            # free (the host bridge previously trusted the emitter's
            # inline ``$str_contains`` check, which admitted
            # lookalike URLs).
            net = _lookup_net_or_err(caller, handle, ret_area)
            if net is None:
                return
            from ._result import Ok
            result = net.get(url)
            if isinstance(result, Ok):
                s_ptr, s_len = _alloc_utf8(caller, result.value)
                _write_result_ok_string(caller, ret_area, s_ptr, s_len)
            else:
                # Err: payload is an IoError instance with
                # .message / .cause String fields.
                err = result.error
                _write_result_err_ioerror(
                    caller, ret_area,
                    getattr(err, "message", str(err)),
                    getattr(err, "cause", ""),
                )

        self.linker.define_func(
            "capa:host/net", "get", ft_net_get_indirect,
            net_get, access_caller=True,
        )

        # net.post: same indirect-return shape as net.get plus a
        # second String arg (the request body).
        ft_net_post_indirect = wasmtime.FuncType(
            [
                wasmtime.ValType.i32(),  # handle (slice 25.3)
                wasmtime.ValType.i32(),  # url_ptr
                wasmtime.ValType.i32(),  # url_len
                wasmtime.ValType.i32(),  # body_ptr
                wasmtime.ValType.i32(),  # body_len
                wasmtime.ValType.i32(),  # ret_area
            ],
            [],
        )

        def net_post(
            caller, handle, url_ptr, url_len, body_ptr, body_len, ret_area,
        ):
            if self._memory is None or self._alloc_export is None:
                raise RuntimeError(
                    "net.post called before memory + $alloc set"
                )
            # Same UTF-8 decode policy as net.get for the URL; the
            # body is decoded as UTF-8 too because the Python-side
            # ``Net.post(url, body)`` takes a Capa String (always
            # valid UTF-8). errors="replace" defends against a
            # malformed-byte fuzz from the guest.
            try:
                url = bytes(
                    self._memory.read(caller, url_ptr, url_ptr + url_len)
                ).decode("utf-8")
            except UnicodeDecodeError as e:
                _write_result_err_ioerror(
                    caller, ret_area, "invalid URL", str(e),
                )
                return
            body = bytes(
                self._memory.read(caller, body_ptr, body_ptr + body_len)
            ).decode("utf-8", errors="replace")
            net = _lookup_net_or_err(caller, handle, ret_area)
            if net is None:
                return
            from ._result import Ok
            result = net.post(url, body)
            if isinstance(result, Ok):
                s_ptr, s_len = _alloc_utf8(caller, result.value)
                _write_result_ok_string(caller, ret_area, s_ptr, s_len)
            else:
                err = result.error
                _write_result_err_ioerror(
                    caller, ret_area,
                    getattr(err, "message", str(err)),
                    getattr(err, "cause", ""),
                )

        self.linker.define_func(
            "capa:host/net", "post", ft_net_post_indirect,
            net_post, access_caller=True,
        )

        # net.restrict_to: slice 25.3 (2026-05-30). Looks up the parent
        # handle, allocates a child Net with the narrowed host set,
        # and returns the child's i32 handle. Mirrors fs.restrict-to;
        # the new handle threads as the receiver of subsequent Net
        # calls in this branch of the program, so a cap restricted
        # to one host and passed across a function boundary keeps
        # its restriction (closes audit slice 25 F1 for Net).
        ft_restrict_to = wasmtime.FuncType(
            [
                wasmtime.ValType.i32(),  # parent handle
                wasmtime.ValType.i32(),  # host_ptr
                wasmtime.ValType.i32(),  # host_len
            ],
            [wasmtime.ValType.i32()],
        )

        def net_restrict_to(caller, parent_handle, host_ptr, host_len):
            if self._memory is None:
                raise RuntimeError(
                    "net.restrict_to called before memory was set"
                )
            try:
                host = bytes(
                    self._memory.read(
                        caller, host_ptr, host_ptr + host_len,
                    )
                ).decode("utf-8")
            except UnicodeDecodeError:
                return 0
            try:
                return self._cap_handles.restrict_net(parent_handle, host)
            except CapHandleError:
                return 0

        self.linker.define_func(
            "capa:host/net", "restrict-to", ft_restrict_to,
            net_restrict_to, access_caller=True,
        )

        # Net.allows(handle, host_ptr, host_len) -> i32 (bool). GAP-2b
        # (2026-06-21): looks up the receiver Net cap and returns
        # ``net.allows(host)`` (exact host-set membership). Bad handle
        # / invalid UTF-8 fail closed (0).
        ft_allows = wasmtime.FuncType(
            [
                wasmtime.ValType.i32(),  # handle
                wasmtime.ValType.i32(),  # host_ptr
                wasmtime.ValType.i32(),  # host_len
            ],
            [wasmtime.ValType.i32()],
        )

        def net_allows(caller, handle, host_ptr, host_len):
            if self._memory is None:
                raise RuntimeError(
                    "net.allows called before memory was set"
                )
            try:
                host = bytes(
                    self._memory.read(caller, host_ptr, host_ptr + host_len)
                ).decode("utf-8")
            except UnicodeDecodeError:
                return 0
            try:
                net = self._cap_handles.lookup(handle, Net)
            except CapHandleError:
                return 0
            return 1 if net.allows(host) else 0

        self.linker.define_func(
            "capa:host/net", "allows", ft_allows,
            net_allows, access_caller=True,
        )

    def _register_db(self) -> None:
        """Register the ``capa:host/db`` interface methods.

        Slice 11 (2026-05): Db is a SQLite-backed capability.

        Slice 25.4 (2026-05-30): every Db op now takes ``handle: u32``
        as its first arg. The host looks up the receiver Db in
        ``self._cap_handles`` and enforces ``db.allows(path)``
        before opening the SQLite connection. Closes the cross-
        function attenuation bug (audit slice 25 F1) for Db: a
        restricted Db handed off to a helper function on Wasm
        previously lost its prefix set because the emitter inlined
        the path check at the literal call site only.

        - ``exec(handle, path, sql)`` returns ``result<_, io-error>``
          (same Err arm shape as Fs.write; Ok arm carries unit).
        - ``query(handle, path, sql)`` returns
          ``result<string, io-error>`` (same Ok/Err arm shapes as
          Fs.read; the Ok string is a JSON-encoded
          ``[[col1, col2, ...], ...]`` array of arrays of
          stringified cell values).
        - ``restrict-to(handle, prefix)`` returns a fresh ``u32``
          handle bound to a narrower prefix set.

        The host opens a fresh ``sqlite3.connect`` per call; the
        cap is stateless from the program's POV.
        """
        import json
        import sqlite3

        from ._fs_guard import PostOpenDenied

        ft_handle_two_string_indirect = wasmtime.FuncType(
            [
                wasmtime.ValType.i32(),  # handle (slice 25.4)
                wasmtime.ValType.i32(),  # path_ptr
                wasmtime.ValType.i32(),  # path_len
                wasmtime.ValType.i32(),  # sql_ptr
                wasmtime.ValType.i32(),  # sql_len
                wasmtime.ValType.i32(),  # ret_area
            ],
            [],
        )

        def _alloc_utf8(caller, text: str) -> tuple[int, int]:
            encoded = text.encode("utf-8")
            if not encoded:
                return 0, 0
            ptr = self._host_alloc(caller, len(encoded))
            self._memory.write(caller, encoded, ptr)
            return ptr, len(encoded)

        def _write_result_ok_string(caller, ret_area, ptr, length):
            self._memory.write(caller, (0).to_bytes(4, "little"), ret_area)
            self._memory.write(
                caller, ptr.to_bytes(4, "little"), ret_area + 4,
            )
            self._memory.write(
                caller, length.to_bytes(4, "little"), ret_area + 8,
            )
            self._memory.write(
                caller, (0).to_bytes(8, "little"), ret_area + 12,
            )

        def _write_result_ok_unit(caller, ret_area):
            # tag=0 (Ok), Ok payload has no flat fields. Zero the
            # remaining 16 bytes so the slot stays deterministic.
            self._memory.write(caller, (0).to_bytes(4, "little"), ret_area)
            self._memory.write(
                caller, (0).to_bytes(16, "little"), ret_area + 4,
            )

        def _write_result_err_ioerror(caller, ret_area, message, cause=""):
            m_ptr, m_len = _alloc_utf8(caller, message)
            c_ptr, c_len = _alloc_utf8(caller, cause)
            self._memory.write(caller, (1).to_bytes(4, "little"), ret_area)
            self._memory.write(
                caller, m_ptr.to_bytes(4, "little"), ret_area + 4,
            )
            self._memory.write(
                caller, m_len.to_bytes(4, "little"), ret_area + 8,
            )
            self._memory.write(
                caller, c_ptr.to_bytes(4, "little"), ret_area + 12,
            )
            self._memory.write(
                caller, c_len.to_bytes(4, "little"), ret_area + 16,
            )

        def _lookup_db_or_err(caller, handle, ret_area):
            """Resolve the receiver Db cap. On failure write an
            Err(IoError) into ``ret_area`` and return None;
            callers short-circuit and skip the syscall."""
            try:
                return self._cap_handles.lookup(handle, Db)
            except CapHandleError as e:
                _write_result_err_ioerror(
                    caller, ret_area,
                    "invalid Db capability handle", str(e),
                )
                return None

        def db_exec(
            caller, handle, path_ptr, path_len, sql_ptr, sql_len, ret_area,
        ):
            if self._memory is None or self._alloc_export is None:
                raise RuntimeError(
                    "db.exec called before memory + $alloc set"
                )
            try:
                path = bytes(
                    self._memory.read(caller, path_ptr, path_ptr + path_len)
                ).decode("utf-8")
                sql = bytes(
                    self._memory.read(caller, sql_ptr, sql_ptr + sql_len)
                ).decode("utf-8")
            except UnicodeDecodeError as e:
                _write_result_err_ioerror(
                    caller, ret_area, "invalid UTF-8", str(e),
                )
                return
            # Slice 25.4: enforce the receiver cap's restriction via
            # the looked-up Db's ``allows(path)``. Pre-slice the
            # host trusted the emitter's inline check; cross-function
            # attenuation broke as a result (audit slice 25 F1).
            db = _lookup_db_or_err(caller, handle, ret_area)
            if db is None:
                return
            if not db.allows(path):
                _write_result_err_ioerror(
                    caller, ret_area,
                    f"Db capability does not permit exec: {path}",
                )
                return
            try:
                # _connect_verified applies the post-open symlink-swap
                # guard (audit 2026-06-17) and installs the
                # ATTACH/DETACH authorizer, so the Wasm backend closes
                # the same TOCTOU window as the Python runtime.
                conn = db._connect_verified(path)
                try:
                    conn.executescript(sql)
                    conn.commit()
                finally:
                    conn.close()
                _write_result_ok_unit(caller, ret_area)
            except PostOpenDenied:
                _write_result_err_ioerror(
                    caller, ret_area,
                    f"Db capability does not permit exec: {path}",
                )
            except (sqlite3.Error, OSError, ValueError) as e:
                _write_result_err_ioerror(
                    caller, ret_area, "SQLite exec failed", str(e),
                )

        def db_query(
            caller, handle, path_ptr, path_len, sql_ptr, sql_len, ret_area,
        ):
            if self._memory is None or self._alloc_export is None:
                raise RuntimeError(
                    "db.query called before memory + $alloc set"
                )
            try:
                path = bytes(
                    self._memory.read(caller, path_ptr, path_ptr + path_len)
                ).decode("utf-8")
                sql = bytes(
                    self._memory.read(caller, sql_ptr, sql_ptr + sql_len)
                ).decode("utf-8")
            except UnicodeDecodeError as e:
                _write_result_err_ioerror(
                    caller, ret_area, "invalid UTF-8", str(e),
                )
                return
            db = _lookup_db_or_err(caller, handle, ret_area)
            if db is None:
                return
            if not db.allows(path):
                _write_result_err_ioerror(
                    caller, ret_area,
                    f"Db capability does not permit query: {path}",
                )
                return
            try:
                conn = db._connect_verified(path)
                try:
                    cur = conn.execute(sql)
                    rows = cur.fetchall()
                finally:
                    conn.close()
                # Same stringify-every-cell policy as the Python
                # runtime so both backends produce identical JSON
                # for the same query against the same on-disk DB.
                stringified = [
                    [
                        "null" if v is None else
                        v if isinstance(v, str) else str(v)
                        for v in row
                    ]
                    for row in rows
                ]
                payload = json.dumps(stringified)
                s_ptr, s_len = _alloc_utf8(caller, payload)
                _write_result_ok_string(caller, ret_area, s_ptr, s_len)
            except PostOpenDenied:
                _write_result_err_ioerror(
                    caller, ret_area,
                    f"Db capability does not permit query: {path}",
                )
            except (sqlite3.Error, OSError, ValueError) as e:
                _write_result_err_ioerror(
                    caller, ret_area, "SQLite query failed", str(e),
                )

        self.linker.define_func(
            "capa:host/db", "exec", ft_handle_two_string_indirect,
            db_exec, access_caller=True,
        )
        self.linker.define_func(
            "capa:host/db", "query", ft_handle_two_string_indirect,
            db_query, access_caller=True,
        )

        # db.restrict-to: slice 25.4 (2026-05-30). Looks up the parent
        # handle, allocates a child Db with the narrowed prefix, and
        # returns the child's i32 handle. Mirrors fs.restrict-to /
        # net.restrict-to.
        ft_restrict_to = wasmtime.FuncType(
            [
                wasmtime.ValType.i32(),  # parent handle
                wasmtime.ValType.i32(),  # prefix_ptr
                wasmtime.ValType.i32(),  # prefix_len
            ],
            [wasmtime.ValType.i32()],
        )

        def db_restrict_to(caller, parent_handle, prefix_ptr, prefix_len):
            if self._memory is None:
                raise RuntimeError(
                    "db.restrict_to called before memory was set"
                )
            try:
                prefix = bytes(
                    self._memory.read(
                        caller, prefix_ptr, prefix_ptr + prefix_len,
                    )
                ).decode("utf-8")
            except UnicodeDecodeError:
                return 0
            try:
                return self._cap_handles.restrict_db(parent_handle, prefix)
            except CapHandleError:
                return 0

        self.linker.define_func(
            "capa:host/db", "restrict-to", ft_restrict_to,
            db_restrict_to, access_caller=True,
        )

        # Db.allows(handle, path_ptr, path_len) -> i32 (bool). GAP-2b
        # (2026-06-21): looks up the receiver Db cap and returns
        # ``db.allows(path)`` (same realpath prefix containment as
        # Fs.allows). Bad handle / invalid UTF-8 fail closed (0).
        ft_allows = wasmtime.FuncType(
            [
                wasmtime.ValType.i32(),  # handle
                wasmtime.ValType.i32(),  # path_ptr
                wasmtime.ValType.i32(),  # path_len
            ],
            [wasmtime.ValType.i32()],
        )

        def db_allows(caller, handle, path_ptr, path_len):
            if self._memory is None:
                raise RuntimeError(
                    "db.allows called before memory was set"
                )
            try:
                path = bytes(
                    self._memory.read(caller, path_ptr, path_ptr + path_len)
                ).decode("utf-8")
            except UnicodeDecodeError:
                return 0
            try:
                db = self._cap_handles.lookup(handle, Db)
            except CapHandleError:
                return 0
            return 1 if db.allows(path) else 0

        self.linker.define_func(
            "capa:host/db", "allows", ft_allows,
            db_allows, access_caller=True,
        )

    def _register_proc(self) -> None:
        """Register the ``capa:host/proc`` interface methods.

        Slice 15 (2026-05): Proc is a sandboxed subprocess
        capability. ``exec`` takes ``(cmd: string, args_json:
        string)`` and returns the canonical-ABI
        ``result<string, io-error>`` shape (same 20-byte ret
        area as Db.query / Fs.read). args_json is a JSON-encoded
        array of strings consumed as the argv tail (e.g.
        ``["status", "--short"]``).

        Execution semantics mirror the Python runtime exactly:
        ``subprocess.run(argv, capture_output=True, timeout=30,
        shell=False)``. Non-zero exit / timeout / malformed
        argv JSON all surface as Err. Stdout is decoded as
        UTF-8 with ``errors='replace'`` to match the rest of
        the host-bridge convention.

        Slice 25.4 (2026-05-30): every Proc op now takes ``handle:
        u32`` as its first arg. The host looks up the receiver Proc
        in ``self._cap_handles`` and enforces ``proc.allows(cmd)``
        before spawning the subprocess. Closes the cross-function
        attenuation bug (audit slice 25 F1) for Proc: a restricted
        Proc handed off to a helper function on Wasm previously
        lost its allow-list because the emitter inlined the
        basename check at the literal call site only.
        ``proc.restrict-to(handle, prefix)`` returns a fresh u32
        handle bound to a narrower allow-list.
        """
        import json
        import subprocess

        ft_handle_two_string_indirect = wasmtime.FuncType(
            [
                wasmtime.ValType.i32(),  # handle (slice 25.4)
                wasmtime.ValType.i32(),  # cmd_ptr
                wasmtime.ValType.i32(),  # cmd_len
                wasmtime.ValType.i32(),  # args_ptr
                wasmtime.ValType.i32(),  # args_len
                wasmtime.ValType.i32(),  # ret_area
            ],
            [],
        )

        def _alloc_utf8(caller, text: str) -> tuple[int, int]:
            encoded = text.encode("utf-8")
            if not encoded:
                return 0, 0
            ptr = self._host_alloc(caller, len(encoded))
            self._memory.write(caller, encoded, ptr)
            return ptr, len(encoded)

        def _write_result_ok_string(caller, ret_area, ptr, length):
            self._memory.write(caller, (0).to_bytes(4, "little"), ret_area)
            self._memory.write(
                caller, ptr.to_bytes(4, "little"), ret_area + 4,
            )
            self._memory.write(
                caller, length.to_bytes(4, "little"), ret_area + 8,
            )
            self._memory.write(
                caller, (0).to_bytes(8, "little"), ret_area + 12,
            )

        def _write_result_err_ioerror(caller, ret_area, message, cause=""):
            m_ptr, m_len = _alloc_utf8(caller, message)
            c_ptr, c_len = _alloc_utf8(caller, cause)
            self._memory.write(caller, (1).to_bytes(4, "little"), ret_area)
            self._memory.write(
                caller, m_ptr.to_bytes(4, "little"), ret_area + 4,
            )
            self._memory.write(
                caller, m_len.to_bytes(4, "little"), ret_area + 8,
            )
            self._memory.write(
                caller, c_ptr.to_bytes(4, "little"), ret_area + 12,
            )
            self._memory.write(
                caller, c_len.to_bytes(4, "little"), ret_area + 16,
            )

        def _lookup_proc_or_err(caller, handle, ret_area):
            """Resolve the receiver Proc cap. On failure write an
            Err(IoError) into ``ret_area`` and return None."""
            try:
                return self._cap_handles.lookup(handle, Proc)
            except CapHandleError as e:
                _write_result_err_ioerror(
                    caller, ret_area,
                    "invalid Proc capability handle", str(e),
                )
                return None

        def proc_exec(
            caller, handle, cmd_ptr, cmd_len, args_ptr, args_len, ret_area,
        ):
            if self._memory is None or self._alloc_export is None:
                raise RuntimeError(
                    "proc.exec called before memory + $alloc set"
                )
            try:
                cmd = bytes(
                    self._memory.read(caller, cmd_ptr, cmd_ptr + cmd_len)
                ).decode("utf-8")
                args_json = bytes(
                    self._memory.read(caller, args_ptr, args_ptr + args_len)
                ).decode("utf-8")
            except UnicodeDecodeError as e:
                _write_result_err_ioerror(
                    caller, ret_area, "invalid UTF-8", str(e),
                )
                return
            # Slice 25.4: enforce the receiver cap's restriction via
            # ``Proc.allows(cmd)`` (basename + suffix-boundary).
            proc = _lookup_proc_or_err(caller, handle, ret_area)
            if proc is None:
                return
            if not proc.allows(cmd):
                _write_result_err_ioerror(
                    caller, ret_area,
                    f"Proc capability does not permit exec: {cmd}",
                )
                return
            try:
                tail = json.loads(args_json)
            except (ValueError, TypeError) as e:
                _write_result_err_ioerror(
                    caller, ret_area,
                    "Proc.exec args_json parse failed", str(e),
                )
                return
            if not isinstance(tail, list) or not all(
                    isinstance(x, str) for x in tail):
                _write_result_err_ioerror(
                    caller, ret_area,
                    "Proc.exec args_json parse failed",
                    "expected a JSON array of strings",
                )
                return
            argv = [cmd, *tail]
            try:
                completed = subprocess.run(
                    argv,
                    capture_output=True,
                    timeout=30,
                    shell=False,
                )
            except subprocess.TimeoutExpired:
                _write_result_err_ioerror(
                    caller, ret_area, "timed out", "30s elapsed",
                )
                return
            except (OSError, ValueError) as e:
                _write_result_err_ioerror(
                    caller, ret_area, "Proc.exec spawn failed", str(e),
                )
                return
            if completed.returncode != 0:
                stderr = completed.stderr.decode("utf-8", errors="replace")
                _write_result_err_ioerror(
                    caller, ret_area, "non-zero exit",
                    f"code={completed.returncode} stderr={stderr!r}",
                )
                return
            stdout = completed.stdout.decode("utf-8", errors="replace")
            s_ptr, s_len = _alloc_utf8(caller, stdout)
            _write_result_ok_string(caller, ret_area, s_ptr, s_len)

        self.linker.define_func(
            "capa:host/proc", "exec", ft_handle_two_string_indirect,
            proc_exec, access_caller=True,
        )

        # proc.restrict-to: slice 25.4 (2026-05-30). Looks up the
        # parent handle, allocates a child Proc with the narrower
        # allow-list, returns the child's i32 handle.
        ft_restrict_to = wasmtime.FuncType(
            [
                wasmtime.ValType.i32(),  # parent handle
                wasmtime.ValType.i32(),  # prefix_ptr
                wasmtime.ValType.i32(),  # prefix_len
            ],
            [wasmtime.ValType.i32()],
        )

        def proc_restrict_to(caller, parent_handle, prefix_ptr, prefix_len):
            if self._memory is None:
                raise RuntimeError(
                    "proc.restrict_to called before memory was set"
                )
            try:
                prefix = bytes(
                    self._memory.read(
                        caller, prefix_ptr, prefix_ptr + prefix_len,
                    )
                ).decode("utf-8")
            except UnicodeDecodeError:
                return 0
            try:
                return self._cap_handles.restrict_proc(parent_handle, prefix)
            except CapHandleError:
                return 0

        self.linker.define_func(
            "capa:host/proc", "restrict-to", ft_restrict_to,
            proc_restrict_to, access_caller=True,
        )

        # Proc.allows(handle, cmd_ptr, cmd_len) -> i32 (bool). GAP-2b
        # (2026-06-21): looks up the receiver Proc cap and returns
        # ``proc.allows(cmd)`` (identity basename + suffix-boundary
        # rule). Bad handle / invalid UTF-8 fail closed (0).
        ft_allows = wasmtime.FuncType(
            [
                wasmtime.ValType.i32(),  # handle
                wasmtime.ValType.i32(),  # cmd_ptr
                wasmtime.ValType.i32(),  # cmd_len
            ],
            [wasmtime.ValType.i32()],
        )

        def proc_allows(caller, handle, cmd_ptr, cmd_len):
            if self._memory is None:
                raise RuntimeError(
                    "proc.allows called before memory was set"
                )
            try:
                cmd = bytes(
                    self._memory.read(caller, cmd_ptr, cmd_ptr + cmd_len)
                ).decode("utf-8")
            except UnicodeDecodeError:
                return 0
            try:
                proc = self._cap_handles.lookup(handle, Proc)
            except CapHandleError:
                return 0
            return 1 if proc.allows(cmd) else 0

        self.linker.define_func(
            "capa:host/proc", "allows", ft_allows,
            proc_allows, access_caller=True,
        )

    def _register_json(self) -> None:
        """Register the ``capa:host/json`` interface methods.

        ``parse(s) -> Result<JsonValue, String>``: parses a JSON
        document by walking Python's ``json.loads`` output and
        allocating the equivalent JsonValue tree in linear memory.

        ``to_string(jv) -> String``: walks a JsonValue tree out of
        linear memory, builds the equivalent Python value, calls
        ``json.dumps``, copies the bytes back into a fresh alloc.

        Both sides share the 16-byte JsonValue layout: tag at
        offset 0, payload at offset 8 in an 8-byte slot. Nested
        ``JArr`` payloads point to ``List<JsonValue>`` headers;
        nested ``JObj`` payloads point to ``Map<String, JsonValue>``
        headers. Numbers use the f64 storage slot; bools / pointers
        use i64-extended; strings are packed (ptr | (len << 32))."""
        import json as _stdlib_json

        # Canonical ABI:
        #   parse: (s_ptr, s_len, ret_area) -> ()  -- 12-byte ret
        #     area holds tag i32 + max(Ok u32, Err string).
        #   to-string: (jv, ret_area) -> ()  -- 8-byte ret area
        #     holds (ptr i32, len i32).
        ft_parse = wasmtime.FuncType(
            [
                wasmtime.ValType.i32(),
                wasmtime.ValType.i32(),
                wasmtime.ValType.i32(),
            ],
            [],
        )
        ft_to_string = wasmtime.FuncType(
            [wasmtime.ValType.i32(), wasmtime.ValType.i32()],
            [],
        )

        # ---- helpers (closures over caller-local self._memory + alloc) ----

        def _read_u32(caller, ptr: int) -> int:
            return int.from_bytes(
                bytes(self._memory.read(caller, ptr, ptr + 4)), "little",
            )

        def _read_i64(caller, ptr: int) -> int:
            raw = bytes(self._memory.read(caller, ptr, ptr + 8))
            return int.from_bytes(raw, "little", signed=False)

        def _read_f64(caller, ptr: int) -> float:
            import struct
            raw = bytes(self._memory.read(caller, ptr, ptr + 8))
            return struct.unpack("<d", raw)[0]

        def _write_u32(caller, ptr: int, val: int) -> None:
            self._memory.write(caller, val.to_bytes(4, "little"), ptr)

        def _write_i64(caller, ptr: int, val: int) -> None:
            self._memory.write(caller, val.to_bytes(8, "little"), ptr)

        def _write_f64(caller, ptr: int, val: float) -> None:
            import struct
            self._memory.write(caller, struct.pack("<d", val), ptr)

        def _alloc_string(caller, text: str) -> tuple[int, int]:
            encoded = text.encode("utf-8")
            if not encoded:
                return 0, 0
            ptr = self._host_alloc(caller, len(encoded))
            self._memory.write(caller, encoded, ptr)
            return ptr, len(encoded)

        def _read_string(caller, ptr: int, length: int) -> str:
            if length <= 0:
                return ""
            return bytes(
                self._memory.read(caller, ptr, ptr + length)
            ).decode("utf-8")

        def _alloc_jv(caller, tag: int) -> int:
            """Allocate a 16-byte JsonValue record with ``tag`` and
            a zero payload slot. Caller fills the payload via the
            appropriate _write_* on offset 8."""
            jv_ptr = self._host_alloc(caller, 16)
            _write_u32(caller, jv_ptr, tag)
            _write_i64(caller, jv_ptr + 8, 0)
            return jv_ptr

        def _alloc_list_of_jv(caller, items: list) -> int:
            """Allocate a 16-byte List header + cap * 4-byte data
            array. Each element is a JsonValue pointer (i32). The
            Wasm side computes elem_size from ``_size_of("JsonValue")``
            which is 4 (sum types are stored by pointer), so the
            data array uses 4-byte slots, NOT 8-byte ones."""
            n = len(items)
            cap = max(n, 8)
            header_ptr = self._host_alloc(caller, 16)
            data_ptr = self._host_alloc(caller, cap * 4) if cap else 0
            _write_u32(caller, header_ptr, n)
            _write_u32(caller, header_ptr + 4, cap)
            _write_u32(caller, header_ptr + 8, data_ptr)
            for i, item in enumerate(items):
                jv_ptr = _py_to_jv(caller, item)
                _write_u32(caller, data_ptr + i * 4, jv_ptr)
            return header_ptr

        def _alloc_map_str_jv(caller, items: dict) -> int:
            """Allocate a 16-byte Map header + cap * 16-byte triple
            array (key_ptr, key_len, value-as-i64)."""
            n = len(items)
            cap = max(n, 8)
            header_ptr = self._host_alloc(caller, 16)
            data_ptr = self._host_alloc(caller, cap * 16) if cap else 0
            _write_u32(caller, header_ptr, n)
            _write_u32(caller, header_ptr + 4, cap)
            _write_u32(caller, header_ptr + 8, data_ptr)
            for i, (k, v) in enumerate(items.items()):
                k_ptr, k_len = _alloc_string(caller, str(k))
                _write_u32(caller, data_ptr + i * 16, k_ptr)
                _write_u32(caller, data_ptr + i * 16 + 4, k_len)
                jv_ptr = _py_to_jv(caller, v)
                _write_i64(caller, data_ptr + i * 16 + 8, jv_ptr & 0xFFFFFFFF)
            return header_ptr

        def _py_to_jv(caller, val) -> int:
            """Recursively walk a Python value (from json.loads) into
            a JsonValue record tree in linear memory; return the
            JsonValue pointer."""
            if val is None:
                return _alloc_jv(caller, 0)  # JNull
            if isinstance(val, bool):
                jv = _alloc_jv(caller, 1)  # JBool
                _write_i64(caller, jv + 8, 1 if val else 0)
                return jv
            if isinstance(val, (int, float)):
                jv = _alloc_jv(caller, 2)  # JNum
                _write_f64(caller, jv + 8, float(val))
                return jv
            if isinstance(val, str):
                jv = _alloc_jv(caller, 3)  # JStr
                s_ptr, s_len = _alloc_string(caller, val)
                packed = (s_ptr & 0xFFFFFFFF) | (
                    (s_len & 0xFFFFFFFF) << 32
                )
                _write_i64(caller, jv + 8, packed)
                return jv
            if isinstance(val, list):
                list_ptr = _alloc_list_of_jv(caller, val)
                jv = _alloc_jv(caller, 4)  # JArr
                _write_i64(caller, jv + 8, list_ptr & 0xFFFFFFFF)
                return jv
            if isinstance(val, dict):
                map_ptr = _alloc_map_str_jv(caller, val)
                jv = _alloc_jv(caller, 5)  # JObj
                _write_i64(caller, jv + 8, map_ptr & 0xFFFFFFFF)
                return jv
            # Fallback: render as String.
            return _py_to_jv(caller, str(val))

        def _list_of_jv_to_py(caller, list_ptr: int) -> list:
            n = _read_u32(caller, list_ptr)
            data_ptr = _read_u32(caller, list_ptr + 8)
            out = []
            for i in range(n):
                # List<JsonValue> slot is i32 (sum types are
                # pointer-stored, size 4 in the Wasm layout).
                jv_ptr = _read_u32(caller, data_ptr + i * 4)
                out.append(_jv_to_py(caller, jv_ptr))
            return out

        def _map_str_jv_to_py(caller, map_ptr: int) -> dict:
            n = _read_u32(caller, map_ptr)
            data_ptr = _read_u32(caller, map_ptr + 8)
            out = {}
            for i in range(n):
                base = data_ptr + i * 16
                k_ptr = _read_u32(caller, base)
                k_len = _read_u32(caller, base + 4)
                key = _read_string(caller, k_ptr, k_len)
                slot = _read_i64(caller, base + 8)
                out[key] = _jv_to_py(caller, slot & 0xFFFFFFFF)
            return out

        def _jv_to_py(caller, jv_ptr: int):
            tag = _read_u32(caller, jv_ptr)
            if tag == 0:  # JNull
                return None
            if tag == 1:  # JBool
                return bool(_read_i64(caller, jv_ptr + 8))
            if tag == 2:  # JNum
                return _read_f64(caller, jv_ptr + 8)
            if tag == 3:  # JStr
                packed = _read_i64(caller, jv_ptr + 8)
                s_ptr = packed & 0xFFFFFFFF
                s_len = (packed >> 32) & 0xFFFFFFFF
                return _read_string(caller, s_ptr, s_len)
            if tag == 4:  # JArr
                inner = _read_i64(caller, jv_ptr + 8) & 0xFFFFFFFF
                return _list_of_jv_to_py(caller, inner)
            if tag == 5:  # JObj
                inner = _read_i64(caller, jv_ptr + 8) & 0xFFFFFFFF
                return _map_str_jv_to_py(caller, inner)
            raise RuntimeError(
                f"unknown JsonValue tag {tag} at ptr {jv_ptr}"
            )

        # ---- the two host functions ----

        def json_parse(caller, s_ptr, s_len, ret_area):
            """result<u32, string> indirect lowering. 12-byte area:
            tag @ 0, Ok-u32 @ 4, Err (msg_ptr, msg_len) @ 4 + 8."""
            if self._memory is None or self._alloc_export is None:
                raise RuntimeError(
                    "json.parse called before memory + $alloc set"
                )
            # Audit fix H3: invalid UTF-8 in the source bytes is the
            # same shape of guest-side bug as malformed JSON; route it
            # through the WIT result<u32, string> Err arm so the guest
            # sees the same observable failure mode (a parseable Err
            # message) it would for any other unparseable input,
            # instead of bubbling ``UnicodeDecodeError`` up through
            # wasmtime and crashing the store.
            try:
                text = _read_string(caller, s_ptr, s_len)
                py_val = _stdlib_json.loads(text)
                jv_ptr = _py_to_jv(caller, py_val)
                _write_u32(caller, ret_area, 0)            # tag Ok
                _write_u32(caller, ret_area + 4, jv_ptr)   # u32 handle
                _write_u32(caller, ret_area + 8, 0)        # pad
            except (
                ValueError, UnicodeDecodeError,
                _stdlib_json.JSONDecodeError,
            ) as e:
                err_ptr, err_len = _alloc_string(caller, str(e))
                _write_u32(caller, ret_area, 1)            # tag Err
                _write_u32(caller, ret_area + 4, err_ptr)
                _write_u32(caller, ret_area + 8, err_len)

        def json_to_string(caller, jv_ptr, ret_area):
            """string indirect lowering. 8-byte area: (ptr, len)."""
            if self._memory is None or self._alloc_export is None:
                raise RuntimeError(
                    "json.to_string called before memory + $alloc set"
                )
            py_val = _jv_to_py(caller, jv_ptr)
            text = _stdlib_json.dumps(py_val)
            ptr, length = _alloc_string(caller, text)
            _write_u32(caller, ret_area, ptr)
            _write_u32(caller, ret_area + 4, length)

        self.linker.define_func(
            "capa:host/json", "parse", ft_parse,
            json_parse, access_caller=True,
        )
        self.linker.define_func(
            "capa:host/json", "to-string", ft_to_string,
            json_to_string, access_caller=True,
        )

    def instantiate(self, wasm_blob: bytes) -> wasmtime.Instance:
        """Load ``wasm_blob`` and instantiate it against the
        registered host imports. Caches the exported memory so
        subsequent host callbacks can resolve string pointers."""
        module = wasmtime.Module(self.engine, wasm_blob)
        instance = self.linker.instantiate(self.store, module)
        exports = instance.exports(self.store)
        if "memory" in exports:
            self._memory = exports["memory"]
        if "alloc" in exports:
            self._alloc_export = exports["alloc"]
        return instance

    def run_main(self, wasm_blob: bytes) -> None:
        """Instantiate and call the module's ``main`` export.

        Pre-slice-25.2: ``fun main(stdio: Stdio)`` lowered to
        ``main()`` on Wasm (every cap param was erased). Slices
        25.2 - 25.6 un-erased Fs / Net / Db / Proc / Env / Clock;
        all six lower to i32 handles the guest threads through
        every privileged op so a restricted cap survives crossing
        function boundaries (audit slice 25 F1). Random / Unsafe /
        Stdio stay erased indefinitely (no attenuation surface to
        thread).

        ``main`` now takes one i32 arg per un-erased cap declared
        in its source signature (in declaration order). To dispatch
        the right root handle to each slot we recover main's
        parameter names from the wasm ``name`` custom section the
        WAT compiler preserves (params are declared as
        ``(param $fs i32)`` / ``(param $net i32)`` / ... so the
        name maps directly to the cap-kind). Programs whose main
        takes no cap params (every i32-free signature) follow the
        legacy no-handle path."""
        instance = self.instantiate(wasm_blob)
        main = instance.exports(self.store)["main"]
        n_params = self._main_param_count(main)
        # The .wasm carries a name section, so recover param names from
        # the blob itself.
        param_names = _read_main_param_names(wasm_blob, n_params)
        self._invoke_main(main, n_params, param_names)

    def run_main_aot(self, module, header: dict) -> None:
        """Instantiate and run a deserialized AOT ``module`` (from
        ``capa.runtime._aot.load_aot``) against the registered host
        imports.

        The serialized ``.cwasm`` has no readable name section, so the
        ``main`` parameter names cannot be recovered from it; they were
        captured at build time and travel in the AOT container header
        (roadmap P1). We take them from ``header`` instead of parsing
        the blob, then share the same root-handle mapping + invocation
        path as ``run_main``."""
        from ._aot import aot_main_param_names
        instance = self.linker.instantiate(self.store, module)
        exports = instance.exports(self.store)
        if "memory" in exports:
            self._memory = exports["memory"]
        if "alloc" in exports:
            self._alloc_export = exports["alloc"]
        main = exports["main"]
        n_params = self._main_param_count(main)
        param_names = aot_main_param_names(header)
        self._invoke_main(main, n_params, param_names)

    def _main_param_count(self, main) -> int:
        """Number of i32 args the ``main`` export takes (0 on any
        introspection failure / a no-cap signature)."""
        try:
            return len(list(main.type(self.store).params))
        except Exception:
            return 0

    def _invoke_main(self, main, n_params: int, param_names: list) -> None:
        """Shared root-handle bootstrap + dispatch for both the JIT
        (``run_main``) and AOT (``run_main_aot``) paths. Allocates the
        root capabilities, maps each of ``main``'s i32 slots to the
        right root handle by parameter name, and calls ``main``.

        Lazy-constructs the roots once per host instance so a re-run
        reuses the same handle-table entries (handle identity stays
        stable across invocations). Unknown / missing param names fall
        back to Fs (the legacy slice-25.2 behaviour) so a blob without
        usable names still runs."""
        # ``panicked`` is a per-host latch the panic builtin sets so
        # the CLI can suppress the wasmtime traceback for a deliberate
        # abort. It is per-host, not per-run, so a host reused for a
        # second program must clear it first -- otherwise a genuine
        # trap (out-of-bounds, etc.) in the second run would be
        # silenced by the stale latch and report without a useful
        # traceback. Cleared at every entry (both run_main and
        # run_main_aot funnel through here).
        self.panicked = False
        if self._root_fs is None:
            self._root_fs = Fs()
        if self._root_net is None:
            self._root_net = Net()
        if self._root_db is None:
            self._root_db = Db()
        if self._root_proc is None:
            self._root_proc = Proc()
        if self._root_env is None:
            self._root_env = Env()
        if self._root_clock is None:
            self._root_clock = Clock()
        if self._root_stdio is None:
            self._root_stdio = Stdio()
        roots = bootstrap_root_handles(
            self._cap_handles,
            fs=self._root_fs,
            net=self._root_net,
            db=self._root_db,
            proc=self._root_proc,
            env=self._root_env,
            clock=self._root_clock,
            stdio=self._root_stdio,
        )
        name_to_root: dict[str, int] = {
            "fs": roots.get("fs", 0),
            "net": roots.get("net", 0),
            "db": roots.get("db", 0),
            "proc": roots.get("proc", 0),
            "env": roots.get("env", 0),
            "clock": roots.get("clock", 0),
        }
        handle_args: list[int] = []
        for i in range(n_params):
            name = param_names[i] if i < len(param_names) else ""
            handle_args.append(name_to_root.get(name, roots.get("fs", 0)))
        main(self.store, *handle_args)


# ---- helpers ----------------------------------------------------


def _read_uleb128(buf: bytes, off: int) -> tuple[int, int]:
    """Decode an unsigned LEB128 from ``buf`` at ``off``; returns
    ``(value, next_offset)``. Used by the wasm name-section parser."""
    val = 0
    shift = 0
    while True:
        b = buf[off]
        off += 1
        val |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            return val, off
        shift += 7


def _read_main_param_names(wasm_blob: bytes, n_params: int) -> list[str]:
    """Recover ``main``'s parameter names from the wasm ``name``
    custom section. Returns a list of length ``n_params`` (or empty
    on any parse failure / absent section).

    Slice 25.3 (2026-05-30): used by ``WasmHost.run_main`` to map
    each i32 param of the ``main`` export to the matching root
    capability handle. The WAT compiler preserves the source-level
    param identifiers (``(param $fs i32) (param $net i32)``) into
    the name section's ``local`` subsection (id 2), keyed by the
    function index of ``main``. We:

    1. Walk the top-level section list looking for the ``name``
       custom section (custom section, id 0, payload starts with
       the section name as a length-prefixed string).
    2. Inside the name section, scan subsection id 1 (function
       names) to find the function index whose name is ``main``.
    3. Scan subsection id 2 (local names) for that function's
       entry, extract the first ``n_params`` local names (in
       wasm-locals these come first, before any non-param local).

    Returns ``[]`` if the section is absent, the lookup fails, or
    the layout doesn't match. Callers must tolerate the empty case
    (falling back to a sensible default per index)."""
    try:
        # Header: magic (4) + version (4) = 8 bytes.
        if len(wasm_blob) < 8 or wasm_blob[:4] != b"\x00asm":
            return []
        off = 8
        name_payload: bytes | None = None
        while off < len(wasm_blob):
            section_id = wasm_blob[off]
            off += 1
            size, off = _read_uleb128(wasm_blob, off)
            payload_start = off
            off += size
            if section_id != 0:
                continue
            # Custom section: payload starts with name as LEB-len-
            # prefixed UTF-8 string.
            j = payload_start
            nlen, j = _read_uleb128(wasm_blob, j)
            name = wasm_blob[j:j + nlen].decode("utf-8", errors="replace")
            j += nlen
            if name == "name":
                name_payload = wasm_blob[j:payload_start + size]
                break
        if name_payload is None:
            return []

        # Walk subsections; cache function-name -> idx, then look
        # up main's local names.
        fn_idx_for_main: int | None = None
        local_names_by_fn: dict[int, list[str]] = {}
        p = 0
        while p < len(name_payload):
            sub_id = name_payload[p]
            p += 1
            sub_size, p = _read_uleb128(name_payload, p)
            sub_payload = name_payload[p:p + sub_size]
            p += sub_size
            if sub_id == 1:
                # function names: namemap (vec of {idx, name}).
                q = 0
                count, q = _read_uleb128(sub_payload, q)
                for _ in range(count):
                    idx, q = _read_uleb128(sub_payload, q)
                    nlen, q = _read_uleb128(sub_payload, q)
                    name = sub_payload[q:q + nlen].decode(
                        "utf-8", errors="replace",
                    )
                    q += nlen
                    if name == "main":
                        fn_idx_for_main = idx
            elif sub_id == 2:
                # local names: indirectnamemap = vec of {fn_idx,
                # namemap}.
                q = 0
                fn_count, q = _read_uleb128(sub_payload, q)
                for _ in range(fn_count):
                    fn_idx, q = _read_uleb128(sub_payload, q)
                    local_count, q = _read_uleb128(sub_payload, q)
                    locals_here: list[tuple[int, str]] = []
                    for _ in range(local_count):
                        local_idx, q = _read_uleb128(sub_payload, q)
                        nlen, q = _read_uleb128(sub_payload, q)
                        name = sub_payload[q:q + nlen].decode(
                            "utf-8", errors="replace",
                        )
                        q += nlen
                        locals_here.append((local_idx, name))
                    # Keep first ``n_params`` local names in
                    # local-index order; those correspond to the
                    # function's parameters (wasm convention:
                    # params come first in the local index space).
                    locals_here.sort(key=lambda t: t[0])
                    local_names_by_fn[fn_idx] = [
                        n for _, n in locals_here
                    ]
        if fn_idx_for_main is None:
            return []
        names = local_names_by_fn.get(fn_idx_for_main, [])
        return names[:n_params]
    except (IndexError, UnicodeDecodeError, ValueError):
        return []
