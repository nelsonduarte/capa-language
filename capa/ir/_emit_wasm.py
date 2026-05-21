"""CIR -> WebAssembly text (WAT) emitter (Phase 6A + 6B).

Phase 6A established the core scalar surface (Int / Bool arithmetic,
control flow). Phase 6B adds capability method calls and string
literals so a Capa program like ``stdio.println("hi")`` can lower
end-to-end.

The emitter produces WAT (text) which the caller assembles to binary
``.wasm`` via ``wasm-tools parse``. WAT is preferred over direct
binary because it is human-readable and easy to debug; the binary
form is mechanically derived from it.

Type mapping:

- Capa ``Int`` -> Wasm ``i64`` (signed 64-bit integer)
- Capa ``Bool`` -> Wasm ``i32`` (0 or 1; wasm has no native bool)
- Capa ``Unit`` -> no Wasm result (functions returning Unit omit
  the ``(result ...)`` clause)
- Capa ``String`` (Phase 6B, literal only) -> two i32s (memory ptr,
  byte length). Pushed sequentially when a string is passed as a
  capability method argument.
- Capa capability types (``Stdio``, ``Fs``, ...) have no Wasm
  representation: the methods they expose are imported into the
  module by name (matching the corresponding WIT interface), so a
  capability "value" carries no information at runtime. Capability
  params on Capa functions are dropped from the Wasm signature.

Phase 6B coverage is intentionally narrow: only Stdio methods with
string-literal arguments. Full String semantics (locals, methods,
concatenation) wait for Phase 6D.
"""

from __future__ import annotations

from typing import List, Optional

from ._nodes import (
    Module, Function, Param, Value, Instr,
    AssignConst, Reassign, BinOp, UnaryOp, Call, MethodCall,
    If, While, Break, Continue, Return,
    MakeStruct, FieldAccess,
    Pattern, PatWildcard, PatIdent, PatLiteral, PatVariant, MatchArm, Match,
    StructDecl, SumDecl,
)
from ._emit_wit import _WIT_SIGNATURES, _KNOWN_CAPABILITIES


# Capa built-in capabilities. Receivers of these types route
# MethodCall instructions to imported Wasm functions rather than
# core method dispatch; their parameters carry no Wasm value.
_BUILTIN_CAPS = {"Stdio", "Fs", "Env", "Clock", "Net", "Random", "Proc", "Db", "Unsafe"}


# Per-type byte size for Capa scalar types. Used by layout
# computation for structs and sum payloads. Strings, Lists, Maps,
# Sets are represented as i32 pointers in this phase but their
# stdlib counterparts only arrive in 6D.
_TYPE_SIZE = {
    "Int":  8,  # i64
    "Bool": 4,  # i32
}


def _size_of(capa_ty: str, sum_layouts: dict, struct_layouts: dict) -> int:
    """Byte size of a Capa type when stored in linear memory.
    Sum types and structs are stored by pointer (4 bytes); their
    actual content lives at the pointed-to address."""
    head = capa_ty.split("<", 1)[0]
    if head in _TYPE_SIZE:
        return _TYPE_SIZE[head]
    if head in sum_layouts or head in struct_layouts:
        return 4  # i32 pointer
    # Conservatively pessimistic: treat unknowns as pointer-sized.
    # Real source-level types should resolve via the analyzer; this
    # fallback only matters during incremental development.
    return 4


def _store_op_for_size(size: int) -> str:
    """Wasm store opcode for a value of given size. The IR only
    produces values of size 4 (i32 / pointer) or 8 (i64); other
    sizes raise."""
    if size == 4:
        return "i32.store"
    if size == 8:
        return "i64.store"
    raise WasmEmissionError(
        f"no store opcode for {size}-byte value"
    )


def _load_op_for_size(size: int) -> str:
    if size == 4:
        return "i32.load"
    if size == 8:
        return "i64.load"
    raise WasmEmissionError(
        f"no load opcode for {size}-byte value"
    )


def _align_up(offset: int, alignment: int) -> int:
    """Round ``offset`` up to a multiple of ``alignment``."""
    return (offset + alignment - 1) & ~(alignment - 1)


def compute_struct_layout(
    decl: StructDecl,
    sum_layouts: dict,
    struct_layouts: dict,
) -> dict:
    """Compute per-field offsets and total size for a struct,
    laying fields out in declaration order with natural alignment.
    Returns a dict with ``fields`` (name -> (offset, size, capa_ty))
    and ``size`` (total bytes, rounded up to 8 for downstream
    alignment)."""
    fields: dict[str, tuple[int, int, str]] = {}
    offset = 0
    for f in decl.fields:
        size = _size_of(f.ty, sum_layouts, struct_layouts)
        offset = _align_up(offset, size)
        fields[f.name] = (offset, size, f.ty)
        offset += size
    return {"fields": fields, "size": _align_up(offset, 8)}


def compute_sum_layout(
    decl: SumDecl,
    sum_layouts: dict,
    struct_layouts: dict,
) -> dict:
    """Compute layout for a sum type:
    - tag (i32) at offset 0
    - per-variant payloads starting at offset 8 (aligned for i64)
    - total size = max over variants of payload end-offset

    Returns a dict with ``variants`` (name -> (tag_value, payloads
    list of (offset, size, capa_ty))) and ``size`` (total bytes,
    fits the largest variant + tag)."""
    variants: dict[str, tuple[int, list[tuple[int, int, str]]]] = {}
    max_size = 8  # tag + padding minimum
    for idx, v in enumerate(decl.variants):
        # Each variant's payloads start at offset 8 (after the tag
        # and padding for 8-byte alignment of the first payload).
        offset = 8
        payloads: list[tuple[int, int, str]] = []
        for ty in v.payload_tys:
            size = _size_of(ty, sum_layouts, struct_layouts)
            offset = _align_up(offset, size)
            payloads.append((offset, size, ty))
            offset += size
        variants[v.name] = (idx, payloads)
        max_size = max(max_size, _align_up(offset, 8))
    return {"variants": variants, "size": max_size}


# Capa scalar types this phase knows how to lower. Any other type
# raises NotImplementedError when encountered; the caller (test or
# tooling) is expected to know what subset of the IR Phase 6A
# accepts.
_CAPA_TO_WASM = {
    "Int": "i64",
    "Bool": "i32",
    "Unit": "",  # no result clause
}


# Comparison ops produce i32 (0 or 1) in Wasm; arithmetic ops
# preserve the operand type (i64).
_INT_BINOP = {
    "+": "i64.add",
    "-": "i64.sub",
    "*": "i64.mul",
    # i64.div_s / i64.rem_s are the signed variants; Capa's source
    # ``/`` and ``%`` follow signed semantics, matching the Python
    # integer floor-div convention for positives. The legacy
    # transpiler also uses Python's ``/`` which does floating-point
    # division; for Phase 6A we treat ``/`` as integer division.
    # A later phase that distinguishes Int and Float will revisit.
    "/": "i64.div_s",
    "%": "i64.rem_s",
}

_CMP_BINOP = {
    "==": "i64.eq",
    "!=": "i64.ne",
    "<":  "i64.lt_s",
    "<=": "i64.le_s",
    ">":  "i64.gt_s",
    ">=": "i64.ge_s",
}


class WasmEmissionError(Exception):
    """Raised when the Wasm emitter hits an IR construct it does
    not yet support. Phase 6A is intentionally narrow; widening the
    error surface is preferred to silently emitting wrong code."""


class WasmEmitter:
    def __init__(self, indent_unit: str = "  "):
        self._lines: List[str] = []
        self._indent = 0
        self._unit = indent_unit
        # Stack of (loop_label, exit_label) tuples so ``break`` and
        # ``continue`` know which loop they target. Wasm has no
        # implicit "innermost loop" branch; every branch names its
        # target block.
        self._loop_labels: list[tuple[str, str]] = []
        # Per-function counter for unique block labels.
        self._block_counter = 0
        # Module-level string pool: maps a Python string to its
        # (offset, length_in_bytes) in the data segment. Populated
        # by ``_intern_string`` as the emitter walks the function
        # bodies; the data segment itself is emitted after every
        # function so all literals are known.
        self._strings: dict[str, tuple[int, int]] = {}
        self._string_data_offset = 0
        # Set of capability classes the emitter has seen in
        # method-call receivers; drives the ``(import ...)``
        # declarations at the top of the module.
        self._used_caps: set[tuple[str, str]] = set()
        # The function currently being emitted; per-instruction
        # handlers consult ``self._current_fn.locals`` to resolve
        # the Capa type of a local without threading the function
        # through every recursive call.
        self._current_fn: Optional[Function] = None
        # Type layouts for structs and sums. Populated from the
        # module's ``types`` list before any function emission so
        # MakeStruct / Call-as-variant / Match / FieldAccess can
        # resolve field offsets and variant tags.
        self._struct_layouts: dict[str, dict] = {}
        self._sum_layouts: dict[str, dict] = {}
        # Reverse index from variant name -> sum type name, so a
        # ``Call(callee_name="Circle", ...)`` resolves to its parent
        # ``Shape`` sum without an enclosing scope hint.
        self._variant_to_sum: dict[str, str] = {}

    # ----- public ------------------------------------------------

    def emit(self, module: Module) -> str:
        # Pass 0: compute layouts for every struct and sum type so
        # subsequent passes can resolve field offsets and variant
        # tags. Layout of struct fields depends on the size of their
        # field types -- which may themselves be sums or structs.
        # We resolve in two passes: stub all type sizes first (treat
        # forward refs as pointer-sized i32 = 4 bytes), then refine
        # if a struct contains an inlined value type. For Phase 6C
        # all aggregate types are heap-allocated and referenced by
        # pointer, so the first pass is already correct; the second
        # pass is a no-op but kept for clarity if future phases
        # inline small structs.
        self._struct_layouts = {}
        self._sum_layouts = {}
        self._variant_to_sum = {}
        for ty in module.types:
            if isinstance(ty, StructDecl):
                self._struct_layouts[ty.name] = compute_struct_layout(
                    ty, self._sum_layouts, self._struct_layouts,
                )
            elif isinstance(ty, SumDecl):
                self._sum_layouts[ty.name] = compute_sum_layout(
                    ty, self._sum_layouts, self._struct_layouts,
                )
                for v in ty.variants:
                    self._variant_to_sum[v.name] = ty.name

        # First pass: walk the module to discover used capability
        # methods and string literals so we can emit imports and
        # the data segment at the top of the module (Wasm requires
        # imports before any function/code section, and we want the
        # data segment in a known location).
        self._used_caps = set()
        self._strings = {}
        self._string_data_offset = 0
        self._discover(module)

        # Stage 1: emit the (module ... ) header with imports and
        # memory.
        body_lines: list[str] = []
        self._lines = body_lines
        self._write("(module")
        self._indent += 1
        # Imports for each used capability method. The Wasm import
        # name follows the WIT interface convention: module name is
        # the lowercased interface (``capa:stdio`` style) so the
        # host's Linker maps interface -> import in one step.
        for cap, method in sorted(self._used_caps):
            import_module = f"capa:{cap.lower()}"
            import_name = method
            params, result = self._cap_method_wasm_sig(cap, method)
            params_str = " ".join(f"(param {t})" for t in params)
            result_str = f" (result {result})" if result else ""
            self._write(
                f'(import "{import_module}" "{import_name}" '
                f'(func ${cap}_{method}{(" " + params_str) if params_str else ""}{result_str}))'
            )
        # Memory + data segment for string literals. Always declare
        # at least one page (64KB) so any string fits without growth
        # logic; the host reads from this memory to materialise
        # string args.
        needs_memory = (
            self._strings
            or self._has_any_caps()
            or self._struct_layouts
            or self._sum_layouts
        )
        if needs_memory:
            self._write('(memory (export "memory") 1)')
            for text, (offset, _len) in sorted(
                self._strings.items(), key=lambda kv: kv[1][0],
            ):
                escaped = self._escape_wat_string(text)
                self._write(f'(data (i32.const {offset}) "{escaped}")')
        # Heap: starts just after the static data segment, aligned
        # to 8 bytes. The ``$alloc`` function below bumps the global
        # forward by the requested size, rounded up to 8.
        if self._struct_layouts or self._sum_layouts:
            heap_start = _align_up(self._string_data_offset, 8)
            self._write(
                f"(global $heap_top (mut i32) (i32.const {heap_start}))"
            )
            self._emit_alloc_function()
        # Stage 2: emit each function.
        for fn in module.functions:
            self._emit_function(fn)
        self._indent -= 1
        self._write(")")
        return "\n".join(self._lines) + "\n"

    def _emit_alloc_function(self) -> None:
        """Emit a bump allocator: ``$alloc(size: i32) -> i32`` that
        returns the current heap_top and advances it by the
        requested size aligned to 8 bytes. No free, no GC; this is
        the simplest correct allocator and matches Phase 6C's
        no-collections scope. A later phase that adds growth or
        compaction replaces this implementation."""
        self._write("(func $alloc (param $size i32) (result i32)")
        self._indent += 1
        self._write("(local $ret i32)")
        # Align $heap_top up to 8 bytes before returning.
        self._write("global.get $heap_top")
        self._write("i32.const 7")
        self._write("i32.add")
        self._write("i32.const -8")
        self._write("i32.and")
        self._write("local.tee $ret")
        self._write("local.get $size")
        self._write("i32.add")
        self._write("global.set $heap_top")
        self._write("local.get $ret")
        self._indent -= 1
        self._write(")")

    # ----- discovery pass ---------------------------------------

    def _discover(self, module: Module) -> None:
        """Walk all functions and collect string literals + used
        capability methods. The discovered set drives import
        declarations and the data segment layout; encountering
        anything outside the supported set is a fatal error so the
        emitted Wasm never references something the host did not
        provide."""
        for fn in module.functions:
            self._discover_instrs(fn.body)

    def _discover_instrs(self, instrs: list[Instr]) -> None:
        for instr in instrs:
            if isinstance(instr, MethodCall) and instr.cap_used:
                cap = instr.cap_used
                if cap not in _BUILTIN_CAPS:
                    raise WasmEmissionError(
                        f"Phase 6B: capability {cap!r} not in the "
                        f"built-in set; user-defined capabilities "
                        f"land in a later phase"
                    )
                key = (cap, instr.method)
                if (cap, instr.method) not in _WIT_SIGNATURES:
                    raise WasmEmissionError(
                        f"Phase 6B: capability method {cap}.{instr.method} "
                        f"has no WIT/Wasm encoding yet; widen the "
                        f"signature tables in capa.ir._emit_wit and "
                        f"capa.ir._emit_wasm together"
                    )
                self._used_caps.add(key)
            # Walk every Value-bearing slot of every instruction for
            # ``lit_str`` literals; the data segment must cover any
            # literal the emitter will reference at use site, not
            # just those that flow into capability calls.
            for v in self._values_of(instr):
                if v.kind == "lit_str":
                    self._intern_string(v.literal)
            if isinstance(instr, If):
                self._discover_instrs(instr.then_body)
                self._discover_instrs(instr.else_body)
            elif isinstance(instr, While):
                self._discover_instrs(instr.cond_setup)
                self._discover_instrs(instr.body)
            elif isinstance(instr, Match):
                for arm in instr.arms:
                    self._discover_instrs(arm.body)

    @staticmethod
    def _values_of(instr: Instr) -> list[Value]:
        """Return every Value-typed slot on ``instr`` so the
        discovery pass can intern string literals reachable from
        anywhere in the function body, not just the few sites the
        previous pass enumerated by hand."""
        out: list[Value] = []
        for attr in (
            "src", "value", "left", "right",
            "operand", "receiver", "iter", "cond", "index",
        ):
            v = getattr(instr, attr, None)
            if isinstance(v, Value):
                out.append(v)
        for v in getattr(instr, "args", []) or []:
            if isinstance(v, Value):
                out.append(v)
        for fname_v in getattr(instr, "fields", []) or []:
            if isinstance(fname_v, tuple) and len(fname_v) == 2:
                v = fname_v[1]
                if isinstance(v, Value):
                    out.append(v)
        for v in getattr(instr, "elements", []) or []:
            if isinstance(v, Value):
                out.append(v)
        for part in getattr(instr, "parts", []) or []:
            if isinstance(part, Value):
                out.append(part)
        return out

    def _intern_string(self, text: str) -> tuple[int, int]:
        if text in self._strings:
            return self._strings[text]
        encoded = text.encode("utf-8")
        offset = self._string_data_offset
        length = len(encoded)
        self._strings[text] = (offset, length)
        # Align next string on a 1-byte boundary -- no padding needed
        # for UTF-8. Add a 0 byte between strings so a hex dump is
        # readable when debugging.
        self._string_data_offset = offset + length + 1
        return (offset, length)

    def _has_any_caps(self) -> bool:
        return len(self._used_caps) > 0

    # ----- capability method signatures -------------------------

    def _cap_method_wasm_sig(
        self, cap: str, method: str,
    ) -> tuple[list[str], str]:
        """Return (param_types, result_type) for the Wasm core
        signature of a capability method. String args expand to two
        i32s (ptr, len). The result_type is empty for void methods.
        Mirrors the WIT signatures in ``_emit_wit._WIT_SIGNATURES``;
        keep the two tables in sync."""
        wit = _WIT_SIGNATURES.get((cap, method))
        if wit is None:
            raise WasmEmissionError(
                f"no Wasm signature for {cap}.{method}"
            )
        # Phase 6B only emits methods taking a single string arg
        # returning unit. Parsing the WIT signature would let us
        # support more shapes; for now, hard-code the pattern.
        if "func(msg: string)" in wit:
            return (["i32", "i32"], "")
        raise WasmEmissionError(
            f"Phase 6B: cap method {cap}.{method} has shape {wit!r} "
            f"that the Wasm emitter does not yet decode"
        )

    @staticmethod
    def _escape_wat_string(s: str) -> str:
        """Escape a Python string for inclusion inside a WAT
        ``(data ... "...")`` literal. WAT data strings use \\HH
        for arbitrary bytes; we go through UTF-8 and escape every
        byte that is not a printable ASCII character (avoiding
        ``"`` and ``\\`` which need special handling)."""
        out = []
        for b in s.encode("utf-8"):
            if 0x20 <= b < 0x7F and b not in (0x22, 0x5C):
                out.append(chr(b))
            else:
                out.append(f"\\{b:02x}")
        return "".join(out)

    # ----- function-level ---------------------------------------

    def _emit_function(self, fn: Function) -> None:
        # Reset per-function state.
        self._block_counter = 0
        self._loop_labels = []
        # Cache the current function so per-instruction handlers can
        # look up local / param Capa types without threading ``fn``
        # through every helper.
        self._current_fn = fn

        # Build the function header: params and result. Capability
        # params are dropped from the Wasm signature because their
        # methods are imported into the module by name -- the param
        # carries no runtime value. String params expand to two
        # i32s (ptr, len) named ``${p.name}_ptr`` / ``${p.name}_len``.
        param_clauses = []
        for p in fn.params:
            if p.ty in _BUILTIN_CAPS:
                continue
            if p.ty == "String":
                param_clauses.append(f"(param ${p.name}_ptr i32)")
                param_clauses.append(f"(param ${p.name}_len i32)")
                continue
            ty = self._wasm_type(p.ty)
            if not ty:
                raise WasmEmissionError(
                    f"function {fn.name!r}: parameter {p.name!r} has Unit "
                    f"type, which has no Wasm representation"
                )
            param_clauses.append(f"(param ${p.name} {ty})")
        params_str = " ".join(param_clauses)
        result_ty = self._wasm_type(fn.return_type)
        result_str = f" (result {result_ty})" if result_ty else ""
        header = (
            f'(func ${fn.name} (export "{fn.name}")'
            f'{(" " + params_str) if params_str else ""}'
            f'{result_str}'
        )
        self._write(header)
        self._indent += 1

        # Collect every local introduced by the function body so we
        # can declare them up front (Wasm requires this).
        param_names = {p.name for p in fn.params}
        local_decls = self._collect_locals(fn, param_names)
        for name, ty in local_decls.items():
            self._write(f"(local ${name} {ty})")

        # Emit body instructions.
        for instr in fn.body:
            self._emit_instr(instr)

        # Wasm's verifier wants a value on the stack at function
        # exit when the result type is non-empty. Capa's source
        # exhaustiveness analysis can guarantee every code path
        # returns, but the verifier does not see that; emit an
        # ``unreachable`` so the trailing code path is well-typed
        # under "no execution reaches here". For Unit returns the
        # implicit fall-through is fine.
        if result_ty:
            self._write("unreachable")

        self._indent -= 1
        self._write(")")

    def _collect_locals(
        self, fn: Function, param_names: set[str],
    ) -> dict[str, str]:
        """Walk every instruction in the function body and gather
        the set of local names (with their Wasm types) that need
        to be declared at the top of the function. Param names are
        excluded because Wasm treats params as locals already.

        Also reserves the match-helper locals ``$_m_scrut`` and
        ``$_m_tag`` if any Match instruction appears in the body;
        emitted Match code reuses these without per-instance unique
        names (sequential and nested matches do not overlap their
        live ranges of these locals)."""
        out: dict[str, str] = {}
        has_match = False
        has_variant_ctor = False

        def value_uses_variant_ctor(v: Value) -> bool:
            return v is not None and v.kind == "variant_ctor"

        def visit(instrs: list[Instr]) -> None:
            nonlocal has_match, has_variant_ctor
            for instr in instrs:
                if isinstance(instr, Match):
                    has_match = True
                    for arm in instr.arms:
                        visit(arm.body)
                # Detect Values of kind variant_ctor anywhere; they
                # require the ``$_alloc_tmp`` local at emit time.
                for attr in ("src", "value", "left", "right",
                             "operand", "receiver", "iter", "cond"):
                    v = getattr(instr, attr, None)
                    if isinstance(v, Value) and value_uses_variant_ctor(v):
                        has_variant_ctor = True
                for v in getattr(instr, "args", []) or []:
                    if isinstance(v, Value) and value_uses_variant_ctor(v):
                        has_variant_ctor = True
                dst = getattr(instr, "dst", None)
                if dst and dst not in param_names and dst not in out:
                    # Look up the Capa type of this local from the
                    # function's locals map; fall back to Int if
                    # unknown (Phase 6A only sees Int / Bool, so
                    # this default is safe within the supported
                    # subset).
                    capa_ty = fn.locals.get(dst, "Int")
                    # Capability locals (``let other = stdio``)
                    # carry no Wasm value; skip declaration.
                    if capa_ty in _BUILTIN_CAPS:
                        continue
                    # String locals expand to a (ptr, len) pair so
                    # the function can carry the value forward. The
                    # convention: ``$name_ptr`` + ``$name_len``, both
                    # i32. ``_push_string_local`` / ``_set_string_local``
                    # emit operations against the pair.
                    if capa_ty == "String":
                        out[f"{dst}_ptr"] = "i32"
                        out[f"{dst}_len"] = "i32"
                        continue
                    wasm_ty = self._wasm_type(capa_ty) or "i64"
                    out[dst] = wasm_ty
                # Recurse into nested instruction lists.
                if isinstance(instr, If):
                    visit(instr.then_body)
                    visit(instr.else_body)
                elif isinstance(instr, While):
                    visit(instr.cond_setup)
                    visit(instr.body)

        visit(fn.body)
        # Pattern-bound identifiers (Circle(r) -> binds r) and other
        # locals introduced by the lowerer but not visible as
        # ``Instr.dst`` (loop iter names, for-iter binds, etc.) live
        # in ``fn.locals``. Sweep them up so the Wasm function
        # declares everything it references.
        for name, capa_ty in fn.locals.items():
            if name in param_names or name in out:
                continue
            if capa_ty in _BUILTIN_CAPS or capa_ty == "Unit":
                continue
            if capa_ty == "String":
                ptr_name = f"{name}_ptr"
                if ptr_name not in out:
                    out[ptr_name] = "i32"
                len_name = f"{name}_len"
                if len_name not in out:
                    out[len_name] = "i32"
                continue
            try:
                wasm_ty = self._wasm_type(capa_ty) or "i64"
            except WasmEmissionError:
                # Conservative default for types whose Wasm shape is
                # not yet decided (e.g. List<T> in Phase 6C). The
                # local is most likely never read in a supported
                # path; allocate as i64 so subsequent emit attempts
                # at least parse before they fail at use-site with
                # a clearer error.
                wasm_ty = "i64"
            out[name] = wasm_ty
        if has_match:
            out["_m_scrut"] = "i32"
            out["_m_tag"] = "i32"
        if has_variant_ctor:
            out["_alloc_tmp"] = "i32"
        return out

    # ----- per-instruction --------------------------------------

    def _emit_instr(self, instr: Instr) -> None:
        if isinstance(instr, AssignConst):
            dst_ty = self._dst_capa_ty(instr.dst)
            if dst_ty in _BUILTIN_CAPS:
                # Capability locals are erased at the Wasm level.
                return
            if dst_ty == "String":
                self._emit_string_assign(instr.dst, instr.src)
                return
            self._push_value(instr.src)
            self._write(f"local.set ${instr.dst}")
            return
        if isinstance(instr, Reassign):
            dst_ty = self._dst_capa_ty(instr.dst)
            if dst_ty in _BUILTIN_CAPS:
                return
            if dst_ty == "String":
                self._emit_string_assign(instr.dst, instr.src)
                return
            self._push_value(instr.src)
            self._write(f"local.set ${instr.dst}")
            return
        if isinstance(instr, MethodCall):
            if instr.cap_used:
                self._emit_cap_method_call(instr)
                return
            raise WasmEmissionError(
                f"Phase 6B: MethodCall on non-capability receiver "
                f"(method {instr.method!r}); String / List / Map / Set "
                f"methods land in Phase 6D"
            )
        if isinstance(instr, MakeStruct):
            self._emit_make_struct(instr)
            return
        if isinstance(instr, FieldAccess):
            self._emit_field_access(instr)
            return
        if isinstance(instr, Match):
            self._emit_match(instr)
            return
        if isinstance(instr, BinOp):
            self._emit_binop(instr)
            return
        if isinstance(instr, UnaryOp):
            self._emit_unaryop(instr)
            return
        if isinstance(instr, If):
            self._push_value(instr.cond)
            self._write("if")
            self._indent += 1
            for sub in instr.then_body:
                self._emit_instr(sub)
            self._indent -= 1
            if instr.else_body:
                self._write("else")
                self._indent += 1
                for sub in instr.else_body:
                    self._emit_instr(sub)
                self._indent -= 1
            self._write("end")
            return
        if isinstance(instr, While):
            # Wasm has no native while-loop; ``loop`` branches to its
            # own start, ``block`` branches to its own end. The
            # canonical encoding wraps a ``loop`` inside a ``block``:
            # ``break`` -> ``br $exit_block``; ``continue`` ->
            # ``br $loop_start``; the cond test at the top of the
            # loop dispatches falsy -> br to exit, truthy -> body.
            self._block_counter += 1
            loop_label = f"$L{self._block_counter}_loop"
            exit_label = f"$L{self._block_counter}_exit"
            self._loop_labels.append((loop_label, exit_label))
            self._write(f"block {exit_label}")
            self._indent += 1
            self._write(f"loop {loop_label}")
            self._indent += 1
            # Recompute the condition each iteration; same pattern as
            # the Python emitter's ``while True / cond_setup / break``.
            for sub in instr.cond_setup:
                self._emit_instr(sub)
            self._push_value(instr.cond)
            self._write("i32.eqz")
            self._write(f"br_if {exit_label}")
            for sub in instr.body:
                self._emit_instr(sub)
            self._write(f"br {loop_label}")
            self._indent -= 1
            self._write("end")
            self._indent -= 1
            self._write("end")
            self._loop_labels.pop()
            return
        if isinstance(instr, Break):
            if not self._loop_labels:
                raise WasmEmissionError("break outside of a loop")
            _, exit_label = self._loop_labels[-1]
            self._write(f"br {exit_label}")
            return
        if isinstance(instr, Continue):
            if not self._loop_labels:
                raise WasmEmissionError("continue outside of a loop")
            loop_label, _ = self._loop_labels[-1]
            self._write(f"br {loop_label}")
            return
        if isinstance(instr, Return):
            if instr.value is not None:
                self._push_value(instr.value)
            self._write("return")
            return
        if isinstance(instr, Call):
            self._emit_user_call(instr)
            return
        raise WasmEmissionError(
            f"Phase 6A: instruction {type(instr).__name__} not supported"
        )

    def _emit_binop(self, instr: BinOp) -> None:
        op = instr.op
        if op in _INT_BINOP:
            self._push_value(instr.left)
            self._push_value(instr.right)
            self._write(_INT_BINOP[op])
            self._write(f"local.set ${instr.dst}")
            return
        if op in _CMP_BINOP:
            self._push_value(instr.left)
            self._push_value(instr.right)
            self._write(_CMP_BINOP[op])
            self._write(f"local.set ${instr.dst}")
            return
        # ``and`` / ``or`` reach the emitter only when the lowerer
        # did NOT short-circuit them (which it does for Bool BinOps
        # at the IR level). Reaching here would mean the IR has a
        # bug; raise rather than silently mis-evaluate.
        raise WasmEmissionError(
            f"Phase 6A: binop {op!r} not supported (and/or are "
            f"short-circuited at the IR level and should not reach "
            f"the Wasm emitter)"
        )

    def _emit_unaryop(self, instr: UnaryOp) -> None:
        op = instr.op
        if op == "-":
            # Wasm has no i64.neg; emit ``0 - x``.
            self._write("i64.const 0")
            self._push_value(instr.operand)
            self._write("i64.sub")
            self._write(f"local.set ${instr.dst}")
            return
        if op == "not":
            # Boolean negation: i32.eqz turns 0 -> 1, anything else
            # -> 0. Matches Capa's ``not`` semantics on Bool.
            self._push_value(instr.operand)
            self._write("i32.eqz")
            self._write(f"local.set ${instr.dst}")
            return
        raise WasmEmissionError(
            f"Phase 6A: unary op {op!r} not supported"
        )

    # ----- user-function calls ----------------------------------

    def _emit_user_call(self, instr: Call) -> None:
        """Lower a Capa-level function call. Two flavours share this
        path because the IR's lowerer represents both as ``Call``:

        - **Variant construction** (``Circle(5)`` etc.). Detected by
          looking up ``callee_name`` in ``_variant_to_sum``. Emits
          ``$alloc`` + tag store + payload stores; the result is a
          pointer to the freshly allocated sum.
        - **Ordinary function call**. Pushes non-capability args
          and emits ``call $name``; the return value, if any,
          binds to ``instr.dst``.

        Capability-typed args are always skipped (capabilities flow
        through module-level imports, not as values)."""
        if instr.callee_name in self._variant_to_sum:
            self._emit_variant_construction(instr)
            return
        for arg in instr.args:
            if arg.ty in _BUILTIN_CAPS:
                continue
            if arg.ty == "String":
                if arg.kind == "lit_str":
                    offset, length = self._intern_string(arg.literal)
                    self._write(f"i32.const {offset}")
                    self._write(f"i32.const {length}")
                elif arg.kind == "local":
                    self._write(f"local.get ${arg.name}_ptr")
                    self._write(f"local.get ${arg.name}_len")
                elif arg.kind == "param":
                    self._write(f"local.get ${arg.name}_ptr")
                    self._write(f"local.get ${arg.name}_len")
                else:
                    raise WasmEmissionError(
                        f"String arg of kind {arg.kind!r} not supported"
                    )
                continue
            self._push_value(arg)
        self._write(f"call ${instr.callee_name}")
        if instr.dst is not None:
            dst_ty = self._dst_capa_ty(instr.dst)
            # If the callee returns a non-empty value, store it in
            # ``instr.dst``. If the dst type is Unit / capability /
            # String, skip the set (those locals are erased at the
            # Wasm level).
            if dst_ty and dst_ty not in _BUILTIN_CAPS and dst_ty not in ("Unit", "String"):
                self._write(f"local.set ${instr.dst}")

    def _emit_variant_construction(self, instr: Call) -> None:
        """Emit code that allocates a sum-type instance, writes the
        variant tag at offset 0, and stores each payload at its
        layout-determined offset. Leaves the i32 pointer in
        ``instr.dst``."""
        sum_name = self._variant_to_sum[instr.callee_name]
        sum_layout = self._sum_layouts[sum_name]
        tag, payload_layouts = sum_layout["variants"][instr.callee_name]
        total_size = sum_layout["size"]
        if len(payload_layouts) != len(instr.args):
            raise WasmEmissionError(
                f"variant {instr.callee_name}: expected "
                f"{len(payload_layouts)} payloads, got {len(instr.args)}"
            )
        # Allocate. Leave pointer in dst local.
        if instr.dst is None:
            raise WasmEmissionError(
                "variant construction must bind a dst (its pointer)"
            )
        self._write(f"i32.const {total_size}")
        self._write("call $alloc")
        self._write(f"local.set ${instr.dst}")
        # Store the discriminant tag at offset 0.
        self._write(f"local.get ${instr.dst}")
        self._write(f"i32.const {tag}")
        self._write("i32.store")
        # Store each payload at its offset.
        for arg, (offset, size, _ty) in zip(instr.args, payload_layouts):
            self._write(f"local.get ${instr.dst}")
            self._push_value(arg)
            self._write(f"{_store_op_for_size(size)} offset={offset}")

    def _emit_make_struct(self, instr: MakeStruct) -> None:
        """Emit alloc + per-field store for a struct literal. The
        pointer to the newly-allocated struct lands in ``instr.dst``.
        Field order follows the declaration; the lowerer guarantees
        ``instr.fields`` matches."""
        layout = self._struct_layouts.get(instr.type_name)
        if layout is None:
            raise WasmEmissionError(
                f"struct {instr.type_name!r} has no layout; was the "
                f"type declared in module.types?"
            )
        self._write(f"i32.const {layout['size']}")
        self._write("call $alloc")
        self._write(f"local.set ${instr.dst}")
        for fname, fval in instr.fields:
            f_info = layout["fields"].get(fname)
            if f_info is None:
                raise WasmEmissionError(
                    f"struct {instr.type_name}: field {fname!r} not in layout"
                )
            offset, size, _ty = f_info
            self._write(f"local.get ${instr.dst}")
            self._push_value(fval)
            self._write(f"{_store_op_for_size(size)} offset={offset}")

    def _emit_field_access(self, instr: FieldAccess) -> None:
        """Load a struct field by offset. The receiver is an i32
        pointer to the struct in linear memory; we add the field's
        layout offset and emit the appropriate load opcode."""
        recv_ty = instr.receiver.ty
        layout = self._struct_layouts.get(recv_ty)
        if layout is None:
            raise WasmEmissionError(
                f"FieldAccess on receiver of type {recv_ty!r}: no "
                f"struct layout known. The IR's type inference must "
                f"have produced an unexpected receiver type."
            )
        f_info = layout["fields"].get(instr.field)
        if f_info is None:
            raise WasmEmissionError(
                f"struct {recv_ty}: field {instr.field!r} not found"
            )
        offset, size, _ty = f_info
        self._push_value(instr.receiver)
        self._write(f"{_load_op_for_size(size)} offset={offset}")
        self._write(f"local.set ${instr.dst}")

    # ----- match emission ---------------------------------------

    def _emit_match(self, instr: Match) -> None:
        """Lower a sum-type match. The scrutinee is an i32 pointer;
        we load the discriminant from offset 0 and dispatch via a
        nested if-else chain (one level per arm), extracting each
        variant's payload into the arm-bound local before running
        the arm body. Phase 6C does not yet emit ``br_table`` for
        dense discriminants -- nested ``if`` is correct and easier
        to read in WAT dumps; an optimisation phase can switch to
        ``br_table`` when contiguous tags warrant it.

        Reuses ``$_m_scrut`` and ``$_m_tag`` locals declared at the
        top of the enclosing function; nested matches are safe
        because each Match consumes the locals before recursing
        into arm bodies.
        """
        scrut_ty = instr.scrutinee.ty
        sum_layout = self._sum_layouts.get(scrut_ty)
        if sum_layout is None:
            raise WasmEmissionError(
                f"Match on scrutinee of type {scrut_ty!r}: only sum "
                f"types are supported in Phase 6C. Int / Bool match "
                f"lands in a later phase (or stays statement-form via "
                f"if/elif)."
            )
        scrut_local = "_m_scrut"
        tag_local = "_m_tag"
        self._push_value(instr.scrutinee)
        self._write(f"local.set ${scrut_local}")
        self._write(f"local.get ${scrut_local}")
        self._write("i32.load")
        self._write(f"local.set ${tag_local}")
        # Emit arms as a nested if/else chain. Track how many
        # ``if`` statements we open so we can close them all at the
        # end. ``else`` blocks open implicitly when we cascade.
        opened = 0
        for arm in instr.arms:
            opened += self._emit_match_arm(arm, scrut_local, tag_local, sum_layout)
        for _ in range(opened):
            self._indent -= 1
            self._write("end")

    def _emit_match_arm(
        self, arm: MatchArm, scrut_local: str, tag_local: str,
        sum_layout: dict,
    ) -> int:
        """Emit one arm. Returns the number of new ``if`` blocks
        opened (0 for a wildcard, 1 for a variant arm). The caller
        emits matching ``end`` instructions after all arms are
        processed."""
        pat = arm.pattern
        if isinstance(pat, PatVariant):
            tag, payload_layouts = sum_layout["variants"][pat.name]
            self._write(f"local.get ${tag_local}")
            self._write(f"i32.const {tag}")
            self._write("i32.eq")
            self._write("if")
            self._indent += 1
            for sub_pat, (offset, size, _ty) in zip(
                pat.payloads, payload_layouts,
            ):
                if isinstance(sub_pat, PatIdent):
                    self._write(f"local.get ${scrut_local}")
                    self._write(f"{_load_op_for_size(size)} offset={offset}")
                    self._write(f"local.set ${sub_pat.name}")
                elif isinstance(sub_pat, PatWildcard):
                    continue
                else:
                    raise WasmEmissionError(
                        f"Phase 6C: nested pattern "
                        f"{type(sub_pat).__name__} inside variant "
                        f"payload not yet supported"
                    )
            for sub in arm.body:
                self._emit_instr(sub)
            # Cascade into the else block where the next arm lives.
            self._indent -= 1
            self._write("else")
            self._indent += 1
            return 1
        if isinstance(pat, PatWildcard):
            # Catch-all: body emits inside the current cascade
            # (which is the open ``else`` of the previous arm).
            for sub in arm.body:
                self._emit_instr(sub)
            return 0
        raise WasmEmissionError(
            f"Phase 6C: match arm pattern {type(pat).__name__} not "
            f"supported (PatVariant + PatWildcard are the current set)"
        )

    # ----- capability method calls ------------------------------

    def _emit_cap_method_call(self, instr: MethodCall) -> None:
        cap = instr.cap_used
        method = instr.method
        # Push each argument. String args (literals or locals)
        # expand to (ptr, len) i32 pairs; scalar args use the
        # regular push path.
        for arg in instr.args:
            if arg.kind == "lit_str":
                offset, length = self._intern_string(arg.literal)
                self._write(f"i32.const {offset}")
                self._write(f"i32.const {length}")
            elif arg.kind == "local" and self._is_string_local(arg.name):
                self._write(f"local.get ${arg.name}_ptr")
                self._write(f"local.get ${arg.name}_len")
            elif arg.kind == "param" and self._param_is_string(arg.name):
                self._write(f"local.get ${arg.name}_ptr")
                self._write(f"local.get ${arg.name}_len")
            else:
                self._push_value(arg)
        self._write(f"call ${cap}_{method}")
        # Result handling: Phase 6B methods all return Unit, so no
        # local.set is needed. When a method returns a value (Phase
        # 6C+), we will local.set $instr.dst here.

    def _is_string_local(self, name: str) -> bool:
        ty = self._current_fn.locals.get(name) if self._current_fn else None
        return ty == "String"

    def _param_is_string(self, name: str) -> bool:
        if self._current_fn is None:
            return False
        for p in self._current_fn.params:
            if p.name == name:
                return p.ty == "String"
        return False

    def _dst_capa_ty(self, name: str) -> str:
        if self._current_fn is None:
            return ""
        return self._current_fn.locals.get(name, "")

    # ----- string locals ----------------------------------------

    def _emit_string_assign(self, dst: str, src: Value) -> None:
        """Bind a String value to the (ptr, len) pair representing
        ``dst``. ``src`` may be a literal (from the pool) or another
        String local."""
        if src.kind == "lit_str":
            offset, length = self._intern_string(src.literal)
            self._write(f"i32.const {offset}")
            self._write(f"local.set ${dst}_ptr")
            self._write(f"i32.const {length}")
            self._write(f"local.set ${dst}_len")
            return
        if src.kind == "local" and self._is_string_local(src.name):
            self._write(f"local.get ${src.name}_ptr")
            self._write(f"local.set ${dst}_ptr")
            self._write(f"local.get ${src.name}_len")
            self._write(f"local.set ${dst}_len")
            return
        raise WasmEmissionError(
            f"cannot bind String dst {dst!r} from value {src!r}"
        )

    # ----- value pushing ----------------------------------------

    def _push_value(self, v: Value) -> None:
        """Emit the instruction(s) that push a Value onto the Wasm
        operand stack. Wasm has no concept of "Value" the way the
        IR does; every operation reads from the stack."""
        if v.kind in ("local", "param"):
            self._write(f"local.get ${v.name}")
            return
        if v.kind == "lit_int":
            self._write(f"i64.const {v.literal}")
            return
        if v.kind == "lit_bool":
            self._write(f"i32.const {1 if v.literal else 0}")
            return
        if v.kind == "lit_unit":
            # Unit has no Wasm representation; pushing a unit value
            # is a no-op. The instruction that asked for the push
            # should not have done so for a Unit-typed sink.
            return
        if v.kind == "variant_ctor":
            # Payload-less variant used as a value (``return Neither``,
            # ``let x = Excellent``, ...). Emit alloc + tag store
            # inline, leaving the pointer on the stack. A function-
            # level ``$_alloc_tmp`` local stores the pointer so we
            # can re-push it after ``i32.store`` consumed the first
            # copy along with the tag value.
            sum_name = self._variant_to_sum.get(v.name)
            if sum_name is None:
                raise WasmEmissionError(
                    f"variant {v.name!r} has no sum-type layout; was "
                    f"the parent ``type`` declared in module.types?"
                )
            sum_layout = self._sum_layouts[sum_name]
            tag, _payloads = sum_layout["variants"][v.name]
            size = sum_layout["size"]
            self._write(f"i32.const {size}")
            self._write("call $alloc")
            self._write("local.tee $_alloc_tmp")
            self._write(f"i32.const {tag}")
            self._write("i32.store")
            self._write("local.get $_alloc_tmp")
            return
        raise WasmEmissionError(
            f"value kind {v.kind!r} not supported "
            f"(no Wasm encoding yet for {v!r})"
        )

    # ----- helpers ----------------------------------------------

    def _wasm_type(self, capa_ty: str) -> str:
        head = capa_ty.split("<", 1)[0]
        if head in _CAPA_TO_WASM:
            return _CAPA_TO_WASM[head]
        # Struct and sum types are stored on the heap and passed by
        # i32 pointer. Locals/params/return values of these types
        # are i32 at the Wasm level.
        if head in self._struct_layouts or head in self._sum_layouts:
            return "i32"
        raise WasmEmissionError(
            f"Capa type {capa_ty!r} has no Wasm encoding yet"
        )

    def _write(self, line: str) -> None:
        if line == "":
            self._lines.append("")
        else:
            self._lines.append(self._unit * self._indent + line)
