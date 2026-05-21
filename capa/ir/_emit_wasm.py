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
    MakeStruct, MakeList, MakeMap, MakeSet, FieldAccess, Index, For,
    FormatStr,
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
# Sets are represented as i32 pointers; their stdlib payloads land
# in 6D and beyond.
_TYPE_SIZE = {
    "Int":    8,  # i64
    "Bool":   4,  # i32
    "Float":  8,  # f64
    # Strings live as (ptr, len) pairs -- two i32s = 8 bytes total.
    # When a struct field has String type, the FieldAccess emitter
    # issues two i32.loads (offset, offset+4) into the bind's
    # ${name}_ptr / ${name}_len locals.
    "String": 8,
}


# Memory layout of a List<T>: 16-byte header (len, cap, data_ptr,
# padding) followed by a separately-allocated element array. The
# header is kept fixed-size so List<T> for any T is a 16-byte
# allocation; the data array's stride depends on T.
_LIST_HEADER_SIZE = 16
_LIST_LEN_OFFSET = 0
_LIST_CAP_OFFSET = 4
_LIST_DATA_OFFSET = 8


# Memory layout of a Map<String, V>: same 16-byte header as List;
# the data array holds (key_ptr, key_len, value) triples each 16
# bytes wide. Phase 6D-3 specialises to String keys and 8-byte
# values (Int / pointer / packed-String-pair). Larger value types
# wait for a later phase that widens the slot.
_MAP_HEADER_SIZE = 16
_MAP_LEN_OFFSET = 0
_MAP_CAP_OFFSET = 4
_MAP_DATA_OFFSET = 8
_MAP_PAIR_SIZE = 16          # key_ptr (4) + key_len (4) + value (8)
_MAP_PAIR_KEY_PTR_OFFSET = 0
_MAP_PAIR_KEY_LEN_OFFSET = 4
_MAP_PAIR_VALUE_OFFSET = 8


# Memory layout of Capa's built-in Option<T>: a sum type with two
# variants (Some with one payload, None with none). Pre-registered
# in the emitter so ``match`` against Option<T> works without the
# user having to declare the type in source.
_OPTION_LAYOUT = {
    "variants": {
        # tag -> 0 for Some, payload at offset 8 (uniform 8-byte slot).
        "Some": (0, [(8, 8, "Any")]),
        # tag -> 1 for None, no payloads.
        "None": (1, []),
    },
    "size": 16,
}


# Memory layout of Capa's built-in Result<T, E>: also pre-registered.
_RESULT_LAYOUT = {
    "variants": {
        "Ok":  (0, [(8, 8, "Any")]),
        "Err": (1, [(8, 8, "Any")]),
    },
    "size": 16,
}


# Memory layout of Capa's built-in IoError struct. The Capa runtime
# defines this in capa.runtime._capabilities; pre-registering the
# Wasm layout here means Capa code that pattern-matches on
# ``Err(io_error)`` and then reads ``io_error.message`` works
# through the existing struct field-access machinery without the
# user declaring the type in source.
_IOERROR_LAYOUT = {
    "fields": {
        # Each String field is 8 bytes (ptr@offset + len@offset+4).
        # The FieldAccess emitter handles the two-load expansion
        # when the field's recorded type is "String".
        "message": (0, 8, "String"),
        "cause":   (8, 8, "String"),
    },
    "size": 16,
}


def _map_value_type(map_ty: str) -> str:
    """Extract V from ``Map<K, V>``. Phase 6D-3 only supports K =
    String, so we ignore K; returning V drives method dispatch.
    Defaults to ``Int`` if the type string lacks args (consistent
    with the List analogue)."""
    if map_ty.startswith("Map<") and map_ty.endswith(">"):
        inner = map_ty[4:-1].strip()
        _k, _, v = inner.partition(",")
        v = v.strip()
        if v.startswith("?") or not v:
            return "Int"
        return v
    return "Int"


def _element_type_of_list(list_ty: str) -> str:
    """Extract T from ``List<T>``. Defaults to ``Int`` if the
    string lacks a type argument (the lowerer occasionally leaves
    bare ``List`` when the analyzer has no precise inference),
    or if the inner type is an unresolved type variable like
    ``?lst_0`` (the analyzer's type-var notation; happens for
    empty literals where inference happens elsewhere). Phase 6D-2
    defaults the unresolved case to Int because that is by far
    the most common element type in practice. A subsequent
    analyzer fix that propagates annotations into IR type strings
    will obsolete this fallback."""
    if list_ty.startswith("List<") and list_ty.endswith(">"):
        inner = list_ty[5:-1].strip()
        if inner.startswith("?"):
            return "Int"
        return inner
    return "Int"


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
    "Float": "f64",
    "Unit": "",  # no result clause
}


# Comparison ops produce i32 (0 or 1) in Wasm; arithmetic ops
# preserve the operand type (i64 for Int, f64 for Float). The
# emitter dispatches on the operand's Capa type to pick the right
# opcode family.
_INT_BINOP = {
    "+": "i64.add",
    "-": "i64.sub",
    "*": "i64.mul",
    "/": "i64.div_s",
    "%": "i64.rem_s",
}

_FLOAT_BINOP = {
    "+": "f64.add",
    "-": "f64.sub",
    "*": "f64.mul",
    "/": "f64.div",
}

_CMP_BINOP = {
    "==": "i64.eq",
    "!=": "i64.ne",
    "<":  "i64.lt_s",
    "<=": "i64.le_s",
    ">":  "i64.gt_s",
    ">=": "i64.ge_s",
}

_FLOAT_CMP_BINOP = {
    "==": "f64.eq",
    "!=": "f64.ne",
    "<":  "f64.lt",
    "<=": "f64.le",
    ">":  "f64.gt",
    ">=": "f64.ge",
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
        # Pre-register Capa's built-in Option<T> and Result<T, E>
        # sum types so the emitter can build / pattern-match them
        # without the user declaring them in source. ``Some``,
        # ``None``, ``Ok``, ``Err`` map to these layouts. User-
        # defined types are added on top, never overriding.
        self._struct_layouts = {"IoError": _IOERROR_LAYOUT}
        self._sum_layouts = {"Option": _OPTION_LAYOUT, "Result": _RESULT_LAYOUT}
        self._variant_to_sum = {
            "Some": "Option", "None": "Option",
            "Ok": "Result", "Err": "Result",
        }

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
        # Pre-intern "true" / "false" if any FormatStr might consume
        # a Bool value at runtime; the data-segment offsets are
        # referenced via i32.const in the dispatch.
        if self._uses_format_str(module):
            self._intern_string("true")
            self._intern_string("false")
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
            # Component Model convention: import names use the form
            # ``<package>/<interface>``. We emit ``capa:host/<cap>``
            # to match the WIT generated by ``capa.ir.emit_wit`` (the
            # ``capa:host`` package contains one interface per
            # built-in capability, lowercased).
            import_module = f"capa:host/{cap.lower()}"
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
            or self._uses_heap_alloc(module)
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
        if (
            self._struct_layouts
            or self._sum_layouts
            or self._uses_heap_alloc(module)
        ):
            heap_start = _align_up(self._string_data_offset, 8)
            self._write(
                f"(global $heap_top (mut i32) (i32.const {heap_start}))"
            )
            self._emit_alloc_function()
            # ``$str_eq`` is only needed when at least one Map
            # operation may run; it compares two (ptr, len) string
            # pairs byte-by-byte. Always emit when a map is in
            # play -- inlining it at every set/get call site would
            # bloat the WAT.
            if self._uses_map_ops(module):
                self._emit_str_eq_function()
            if self._uses_format_str(module):
                self._emit_itoa_function()
                if self._uses_float_format(module):
                    self._emit_ftoa_function()
        # Stage 2: emit each function.
        for fn in module.functions:
            self._emit_function(fn)
        self._indent -= 1
        self._write(")")
        return "\n".join(self._lines) + "\n"

    def _uses_heap_alloc(self, module: Module) -> bool:
        """Detect whether any function body contains an instruction
        that allocates on the heap. Used to decide whether the
        module needs the ``$alloc`` helper and the ``$heap_top``
        global."""
        # Method names that allocate when called.
        _ALLOC_METHODS_LIST = {"push"}
        _ALLOC_METHODS_STRING = {"substring", "to_upper", "to_lower"}

        def visit(instrs: list[Instr]) -> bool:
            for instr in instrs:
                if isinstance(instr, (MakeList, MakeMap, MakeSet, FormatStr)):
                    return True
                if isinstance(instr, MethodCall):
                    recv_ty = instr.receiver.ty or ""
                    if recv_ty.startswith("List") and instr.method in _ALLOC_METHODS_LIST:
                        return True
                    if recv_ty == "String" and instr.method in _ALLOC_METHODS_STRING:
                        return True
                    if recv_ty.startswith("Map") and instr.method in ("set", "get"):
                        return True
                if isinstance(instr, If):
                    if visit(instr.then_body) or visit(instr.else_body):
                        return True
                if isinstance(instr, While):
                    if visit(instr.cond_setup) or visit(instr.body):
                        return True
                if isinstance(instr, For):
                    if visit(instr.body):
                        return True
                if isinstance(instr, Match):
                    for arm in instr.arms:
                        if visit(arm.body):
                            return True
            return False
        for fn in module.functions:
            if visit(fn.body):
                return True
        return False

    def _uses_float_format(self, module: Module) -> bool:
        """True if any ``FormatStr`` instruction has a Float value
        part, which is what gates emission of the ``$ftoa`` helper."""
        def visit(instrs: list[Instr]) -> bool:
            for instr in instrs:
                if isinstance(instr, FormatStr):
                    for p in instr.parts:
                        if isinstance(p, Value) and p.ty == "Float":
                            return True
                if isinstance(instr, If):
                    if visit(instr.then_body) or visit(instr.else_body):
                        return True
                if isinstance(instr, While):
                    if visit(instr.cond_setup) or visit(instr.body):
                        return True
                if isinstance(instr, For):
                    if visit(instr.body):
                        return True
                if isinstance(instr, Match):
                    for arm in instr.arms:
                        if visit(arm.body):
                            return True
            return False
        for fn in module.functions:
            if visit(fn.body):
                return True
        return False

    def _uses_format_str(self, module: Module) -> bool:
        """True if any function body contains a ``FormatStr``
        instruction. Drives the emission of the ``$itoa`` helper
        (and pre-interning of ``"true"`` / ``"false"`` for Bool
        parts)."""
        def visit(instrs: list[Instr]) -> bool:
            for instr in instrs:
                if isinstance(instr, FormatStr):
                    return True
                if isinstance(instr, If):
                    if visit(instr.then_body) or visit(instr.else_body):
                        return True
                if isinstance(instr, While):
                    if visit(instr.cond_setup) or visit(instr.body):
                        return True
                if isinstance(instr, For):
                    if visit(instr.body):
                        return True
                if isinstance(instr, Match):
                    for arm in instr.arms:
                        if visit(arm.body):
                            return True
            return False
        for fn in module.functions:
            if visit(fn.body):
                return True
        return False

    def _uses_map_ops(self, module: Module) -> bool:
        """True if the module touches a Map or a String method that
        relies on byte-string equality (contains / starts_with /
        ends_with). Drives whether the ``$str_eq`` helper is
        emitted."""
        def visit(instrs: list[Instr]) -> bool:
            for instr in instrs:
                if isinstance(instr, MakeMap):
                    return True
                if isinstance(instr, MethodCall):
                    recv_ty = instr.receiver.ty or ""
                    if recv_ty.startswith("Map"):
                        return True
                    if recv_ty == "String" and instr.method in (
                        "contains", "starts_with", "ends_with",
                    ):
                        return True
                if isinstance(instr, If):
                    if visit(instr.then_body) or visit(instr.else_body):
                        return True
                if isinstance(instr, While):
                    if visit(instr.cond_setup) or visit(instr.body):
                        return True
                if isinstance(instr, For):
                    if visit(instr.body):
                        return True
                if isinstance(instr, Match):
                    for arm in instr.arms:
                        if visit(arm.body):
                            return True
            return False
        for fn in module.functions:
            if visit(fn.body):
                return True
        return False

    def _emit_str_eq_function(self) -> None:
        """Helper: ``$str_eq(p1: i32, l1: i32, p2: i32, l2: i32) -> i32``
        returns 1 if the two byte slices are equal, 0 otherwise.
        Length mismatch is the fast-path no-match; the byte-by-byte
        compare loops only when lengths match.

        Used by Map.set / Map.get / Map.contains_key to identify
        the matching slot in the linear-scan key array."""
        self._write(
            "(func $str_eq (param $p1 i32) (param $l1 i32) "
            "(param $p2 i32) (param $l2 i32) (result i32)"
        )
        self._indent += 1
        self._write("(local $i i32)")
        # Length mismatch: return 0.
        self._write("local.get $l1")
        self._write("local.get $l2")
        self._write("i32.ne")
        self._write("if")
        self._indent += 1
        self._write("i32.const 0")
        self._write("return")
        self._indent -= 1
        self._write("end")
        # Byte-by-byte loop.
        self._write("i32.const 0")
        self._write("local.set $i")
        self._write("block $eq_exit (result i32)")
        self._indent += 1
        self._write("loop $eq_loop")
        self._indent += 1
        # if i >= l1: exit with 1.
        self._write("local.get $i")
        self._write("local.get $l1")
        self._write("i32.ge_s")
        self._write("if")
        self._indent += 1
        self._write("i32.const 1")
        self._write("br $eq_exit")
        self._indent -= 1
        self._write("end")
        # Load byte from p1+i and p2+i, compare.
        self._write("local.get $p1")
        self._write("local.get $i")
        self._write("i32.add")
        self._write("i32.load8_u")
        self._write("local.get $p2")
        self._write("local.get $i")
        self._write("i32.add")
        self._write("i32.load8_u")
        self._write("i32.ne")
        self._write("if")
        self._indent += 1
        self._write("i32.const 0")
        self._write("br $eq_exit")
        self._indent -= 1
        self._write("end")
        # i += 1; continue.
        self._write("local.get $i")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $i")
        self._write("br $eq_loop")
        self._indent -= 1
        self._write("end")
        # Wasm's stack type checker wants a value at every path's
        # exit; the loop never falls through (every iteration ends
        # with either ``br $eq_exit`` or ``br $eq_loop``) but the
        # verifier cannot prove that. Mark the fall-through as
        # unreachable so the block's i32 result type is satisfied.
        self._write("unreachable")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write(")")

    def _emit_itoa_function(self) -> None:
        """Helper: ``$itoa(n: i64) -> (i32 ptr, i32 len)`` writes
        the decimal representation of ``n`` into freshly-allocated
        heap memory and returns its (ptr, len). Handles negative
        numbers with a leading ``-``; max output is 21 bytes
        (``-9223372036854775808`` is 20 chars + sign), so we always
        reserve 32 to leave room for a future hex prefix.

        Algorithm: write digits backwards into a scratch buffer at
        the top of the alloc, then memory.copy them forward into a
        tight result buffer. The two-step approach keeps the loop
        trivial; the cost is one extra alloc + copy per int."""
        self._write("(func $itoa (param $n i64) (result i32 i32)")
        self._indent += 1
        self._write("(local $abs i64)")
        self._write("(local $neg i32)")
        self._write("(local $buf i32)")
        self._write("(local $i i32)")
        self._write("(local $digit i32)")
        self._write("(local $ret_ptr i32)")
        self._write("(local $ret_len i32)")
        # Allocate 32-byte scratch buffer.
        self._write("i32.const 32")
        self._write("call $alloc")
        self._write("local.set $buf")
        # Handle sign.
        self._write("local.get $n")
        self._write("i64.const 0")
        self._write("i64.lt_s")
        self._write("if")
        self._indent += 1
        self._write("i32.const 1")
        self._write("local.set $neg")
        self._write("i64.const 0")
        self._write("local.get $n")
        self._write("i64.sub")
        self._write("local.set $abs")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        self._write("local.get $n")
        self._write("local.set $abs")
        self._indent -= 1
        self._write("end")
        # Write digits backwards into buf+31, buf+30, ... at index $i.
        # $i tracks how many digits we wrote.
        self._write("i32.const 0")
        self._write("local.set $i")
        self._block_counter += 1
        loop = f"$itoa{self._block_counter}_loop"
        exit_ = f"$itoa{self._block_counter}_exit"
        self._write(f"block {exit_}")
        self._indent += 1
        self._write(f"loop {loop}")
        self._indent += 1
        # digit = abs % 10
        self._write("local.get $abs")
        self._write("i64.const 10")
        self._write("i64.rem_u")
        self._write("i32.wrap_i64")
        self._write("local.set $digit")
        # buf[31 - i] = '0' + digit
        self._write("local.get $buf")
        self._write("i32.const 31")
        self._write("local.get $i")
        self._write("i32.sub")
        self._write("i32.add")
        self._write("local.get $digit")
        self._write("i32.const 48")    # '0'
        self._write("i32.add")
        self._write("i32.store8")
        self._write("local.get $i")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $i")
        # abs /= 10
        self._write("local.get $abs")
        self._write("i64.const 10")
        self._write("i64.div_u")
        self._write("local.tee $abs")
        # if abs == 0: exit.
        self._write("i64.eqz")
        self._write(f"br_if {exit_}")
        self._write(f"br {loop}")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")
        # Optionally prepend '-'.
        self._write("local.get $neg")
        self._write("if")
        self._indent += 1
        self._write("local.get $buf")
        self._write("i32.const 31")
        self._write("local.get $i")
        self._write("i32.sub")
        self._write("i32.const 1")
        self._write("i32.sub")
        self._write("i32.add")
        self._write("i32.const 45")    # '-'
        self._write("i32.store8")
        self._write("local.get $i")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $i")
        self._indent -= 1
        self._write("end")
        # ret_ptr = buf + 32 - i; ret_len = i. Return (ret_ptr, ret_len).
        self._write("local.get $buf")
        self._write("i32.const 32")
        self._write("local.get $i")
        self._write("i32.sub")
        self._write("i32.add")
        self._write("local.get $i")
        self._indent -= 1
        self._write(")")

    def _emit_ftoa_function(self) -> None:
        """``$ftoa(f: f64) -> (i32 ptr, i32 len)``: format a double
        as ``<int>.<6 decimal digits>`` (with optional leading
        minus). Fixed 6-decimal precision; sufficient for the
        ``${time}`` style interpolation in Capa source. Allocates
        a fresh buffer per call.

        Strategy: separate integer and fractional parts via
        ``f64.trunc``, reuse the existing ``$itoa`` for the
        integer part, then write 6 zero-padded fractional digits
        into the buffer at the trailing positions.
        """
        self._write("(func $ftoa (param $f f64) (result i32 i32)")
        self._indent += 1
        self._write("(local $abs f64)")
        self._write("(local $neg i32)")
        self._write("(local $int_part i64)")
        self._write("(local $frac_int i64)")
        self._write("(local $int_ptr i32)")
        self._write("(local $int_len i32)")
        self._write("(local $buf i32)")
        self._write("(local $write_pos i32)")
        self._write("(local $i i32)")
        self._write("(local $digit i32)")
        # neg = f < 0; abs = neg ? -f : f
        self._write("local.get $f")
        self._write("f64.const 0")
        self._write("f64.lt")
        self._write("local.tee $neg")
        self._write("if")
        self._indent += 1
        self._write("local.get $f")
        self._write("f64.neg")
        self._write("local.set $abs")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        self._write("local.get $f")
        self._write("local.set $abs")
        self._indent -= 1
        self._write("end")
        # int_part = trunc(abs) as i64
        self._write("local.get $abs")
        self._write("f64.trunc")
        self._write("i64.trunc_f64_u")
        self._write("local.set $int_part")
        # frac_int = (abs - trunc(abs)) * 1_000_000 as i64
        self._write("local.get $abs")
        self._write("local.get $abs")
        self._write("f64.trunc")
        self._write("f64.sub")
        self._write("f64.const 1000000")
        self._write("f64.mul")
        self._write("i64.trunc_f64_u")
        self._write("local.set $frac_int")
        # itoa(int_part) -> (int_ptr, int_len)
        self._write("local.get $int_part")
        self._write("call $itoa")
        self._write("local.set $int_len")
        self._write("local.set $int_ptr")
        # Allocate result buffer = int_len + 1 ('.') + 6 (digits) + 1 ('-')
        self._write("local.get $int_len")
        self._write("i32.const 8")
        self._write("i32.add")
        self._write("call $alloc")
        self._write("local.set $buf")
        # Write '-' if neg, increment write_pos accordingly.
        self._write("i32.const 0")
        self._write("local.set $write_pos")
        self._write("local.get $neg")
        self._write("if")
        self._indent += 1
        self._write("local.get $buf")
        self._write("i32.const 45")  # '-'
        self._write("i32.store8")
        self._write("i32.const 1")
        self._write("local.set $write_pos")
        self._indent -= 1
        self._write("end")
        # memory.copy(buf + write_pos, int_ptr, int_len)
        self._write("local.get $buf")
        self._write("local.get $write_pos")
        self._write("i32.add")
        self._write("local.get $int_ptr")
        self._write("local.get $int_len")
        self._write("memory.copy")
        # write_pos += int_len
        self._write("local.get $write_pos")
        self._write("local.get $int_len")
        self._write("i32.add")
        self._write("local.set $write_pos")
        # Write '.'
        self._write("local.get $buf")
        self._write("local.get $write_pos")
        self._write("i32.add")
        self._write("i32.const 46")  # '.'
        self._write("i32.store8")
        self._write("local.get $write_pos")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $write_pos")
        # Pre-fill 6 zeros for fractional region, then overwrite
        # right-to-left from frac_int.
        self._write("i32.const 0")
        self._write("local.set $i")
        self._block_counter += 1
        zloop = f"$ftoa{self._block_counter}_zloop"
        zexit = f"$ftoa{self._block_counter}_zexit"
        self._write(f"block {zexit}")
        self._indent += 1
        self._write(f"loop {zloop}")
        self._indent += 1
        self._write("local.get $i")
        self._write("i32.const 6")
        self._write("i32.ge_s")
        self._write(f"br_if {zexit}")
        self._write("local.get $buf")
        self._write("local.get $write_pos")
        self._write("i32.add")
        self._write("local.get $i")
        self._write("i32.add")
        self._write("i32.const 48")  # '0'
        self._write("i32.store8")
        self._write("local.get $i")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $i")
        self._write(f"br {zloop}")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")
        # Overwrite from frac_int. Each digit goes to
        # buf + write_pos + (5 - i), then frac /= 10, i++ until
        # i == 6 or frac == 0.
        self._write("i32.const 0")
        self._write("local.set $i")
        self._block_counter += 1
        dloop = f"$ftoa{self._block_counter}_dloop"
        dexit = f"$ftoa{self._block_counter}_dexit"
        self._write(f"block {dexit}")
        self._indent += 1
        self._write(f"loop {dloop}")
        self._indent += 1
        self._write("local.get $i")
        self._write("i32.const 6")
        self._write("i32.ge_s")
        self._write(f"br_if {dexit}")
        # digit = frac_int % 10
        self._write("local.get $frac_int")
        self._write("i64.const 10")
        self._write("i64.rem_u")
        self._write("i32.wrap_i64")
        self._write("local.set $digit")
        # buf + write_pos + 5 - i = '0' + digit
        self._write("local.get $buf")
        self._write("local.get $write_pos")
        self._write("i32.add")
        self._write("i32.const 5")
        self._write("local.get $i")
        self._write("i32.sub")
        self._write("i32.add")
        self._write("local.get $digit")
        self._write("i32.const 48")
        self._write("i32.add")
        self._write("i32.store8")
        # frac_int /= 10
        self._write("local.get $frac_int")
        self._write("i64.const 10")
        self._write("i64.div_u")
        self._write("local.set $frac_int")
        self._write("local.get $i")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $i")
        self._write(f"br {dloop}")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")
        # Return: ptr = buf, len = write_pos + 6
        self._write("local.get $buf")
        self._write("local.get $write_pos")
        self._write("i32.const 6")
        self._write("i32.add")
        self._indent -= 1
        self._write(")")

    def _emit_alloc_function(self) -> None:
        """Emit a bump allocator: ``$alloc(size: i32) -> i32`` that
        returns the current heap_top and advances it by the
        requested size aligned to 8 bytes. No free, no GC; this is
        the simplest correct allocator and matches Phase 6C's
        no-collections scope. A later phase that adds growth or
        compaction replaces this implementation.

        Exported so host bridges (capa:host/env etc.) can allocate
        Option / Result wrappers in linear memory before handing
        them back to the wasm code."""
        self._write('(func $alloc (export "alloc") (param $size i32) (result i32)')
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
            # FormatStr's literal parts are bare Python strings, not
            # Values; intern them here so they share the data
            # segment with everything else.
            if isinstance(instr, FormatStr):
                for part in instr.parts:
                    if isinstance(part, str) and part:
                        self._intern_string(part)
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
        keep the two tables in sync.

        Phase 6F still hand-codes a handful of WIT patterns rather
        than parsing the WIT shape generally; widening this table
        is the natural extension when new capability methods land."""
        wit = _WIT_SIGNATURES.get((cap, method))
        if wit is None:
            raise WasmEmissionError(
                f"no Wasm signature for {cap}.{method}"
            )
        if "func(msg: string)" in wit:
            return (["i32", "i32"], "")
        if "func() -> f64" in wit:
            return ([], "f64")
        if "func() -> s64" in wit or "func() -> i64" in wit:
            return ([], "i64")
        if "func(name: string) -> option<string>" in wit:
            # Single string arg (ptr, len), returns an i32 pointer
            # to an Option<String> allocated in linear memory by
            # the host. The Option uses Capa's standard layout
            # (tag@0, payload@8) so the IR's match emitter handles
            # it without further plumbing.
            return (["i32", "i32"], "i32")
        if "func(path: string) -> result<string, io-error>" in wit:
            # Same shape as Env.get above: one string arg, i32
            # pointer to a Result<String, IoError> built on the
            # heap.
            return (["i32", "i32"], "i32")
        if "func(path: string, content: string) -> result<_, io-error>" in wit:
            # Two strings in (ptr, len pairs), i32 pointer return.
            return (["i32", "i32", "i32", "i32"], "i32")
        raise WasmEmissionError(
            f"cap method {cap}.{method} has shape {wit!r} that "
            f"the Wasm emitter does not yet decode"
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
        # String return -> multi-value (i32 ptr, i32 len). Wasm 2.0
        # supports multi-value, and wasmtime exposes it to Python
        # as a tuple. Other types use the single-value result form.
        if fn.return_type == "String":
            result_str = " (result i32 i32)"
            result_ty = "string"  # any truthy non-empty value
        else:
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
        has_list = False
        has_for = False
        has_list_contains_i64 = False
        has_map = False
        has_string_method = False
        has_format_str = False

        def value_uses_variant_ctor(v: Value) -> bool:
            return v is not None and v.kind == "variant_ctor"

        def visit(instrs: list[Instr]) -> None:
            nonlocal has_match, has_variant_ctor, has_list, has_for
            nonlocal has_list_contains_i64, has_map, has_string_method
            nonlocal has_format_str
            for instr in instrs:
                if isinstance(instr, Match):
                    has_match = True
                    for arm in instr.arms:
                        visit(arm.body)
                if isinstance(instr, MakeList):
                    has_list = True
                if isinstance(instr, MakeMap):
                    has_map = True
                if isinstance(instr, For):
                    has_for = True
                    visit(instr.body)
                if isinstance(instr, FormatStr):
                    has_format_str = True
                if isinstance(instr, MethodCall):
                    recv_ty = instr.receiver.ty or ""
                    if recv_ty.startswith("Map"):
                        has_map = True
                    if recv_ty == "String":
                        has_string_method = True
                    if instr.method == "contains" and recv_ty.startswith("List"):
                        elem_ty = _element_type_of_list(recv_ty)
                        if self._size_of(elem_ty) == 8:
                            has_list_contains_i64 = True
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
        # ``_m_scrut`` / ``_m_tag`` are used by both Match and For
        # loops (they double as iter-pointer and index registers).
        # ``_alloc_tmp`` is used by variant-ctor pushes and by
        # MakeList for the data-array base pointer.
        if has_match or has_for:
            out["_m_scrut"] = "i32"
            out["_m_tag"] = "i32"
        if has_variant_ctor or has_list or has_map:
            out["_alloc_tmp"] = "i32"
        if has_list_contains_i64 or has_map or has_match:
            # has_match also needs the i64 scratch when a String
            # payload is unpacked from an Option/Result/variant.
            out["_alloc_tmp_i64"] = "i64"
        if has_map:
            # Match/For scratch locals double as Map scan helpers
            # (map_local, idx_local). Plus map-specific scratch.
            out.setdefault("_m_scrut", "i32")
            out.setdefault("_m_tag", "i32")
            out["_alloc_tmp_key_len"] = "i32"
            out["_alloc_tmp_pair"] = "i32"
            out["_alloc_tmp_newcap"] = "i32"
            out["_alloc_tmp_new_data"] = "i32"
            out["_alloc_tmp_result"] = "i32"
        if has_format_str:
            # FormatStr scratch: per-value (ptr, len) stashes plus
            # total-length / buffer / position registers.
            for i in range(8):
                out.setdefault(f"_fs_p{i}", "i32")
                out.setdefault(f"_fs_l{i}", "i32")
            out["_fs_total_len"] = "i32"
            out["_fs_buf"] = "i32"
            out["_fs_pos"] = "i32"
        if has_string_method:
            # Scratch locals for the String method handlers. All i32:
            # one pair of (ptr, len) for the receiver, one for the
            # second operand (needle / prefix / suffix), plus index,
            # start, end, new_ptr, new_len, byte registers.
            for name in (
                "_str_a_ptr", "_str_a_len",
                "_str_b_ptr", "_str_b_len",
                "_str_i", "_str_start", "_str_end",
                "_str_new_ptr", "_str_new_len",
                "_str_byte",
            ):
                out.setdefault(name, "i32")
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
            recv_ty = instr.receiver.ty or ""
            if recv_ty.startswith("List"):
                self._emit_list_method_call(instr)
                return
            if recv_ty.startswith("Map"):
                self._emit_map_method_call(instr)
                return
            if recv_ty == "String":
                self._emit_string_method_call(instr)
                return
            raise WasmEmissionError(
                f"MethodCall on receiver of type {recv_ty!r} "
                f"(method {instr.method!r}); Set methods land in "
                f"a later 6D sub-phase"
            )
        if isinstance(instr, MakeStruct):
            self._emit_make_struct(instr)
            return
        if isinstance(instr, MakeList):
            self._emit_make_list(instr)
            return
        if isinstance(instr, MakeMap):
            self._emit_make_map(instr)
            return
        if isinstance(instr, FieldAccess):
            self._emit_field_access(instr)
            return
        if isinstance(instr, Index):
            self._emit_index(instr)
            return
        if isinstance(instr, For):
            self._emit_for(instr)
            return
        if isinstance(instr, Match):
            self._emit_match(instr)
            return
        if isinstance(instr, FormatStr):
            self._emit_format_str(instr)
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
                # String returns push (ptr, len) as a pair so the
                # multi-value ``(result i32 i32)`` signature is
                # satisfied; other types push a single value.
                if instr.value.ty == "String":
                    self._push_string_value_as_ptr_len(instr.value)
                else:
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
        # Dispatch on operand type: Float operands use f64.* opcodes,
        # everything else stays on the i64 / i32 path.
        is_float = instr.left.ty == "Float" or instr.right.ty == "Float"
        if op in _INT_BINOP and is_float:
            if op == "%":
                raise WasmEmissionError(
                    "Float modulo not supported at the Wasm level"
                )
            self._push_value(instr.left)
            self._push_value(instr.right)
            self._write(_FLOAT_BINOP[op])
            self._write(f"local.set ${instr.dst}")
            return
        if op in _INT_BINOP:
            self._push_value(instr.left)
            self._push_value(instr.right)
            self._write(_INT_BINOP[op])
            self._write(f"local.set ${instr.dst}")
            return
        if op in _CMP_BINOP and is_float:
            self._push_value(instr.left)
            self._push_value(instr.right)
            self._write(_FLOAT_CMP_BINOP[op])
            self._write(f"local.set ${instr.dst}")
            return
        if op in _CMP_BINOP:
            self._push_value(instr.left)
            self._push_value(instr.right)
            self._write(_CMP_BINOP[op])
            self._write(f"local.set ${instr.dst}")
            return
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
        # Store each payload at its offset. Phase 7B+ uses uniform
        # 8-byte payload slots for Option / Result. The arg's type
        # determines whether we store directly (Int -> i64) or
        # pack/extend:
        # - String: pack (ptr, len) into i64 = ptr | (len << 32)
        # - Pointer-shaped (struct, sum, list, map): extend i32
        #   to i64 to fit the uniform slot
        # - Bool: extend i32 to i64
        # - Int / Float: store as-is at the i64 slot
        for arg, (offset, size, _ty) in zip(instr.args, payload_layouts):
            self._write(f"local.get ${instr.dst}")
            if size == 8 and arg.ty == "String":
                # Pack (ptr, len) into i64.
                self._push_string_value_as_ptr_len(arg)
                # Stack: [..., dst, ptr, len]
                self._write("i64.extend_i32_u")  # len -> i64
                self._write("i64.const 32")
                self._write("i64.shl")
                # Stack: [..., dst, ptr, (len << 32)]
                self._write(f"local.tee $_alloc_tmp_i64")
                # Drop and re-fetch with ptr; simpler approach:
                # save the high part, then OR with ptr.
                self._write("drop")
                self._write("i64.extend_i32_u")  # ptr -> i64
                self._write("local.get $_alloc_tmp_i64")
                self._write("i64.or")
                self._write(f"i64.store offset={offset}")
                continue
            if size == 8 and arg.ty == "Bool":
                self._push_value(arg)
                self._write("i64.extend_i32_u")
                self._write(f"i64.store offset={offset}")
                continue
            if size == 8 and (
                arg.ty.split("<", 1)[0] in self._struct_layouts
                or arg.ty.split("<", 1)[0] in self._sum_layouts
                or arg.ty.startswith(("List", "Map", "Set"))
            ):
                # Pointer payload: extend i32 to i64.
                self._push_value(arg)
                self._write("i64.extend_i32_u")
                self._write(f"i64.store offset={offset}")
                continue
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
        layout offset and emit the appropriate load opcode.

        String fields expand to two i32 loads (offset, offset+4)
        into the destination String's ``${dst}_ptr`` and
        ``${dst}_len`` locals -- mirroring how String params and
        locals carry their (ptr, len) pair through the emitter."""
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
        offset, size, field_ty = f_info
        if field_ty == "String":
            # Two i32 loads: ptr@offset, len@offset+4 -> dst's pair.
            self._push_value(instr.receiver)
            self._write(f"i32.load offset={offset}")
            self._write(f"local.set ${instr.dst}_ptr")
            self._push_value(instr.receiver)
            self._write(f"i32.load offset={offset + 4}")
            self._write(f"local.set ${instr.dst}_len")
            return
        self._push_value(instr.receiver)
        self._write(f"{_load_op_for_size(size)} offset={offset}")
        self._write(f"local.set ${instr.dst}")

    # ----- string methods ---------------------------------------

    def _emit_string_method_call(self, instr: MethodCall) -> None:
        """Dispatch a method on a String receiver. Strings are
        (ptr, len) pairs throughout; this method's job is to read
        from the receiver, optionally allocate a fresh buffer, and
        bind the result to ``instr.dst``.

        Methods supported in Phase 6D-4: length, is_empty,
        contains, starts_with, ends_with, substring, to_upper,
        to_lower, trim, trim_start, trim_end, char_at, index_of.
        ``split`` and ``replace`` are deferred until List<String>
        support arrives in a later sub-phase."""
        method = instr.method
        recv = instr.receiver
        dst = instr.dst

        # Push (recv_ptr, recv_len) onto the operand stack twice
        # for any method that compares against a needle; the two
        # copies live in scratch locals so we can read multiple
        # times without re-evaluating the receiver.
        if method == "length":
            self._push_string_len_only(recv)
            self._write("i64.extend_i32_s")
            if dst is not None:
                self._write(f"local.set ${dst}")
            return
        if method == "is_empty":
            self._push_string_len_only(recv)
            self._write("i32.eqz")
            if dst is not None:
                self._write(f"local.set ${dst}")
            return
        if method == "contains":
            self._emit_string_contains(recv, instr.args[0])
            if dst is not None:
                self._write(f"local.set ${dst}")
            return
        if method == "starts_with":
            self._emit_string_starts_with(recv, instr.args[0])
            if dst is not None:
                self._write(f"local.set ${dst}")
            return
        if method == "ends_with":
            self._emit_string_ends_with(recv, instr.args[0])
            if dst is not None:
                self._write(f"local.set ${dst}")
            return
        if method == "substring":
            self._emit_string_substring(recv, instr.args[0], instr.args[1], dst)
            return
        if method == "to_upper":
            self._emit_string_case_transform(recv, dst, upper=True)
            return
        if method == "to_lower":
            self._emit_string_case_transform(recv, dst, upper=False)
            return
        if method == "trim":
            self._emit_string_trim(recv, dst, left=True, right=True)
            return
        if method == "trim_start":
            self._emit_string_trim(recv, dst, left=True, right=False)
            return
        if method == "trim_end":
            self._emit_string_trim(recv, dst, left=False, right=True)
            return
        raise WasmEmissionError(
            f"Phase 6D-4: String method {method!r} not supported "
            f"(split / replace / char_at / index_of land later)"
        )

    def _push_string_len_only(self, v: Value) -> None:
        """Push just the length component (i32) of a String value
        onto the operand stack. Used by length / is_empty handlers
        that do not need the pointer."""
        if v.kind == "lit_str":
            _offset, length = self._intern_string(v.literal)
            self._write(f"i32.const {length}")
            return
        if v.kind in ("local", "param"):
            self._write(f"local.get ${v.name}_len")
            return
        raise WasmEmissionError(
            f"cannot push string length of Value kind {v.kind!r}"
        )

    def _set_string_dst(self, dst: str) -> None:
        """Pop (ptr, len) from the operand stack into the dst
        String's two locals. Used by every method that returns a
        String. The push order is (ptr, len) so the consumer sets
        len first (top of stack), then ptr."""
        self._write(f"local.set ${dst}_len")
        self._write(f"local.set ${dst}_ptr")

    def _emit_string_contains(self, recv: Value, needle: Value) -> None:
        """Linear scan: ``recv.contains(needle)``. For each position
        i in [0, recv.len - needle.len], check if needle equals
        recv[i:i+needle.len]; return 1 on first match, 0 if
        exhausted. Empty needle is treated as always-found."""
        # Save (ptr, len) for both receiver and needle.
        self._push_string_value_as_ptr_len(recv)
        self._write("local.set $_str_a_len")
        self._write("local.set $_str_a_ptr")
        self._push_string_value_as_ptr_len(needle)
        self._write("local.set $_str_b_len")
        self._write("local.set $_str_b_ptr")
        # i = 0; while i + needle.len <= recv.len, str_eq the slice.
        self._write("i32.const 0")
        self._write("local.set $_str_i")
        self._block_counter += 1
        loop = f"$Sc{self._block_counter}_loop"
        exit_ = f"$Sc{self._block_counter}_exit"
        self._write(f"block {exit_} (result i32)")
        self._indent += 1
        self._write(f"loop {loop}")
        self._indent += 1
        # Guard: i + needle.len > recv.len → done with 0.
        self._write("local.get $_str_i")
        self._write("local.get $_str_b_len")
        self._write("i32.add")
        self._write("local.get $_str_a_len")
        self._write("i32.gt_s")
        self._write("if")
        self._indent += 1
        self._write("i32.const 0")
        self._write(f"br {exit_}")
        self._indent -= 1
        self._write("end")
        # str_eq(recv.ptr + i, needle.len, needle.ptr, needle.len)
        self._write("local.get $_str_a_ptr")
        self._write("local.get $_str_i")
        self._write("i32.add")
        self._write("local.get $_str_b_len")
        self._write("local.get $_str_b_ptr")
        self._write("local.get $_str_b_len")
        self._write("call $str_eq")
        self._write("if")
        self._indent += 1
        self._write("i32.const 1")
        self._write(f"br {exit_}")
        self._indent -= 1
        self._write("end")
        # i++; continue.
        self._write("local.get $_str_i")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $_str_i")
        self._write(f"br {loop}")
        self._indent -= 1
        self._write("end")
        self._write("unreachable")
        self._indent -= 1
        self._write("end")

    def _emit_string_starts_with(self, recv: Value, prefix: Value) -> None:
        """``recv.starts_with(prefix)``: false if prefix.len >
        recv.len, else compare the first prefix.len bytes."""
        self._push_string_value_as_ptr_len(prefix)
        self._write("local.set $_str_b_len")
        self._write("local.set $_str_b_ptr")
        self._push_string_value_as_ptr_len(recv)
        self._write("local.set $_str_a_len")
        self._write("local.set $_str_a_ptr")
        # if prefix.len > recv.len: 0
        self._block_counter += 1
        exit_ = f"$Ss{self._block_counter}_exit"
        self._write(f"block {exit_} (result i32)")
        self._indent += 1
        self._write("local.get $_str_b_len")
        self._write("local.get $_str_a_len")
        self._write("i32.gt_s")
        self._write("if")
        self._indent += 1
        self._write("i32.const 0")
        self._write(f"br {exit_}")
        self._indent -= 1
        self._write("end")
        # str_eq(recv.ptr, prefix.len, prefix.ptr, prefix.len)
        self._write("local.get $_str_a_ptr")
        self._write("local.get $_str_b_len")
        self._write("local.get $_str_b_ptr")
        self._write("local.get $_str_b_len")
        self._write("call $str_eq")
        self._indent -= 1
        self._write("end")

    def _emit_string_ends_with(self, recv: Value, suffix: Value) -> None:
        """``recv.ends_with(suffix)``: false if suffix.len >
        recv.len, else compare the last suffix.len bytes."""
        self._push_string_value_as_ptr_len(suffix)
        self._write("local.set $_str_b_len")
        self._write("local.set $_str_b_ptr")
        self._push_string_value_as_ptr_len(recv)
        self._write("local.set $_str_a_len")
        self._write("local.set $_str_a_ptr")
        self._block_counter += 1
        exit_ = f"$Se{self._block_counter}_exit"
        self._write(f"block {exit_} (result i32)")
        self._indent += 1
        # if suffix.len > recv.len: 0
        self._write("local.get $_str_b_len")
        self._write("local.get $_str_a_len")
        self._write("i32.gt_s")
        self._write("if")
        self._indent += 1
        self._write("i32.const 0")
        self._write(f"br {exit_}")
        self._indent -= 1
        self._write("end")
        # offset = recv.len - suffix.len
        # str_eq(recv.ptr + offset, suffix.len, suffix.ptr, suffix.len)
        self._write("local.get $_str_a_ptr")
        self._write("local.get $_str_a_len")
        self._write("local.get $_str_b_len")
        self._write("i32.sub")
        self._write("i32.add")
        self._write("local.get $_str_b_len")
        self._write("local.get $_str_b_ptr")
        self._write("local.get $_str_b_len")
        self._write("call $str_eq")
        self._indent -= 1
        self._write("end")

    def _emit_string_substring(
        self, recv: Value, start: Value, end: Value, dst: Optional[str],
    ) -> None:
        """``recv.substring(start, end)``: allocate ``end-start``
        bytes, memory.copy from ``recv.ptr + start``, leave the
        result in dst's (ptr, len) locals."""
        if dst is None:
            return
        # Save receiver ptr + len.
        self._push_string_value_as_ptr_len(recv)
        self._write("local.set $_str_a_len")
        self._write("local.set $_str_a_ptr")
        # Save start and end as i32 (the IR pushes Int as i64;
        # narrow with i32.wrap_i64).
        self._push_value(start)
        self._write("i32.wrap_i64")
        self._write("local.set $_str_start")
        self._push_value(end)
        self._write("i32.wrap_i64")
        self._write("local.set $_str_end")
        # new_len = end - start
        self._write("local.get $_str_end")
        self._write("local.get $_str_start")
        self._write("i32.sub")
        self._write("local.tee $_str_new_len")
        # alloc(new_len)
        self._write("call $alloc")
        self._write("local.tee $_str_new_ptr")
        # memory.copy(dst=new_ptr, src=recv.ptr + start, n=new_len)
        self._write("local.get $_str_a_ptr")
        self._write("local.get $_str_start")
        self._write("i32.add")
        self._write("local.get $_str_new_len")
        self._write("memory.copy")
        # Bind dst.
        self._write("local.get $_str_new_ptr")
        self._write("local.get $_str_new_len")
        self._set_string_dst(dst)

    def _emit_string_case_transform(
        self, recv: Value, dst: Optional[str], upper: bool,
    ) -> None:
        """``recv.to_upper()`` / ``recv.to_lower()`` allocate a
        fresh ``recv.len`` buffer and copy each byte with ASCII
        case folding. Non-ASCII bytes pass through unchanged --
        Phase 6D-4's "ASCII-only" caveat that the legacy Python
        runtime does not have (it uses Python's full Unicode
        ``.upper()``); a UTF-8-aware version arrives when the
        stdlib grows a real character iterator."""
        if dst is None:
            return
        self._push_string_value_as_ptr_len(recv)
        self._write("local.set $_str_a_len")
        self._write("local.set $_str_a_ptr")
        # Allocate new buffer of the same length.
        self._write("local.get $_str_a_len")
        self._write("call $alloc")
        self._write("local.set $_str_new_ptr")
        # i = 0; while i < len, transform byte.
        self._write("i32.const 0")
        self._write("local.set $_str_i")
        self._block_counter += 1
        loop = f"$Sx{self._block_counter}_loop"
        exit_ = f"$Sx{self._block_counter}_exit"
        self._write(f"block {exit_}")
        self._indent += 1
        self._write(f"loop {loop}")
        self._indent += 1
        # Guard: i >= len → done.
        self._write("local.get $_str_i")
        self._write("local.get $_str_a_len")
        self._write("i32.ge_s")
        self._write(f"br_if {exit_}")
        # Load byte.
        self._write("local.get $_str_a_ptr")
        self._write("local.get $_str_i")
        self._write("i32.add")
        self._write("i32.load8_u")
        # Case transform.
        if upper:
            # if b >= 'a' (0x61) && b <= 'z' (0x7a), subtract 32.
            self._write("local.tee $_str_byte")
            self._write("i32.const 97")
            self._write("i32.ge_u")
            self._write("local.get $_str_byte")
            self._write("i32.const 122")
            self._write("i32.le_u")
            self._write("i32.and")
            self._write("if")
            self._indent += 1
            self._write("local.get $_str_byte")
            self._write("i32.const 32")
            self._write("i32.sub")
            self._write("local.set $_str_byte")
            self._indent -= 1
            self._write("end")
        else:
            # if b >= 'A' (0x41) && b <= 'Z' (0x5a), add 32.
            self._write("local.tee $_str_byte")
            self._write("i32.const 65")
            self._write("i32.ge_u")
            self._write("local.get $_str_byte")
            self._write("i32.const 90")
            self._write("i32.le_u")
            self._write("i32.and")
            self._write("if")
            self._indent += 1
            self._write("local.get $_str_byte")
            self._write("i32.const 32")
            self._write("i32.add")
            self._write("local.set $_str_byte")
            self._indent -= 1
            self._write("end")
        # Store the (possibly transformed) byte to new_ptr + i.
        self._write("local.get $_str_new_ptr")
        self._write("local.get $_str_i")
        self._write("i32.add")
        self._write("local.get $_str_byte")
        self._write("i32.store8")
        # i++.
        self._write("local.get $_str_i")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $_str_i")
        self._write(f"br {loop}")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")
        # Bind dst.
        self._write("local.get $_str_new_ptr")
        self._write("local.get $_str_a_len")
        self._set_string_dst(dst)

    def _emit_string_trim(
        self, recv: Value, dst: Optional[str], left: bool, right: bool,
    ) -> None:
        """``recv.trim()`` returns a (ptr, len) view into the
        original buffer with leading/trailing ASCII whitespace
        skipped. No allocation; trim is purely a bounds adjustment.
        Whitespace: space, tab, newline, carriage return."""
        if dst is None:
            return
        self._push_string_value_as_ptr_len(recv)
        self._write("local.set $_str_a_len")
        self._write("local.set $_str_a_ptr")
        # start = 0; end = recv.len.
        self._write("i32.const 0")
        self._write("local.set $_str_start")
        self._write("local.get $_str_a_len")
        self._write("local.set $_str_end")
        if left:
            self._block_counter += 1
            lloop = f"$St{self._block_counter}_lloop"
            lexit = f"$St{self._block_counter}_lexit"
            self._write(f"block {lexit}")
            self._indent += 1
            self._write(f"loop {lloop}")
            self._indent += 1
            # if start >= end: stop trimming.
            self._write("local.get $_str_start")
            self._write("local.get $_str_end")
            self._write("i32.ge_s")
            self._write(f"br_if {lexit}")
            # if byte at start is whitespace, advance.
            self._write("local.get $_str_a_ptr")
            self._write("local.get $_str_start")
            self._write("i32.add")
            self._write("i32.load8_u")
            self._emit_byte_is_whitespace()
            self._write("i32.eqz")
            self._write(f"br_if {lexit}")
            self._write("local.get $_str_start")
            self._write("i32.const 1")
            self._write("i32.add")
            self._write("local.set $_str_start")
            self._write(f"br {lloop}")
            self._indent -= 1
            self._write("end")
            self._indent -= 1
            self._write("end")
        if right:
            self._block_counter += 1
            rloop = f"$St{self._block_counter}_rloop"
            rexit = f"$St{self._block_counter}_rexit"
            self._write(f"block {rexit}")
            self._indent += 1
            self._write(f"loop {rloop}")
            self._indent += 1
            self._write("local.get $_str_end")
            self._write("local.get $_str_start")
            self._write("i32.le_s")
            self._write(f"br_if {rexit}")
            # Look at byte at end-1.
            self._write("local.get $_str_a_ptr")
            self._write("local.get $_str_end")
            self._write("i32.const 1")
            self._write("i32.sub")
            self._write("i32.add")
            self._write("i32.load8_u")
            self._emit_byte_is_whitespace()
            self._write("i32.eqz")
            self._write(f"br_if {rexit}")
            self._write("local.get $_str_end")
            self._write("i32.const 1")
            self._write("i32.sub")
            self._write("local.set $_str_end")
            self._write(f"br {rloop}")
            self._indent -= 1
            self._write("end")
            self._indent -= 1
            self._write("end")
        # Result: (recv.ptr + start, end - start)
        self._write("local.get $_str_a_ptr")
        self._write("local.get $_str_start")
        self._write("i32.add")
        self._write("local.get $_str_end")
        self._write("local.get $_str_start")
        self._write("i32.sub")
        self._set_string_dst(dst)

    def _emit_byte_is_whitespace(self) -> None:
        """Consume an i32 byte on the stack; push i32 1 if it is
        ASCII whitespace (space, tab, LF, CR), else 0. Used by
        trim methods."""
        # Save the byte into $_str_byte so we can compare against
        # each whitespace character without re-reading from memory.
        self._write("local.set $_str_byte")
        self._write("local.get $_str_byte")
        self._write("i32.const 32")        # space
        self._write("i32.eq")
        self._write("local.get $_str_byte")
        self._write("i32.const 9")         # tab
        self._write("i32.eq")
        self._write("i32.or")
        self._write("local.get $_str_byte")
        self._write("i32.const 10")        # LF
        self._write("i32.eq")
        self._write("i32.or")
        self._write("local.get $_str_byte")
        self._write("i32.const 13")        # CR
        self._write("i32.eq")
        self._write("i32.or")

    # ----- maps -------------------------------------------------

    def _emit_make_map(self, instr: MakeMap) -> None:
        """Allocate a Map<String, V> header (16 bytes) + an initial
        data array of 8 pair slots (8 * 16 = 128 bytes). Layout
        matches Phase 6D-2 List for the header; the data slots are
        (key_ptr, key_len, value) triples each 16 bytes wide."""
        initial_cap = 8
        self._write(f"i32.const {_MAP_HEADER_SIZE}")
        self._write("call $alloc")
        self._write(f"local.set ${instr.dst}")
        self._write(f"local.get ${instr.dst}")
        self._write("i32.const 0")
        self._write(f"i32.store offset={_MAP_LEN_OFFSET}")
        self._write(f"local.get ${instr.dst}")
        self._write(f"i32.const {initial_cap}")
        self._write(f"i32.store offset={_MAP_CAP_OFFSET}")
        # Data array allocation. Save the freshly-allocated pointer
        # to ``$_alloc_tmp`` so we can both write it into the header
        # and reuse it for any later per-pair element initialisation
        # (currently none for an empty map). The store consumes
        # (addr=header_ptr, value=data_ptr): wasm pops value first,
        # then addr, so the push order must be addr-then-value.
        self._write(f"i32.const {initial_cap * _MAP_PAIR_SIZE}")
        self._write("call $alloc")
        self._write("local.set $_alloc_tmp")
        self._write(f"local.get ${instr.dst}")
        self._write("local.get $_alloc_tmp")
        self._write(f"i32.store offset={_MAP_DATA_OFFSET}")

    def _emit_map_method_call(self, instr: MethodCall) -> None:
        """Dispatch Map<String, V> methods. Phase 6D-3 supports:
        - length / is_empty: read header
        - set(k, v): linear scan, overwrite-or-append
        - contains_key(k): linear scan -> Bool
        - get(k): linear scan -> Option<V>

        Other methods (keys, values, pairs, ...) wait until List<T>
        can hold structured element types (tuples, strings) in 6D-4."""
        recv = instr.receiver
        method = instr.method
        recv_ty = recv.ty
        value_ty = _map_value_type(recv_ty)

        if method == "length":
            self._push_value(recv)
            self._write(f"i32.load offset={_MAP_LEN_OFFSET}")
            self._write("i64.extend_i32_s")
            if instr.dst is not None:
                self._write(f"local.set ${instr.dst}")
            return
        if method == "is_empty":
            self._push_value(recv)
            self._write(f"i32.load offset={_MAP_LEN_OFFSET}")
            self._write("i32.eqz")
            if instr.dst is not None:
                self._write(f"local.set ${instr.dst}")
            return
        if method == "set":
            self._emit_map_set(recv, instr.args[0], instr.args[1], value_ty)
            return
        if method == "contains_key":
            self._emit_map_contains_key(recv, instr.args[0])
            if instr.dst is not None:
                self._write(f"local.set ${instr.dst}")
            return
        if method == "get":
            self._emit_map_get(recv, instr.args[0], value_ty)
            if instr.dst is not None:
                self._write(f"local.set ${instr.dst}")
            return
        raise WasmEmissionError(
            f"Phase 6D-3: Map method {method!r} not yet supported "
            f"(keys / values / pairs need List of pairs, 6D-4+)"
        )

    def _push_string_value_as_ptr_len(self, v: Value) -> None:
        """Push a String value as two consecutive i32s (ptr, len).
        Used for map keys and any other site that needs to flatten
        a String onto the operand stack."""
        if v.kind == "lit_str":
            offset, length = self._intern_string(v.literal)
            self._write(f"i32.const {offset}")
            self._write(f"i32.const {length}")
            return
        if v.kind == "local":
            self._write(f"local.get ${v.name}_ptr")
            self._write(f"local.get ${v.name}_len")
            return
        if v.kind == "param":
            self._write(f"local.get ${v.name}_ptr")
            self._write(f"local.get ${v.name}_len")
            return
        raise WasmEmissionError(
            f"cannot push string Value of kind {v.kind!r} as (ptr, len)"
        )

    def _push_map_value_as_i64(self, v: Value, value_ty: str) -> None:
        """Push a Map value onto the stack as a 64-bit packed slot.
        Int values use i64 directly; Bool / pointers are extended
        to i64 from their i32 wire form. Phase 6D-3 does not yet
        support String values (would need to pack ptr+len into 64
        bits or widen the slot)."""
        if value_ty == "Int":
            self._push_value(v)
            return
        if value_ty == "Bool":
            self._push_value(v)
            self._write("i64.extend_i32_s")
            return
        if value_ty == "String":
            raise WasmEmissionError(
                "Phase 6D-3: Map<String, String> not yet supported; "
                "widening the value slot to 16 bytes lands in 6D-4"
            )
        # Pointer-shaped types (struct, sum, list, map). Extend i32
        # to i64 to fit the uniform value slot.
        if value_ty.split("<", 1)[0] in self._struct_layouts \
                or value_ty.split("<", 1)[0] in self._sum_layouts \
                or value_ty.startswith(("List", "Map", "Set")):
            self._push_value(v)
            self._write("i64.extend_i32_u")
            return
        raise WasmEmissionError(
            f"Phase 6D-3: Map value type {value_ty!r} not supported"
        )

    def _emit_map_set(
        self, recv: Value, k: Value, v: Value, value_ty: str,
    ) -> None:
        """Linear-scan ``m.set(k, v)``: replace value at existing
        key or append a new pair, growing the data array if at
        cap. Uses ``$_m_scrut`` for the map pointer, ``$_m_tag``
        for the iteration index, and ``$_alloc_tmp`` / ``$_alloc_tmp_i64``
        for the new value buffer."""
        map_local = "_m_scrut"
        idx_local = "_m_tag"
        key_ptr_local = "_alloc_tmp"
        key_len_local = "_alloc_tmp_key_len"
        value_local = "_alloc_tmp_i64"

        # Stash receiver and key into scratch locals.
        self._push_value(recv)
        self._write(f"local.set ${map_local}")
        self._push_string_value_as_ptr_len(k)
        self._write(f"local.set ${key_len_local}")
        self._write(f"local.set ${key_ptr_local}")
        # Stash the value (packed to i64).
        self._push_map_value_as_i64(v, value_ty)
        self._write(f"local.set ${value_local}")
        # Two-level block: $set_done wraps the whole operation;
        # $scan_exit lets the inner scan terminate when the key is
        # not found. The overwrite branch ``br $set_done`` skips
        # the append fallback; the scan-not-found path falls
        # through to the append code below.
        self._write("i32.const 0")
        self._write(f"local.set ${idx_local}")
        self._block_counter += 1
        set_done = f"$Mset{self._block_counter}_done"
        scan_loop = f"$Mset{self._block_counter}_loop"
        scan_exit = f"$Mset{self._block_counter}_exit"
        self._write(f"block {set_done}")
        self._indent += 1
        self._write(f"block {scan_exit}")
        self._indent += 1
        self._write(f"loop {scan_loop}")
        self._indent += 1
        # Guard: idx >= len → exit scan, fall through to append.
        self._write(f"local.get ${idx_local}")
        self._write(f"local.get ${map_local}")
        self._write(f"i32.load offset={_MAP_LEN_OFFSET}")
        self._write("i32.ge_s")
        self._write(f"br_if {scan_exit}")
        # pair_base = data_ptr + idx * 16
        self._write(f"local.get ${map_local}")
        self._write(f"i32.load offset={_MAP_DATA_OFFSET}")
        self._write(f"local.get ${idx_local}")
        self._write(f"i32.const {_MAP_PAIR_SIZE}")
        self._write("i32.mul")
        self._write("i32.add")
        self._write(f"local.tee $_alloc_tmp_pair")
        # Compare keys: $str_eq(pair.key_ptr, pair.key_len, key_ptr, key_len)
        self._write(f"i32.load offset={_MAP_PAIR_KEY_PTR_OFFSET}")
        self._write(f"local.get $_alloc_tmp_pair")
        self._write(f"i32.load offset={_MAP_PAIR_KEY_LEN_OFFSET}")
        self._write(f"local.get ${key_ptr_local}")
        self._write(f"local.get ${key_len_local}")
        self._write("call $str_eq")
        self._write("if")
        self._indent += 1
        # Match: overwrite value and exit (skip append).
        self._write(f"local.get $_alloc_tmp_pair")
        self._write(f"local.get ${value_local}")
        self._write(f"i64.store offset={_MAP_PAIR_VALUE_OFFSET}")
        self._write(f"br {set_done}")
        self._indent -= 1
        self._write("end")
        # idx++ and loop.
        self._write(f"local.get ${idx_local}")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write(f"local.set ${idx_local}")
        self._write(f"br {scan_loop}")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")

        # Append branch: idx == len (reached via $scan_exit).
        # Check capacity; grow if needed.
        self._write(f"local.get ${map_local}")
        self._write(f"i32.load offset={_MAP_LEN_OFFSET}")
        self._write(f"local.get ${map_local}")
        self._write(f"i32.load offset={_MAP_CAP_OFFSET}")
        self._write("i32.ge_s")
        self._write("if")
        self._indent += 1
        self._emit_map_grow(map_local)
        self._indent -= 1
        self._write("end")
        # pair_base = data_ptr + len * 16
        self._write(f"local.get ${map_local}")
        self._write(f"i32.load offset={_MAP_DATA_OFFSET}")
        self._write(f"local.get ${map_local}")
        self._write(f"i32.load offset={_MAP_LEN_OFFSET}")
        self._write(f"i32.const {_MAP_PAIR_SIZE}")
        self._write("i32.mul")
        self._write("i32.add")
        self._write(f"local.tee $_alloc_tmp_pair")
        # Store key_ptr, key_len, value.
        self._write(f"local.get ${key_ptr_local}")
        self._write(f"i32.store offset={_MAP_PAIR_KEY_PTR_OFFSET}")
        self._write(f"local.get $_alloc_tmp_pair")
        self._write(f"local.get ${key_len_local}")
        self._write(f"i32.store offset={_MAP_PAIR_KEY_LEN_OFFSET}")
        self._write(f"local.get $_alloc_tmp_pair")
        self._write(f"local.get ${value_local}")
        self._write(f"i64.store offset={_MAP_PAIR_VALUE_OFFSET}")
        # Increment len.
        self._write(f"local.get ${map_local}")
        self._write(f"local.get ${map_local}")
        self._write(f"i32.load offset={_MAP_LEN_OFFSET}")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write(f"i32.store offset={_MAP_LEN_OFFSET}")
        # Close the outer $set_done block.
        self._indent -= 1
        self._write("end")

    def _emit_map_grow(self, map_local: str) -> None:
        """Grow the map's data array by doubling capacity. Uses
        ``memory.copy`` to move existing pairs into the fresh
        allocation. The new cap is written to the header along
        with the new data_ptr.

        Uses ``$_alloc_tmp_new_data`` for the freshly-allocated
        data array so the caller's other ``$_alloc_tmp_*`` slots
        (e.g. the key_ptr being inserted) are not clobbered."""
        # new_cap = cap * 2 (min 8 if cap was 0).
        self._write(f"local.get ${map_local}")
        self._write(f"i32.load offset={_MAP_CAP_OFFSET}")
        self._write("i32.const 2")
        self._write("i32.mul")
        self._write("local.tee $_alloc_tmp_newcap")
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        self._write("i32.const 8")
        self._write("local.set $_alloc_tmp_newcap")
        self._indent -= 1
        self._write("end")
        # Allocate new data area.
        self._write("local.get $_alloc_tmp_newcap")
        self._write(f"i32.const {_MAP_PAIR_SIZE}")
        self._write("i32.mul")
        self._write("call $alloc")
        self._write("local.tee $_alloc_tmp_new_data")
        # memory.copy(dst=new_data, src=old_data, n=len*pair_size).
        self._write(f"local.get ${map_local}")
        self._write(f"i32.load offset={_MAP_DATA_OFFSET}")
        self._write(f"local.get ${map_local}")
        self._write(f"i32.load offset={_MAP_LEN_OFFSET}")
        self._write(f"i32.const {_MAP_PAIR_SIZE}")
        self._write("i32.mul")
        self._write("memory.copy")
        # Update header.
        self._write(f"local.get ${map_local}")
        self._write("local.get $_alloc_tmp_new_data")
        self._write(f"i32.store offset={_MAP_DATA_OFFSET}")
        self._write(f"local.get ${map_local}")
        self._write("local.get $_alloc_tmp_newcap")
        self._write(f"i32.store offset={_MAP_CAP_OFFSET}")

    def _emit_map_contains_key(self, recv: Value, k: Value) -> None:
        """Linear-scan ``m.contains_key(k)``. Leaves an i32 (0/1)
        on the stack."""
        map_local = "_m_scrut"
        idx_local = "_m_tag"
        key_ptr_local = "_alloc_tmp"
        key_len_local = "_alloc_tmp_key_len"
        self._push_value(recv)
        self._write(f"local.set ${map_local}")
        self._push_string_value_as_ptr_len(k)
        self._write(f"local.set ${key_len_local}")
        self._write(f"local.set ${key_ptr_local}")
        self._write("i32.const 0")
        self._write(f"local.set ${idx_local}")
        self._block_counter += 1
        loop = f"$Mck{self._block_counter}_loop"
        exit_ = f"$Mck{self._block_counter}_exit"
        self._write(f"block {exit_} (result i32)")
        self._indent += 1
        self._write(f"loop {loop}")
        self._indent += 1
        # Guard.
        self._write(f"local.get ${idx_local}")
        self._write(f"local.get ${map_local}")
        self._write(f"i32.load offset={_MAP_LEN_OFFSET}")
        self._write("i32.ge_s")
        self._write("if")
        self._indent += 1
        self._write("i32.const 0")
        self._write(f"br {exit_}")
        self._indent -= 1
        self._write("end")
        # Compare key.
        self._write(f"local.get ${map_local}")
        self._write(f"i32.load offset={_MAP_DATA_OFFSET}")
        self._write(f"local.get ${idx_local}")
        self._write(f"i32.const {_MAP_PAIR_SIZE}")
        self._write("i32.mul")
        self._write("i32.add")
        self._write(f"local.tee $_alloc_tmp_pair")
        self._write(f"i32.load offset={_MAP_PAIR_KEY_PTR_OFFSET}")
        self._write(f"local.get $_alloc_tmp_pair")
        self._write(f"i32.load offset={_MAP_PAIR_KEY_LEN_OFFSET}")
        self._write(f"local.get ${key_ptr_local}")
        self._write(f"local.get ${key_len_local}")
        self._write("call $str_eq")
        self._write("if")
        self._indent += 1
        self._write("i32.const 1")
        self._write(f"br {exit_}")
        self._indent -= 1
        self._write("end")
        # idx++, loop.
        self._write(f"local.get ${idx_local}")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write(f"local.set ${idx_local}")
        self._write(f"br {loop}")
        self._indent -= 1
        self._write("end")
        # Verifier-satisfying terminator: the loop never falls
        # through (it either br's to $exit_ with a value or br's
        # back to itself), but Wasm's static checker cannot prove
        # that, so we mark fall-through as unreachable.
        self._write("unreachable")
        self._indent -= 1
        self._write("end")

    def _emit_map_get(self, recv: Value, k: Value, value_ty: str) -> None:
        """Linear-scan ``m.get(k)`` returning an Option<V> pointer.
        Allocates a fresh 16-byte Option<V> with tag=Some + value
        on hit, or tag=None on miss."""
        map_local = "_m_scrut"
        idx_local = "_m_tag"
        key_ptr_local = "_alloc_tmp"
        key_len_local = "_alloc_tmp_key_len"
        result_local = "_alloc_tmp_result"
        self._push_value(recv)
        self._write(f"local.set ${map_local}")
        self._push_string_value_as_ptr_len(k)
        self._write(f"local.set ${key_len_local}")
        self._write(f"local.set ${key_ptr_local}")
        # Alloc the Option result up front; we will fill the tag
        # (and maybe value) below depending on hit/miss.
        self._write(f"i32.const {_OPTION_LAYOUT['size']}")
        self._write("call $alloc")
        self._write(f"local.set ${result_local}")
        self._write("i32.const 0")
        self._write(f"local.set ${idx_local}")
        self._block_counter += 1
        loop = f"$Mget{self._block_counter}_loop"
        exit_ = f"$Mget{self._block_counter}_exit"
        self._write(f"block {exit_}")
        self._indent += 1
        self._write(f"loop {loop}")
        self._indent += 1
        # Guard: idx >= len -> miss path.
        self._write(f"local.get ${idx_local}")
        self._write(f"local.get ${map_local}")
        self._write(f"i32.load offset={_MAP_LEN_OFFSET}")
        self._write("i32.ge_s")
        self._write("if")
        self._indent += 1
        # Miss: store tag=None.
        self._write(f"local.get ${result_local}")
        self._write(f"i32.const 1")  # None tag
        self._write("i32.store")
        self._write(f"br {exit_}")
        self._indent -= 1
        self._write("end")
        # Compare key.
        self._write(f"local.get ${map_local}")
        self._write(f"i32.load offset={_MAP_DATA_OFFSET}")
        self._write(f"local.get ${idx_local}")
        self._write(f"i32.const {_MAP_PAIR_SIZE}")
        self._write("i32.mul")
        self._write("i32.add")
        self._write(f"local.tee $_alloc_tmp_pair")
        self._write(f"i32.load offset={_MAP_PAIR_KEY_PTR_OFFSET}")
        self._write(f"local.get $_alloc_tmp_pair")
        self._write(f"i32.load offset={_MAP_PAIR_KEY_LEN_OFFSET}")
        self._write(f"local.get ${key_ptr_local}")
        self._write(f"local.get ${key_len_local}")
        self._write("call $str_eq")
        self._write("if")
        self._indent += 1
        # Hit: store tag=Some + value from pair.
        self._write(f"local.get ${result_local}")
        self._write("i32.const 0")  # Some tag
        self._write("i32.store")
        self._write(f"local.get ${result_local}")
        self._write(f"local.get $_alloc_tmp_pair")
        self._write(f"i64.load offset={_MAP_PAIR_VALUE_OFFSET}")
        self._write(f"i64.store offset={_OPTION_LAYOUT['variants']['Some'][1][0][0]}")
        self._write(f"br {exit_}")
        self._indent -= 1
        self._write("end")
        # idx++, loop.
        self._write(f"local.get ${idx_local}")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write(f"local.set ${idx_local}")
        self._write(f"br {loop}")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")
        # Leave result pointer on the stack.
        self._write(f"local.get ${result_local}")

    # ----- list methods -----------------------------------------

    def _emit_list_method_call(self, instr: MethodCall) -> None:
        """Dispatch a method on a List receiver. Methods that read
        the header (length, is_empty) emit a single i32.load + a
        compare/store. ``push`` does grow-if-needed + store + len
        increment. ``contains`` walks the array linearly. Methods
        that need closures (map / filter / fold / find) raise; they
        land in Phase 6E."""
        recv = instr.receiver
        method = instr.method
        recv_ty = recv.ty
        elem_ty = _element_type_of_list(recv_ty)
        elem_size = self._size_of(elem_ty)

        if method == "length":
            # Result is Int (i64). Capa.List.length returns the
            # number of elements; the header stores it as i32, so
            # extend to i64 before binding the dst.
            self._push_value(recv)
            self._write(f"i32.load offset={_LIST_LEN_OFFSET}")
            self._write("i64.extend_i32_s")
            if instr.dst is not None:
                self._write(f"local.set ${instr.dst}")
            return
        if method == "is_empty":
            self._push_value(recv)
            self._write(f"i32.load offset={_LIST_LEN_OFFSET}")
            self._write("i32.eqz")
            if instr.dst is not None:
                self._write(f"local.set ${instr.dst}")
            return
        if method == "push":
            self._emit_list_push(recv, instr.args[0], elem_size, elem_ty)
            return
        if method == "get":
            # List<T>.get returns Option<T>. Building Option here
            # requires the Option sum-type layout, which lives in
            # the module's user-defined types. Defer this until the
            # standard library wraps Option centrally in 6D-3.
            raise WasmEmissionError(
                "Phase 6D-2: List.get returning Option<T> not yet "
                "supported; use direct indexing xs[i]"
            )
        if method == "contains":
            self._emit_list_contains(recv, instr.args[0], elem_size, elem_ty)
            if instr.dst is not None:
                self._write(f"local.set ${instr.dst}")
            return
        raise WasmEmissionError(
            f"Phase 6D-2: List method {method!r} not supported "
            f"(map / filter / fold need closures, see 6E)"
        )

    def _emit_list_push(
        self, recv: Value, elem: Value, elem_size: int, elem_ty: str,
    ) -> None:
        """Emit ``recv.push(elem)``. Grows the data array if the
        list is at capacity (doubling strategy); stores the element
        at ``data_ptr + len * elem_size``; increments len.

        Uses ``$_m_scrut`` / ``$_m_tag`` / ``$_alloc_tmp`` as scratch
        for the list pointer, current length, and new data pointer
        respectively; these are guaranteed declared by
        ``_collect_locals``."""
        list_local = "_m_scrut"
        len_local = "_m_tag"
        # Stash the list pointer so we can re-read header fields
        # without re-evaluating the receiver.
        self._push_value(recv)
        self._write(f"local.set ${list_local}")
        # Branch: if len >= cap, grow. Otherwise reuse data array.
        self._write(f"local.get ${list_local}")
        self._write(f"i32.load offset={_LIST_LEN_OFFSET}")
        self._write(f"local.tee ${len_local}")
        self._write(f"local.get ${list_local}")
        self._write(f"i32.load offset={_LIST_CAP_OFFSET}")
        self._write("i32.ge_s")
        self._write("if")
        self._indent += 1
        # Grow: new_cap = max(cap * 2, 8). Allocate fresh data, copy
        # old contents, install in header. ``memory.copy`` (bulk
        # memory ops) is supported by wasmtime; we use it for the
        # element copy because the loop alternative would be tedious
        # to emit by hand.
        self._write(f"local.get ${list_local}")
        self._write(f"i32.load offset={_LIST_CAP_OFFSET}")
        self._write("i32.const 2")
        self._write("i32.mul")
        # If cap was 0, new_cap is 0; bump to 8 in that case.
        self._write("local.tee $_alloc_tmp")
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        self._write("i32.const 8")
        self._write("local.set $_alloc_tmp")
        self._indent -= 1
        self._write("end")
        # Allocate new data array: $_alloc_tmp * elem_size bytes.
        self._write("local.get $_alloc_tmp")
        self._write(f"i32.const {elem_size}")
        self._write("i32.mul")
        self._write("call $alloc")
        # Stack: new_data_ptr. Save it.
        self._write("local.tee $_m_tag")  # reuse len_local as new_data
        # Now memory.copy: dst=new_data, src=old_data, n=len*elem_size
        # Sequence: dst, src, size.
        self._write(f"local.get ${list_local}")
        self._write(f"i32.load offset={_LIST_DATA_OFFSET}")
        self._write(f"local.get ${list_local}")
        self._write(f"i32.load offset={_LIST_LEN_OFFSET}")
        self._write(f"i32.const {elem_size}")
        self._write("i32.mul")
        self._write("memory.copy")
        # Update header: data_ptr = new_data, cap = new_cap.
        self._write(f"local.get ${list_local}")
        self._write("local.get $_m_tag")
        self._write(f"i32.store offset={_LIST_DATA_OFFSET}")
        self._write(f"local.get ${list_local}")
        self._write("local.get $_alloc_tmp")
        self._write(f"i32.store offset={_LIST_CAP_OFFSET}")
        # Refresh the cached len_local; it lost its value when we
        # reused $_m_tag.
        self._write(f"local.get ${list_local}")
        self._write(f"i32.load offset={_LIST_LEN_OFFSET}")
        self._write(f"local.set ${len_local}")
        self._indent -= 1
        self._write("end")
        # Store the new element at data[len]. Address = data_ptr +
        # len * elem_size.
        self._write(f"local.get ${list_local}")
        self._write(f"i32.load offset={_LIST_DATA_OFFSET}")
        self._write(f"local.get ${len_local}")
        self._write(f"i32.const {elem_size}")
        self._write("i32.mul")
        self._write("i32.add")
        self._push_value(elem)
        self._write(_store_op_for_size(elem_size))
        # Increment len.
        self._write(f"local.get ${list_local}")
        self._write(f"local.get ${len_local}")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write(f"i32.store offset={_LIST_LEN_OFFSET}")

    def _emit_list_contains(
        self, recv: Value, needle: Value, elem_size: int, elem_ty: str,
    ) -> None:
        """Emit a linear-scan ``recv.contains(needle)``. Leaves an
        i32 0/1 on the stack. String element type would need a
        per-byte comparator and is deferred until 6D-4."""
        if elem_ty == "String":
            raise WasmEmissionError(
                "Phase 6D-2: List<String>.contains not yet supported"
            )
        list_local = "_m_scrut"
        idx_local = "_m_tag"
        # Compare op depends on element width.
        eq_op = "i64.eq" if elem_size == 8 else "i32.eq"
        load_op = _load_op_for_size(elem_size)
        # Push needle once into a fresh local; reusing $_alloc_tmp.
        # Needle is a scalar (Int or Bool) so it fits in i64 / i32.
        if elem_size == 8:
            self._push_value(needle)
            self._write(f"local.set $_alloc_tmp_i64")
            needle_local = "_alloc_tmp_i64"
        else:
            self._push_value(needle)
            self._write(f"local.set $_alloc_tmp")
            needle_local = "_alloc_tmp"
        self._push_value(recv)
        self._write(f"local.set ${list_local}")
        self._write("i32.const 0")
        self._write(f"local.set ${idx_local}")
        # Loop: while idx < len, compare element with needle; break
        # with 1 on match; fall through to 0 if none matched.
        self._block_counter += 1
        loop_label = f"$C{self._block_counter}_loop"
        exit_label = f"$C{self._block_counter}_exit"
        self._write(f"block {exit_label} (result i32)")
        self._indent += 1
        self._write(f"loop {loop_label}")
        self._indent += 1
        # Guard: idx >= len -> push 0 and exit.
        self._write(f"local.get ${idx_local}")
        self._write(f"local.get ${list_local}")
        self._write(f"i32.load offset={_LIST_LEN_OFFSET}")
        self._write("i32.ge_s")
        self._write("if")
        self._indent += 1
        self._write("i32.const 0")
        self._write(f"br {exit_label}")
        self._indent -= 1
        self._write("end")
        # Compare element with needle.
        self._write(f"local.get ${list_local}")
        self._write(f"i32.load offset={_LIST_DATA_OFFSET}")
        self._write(f"local.get ${idx_local}")
        self._write(f"i32.const {elem_size}")
        self._write("i32.mul")
        self._write("i32.add")
        self._write(load_op)
        self._write(f"local.get ${needle_local}")
        self._write(eq_op)
        self._write("if")
        self._indent += 1
        self._write("i32.const 1")
        self._write(f"br {exit_label}")
        self._indent -= 1
        self._write("end")
        # Advance index and loop.
        self._write(f"local.get ${idx_local}")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write(f"local.set ${idx_local}")
        self._write(f"br {loop_label}")
        self._indent -= 1
        self._write("end")
        # Loop never falls through; the outer block expects an
        # i32 result, so an unreachable terminator satisfies the
        # type-checker without producing a spurious value.
        self._write("unreachable")
        self._indent -= 1
        self._write("end")

    # ----- lists ------------------------------------------------

    def _emit_make_list(self, instr: MakeList) -> None:
        """Allocate a List<T> header (16 bytes) + an element data
        array sized for the literal's elements. Store len = cap =
        n, then write each element at its index. The list pointer
        lands in ``instr.dst``."""
        list_ty = self._dst_capa_ty(instr.dst) or "List<Int>"
        elem_ty = _element_type_of_list(list_ty)
        elem_size = self._size_of(elem_ty)
        n = len(instr.elements)
        # Allocate the header. Empty literals get cap=8 so a
        # subsequent ``push`` lands without immediate realloc.
        cap = max(n, 8)
        self._write(f"i32.const {_LIST_HEADER_SIZE}")
        self._write("call $alloc")
        self._write(f"local.set ${instr.dst}")
        # Store len and cap. Header layout: len@0, cap@4, data_ptr@8.
        self._write(f"local.get ${instr.dst}")
        self._write(f"i32.const {n}")
        self._write(f"i32.store offset={_LIST_LEN_OFFSET}")
        self._write(f"local.get ${instr.dst}")
        self._write(f"i32.const {cap}")
        self._write(f"i32.store offset={_LIST_CAP_OFFSET}")
        # Allocate the data array (cap * elem_size); record the
        # base pointer in the header's data slot. Even for empty
        # literals we allocate an array of cap slots so push has
        # somewhere to write without an immediate grow.
        data_bytes = cap * elem_size
        self._write(f"i32.const {data_bytes}")
        self._write("call $alloc")
        # Stack: data_ptr; duplicate before storing so we keep a
        # copy for the element writes below.
        self._write("local.tee $_alloc_tmp")  # data_ptr saved in tmp
        self._write(f"local.get ${instr.dst}")
        self._write(f"local.get $_alloc_tmp")
        self._write(f"i32.store offset={_LIST_DATA_OFFSET}")
        # Write each literal element. ``_alloc_tmp`` holds the base
        # pointer of the data array.
        store_op = _store_op_for_size(elem_size)
        for i, elem in enumerate(instr.elements):
            self._write(f"local.get $_alloc_tmp")
            self._push_value(elem)
            self._write(f"{store_op} offset={i * elem_size}")
        # Drop the leftover from local.tee (it lives in $_alloc_tmp
        # but the stack value persisted). i32.store consumed the tag
        # offset's stack value already in the data_ptr store above,
        # so the stack is balanced at this point.

    def _emit_index(self, instr: Index) -> None:
        """Lower ``xs[i]`` for a List receiver. Loads
        ``data_ptr + i * elem_size`` from memory. The bounds
        check is the analyzer's job (or the IR's; the Wasm path
        trusts that the index is valid)."""
        recv_ty = instr.receiver.ty
        if not recv_ty.startswith("List"):
            raise WasmEmissionError(
                f"Index on receiver of type {recv_ty!r}: only List "
                f"indexing is supported in Phase 6D-2"
            )
        elem_ty = _element_type_of_list(recv_ty)
        elem_size = self._size_of(elem_ty)
        load_op = _load_op_for_size(elem_size)
        # Compute address: data_ptr + index * elem_size.
        self._push_value(instr.receiver)
        self._write(f"i32.load offset={_LIST_DATA_OFFSET}")
        # Index needs to be an i32 offset; the IR's Value for the
        # index is typically lit_int (i64) or local Int (i64).
        # Cast i64 -> i32 with ``i32.wrap_i64``.
        self._push_value(instr.index)
        self._write("i32.wrap_i64")
        self._write(f"i32.const {elem_size}")
        self._write("i32.mul")
        self._write("i32.add")
        self._write(load_op)
        self._write(f"local.set ${instr.dst}")

    def _emit_for(self, instr: For) -> None:
        """Lower ``for x in xs`` for a List iterator. Emits a
        counted loop:
        ``i = 0; while i < len(xs) { x = xs[i]; ...body...; i += 1 }``
        Uses the function's match-helper locals (``$_m_scrut`` and
        ``$_m_tag``) as scratch space for the iterator pointer and
        index, plus the bind name's own local for the element."""
        iter_ty = instr.iter.ty
        if not iter_ty.startswith("List"):
            raise WasmEmissionError(
                f"For-iter over type {iter_ty!r}: only List iteration "
                f"is supported in Phase 6D-2 (range iteration lands "
                f"in a later phase)"
            )
        elem_ty = _element_type_of_list(iter_ty)
        elem_size = self._size_of(elem_ty)
        load_op = _load_op_for_size(elem_size)
        # We need a list-pointer scratch and an index scratch. Reuse
        # the match helpers; their live range does not overlap the
        # for loop's body (no match runs concurrently). The IR
        # walker has ensured these locals exist when needed (see
        # ``_collect_locals``).
        list_local = "_m_scrut"
        idx_local = "_m_tag"
        # Capture the list pointer in $list_local.
        self._push_value(instr.iter)
        self._write(f"local.set ${list_local}")
        self._write(f"i32.const 0")
        self._write(f"local.set ${idx_local}")
        # block/loop encoding (same shape as while):
        self._block_counter += 1
        loop_label = f"$F{self._block_counter}_loop"
        exit_label = f"$F{self._block_counter}_exit"
        self._loop_labels.append((loop_label, exit_label))
        self._write(f"block {exit_label}")
        self._indent += 1
        self._write(f"loop {loop_label}")
        self._indent += 1
        # Loop guard: if idx >= len(list), exit.
        self._write(f"local.get ${idx_local}")
        self._write(f"local.get ${list_local}")
        self._write(f"i32.load offset={_LIST_LEN_OFFSET}")
        self._write("i32.ge_s")
        self._write(f"br_if {exit_label}")
        # Bind the iteration variable: list.data[idx].
        self._write(f"local.get ${list_local}")
        self._write(f"i32.load offset={_LIST_DATA_OFFSET}")
        self._write(f"local.get ${idx_local}")
        self._write(f"i32.const {elem_size}")
        self._write("i32.mul")
        self._write("i32.add")
        self._write(load_op)
        if elem_ty == "String":
            # String iteration is exotic: each element is a (ptr,
            # len) pair stored consecutively. The simple load above
            # reads only one half. Defer until 6D-4 when full
            # String support arrives.
            raise WasmEmissionError(
                "Phase 6D-2: for-iter over List<String> not yet "
                "supported; iterate over List<Int> or a pointer-typed "
                "element type"
            )
        self._write(f"local.set ${instr.name}")
        # Body.
        for sub in instr.body:
            self._emit_instr(sub)
        # Increment idx and continue.
        self._write(f"local.get ${idx_local}")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write(f"local.set ${idx_local}")
        self._write(f"br {loop_label}")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")
        self._loop_labels.pop()

    def _size_of(self, capa_ty: str) -> int:
        """Wrapper around the module-level ``_size_of`` that
        consults the emitter's known struct/sum layouts."""
        return _size_of(capa_ty, self._sum_layouts, self._struct_layouts)

    # ----- format strings ---------------------------------------

    def _emit_format_str(self, instr: FormatStr) -> None:
        """Lower a ``FormatStr`` to the equivalent inline string
        building: stash each Value part's (ptr, len), sum total
        length, allocate, memory.copy each piece in order, bind dst.

        Phase 6F supports Int / Bool / String value parts. Int uses
        the ``$itoa`` helper for decimal conversion; Bool indexes
        pre-interned ``"true"`` / ``"false"`` literals; String
        copies its existing (ptr, len). Up to 8 value parts per
        format string -- a generous ceiling that covers all of the
        gallery / demo programs without runtime cost."""
        if instr.dst is None:
            return
        value_parts = [p for p in instr.parts if isinstance(p, Value)]
        if len(value_parts) > 8:
            raise WasmEmissionError(
                f"FormatStr with {len(value_parts)} value parts "
                f"exceeds the Phase 6F max of 8"
            )
        # Stash each Value part's (ptr, len) into scratch locals.
        # Index into the parts-of-Value subset, not the full parts.
        value_idx = 0
        for part in instr.parts:
            if isinstance(part, Value):
                self._emit_format_part_stash(part, value_idx)
                value_idx += 1
        # Compute total length.
        literal_len = sum(
            len(p.encode("utf-8")) for p in instr.parts if isinstance(p, str)
        )
        self._write(f"i32.const {literal_len}")
        for i in range(len(value_parts)):
            self._write(f"local.get $_fs_l{i}")
            self._write("i32.add")
        self._write("local.set $_fs_total_len")
        # Allocate result buffer.
        self._write("local.get $_fs_total_len")
        self._write("call $alloc")
        self._write("local.set $_fs_buf")
        # Write pieces in order. Track write position in $_fs_pos.
        self._write("i32.const 0")
        self._write("local.set $_fs_pos")
        value_idx = 0
        for part in instr.parts:
            if isinstance(part, str):
                if not part:
                    continue
                offset, length = self._intern_string(part)
                # memory.copy(dst=buf+pos, src=lit_ptr, n=lit_len)
                self._write("local.get $_fs_buf")
                self._write("local.get $_fs_pos")
                self._write("i32.add")
                self._write(f"i32.const {offset}")
                self._write(f"i32.const {length}")
                self._write("memory.copy")
                self._write("local.get $_fs_pos")
                self._write(f"i32.const {length}")
                self._write("i32.add")
                self._write("local.set $_fs_pos")
            else:
                # Value: memory.copy from stashed ptr.
                self._write("local.get $_fs_buf")
                self._write("local.get $_fs_pos")
                self._write("i32.add")
                self._write(f"local.get $_fs_p{value_idx}")
                self._write(f"local.get $_fs_l{value_idx}")
                self._write("memory.copy")
                self._write("local.get $_fs_pos")
                self._write(f"local.get $_fs_l{value_idx}")
                self._write("i32.add")
                self._write("local.set $_fs_pos")
                value_idx += 1
        # Bind dst.
        self._write("local.get $_fs_buf")
        self._write("local.get $_fs_total_len")
        self._set_string_dst(instr.dst)

    def _emit_format_part_stash(self, v: Value, idx: int) -> None:
        """Compute the (ptr, len) representation of ``v`` for inline
        string building and stash into ``$_fs_p{idx}`` /
        ``$_fs_l{idx}``."""
        ty = v.ty
        if ty == "String":
            self._push_string_value_as_ptr_len(v)
            self._write(f"local.set $_fs_l{idx}")
            self._write(f"local.set $_fs_p{idx}")
            return
        if ty == "Int":
            self._push_value(v)
            self._write("call $itoa")
            self._write(f"local.set $_fs_l{idx}")
            self._write(f"local.set $_fs_p{idx}")
            return
        if ty == "Float":
            self._push_value(v)
            self._write("call $ftoa")
            self._write(f"local.set $_fs_l{idx}")
            self._write(f"local.set $_fs_p{idx}")
            return
        if ty == "Bool":
            # Use pre-interned "true" / "false". Branch on the value
            # at runtime and stash the right (ptr, len) pair.
            true_off, true_len = self._intern_string("true")
            false_off, false_len = self._intern_string("false")
            self._push_value(v)
            self._write("if")
            self._indent += 1
            self._write(f"i32.const {true_off}")
            self._write(f"local.set $_fs_p{idx}")
            self._write(f"i32.const {true_len}")
            self._write(f"local.set $_fs_l{idx}")
            self._indent -= 1
            self._write("else")
            self._indent += 1
            self._write(f"i32.const {false_off}")
            self._write(f"local.set $_fs_p{idx}")
            self._write(f"i32.const {false_len}")
            self._write(f"local.set $_fs_l{idx}")
            self._indent -= 1
            self._write("end")
            return
        raise WasmEmissionError(
            f"Phase 6F: FormatStr value of type {ty!r} not supported "
            f"(Int / Bool / String only)"
        )

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
        # Sum-layout lookups strip generic args: ``Option<Int>`` ->
        # ``Option``. The built-in Option / Result and user-defined
        # sums are all keyed by the bare type name.
        sum_layout = self._sum_layouts.get(scrut_ty.split("<", 1)[0])
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
                    bind_ty = (
                        self._current_fn.locals.get(sub_pat.name, "")
                        if self._current_fn else ""
                    )
                    if bind_ty == "String":
                        # String payload is packed into the i64
                        # slot: low 32 bits = ptr, high 32 bits =
                        # len. Unpack into the bind's (ptr, len)
                        # locals so downstream String operations
                        # work transparently.
                        self._write(f"local.get ${scrut_local}")
                        self._write(f"i64.load offset={offset}")
                        self._write(f"local.tee $_alloc_tmp_i64")
                        self._write("i32.wrap_i64")
                        self._write(f"local.set ${sub_pat.name}_ptr")
                        self._write("local.get $_alloc_tmp_i64")
                        self._write("i64.const 32")
                        self._write("i64.shr_u")
                        self._write("i32.wrap_i64")
                        self._write(f"local.set ${sub_pat.name}_len")
                    elif size == 8 and (
                        bind_ty.split("<", 1)[0] in self._struct_layouts
                        or bind_ty.split("<", 1)[0] in self._sum_layouts
                        or bind_ty.startswith(("List", "Map", "Set"))
                    ):
                        # Pointer-shaped payload (struct / sum /
                        # collection) stored in the uniform 8-byte
                        # slot via i64.extend; unpack with
                        # i32.wrap_i64.
                        self._write(f"local.get ${scrut_local}")
                        self._write(f"i64.load offset={offset}")
                        self._write("i32.wrap_i64")
                        self._write(f"local.set ${sub_pat.name}")
                    else:
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
        # Result handling. Void methods (Stdio.print/println) leave
        # nothing on the stack; methods with a return value (e.g.
        # Clock.now_secs -> f64) leave a single primitive that we
        # bind to ``instr.dst``. The dispatch consults the cap's
        # WIT signature to know whether to expect a result.
        _params, result_ty = self._cap_method_wasm_sig(cap, method)
        if result_ty and instr.dst is not None:
            self._write(f"local.set ${instr.dst}")

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
        if v.kind == "lit_float":
            # WAT accepts standard float literal syntax. We rely on
            # Python's repr() to produce a parseable form for any
            # finite value the source contained.
            self._write(f"f64.const {v.literal!r}")
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
        # Collection types: List / Map / Set are also heap pointers.
        # Their stdlib methods will resolve dispatch on the receiver
        # type string later, but at the value-shape level they are
        # i32 pointers identical to structs.
        if head in ("List", "Map", "Set"):
            return "i32"
        raise WasmEmissionError(
            f"Capa type {capa_ty!r} has no Wasm encoding yet"
        )

    def _write(self, line: str) -> None:
        if line == "":
            self._lines.append("")
        else:
            self._lines.append(self._unit * self._indent + line)
