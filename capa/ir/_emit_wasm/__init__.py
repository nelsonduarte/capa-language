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

from .._nodes import (
    Module, Function, Param, Value, Instr,
    AssignConst, Reassign, BinOp, UnaryOp, Call, MethodCall,
    If, While, Break, Continue, Return, TryUnwrap,
    MakeStruct, MakeList, MakeMap, MakeSet, MakeTuple,
    FieldAccess, Index, For,
    FormatStr, MakeLambda,
    Pattern, PatWildcard, PatIdent, PatLiteral, PatVariant, MatchArm, Match,
    StructDecl, SumDecl,
)
from .._emit_wit import _WIT_SIGNATURES, _KNOWN_CAPABILITIES
from ._layout import (
    WasmEmissionError,
    _BUILTIN_CAPS,
    _TYPE_SIZE,
    _LIST_HEADER_SIZE, _LIST_LEN_OFFSET, _LIST_CAP_OFFSET, _LIST_DATA_OFFSET,
    _MAP_HEADER_SIZE, _MAP_LEN_OFFSET, _MAP_CAP_OFFSET, _MAP_DATA_OFFSET,
    _MAP_PAIR_SIZE, _MAP_PAIR_KEY_PTR_OFFSET, _MAP_PAIR_KEY_LEN_OFFSET, _MAP_PAIR_VALUE_OFFSET,
    _OPTION_LAYOUT, _RESULT_LAYOUT, _IOERROR_LAYOUT, _JSONVALUE_LAYOUT,
    _map_value_type, _element_type_of_list,
    _size_of, _store_op_for_size, _load_op_for_size, _align_up,
    compute_struct_layout, compute_sum_layout,
)
from ._runtime import _RuntimeHelpersMixin
from ._match import _MatchEmissionMixin
from ._strings import _StringEmissionMixin
from ._maps import _MapEmissionMixin
from ._lists import _ListEmissionMixin
from ._closures import _ClosureEmissionMixin
from ._json import _JsonEmissionMixin
from ._option import _OptionEmissionMixin
from ._traits import _TraitEmissionMixin
from ._tuples import _TupleEmissionMixin


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


class WasmEmitter(
    _RuntimeHelpersMixin,
    _MatchEmissionMixin,
    _StringEmissionMixin,
    _MapEmissionMixin,
    _ListEmissionMixin,
    _ClosureEmissionMixin,
    _JsonEmissionMixin,
    _OptionEmissionMixin,
    _TraitEmissionMixin,
    _TupleEmissionMixin,
):
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
        # Lifted lambdas: one entry per MakeLambda in the module.
        # Populated during the discover pass and emitted as
        # top-level functions before any user function.
        self._lifted_lambdas: list[dict] = []
        # Map (parent_fn_name, MakeLambda.dst) -> the index into
        # _lifted_lambdas for use at the MakeLambda emit site.
        # Keying by parent name is required because the IR's
        # ``fresh_local`` counter resets per function, so multiple
        # lambdas across different functions share dst names like
        # ``_ir_lambda0``. The emitter resolves the right entry by
        # consulting ``self._current_fn.name`` at MakeLambda time.
        self._lambda_by_dst: dict[tuple[str, str], int] = {}
        # Per-signature dedup table for ``(type $sig_N ...)`` decls.
        # Key: a stable string like "(i32 i64) -> i64"; value: an
        # integer index N.
        self._closure_sig_keys: dict[str, int] = {}
        # When emitting a lifted-lambda body, captures live in
        # this map (name -> (offset, capa_ty)). ``_push_value``
        # and the String pushers consult it.
        self._current_captures: dict[str, tuple[int, str]] = {}
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
        self._sum_layouts = {
            "Option": _OPTION_LAYOUT,
            "Result": _RESULT_LAYOUT,
            "JsonValue": _JSONVALUE_LAYOUT,
        }
        self._variant_to_sum = {
            "Some": "Option", "None": "Option",
            "Ok": "Result", "Err": "Result",
            "JNull": "JsonValue", "JBool": "JsonValue", "JNum": "JsonValue",
            "JStr": "JsonValue", "JArr": "JsonValue", "JObj": "JsonValue",
        }
        # Trait dispatch: build trait_name -> impl map for traits
        # with exactly one implementor. Multi-impl traits leave the
        # entry empty; dispatch path raises when it hits one.
        self._setup_trait_dispatch(module)
        # Module-level constants: name -> Value (the RHS literal).
        # Populated below from ``module.consts``. _push_value
        # consults this when it sees Value(kind="global", ...) so
        # use sites inline the literal rather than emitting a
        # global.get. Only literal-RHS consts land here; consts
        # with computed bodies raise at the use site so a future
        # Wasm-global-with-start-fn pass can take over cleanly.
        self._const_values: dict[str, Value] = {}
        for c in module.consts:
            if len(c.body) == 1 and isinstance(c.body[0], AssignConst):
                src = c.body[0].src
                if src.kind in ("lit_int", "lit_float",
                                "lit_bool", "lit_str", "lit_unit"):
                    self._const_values[c.name] = src

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

        # Refine pattern-binder types from variant payload layouts
        # BEFORE any helper-detection (uses_float_format etc.) reads
        # fn.locals. The analyzer's pattern-side type inference is
        # incomplete for builtin sum types (JsonValue / Option /
        # Result with non-Int payloads), leaving binders as Unknown.
        # The sum layout always knows what each variant carries.
        for fn in module.functions:
            self._refine_pattern_binder_types(fn, fn.body)

        # First pass: walk the module to discover used capability
        # methods and string literals so we can emit imports and
        # the data segment at the top of the module (Wasm requires
        # imports before any function/code section, and we want the
        # data segment in a known location).
        self._used_caps = set()
        self._strings = {}
        self._string_data_offset = 0
        self._lifted_lambdas = []
        self._lambda_by_dst = {}
        self._closure_sig_keys = {}
        # Pre-intern "true" / "false" if any FormatStr might consume
        # a Bool value at runtime; the data-segment offsets are
        # referenced via i32.const in the dispatch.
        if self._uses_format_str(module):
            self._intern_string("true")
            self._intern_string("false")
        self._discover(module)
        self._discover_lambdas(module)

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
            # parse_int / parse_float are built-in free functions
            # routed to runtime helpers. Emit only when used.
            if self._uses_parse_int(module):
                self._emit_parse_int_function()
            if self._uses_parse_float(module):
                self._emit_parse_float_function()
        # Closure infrastructure: function table + (type) decls +
        # each lifted lambda is a top-level function below.
        if self._lifted_lambdas:
            self._emit_closure_types_and_table()
            for lifted in self._lifted_lambdas:
                self._emit_lifted_lambda(lifted)
        # Stage 2: emit each function. Impl methods are emitted as
        # additional top-level functions with mangled names
        # (<TypeName>_<method_name>) so MethodCall dispatch on a
        # trait receiver can route to them via call $<mangled>.
        for fn in module.functions:
            self._emit_function(fn)
        self._emit_impl_methods(module)
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
                if isinstance(instr, (MakeList, MakeMap, MakeSet, FormatStr, MakeLambda)):
                    return True
                if isinstance(instr, MethodCall):
                    recv_ty = instr.receiver.ty or ""
                    if recv_ty.startswith("List") and instr.method in _ALLOC_METHODS_LIST:
                        return True
                    if recv_ty == "String" and instr.method in _ALLOC_METHODS_STRING:
                        return True
                    if recv_ty.startswith("Map") and instr.method in ("set", "get"):
                        return True
                    if recv_ty.startswith("List") and instr.method in ("map", "filter", "fold"):
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

    def _refine_pattern_binder_types(
        self, fn: Function, instrs: list[Instr],
    ) -> None:
        """Walk every Match in ``instrs`` and update ``fn.locals``
        for PatVariant payload binders whose recorded type is
        Unknown / missing. The variant's payload layout owns the
        authoritative type."""
        for instr in instrs:
            if isinstance(instr, Match):
                scrut_head = (instr.scrutinee.ty or "").split("<", 1)[0]
                sum_layout = self._sum_layouts.get(scrut_head)
                if sum_layout is not None:
                    for arm in instr.arms:
                        if not isinstance(arm.pattern, PatVariant):
                            continue
                        entry = sum_layout["variants"].get(arm.pattern.name)
                        if entry is None:
                            continue
                        _tag, payload_layouts = entry
                        for sub_pat, (_off, _sz, payload_ty) in zip(
                            arm.pattern.payloads, payload_layouts,
                        ):
                            if not isinstance(sub_pat, PatIdent):
                                continue
                            cur = fn.locals.get(sub_pat.name, "")
                            if (cur in ("", "Unknown", "?", "Any")
                                    or cur.startswith("?")):
                                if payload_ty and payload_ty != "Any":
                                    fn.locals[sub_pat.name] = payload_ty
                # String-scrutinee match: PatIdent arm binds the
                # whole scrutinee value. The emitter routes binds
                # to ${name}_ptr / ${name}_len, so fn.locals must
                # record "String" for the local-decl sweep to
                # allocate the pair.
                if (instr.scrutinee.ty or "") == "String":
                    for arm in instr.arms:
                        if isinstance(arm.pattern, PatIdent):
                            cur = fn.locals.get(arm.pattern.name, "")
                            if (cur in ("", "Unknown", "?")
                                    or cur.startswith("?")):
                                fn.locals[arm.pattern.name] = "String"
                for arm in instr.arms:
                    self._refine_pattern_binder_types(fn, arm.body)
            elif isinstance(instr, If):
                self._refine_pattern_binder_types(fn, instr.then_body)
                self._refine_pattern_binder_types(fn, instr.else_body)
            elif isinstance(instr, While):
                self._refine_pattern_binder_types(fn, instr.cond_setup)
                self._refine_pattern_binder_types(fn, instr.body)
            elif isinstance(instr, For):
                self._refine_pattern_binder_types(fn, instr.body)

    def _uses_float_format(self, module: Module) -> bool:
        """True if any ``FormatStr`` instruction has a Float value
        part, which is what gates emission of the ``$ftoa`` helper.

        Consults each function's ``locals`` dict as a fallback when
        a value's ``ty`` is unresolved -- the match emitter refines
        pattern-binder types into ``fn.locals`` after the analyzer
        leaves them as Unknown, and the FormatStr dispatcher uses
        the same fallback at emit time."""
        def _eff_ty(p: Value, fn: Function) -> str:
            if p.ty and p.ty not in ("?", "Unknown", "Any"):
                return p.ty
            if p.kind in ("local", "param") and p.name in fn.locals:
                return fn.locals[p.name]
            return p.ty or ""
        for fn in module.functions:
            def visit(instrs: list[Instr], fn=fn) -> bool:
                for instr in instrs:
                    if isinstance(instr, FormatStr):
                        for p in instr.parts:
                            if isinstance(p, Value) and _eff_ty(p, fn) == "Float":
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
            if visit(fn.body):
                return True
        return False

    def _uses_parse_int(self, module: Module) -> bool:
        return self._uses_builtin_free_fn(module, "parse_int")

    def _uses_parse_float(self, module: Module) -> bool:
        return self._uses_builtin_free_fn(module, "parse_float")

    def _uses_builtin_free_fn(self, module: Module, name: str) -> bool:
        """True if any function or impl-method body Calls
        ``name``. Used to gate emission of optional runtime
        helpers like ``$parse_int`` / ``$parse_float``."""
        def visit(instrs: list[Instr]) -> bool:
            for instr in instrs:
                if isinstance(instr, Call) and instr.callee_name == name:
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
        for impl in module.impls:
            for method in impl.methods:
                if visit(method.body):
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
                    # String-scrutinee match calls $str_eq per arm.
                    if (instr.scrutinee.ty or "") == "String":
                        return True
                    for arm in instr.arms:
                        if visit(arm.body):
                            return True
            return False
        for fn in module.functions:
            if visit(fn.body):
                return True
        return False

    # ----- discovery pass ---------------------------------------

    def _discover(self, module: Module) -> None:
        """Walk all functions and collect string literals + used
        capability methods. The discovered set drives import
        declarations and the data segment layout; encountering
        anything outside the supported set is a fatal error so the
        emitted Wasm never references something the host did not
        provide.

        Also walks every impl method body so the cap calls inside
        impl methods (e.g. ``self.stdio.println(...)`` in
        ``impl Logger for StdioLogger``) contribute their imports
        to the module just like top-level function bodies."""
        for fn in module.functions:
            self._discover_instrs(fn.body)
        for impl in module.impls:
            for method in impl.methods:
                self._discover_instrs(method.body)

    def _discover_instrs(self, instrs: list[Instr]) -> None:
        for instr in instrs:
            # Cap dispatch: prefer instr.cap_used, fall back to the
            # receiver type for impl-method-internal calls where
            # the analyzer doesn't propagate cap_used through. The
            # emit-side dispatch in _emit_instr mirrors this rule.
            cap_from_recv = None
            if isinstance(instr, MethodCall) and not instr.cap_used:
                rty = (instr.receiver.ty or "")
                if rty in _BUILTIN_CAPS:
                    cap_from_recv = rty
            if isinstance(instr, MethodCall) and (instr.cap_used or cap_from_recv):
                cap = instr.cap_used or cap_from_recv
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
            # parse_json / to_json are free functions but route
            # through a synthetic ``Json`` capability so the import
            # machinery treats them the same as Stdio / Fs / Env.
            if isinstance(instr, Call):
                if instr.callee_name == "parse_json":
                    self._used_caps.add(("Json", "parse"))
                elif instr.callee_name == "to_json":
                    self._used_caps.add(("Json", "to_string"))
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
            elif isinstance(instr, For):
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
        if "func() -> list<string>" in wit:
            # Returns an i32 pointer to a List<String> built by
            # the host in linear memory.
            return ([], "i32")
        if "func(prefix: string)" in wit and "->" not in wit:
            # Fs.restrict_to: a string-arg, no-result no-op at the
            # Wasm level. The capability discipline is enforced
            # by the analyzer; at runtime the import is shared.
            return (["i32", "i32"], "")
        if "func(s: string) -> result<i32, string>" in wit:
            # Json.parse: one string arg (ptr, len), returns i32
            # pointer to a Result<JsonValue, String> built on the
            # heap by the host.
            return (["i32", "i32"], "i32")
        if "func(jv: i32) -> string" in wit:
            # Json.to_string: i32 JsonValue pointer in, (ptr, len)
            # pair out. Wasm core supports multi-value returns since
            # the 2.0 spec, which is what wasmtime accepts.
            return (["i32"], "i32 i32")
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
        has_make_lambda = False
        has_list_hof = False
        has_json_method = False
        has_json_parse = False
        has_list_string = False
        has_optres_method = False
        has_list_method = False
        has_tuple = False

        def value_uses_variant_ctor(v: Value) -> bool:
            return v is not None and v.kind == "variant_ctor"

        def visit(instrs: list[Instr]) -> None:
            nonlocal has_match, has_variant_ctor, has_list, has_for
            nonlocal has_list_contains_i64, has_map, has_string_method
            nonlocal has_format_str, has_make_lambda, has_list_hof
            nonlocal has_json_method, has_json_parse
            nonlocal has_list_string, has_optres_method
            nonlocal has_list_method, has_tuple
            for instr in instrs:
                if isinstance(instr, Match):
                    has_match = True
                    # String-scrutinee match emits $str_eq calls and
                    # reuses the String-method scratch (_str_a_*).
                    if (instr.scrutinee.ty or "") == "String":
                        has_string_method = True
                    # Refine binder types from the variant's payload
                    # layout. The analyzer's pattern-side type
                    # inference is incomplete for builtin sum types
                    # (JsonValue / Option / Result with non-Int
                    # payloads), leaving the binder as Unknown. The
                    # sum layout always knows the payload type, so
                    # use it to fix fn.locals before any local-decl
                    # emission consumes the (wrong) Unknown type.
                    scrut_head = (instr.scrutinee.ty or "").split("<", 1)[0]
                    sum_layout = self._sum_layouts.get(scrut_head)
                    if sum_layout is not None:
                        for arm in instr.arms:
                            if not isinstance(arm.pattern, PatVariant):
                                continue
                            entry = sum_layout["variants"].get(arm.pattern.name)
                            if entry is None:
                                continue
                            _tag, payload_layouts = entry
                            for sub_pat, (_off, _sz, payload_ty) in zip(
                                arm.pattern.payloads, payload_layouts,
                            ):
                                if not isinstance(sub_pat, PatIdent):
                                    continue
                                cur = fn.locals.get(sub_pat.name, "")
                                if (cur in ("", "Unknown", "?")
                                        or cur.startswith("?")
                                        or cur == "Any"):
                                    if payload_ty and payload_ty != "Any":
                                        fn.locals[sub_pat.name] = payload_ty
                    # String-scrutinee match: PatIdent arm binds the
                    # whole scrutinee to a String local. The emitter
                    # writes to ${name}_ptr / ${name}_len; refine
                    # fn.locals so the local-decl sweep allocates the
                    # pair instead of a default-i64 ``$name``.
                    if (instr.scrutinee.ty or "") == "String":
                        for arm in instr.arms:
                            if isinstance(arm.pattern, PatIdent):
                                cur = fn.locals.get(arm.pattern.name, "")
                                if (cur in ("", "Unknown", "?")
                                        or cur.startswith("?")):
                                    fn.locals[arm.pattern.name] = "String"
                    for arm in instr.arms:
                        visit(arm.body)
                if isinstance(instr, MakeTuple):
                    # MakeTuple's String-element path packs (ptr,
                    # len) into i64 via _alloc_tmp_i64; Index over
                    # a tuple's String slot unpacks via the same
                    # scratch.
                    has_tuple = True
                if isinstance(instr, MakeList):
                    has_list = True
                    # MakeList over String elements needs the i64
                    # scratch for the (ptr, len) -> packed-i64 dance.
                    dst_ty = fn.locals.get(instr.dst, "") if instr.dst else ""
                    if _element_type_of_list(dst_ty) == "String":
                        has_list_string = True
                if isinstance(instr, Index):
                    # Index over List<String> unpacks a packed i64
                    # via _alloc_tmp_i64. Same goes for tuple
                    # indices when the slot type is String.
                    recv_ty = instr.receiver.ty or ""
                    if (recv_ty.startswith("List")
                            and _element_type_of_list(recv_ty) == "String"):
                        has_list_string = True
                    if recv_ty.startswith("(") and recv_ty.endswith(")"):
                        has_tuple = True
                if isinstance(instr, MakeMap):
                    has_map = True
                if isinstance(instr, MakeLambda):
                    has_make_lambda = True
                if isinstance(instr, For):
                    has_for = True
                    visit(instr.body)
                if isinstance(instr, FormatStr):
                    has_format_str = True
                if isinstance(instr, TryUnwrap):
                    # The `?` lowering stashes the receiver in
                    # $_m_scrut and the packed-i64 in $_alloc_tmp_i64
                    # for String payload unpacking. Both locals are
                    # declared via has_match + the i64-scratch group.
                    has_match = True
                if isinstance(instr, BinOp) and instr.op == "+":
                    # String concatenation reuses the same _str_*
                    # scratch locals as the String methods. The
                    # operand type tells us; both operands have
                    # type String when concat applies.
                    if (instr.left.ty == "String"
                            or instr.right.ty == "String"):
                        has_string_method = True
                if isinstance(instr, MethodCall):
                    recv_ty = instr.receiver.ty or ""
                    if recv_ty.startswith("Map"):
                        has_map = True
                    if recv_ty == "String":
                        has_string_method = True
                    if recv_ty.startswith("List"):
                        # List method calls (push / contains / get
                        # / length / is_empty / ...) reuse $_m_scrut
                        # and $_m_tag as their list-pointer and
                        # length scratch.
                        has_list_method = True
                    if instr.method == "contains" and recv_ty.startswith("List"):
                        elem_ty = _element_type_of_list(recv_ty)
                        if self._size_of(elem_ty) == 8:
                            has_list_contains_i64 = True
                    if recv_ty.startswith("List") and instr.method in (
                        "map", "filter", "fold",
                    ):
                        has_list_hof = True
                    if recv_ty == "JsonValue":
                        has_json_method = True
                    if (recv_ty.startswith("Option")
                            or recv_ty.startswith("Result")):
                        has_optres_method = True
                    if instr.method == "split" and recv_ty == "String":
                        # split returns List<String>; uses _alloc_tmp_i64
                        # for the per-chunk packing dance.
                        has_list_string = True
                    if (instr.method == "push"
                            and recv_ty.startswith("List")
                            and _element_type_of_list(recv_ty) == "String"):
                        # List<String>.push packs (ptr, len) via
                        # _alloc_tmp_i64.
                        has_list_string = True
                    if (instr.method == "get"
                            and recv_ty.startswith("List")):
                        # List.get builds an Option<T> result and
                        # reuses _m_scrut / _m_tag / _alloc_tmp_result.
                        has_optres_method = True
                        has_list = True
                if isinstance(instr, Call):
                    if instr.callee_name == "parse_json":
                        has_json_parse = True
                    elif instr.callee_name == "to_json":
                        has_json_parse = True
                    elif instr.callee_name in self._variant_to_sum:
                        # Variant-construction Call with payloads. The
                        # String payload path packs (ptr, len) via
                        # _alloc_tmp_i64; treat any payload-bearing
                        # variant call as variant_ctor for scratch-
                        # local purposes.
                        has_variant_ctor = True
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
        if has_match or has_for or has_list_method:
            out["_m_scrut"] = "i32"
            out["_m_tag"] = "i32"
        if has_for:
            # For-loop owns its own scratch locals so a match in
            # the body can't clobber the iteration state.
            out["_f_list"] = "i32"
            out["_f_idx"] = "i32"
        if has_match:
            # Nested PatVariant arms (depth 1) stash the inner
            # scrutinee pointer here; flat arms never touch it.
            out["_m_scrut_inner"] = "i32"
        if has_variant_ctor or has_list or has_map:
            out["_alloc_tmp"] = "i32"
        if (has_list_contains_i64 or has_map or has_match or has_for
                or has_variant_ctor or has_json_method or has_list_string
                or has_optres_method or has_tuple):
            # The i64 scratch is shared by: List.contains for i64
            # elements, Map scan (value packing), match-arm String
            # unpacking, for-iter over List<String> (packed i64
            # slot), variant-construction (String payload packing),
            # JsonValue as_X projection, and List<String>
            # construction / indexing / split (per-element packing).
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
        if has_json_method:
            # JsonValue method emit reuses the match scrut local for
            # the receiver pointer and needs an Option-result alloc
            # slot. _alloc_tmp_i64 is needed for the as_int /
            # as_X paths.
            out.setdefault("_m_scrut", "i32")
            out.setdefault("_alloc_tmp_result", "i32")
            out.setdefault("_alloc_tmp_i64", "i64")
        if has_format_str:
            # FormatStr scratch: per-value (ptr, len) stashes plus
            # total-length / buffer / position registers.
            for i in range(8):
                out.setdefault(f"_fs_p{i}", "i32")
                out.setdefault(f"_fs_l{i}", "i32")
            out["_fs_total_len"] = "i32"
            out["_fs_buf"] = "i32"
            out["_fs_pos"] = "i32"
        if has_make_lambda:
            # MakeLambda emission uses ``$_lam_env_tmp`` as scratch
            # for the freshly-allocated env pointer (or 0 for no
            # captures).
            out["_lam_env_tmp"] = "i32"
        if has_list_hof:
            # List HOFs (map/filter/fold) need: a stash for the
            # closure value (i64), an iteration index, plus the
            # filter-path grow scratch.
            out.setdefault("_m_scrut", "i32")
            out.setdefault("_m_tag", "i32")
            out.setdefault("_alloc_tmp", "i32")
            out["_lam_fn_tmp"] = "i64"
            out["_lam_idx"] = "i32"
            out["_lam_grow_len"] = "i32"
            out["_lam_grow_cap"] = "i32"
            out["_lam_new_data"] = "i32"
            out.setdefault("_alloc_tmp_i64", "i64")
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
        if has_list_string:
            # split() reuses the match-helper $_m_tag as its chunk
            # counter; MakeList<String> and Index<List<String>>
            # rely on $_alloc_tmp + $_alloc_tmp_i64 already declared
            # by the variant_ctor / for-loop branches above.
            out.setdefault("_m_tag", "i32")
            out.setdefault("_alloc_tmp", "i32")
        if has_optres_method:
            # Option/Result method dispatch stashes the receiver
            # pointer in $_m_scrut so the tag check + payload load
            # can both read it. List.get also reuses this flag to
            # build its Option<T> result via $_alloc_tmp_result.
            out.setdefault("_m_scrut", "i32")
            out.setdefault("_m_tag", "i32")
            out.setdefault("_alloc_tmp_result", "i32")
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
            # Built-in cap dispatch: prefer instr.cap_used (set by
            # the analyzer for direct calls), but fall back to the
            # receiver type for impl-method-internal calls where
            # the analyzer doesn't propagate cap_used through.
            # Receiver type itself may be Unknown when the IR
            # Value was captured at lowering time before the
            # analyzer's type info reached it; fall back to the
            # fn.locals entry which the emitter populates for
            # impl-method ``self`` and pattern binders.
            recv_ty_pre = self._effective_value_ty(instr.receiver)
            if instr.cap_used:
                self._emit_cap_method_call(instr)
                return
            if recv_ty_pre in _BUILTIN_CAPS:
                # Synthesise cap_used from the receiver type. Mutate
                # a copy so the IR module stays untouched.
                import dataclasses
                synth = dataclasses.replace(instr, cap_used=recv_ty_pre)
                self._emit_cap_method_call(synth)
                return
            # Use the effective type for downstream receiver-shape
            # dispatch so impl-method self.method() resolves cleanly.
            recv_ty = recv_ty_pre or ""
            if recv_ty.startswith("List"):
                self._emit_list_method_call(instr)
                return
            if recv_ty.startswith("Map"):
                self._emit_map_method_call(instr)
                return
            if recv_ty == "String":
                self._emit_string_method_call(instr)
                return
            if recv_ty == "JsonValue":
                self._emit_jsonvalue_method_call(instr)
                return
            if recv_ty.startswith("Option") or recv_ty.startswith("Result"):
                self._emit_option_method_call(instr)
                return
            recv_head = recv_ty.split("<", 1)[0]
            if (recv_head, instr.method) in self._method_table:
                self._emit_trait_method_call(instr)
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
        if isinstance(instr, MakeTuple):
            self._emit_make_tuple(instr)
            return
        if isinstance(instr, MakeLambda):
            self._emit_make_lambda(instr)
            return
        if isinstance(instr, FieldAccess):
            self._emit_field_access(instr)
            return
        if isinstance(instr, Index):
            # Tuple receivers go through the type-aware tuple
            # emitter. List receivers use the size-dispatched
            # path in _lists.
            recv_ty = self._effective_value_ty(instr.receiver)
            if self._is_tuple_ty(recv_ty):
                self._emit_tuple_index(instr)
                return
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
        if isinstance(instr, TryUnwrap):
            self._emit_try_unwrap(instr)
            return
        raise WasmEmissionError(
            f"Phase 6A: instruction {type(instr).__name__} not supported"
        )

    def _emit_try_unwrap(self, instr: TryUnwrap) -> None:
        """Lower the ``?`` operator. ``instr.src`` is an i32 pointer
        to a 16-byte sum record (Result<T, E> or Option<T>). If the
        tag at offset 0 is 1 (Err / None), return the original
        pointer from the enclosing function early. Otherwise extract
        the payload at offset 8 into ``instr.dst``.

        Mirrors the sum-type Match arm-extraction logic but elides
        the per-arm cascade since we only care about Ok/Err
        discrimination."""
        src_ty = instr.src.ty
        # Strip generic args: ``Option<Int>`` -> ``Option``.
        head = src_ty.split("<", 1)[0]
        if head not in ("Option", "Result"):
            raise WasmEmissionError(
                f"TryUnwrap on type {src_ty!r}: only Option<T> and "
                f"Result<T, E> are supported"
            )
        self._push_value(instr.src)
        self._write("local.set $_m_scrut")
        # Tag check: 1 = Err / None -> early return.
        self._write("local.get $_m_scrut")
        self._write("i32.load")
        self._write("i32.const 1")
        self._write("i32.eq")
        self._write("if")
        self._indent += 1
        self._write("local.get $_m_scrut")
        self._write("return")
        self._indent -= 1
        self._write("end")
        # Ok / Some path: load payload at offset 8.
        dst_ty = self._dst_capa_ty(instr.dst)
        if dst_ty == "String":
            # Payload packed as i64 (ptr low / len high). Unpack
            # into dst's (ptr, len) locals.
            self._write("local.get $_m_scrut")
            self._write("i64.load offset=8")
            self._write("local.set $_alloc_tmp_i64")
            self._write("local.get $_alloc_tmp_i64")
            self._write("i32.wrap_i64")
            self._write(f"local.set ${instr.dst}_ptr")
            self._write("local.get $_alloc_tmp_i64")
            self._write("i64.const 32")
            self._write("i64.shr_u")
            self._write("i32.wrap_i64")
            self._write(f"local.set ${instr.dst}_len")
            return
        head_dst = dst_ty.split("<", 1)[0] if dst_ty else ""
        if head_dst in self._struct_layouts or head_dst in self._sum_layouts \
                or (dst_ty and dst_ty.startswith(("List", "Map", "Set"))):
            # Pointer-shaped payload stored as i64.extend; unpack.
            self._write("local.get $_m_scrut")
            self._write("i64.load offset=8")
            self._write("i32.wrap_i64")
            self._write(f"local.set ${instr.dst}")
            return
        # Scalar (Int / Bool / Float / Unit / Unknown). Dispatch
        # on the dst type rather than wasm_type so Unit doesn't
        # accidentally land on the Bool-narrowing path (Unit has
        # no real value; the Ok payload slot is a placeholder).
        self._write("local.get $_m_scrut")
        if dst_ty == "Float":
            self._write("f64.load offset=8")
        elif dst_ty == "Bool":
            self._write("i64.load offset=8")
            self._write("i32.wrap_i64")
        else:
            # Int / Unit / Unknown all stored as i64 in the slot;
            # the dst local was declared i64 by the locals sweep.
            self._write("i64.load offset=8")
        self._write(f"local.set ${instr.dst}")

    def _emit_binop(self, instr: BinOp) -> None:
        op = instr.op
        # Dispatch on operand type: Float operands use f64.* opcodes,
        # String operands use ``$str_eq`` for equality, everything
        # else stays on the i64 / i32 path.
        is_string = instr.left.ty == "String" or instr.right.ty == "String"
        if is_string and op == "==":
            self._push_string_value_as_ptr_len(instr.left)
            self._push_string_value_as_ptr_len(instr.right)
            self._write("call $str_eq")
            self._write(f"local.set ${instr.dst}")
            return
        if is_string and op == "!=":
            self._push_string_value_as_ptr_len(instr.left)
            self._push_string_value_as_ptr_len(instr.right)
            self._write("call $str_eq")
            self._write("i32.eqz")
            self._write(f"local.set ${instr.dst}")
            return
        if is_string and op == "+":
            # Concatenate two strings. Allocates a fresh buffer of
            # combined length, memory.copies each source.
            self._emit_string_concat(instr)
            return
        if is_string:
            raise WasmEmissionError(
                f"String operator {op!r} not supported at the Wasm level"
            )
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
        # Bool == / != use the i32 comparison opcodes; the default
        # _CMP_BINOP table is keyed for i64 (Int). Consult effective
        # types so binders typed Unknown route via fn.locals.
        left_ty = self._effective_value_ty(instr.left)
        right_ty = self._effective_value_ty(instr.right)
        if op in _CMP_BINOP and (left_ty == "Bool" or right_ty == "Bool"):
            if op not in ("==", "!="):
                raise WasmEmissionError(
                    f"Bool operands do not support {op!r} (only "
                    f"== and != are defined for Bool comparisons)"
                )
            self._push_value(instr.left)
            self._push_value(instr.right)
            self._write("i32.eq" if op == "==" else "i32.ne")
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
        """Lower a Capa-level function call. Three flavours share this
        path because the IR's lowerer represents them all as ``Call``:

        - **Variant construction** (``Circle(5)`` etc.).
        - **Closure call** (callee is a local or param of Fun(...) type):
          unpack env_ptr + fn_idx from the closure i64 and dispatch
          via ``call_indirect``.
        - **Ordinary function call**: push non-capability args, ``call
          $name``, bind the result.

        Capability-typed args are always skipped (capabilities flow
        through module-level imports, not as values)."""
        if instr.callee_name in self._variant_to_sum:
            self._emit_variant_construction(instr)
            return
        # Built-in free functions that route through host bridges.
        # parse_json / to_json take String / JsonValue and would
        # otherwise miss the ``call $<name>`` path because no Capa
        # function declares them.
        if instr.callee_name == "parse_json":
            self._emit_call_host_json_parse(instr)
            return
        if instr.callee_name == "to_json":
            self._emit_call_host_json_to_string(instr)
            return
        # parse_int / parse_float route to runtime helpers
        # ($parse_int / $parse_float). The arg is a String pushed
        # as (ptr, len); the return is an Option<Int> / Option<Float>
        # pointer.
        if instr.callee_name in ("parse_int", "parse_float") \
                and len(instr.args) == 1:
            arg = instr.args[0]
            if arg.kind == "lit_str":
                offset, length = self._intern_string(arg.literal)
                self._write(f"i32.const {offset}")
                self._write(f"i32.const {length}")
            else:
                self._push_string_value_as_ptr_len(arg)
            self._write(f"call ${instr.callee_name}")
            if instr.dst is not None:
                self._write(f"local.set ${instr.dst}")
            return
        # Numeric conversion intrinsics. These lower to one Wasm
        # instruction each; faster (and simpler) than a host bridge.
        if instr.callee_name == "to_float" and len(instr.args) == 1:
            self._push_value(instr.args[0])
            self._write("f64.convert_i64_s")
            if instr.dst is not None:
                self._write(f"local.set ${instr.dst}")
            return
        if instr.callee_name == "to_int" and len(instr.args) == 1:
            self._push_value(instr.args[0])
            self._write("i64.trunc_f64_s")
            if instr.dst is not None:
                self._write(f"local.set ${instr.dst}")
            return
        # Closure call: callee is a local / param of Fun type.
        callee_ty = self._lookup_local_or_param_ty(instr.callee_name)
        if callee_ty and callee_ty.startswith("Fun"):
            self._emit_closure_call(instr, callee_ty)
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
            # ``instr.dst``. Capability / Unit dsts have no Wasm
            # representation; String returns are multi-value
            # (i32 i32) and need to land in the dst's _ptr / _len
            # pair (in reverse stack order: len is on top, then ptr).
            if dst_ty == "String":
                self._write(f"local.set ${instr.dst}_len")
                self._write(f"local.set ${instr.dst}_ptr")
            elif dst_ty and dst_ty not in _BUILTIN_CAPS and dst_ty != "Unit":
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
            arg_head = arg.ty.split("<", 1)[0]
            is_pointer_shape = (
                arg_head in self._struct_layouts
                or arg_head in self._sum_layouts
                or arg.ty.startswith(("List", "Map", "Set"))
                # Variant constructors produce a sum-record pointer
                # (i32); the Value's ty carries the variant name
                # (e.g. "HelpRequested") rather than the sum name
                # (e.g. "ArgError"), so resolve via _variant_to_sum.
                or arg.ty in self._variant_to_sum
                or arg.kind == "variant_ctor"
            )
            if size == 8 and is_pointer_shape:
                # Pointer payload: extend i32 to i64.
                self._push_value(arg)
                self._write("i64.extend_i32_u")
                self._write(f"i64.store offset={offset}")
                continue
            if size == 8 and arg.ty == "Float":
                # Float payload stays as f64 in the slot.
                self._push_value(arg)
                self._write(f"f64.store offset={offset}")
                continue
            if arg.ty == "Unit" or arg.kind == "lit_unit":
                # Unit values have no Wasm representation;
                # _push_value is a no-op. Write a placeholder zero
                # into the slot so it stays deterministically
                # initialised. The dst addr was already pushed at
                # the top of this iteration.
                self._write("i64.const 0")
                self._write(f"i64.store offset={offset}")
                continue
            self._push_value(arg)
            self._write(f"{_store_op_for_size(size)} offset={offset}")

    def _emit_make_struct(self, instr: MakeStruct) -> None:
        """Emit alloc + per-field store for a struct literal. The
        pointer to the newly-allocated struct lands in ``instr.dst``.
        Field order follows the declaration; the lowerer guarantees
        ``instr.fields`` matches.

        String fields are stored as two adjacent i32s (ptr@offset,
        len@offset+4) so the FieldAccess emitter can recover the
        pair without unpacking. Other field types use the regular
        size-dispatched store."""
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
            offset, size, field_ty = f_info
            if field_ty in _BUILTIN_CAPS:
                # Capability field: erased at the Wasm level. The
                # slot exists in the struct layout (so subsequent
                # FieldAccess on it returns *something*), but no
                # value is stored; the FieldAccess emitter knows
                # not to read from a capability-typed field. We
                # could omit the slot entirely, but keeping it
                # makes layouts uniform with the analyzer's view.
                continue
            if field_ty == "String":
                # Two i32 stores: ptr at offset, len at offset+4.
                self._write(f"local.get ${instr.dst}")
                self._push_string_field_ptr_only(fval)
                self._write(f"i32.store offset={offset}")
                self._write(f"local.get ${instr.dst}")
                self._push_string_field_len_only(fval)
                self._write(f"i32.store offset={offset + 4}")
                continue
            self._write(f"local.get ${instr.dst}")
            self._push_value(fval)
            if field_ty == "Float":
                # f64 field stays as a native f64 slot; using
                # ``i64.store`` here would trip the Wasm validator
                # because ``_push_value`` left an f64 on the stack.
                self._write(f"f64.store offset={offset}")
            else:
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
            # Analyzer-side type-propagation gap: the FieldAccess's
            # receiver Value sometimes carries ``ty="Unknown"`` even
            # though the receiver itself is a local with a concrete
            # struct type recorded in fn.locals. Fall back to the
            # local's declared type before giving up.
            if (instr.receiver.kind in ("local", "param")
                    and self._current_fn is not None
                    and instr.receiver.name in self._current_fn.locals):
                fallback = self._current_fn.locals[instr.receiver.name]
                layout = self._struct_layouts.get(fallback)
                if layout is not None:
                    recv_ty = fallback
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
        if field_ty in _BUILTIN_CAPS:
            # Capability field: erased at the Wasm level. The dst
            # local has no Wasm representation either; consumers
            # that need to invoke a method on the capability route
            # to the imported function by name without reading the
            # receiver value.
            return
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
        if field_ty == "Float":
            # f64 slot: load the native f64, not an i64 reinterp.
            self._write(f"f64.load offset={offset}")
        else:
            self._write(f"{_load_op_for_size(size)} offset={offset}")
        self._write(f"local.set ${instr.dst}")

    def _size_of(self, capa_ty: str) -> int:
        """Wrapper around the module-level ``_size_of`` that
        consults the emitter's known struct/sum layouts."""
        return _size_of(capa_ty, self._sum_layouts, self._struct_layouts)

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

    def _lookup_local_or_param_ty(self, name: str) -> Optional[str]:
        """Find ``name`` in the current function's locals or
        params and return its Capa type string, or None if not
        present. Used by ``_emit_user_call`` to detect closure
        callees (callee_name is a local of Fun(...) type) before
        falling back to the ``call $name`` path for top-level
        functions."""
        if self._current_fn is None:
            return None
        ty = self._current_fn.locals.get(name)
        if ty is not None:
            return ty
        for p in self._current_fn.params:
            if p.name == name:
                return p.ty
        return None

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

    def _effective_value_ty(self, v: Value) -> str:
        """Resolve a Value's effective Capa type. The IR sometimes
        carries Unknown on Values captured at lowering time before
        the analyzer's type info reached them (impl-method ``self``,
        pattern binders for builtin sum-type variants). When the
        Value is a local or param, consult fn.locals for a
        refined entry, fall back to the param list, and only then
        accept the raw v.ty.

        Returns the empty string when nothing concrete is
        recoverable; callers should treat that as Unknown."""
        ty = v.ty or ""
        if ty and ty not in ("Unknown", "?") and not ty.startswith("?"):
            return ty
        if v.kind in ("local", "param") and self._current_fn is not None:
            from_locals = self._current_fn.locals.get(v.name, "")
            if from_locals and from_locals not in ("Unknown", "?"):
                return from_locals
            for p in self._current_fn.params:
                if p.name == v.name and p.ty and p.ty not in ("Unknown", "?"):
                    return p.ty
        return ty

    # ----- value pushing ----------------------------------------

    def _push_value(self, v: Value) -> None:
        """Emit the instruction(s) that push a Value onto the Wasm
        operand stack. Wasm has no concept of "Value" the way the
        IR does; every operation reads from the stack.

        Inside a lifted lambda body, captured locals load from the
        env record at their layout offset instead of a Wasm local.
        Non-String types use the standard size-dispatched load;
        String captures route through ``_push_string_value_as_ptr_len``
        which has its own env-aware path."""
        if v.kind in ("local", "param") and v.name in self._current_captures:
            offset, capa_ty = self._current_captures[v.name]
            if capa_ty != "String":
                self._write("local.get $env")
                size = self._size_of(capa_ty)
                self._write(f"{_load_op_for_size(size)} offset={offset}")
                return
        if v.kind == "global" and v.name in self._const_values:
            # Module-level constant: inline the RHS literal at the
            # use site. Recurse into the literal Value via the same
            # push path so the lit_int / lit_bool / lit_str / etc.
            # cases below handle the actual emission.
            self._push_value(self._const_values[v.name])
            return
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
        if v.kind == "lit_str":
            # String literal pushed as a packed i64 (ptr |
            # (len << 32)). Callers that need (ptr, len) as two
            # i32s should use _push_string_value_as_ptr_len
            # explicitly; the packed form here is what every
            # uniform 8-byte slot expects (tuple slot, Map value
            # slot, variant payload slot).
            offset, length = self._intern_string(v.literal)
            self._write(f"i64.const {offset | (length << 32)}")
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
        # ``()`` is Capa's empty-tuple / Unit alias from the type
        # printer; treat it the same as Unit (no Wasm result).
        if capa_ty == "()":
            return ""
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
        # Closures are packed i64: (fn_idx << 32) | env_ptr.
        if capa_ty.startswith("Fun"):
            return "i64"
        # User-defined trait / capability with a unique impl:
        # values are i32 pointers to the impl's struct.
        if head in self._trait_to_impl:
            return "i32"
        # Tuples render as ``(T1, T2, ...)``. Stored on the heap
        # as 16-byte records (one uniform 8-byte slot per element
        # for up to 2 elements; arities other than 2 are deferred).
        if capa_ty.startswith("(") and capa_ty.endswith(")"):
            return "i32"
        # Payloadless variant values (e.g. ``Low`` for a Severity
        # sum) carry the variant name as their .ty rather than the
        # parent sum name. Resolve via _variant_to_sum.
        if head in self._variant_to_sum:
            return "i32"
        # Unresolved tyvars (``?`` or analyzer's ``?lst_N``) default
        # to i64 so the Wasm verifier accepts the local declaration;
        # callers that use the local with a wrong type will surface
        # the issue at instruction emission time.
        if capa_ty.startswith("?") or capa_ty in ("Unknown", ""):
            return "i64"
        raise WasmEmissionError(
            f"Capa type {capa_ty!r} has no Wasm encoding yet"
        )

    def _write(self, line: str) -> None:
        if line == "":
            self._lines.append("")
        else:
            self._lines.append(self._unit * self._indent + line)
