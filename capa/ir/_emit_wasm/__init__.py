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
    If, While, Break, Continue, Return,
    MakeStruct, MakeList, MakeMap, MakeSet, FieldAccess, Index, For,
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
    _OPTION_LAYOUT, _RESULT_LAYOUT, _IOERROR_LAYOUT,
    _map_value_type, _element_type_of_list,
    _size_of, _store_op_for_size, _load_op_for_size, _align_up,
    compute_struct_layout, compute_sum_layout,
)
from ._runtime import _RuntimeHelpersMixin
from ._match import _MatchEmissionMixin
from ._strings import _StringEmissionMixin
from ._maps import _MapEmissionMixin
from ._lists import _ListEmissionMixin


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
        # Closure infrastructure: function table + (type) decls +
        # each lifted lambda is a top-level function below.
        if self._lifted_lambdas:
            self._emit_closure_types_and_table()
            for lifted in self._lifted_lambdas:
                self._emit_lifted_lambda(lifted)
        # Stage 2: emit each function.
        for fn in module.functions:
            self._emit_function(fn)
        self._indent -= 1
        self._write(")")
        return "\n".join(self._lines) + "\n"

    def _emit_closure_types_and_table(self) -> None:
        """Emit the ``(type $sig_N ...)`` declarations for every
        unique closure signature, then a single ``(table $fnref
        N N funcref)`` + ``(elem ...)`` to populate the function
        table with the lifted lambda names. The order of elem
        entries matches each lambda's ``fn_idx``."""
        # Sort by sig_idx for determinism.
        sig_pairs = sorted(self._closure_sig_keys.items(), key=lambda kv: kv[1])
        for sig_key, sig_idx in sig_pairs:
            # ``sig_key`` is "(<params>) -> <result>"; convert to
            # WAT ``(type $sig_N (func (param ...) (result ...)))``
            params_part, _, result_part = sig_key.partition(") -> ")
            params_part = params_part.lstrip("(")
            param_clauses = "".join(
                f" (param {t})" for t in params_part.split()
            )
            result_clause = (
                f" (result {result_part})"
                if result_part and result_part != "()"
                else ""
            )
            self._write(
                f"(type $sig_{sig_idx} (func{param_clauses}{result_clause}))"
            )
        n = len(self._lifted_lambdas)
        self._write(f"(table $fnref {n} {n} funcref)")
        names = " ".join(f"${l['name']}" for l in self._lifted_lambdas)
        self._write(f"(elem (i32.const 0) {names})")

    def _emit_lifted_lambda(self, lifted: dict) -> None:
        """Emit a top-level Wasm function for a lifted lambda.
        The first param is always ``$env`` (i32 pointer to the
        env record, or 0 for no-capture lambdas). Body emission
        uses ``self._current_captures`` so captured local
        references load from env instead of looking up a Wasm
        local that does not exist."""
        # Save outer state.
        prev_fn = self._current_fn
        prev_captures = self._current_captures
        prev_block_counter = self._block_counter
        prev_loop_labels = self._loop_labels

        # Synthesise a fn-shaped record so existing
        # _collect_locals / _emit_instr paths consult the right
        # ``fn.locals`` (we use ``Function`` with an empty
        # ``locals`` dict + the lambda's own params + the body).
        synth_fn = Function(
            name=lifted["name"],
            params=lifted["params"],
            return_type=lifted["return_type"] or "Unit",
            declared_caps=[],
            body=lifted["body"],
            locals=lifted["locals"],
        )
        self._current_fn = synth_fn
        self._current_captures = lifted["captures"]
        self._block_counter = 0
        self._loop_labels = []

        # Header.
        param_clauses = ["(param $env i32)"]
        for p in lifted["params"]:
            ty = self._wasm_type(p.ty)
            if p.ty == "String":
                param_clauses.append(f"(param ${p.name}_ptr i32)")
                param_clauses.append(f"(param ${p.name}_len i32)")
            else:
                param_clauses.append(f"(param ${p.name} {ty})")
        params_str = " ".join(param_clauses)
        result_str = (
            f" (result {lifted['result_wasm_ty']})"
            if lifted["result_wasm_ty"] else ""
        )
        self._write(
            f"(func ${lifted['name']} (type $sig_{lifted['sig_idx']}) "
            f"{params_str}{result_str}"
        )
        self._indent += 1
        # Declare locals. Same logic as a regular function: walk
        # body for every introduced dst.
        param_names = {p.name for p in lifted["params"]} | {"env"}
        local_decls = self._collect_locals(synth_fn, param_names)
        for name, ty in local_decls.items():
            self._write(f"(local ${name} {ty})")
        for instr in lifted["body"]:
            self._emit_instr(instr)
        if lifted["result_wasm_ty"]:
            self._write("unreachable")
        self._indent -= 1
        self._write(")")

        # Restore outer state.
        self._current_fn = prev_fn
        self._current_captures = prev_captures
        self._block_counter = prev_block_counter
        self._loop_labels = prev_loop_labels


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

    def _discover_lambdas(self, module: Module) -> None:
        """Walk every function's body, collect MakeLambda
        instructions, compute the env layout + signature for each
        and assign fn_idx (function table index). Also intern
        strings that appear in lambda bodies; discovery passes
        normally see the function body, but MakeLambda bodies are
        a separate Instr list.

        Lambdas inside lambdas are rejected here -- nested closure
        records would need an env-of-env shape that Phase 6E does
        not support."""

        def visit(instrs: list[Instr], parent_fn: Function, inside_lambda: bool) -> None:
            for instr in instrs:
                if isinstance(instr, MakeLambda):
                    if inside_lambda:
                        raise WasmEmissionError(
                            "Phase 6E: lambdas inside lambdas are "
                            "not supported (would need env-of-env)"
                        )
                    self._register_lambda(instr, parent_fn)
                # Discover-time string interning for the lambda body
                # has already been handled by ``_discover`` -- it
                # walks parent_fn.body and intern_strings any
                # ``lit_str`` Values it finds. MakeLambda's body is
                # NOT a child of parent_fn.body for that walk, so
                # we re-walk it here:
                if isinstance(instr, MakeLambda):
                    self._discover_instrs(instr.body)
                    visit(instr.body, parent_fn, True)
                if isinstance(instr, If):
                    visit(instr.then_body, parent_fn, inside_lambda)
                    visit(instr.else_body, parent_fn, inside_lambda)
                elif isinstance(instr, While):
                    visit(instr.cond_setup, parent_fn, inside_lambda)
                    visit(instr.body, parent_fn, inside_lambda)
                elif isinstance(instr, For):
                    visit(instr.body, parent_fn, inside_lambda)
                elif isinstance(instr, Match):
                    for arm in instr.arms:
                        visit(arm.body, parent_fn, inside_lambda)

        for fn in module.functions:
            visit(fn.body, fn, False)

    def _register_lambda(self, instr: MakeLambda, parent_fn: Function) -> None:
        """Compute captures + env layout + signature for one
        lambda; append the resulting record to ``_lifted_lambdas``
        and assign it an fn_idx."""
        # ------- free-variable analysis -------
        own_params: set[str] = {p.name for p in instr.params}
        defined_in_body: set[str] = set()

        def collect_defs(instrs: list[Instr]) -> None:
            for i in instrs:
                dst = getattr(i, "dst", None)
                if dst:
                    defined_in_body.add(dst)
                if isinstance(i, For):
                    defined_in_body.add(i.name)
                    collect_defs(i.body)
                elif isinstance(i, If):
                    collect_defs(i.then_body)
                    collect_defs(i.else_body)
                elif isinstance(i, While):
                    collect_defs(i.cond_setup)
                    collect_defs(i.body)
                elif isinstance(i, Match):
                    for arm in i.arms:
                        collect_defs(arm.body)
                        # Pattern-bound names also count as defined.
                        self._collect_pattern_names(arm.pattern, defined_in_body)

        collect_defs(instr.body)

        referenced: set[str] = set()

        def collect_refs(v: Value) -> None:
            if v.kind in ("local", "param") and v.name:
                referenced.add(v.name)

        def visit_for_refs(instrs: list[Instr]) -> None:
            for i in instrs:
                for v in self._values_of(i):
                    collect_refs(v)
                if isinstance(i, If):
                    collect_refs(i.cond)
                    visit_for_refs(i.then_body)
                    visit_for_refs(i.else_body)
                elif isinstance(i, While):
                    visit_for_refs(i.cond_setup)
                    collect_refs(i.cond)
                    visit_for_refs(i.body)
                elif isinstance(i, For):
                    collect_refs(i.iter)
                    visit_for_refs(i.body)
                elif isinstance(i, Match):
                    collect_refs(i.scrutinee)
                    for arm in i.arms:
                        visit_for_refs(arm.body)

        visit_for_refs(instr.body)

        captures_names = (referenced - defined_in_body - own_params)

        # ------- env layout -------
        env_layout: dict[str, tuple[int, str]] = {}
        offset = 0
        # Sort for deterministic layouts (helps debugging + tests).
        for name in sorted(captures_names):
            capa_ty = (
                parent_fn.locals.get(name)
                or self._params_lookup(parent_fn, name)
                or "Unknown"
            )
            if capa_ty in _BUILTIN_CAPS:
                # Capability captures are free at the Wasm level.
                continue
            size = self._size_of(capa_ty)
            offset = _align_up(offset, size)
            env_layout[name] = (offset, capa_ty)
            offset += size
        env_size = _align_up(offset, 8) if offset > 0 else 0

        # ------- signature -------
        # ``(param i32) (param ...) -> (result ...)`` rendered as
        # a stable string so duplicates dedupe.
        param_wasm_tys = []
        param_wasm_tys.append("i32")  # env_ptr always first
        for p in instr.params:
            t = self._wasm_type(p.ty)
            if not t:
                raise WasmEmissionError(
                    f"lambda param {p.name!r} has Unit type, which "
                    f"has no Wasm encoding"
                )
            param_wasm_tys.append(t)
        result_ty = (
            self._wasm_type(instr.return_type) if instr.return_type else ""
        )
        sig_key = f"({' '.join(param_wasm_tys)}) -> {result_ty or '()'}"
        if sig_key not in self._closure_sig_keys:
            self._closure_sig_keys[sig_key] = len(self._closure_sig_keys)
        sig_idx = self._closure_sig_keys[sig_key]

        # Copy out the body's locals from the parent function's
        # locals dict so the synthesised lifted function carries
        # precise types for ``_collect_locals``.
        body_locals: dict[str, str] = {}
        for name in defined_in_body:
            if name in parent_fn.locals:
                body_locals[name] = parent_fn.locals[name]

        fn_idx = len(self._lifted_lambdas)
        lifted_name = f"lambda_{fn_idx}"
        self._lifted_lambdas.append({
            "name": lifted_name,
            "params": list(instr.params),
            "return_type": instr.return_type,
            "body": instr.body,
            "locals": body_locals,
            "captures": env_layout,
            "env_size": env_size,
            "param_wasm_tys": param_wasm_tys,
            "result_wasm_ty": result_ty,
            "sig_key": sig_key,
            "sig_idx": sig_idx,
            "fn_idx": fn_idx,
        })
        self._lambda_by_dst[(parent_fn.name, instr.dst)] = fn_idx

    def _collect_pattern_names(self, pat: Pattern, out: set[str]) -> None:
        if isinstance(pat, PatIdent):
            out.add(pat.name)
            return
        if isinstance(pat, PatVariant):
            for sub in pat.payloads:
                self._collect_pattern_names(sub, out)
            return
        # PatWildcard / PatLiteral introduce no names.

    @staticmethod
    def _params_lookup(fn: Function, name: str) -> Optional[str]:
        for p in fn.params:
            if p.name == name:
                return p.ty
        return None

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

        def value_uses_variant_ctor(v: Value) -> bool:
            return v is not None and v.kind == "variant_ctor"

        def visit(instrs: list[Instr]) -> None:
            nonlocal has_match, has_variant_ctor, has_list, has_for
            nonlocal has_list_contains_i64, has_map, has_string_method
            nonlocal has_format_str, has_make_lambda, has_list_hof
            for instr in instrs:
                if isinstance(instr, Match):
                    has_match = True
                    for arm in instr.arms:
                        visit(arm.body)
                if isinstance(instr, MakeList):
                    has_list = True
                if isinstance(instr, MakeMap):
                    has_map = True
                if isinstance(instr, MakeLambda):
                    has_make_lambda = True
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
                    if recv_ty.startswith("List") and instr.method in (
                        "map", "filter", "fold",
                    ):
                        has_list_hof = True
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
        if has_list_contains_i64 or has_map or has_match or has_for:
            # The i64 scratch is shared by: List.contains for i64
            # elements, Map scan (value packing), match-arm String
            # unpacking, and for-iter over List<String> (where the
            # element slot is a packed i64).
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
        if isinstance(instr, MakeLambda):
            self._emit_make_lambda(instr)
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

    # ----- lambdas / closures -----------------------------------

    def _emit_make_lambda(self, instr: MakeLambda) -> None:
        """Materialise a closure value for ``instr.dst``. If the
        lambda captures any non-capability locals, allocate an env
        record on the heap and store each capture's bits at its
        layout offset. Pack (fn_idx, env_ptr) into an i64 and bind
        the dst.

        Captures of String locals store two i32s (ptr, len). Other
        types store via the size-dispatched store opcode."""
        # The discovery pass keyed lifted lambdas by
        # (parent_fn_name, dst); use the current function's name
        # to disambiguate when multiple functions reuse the same
        # ``_ir_lambdaN`` dst (the IR's fresh-local counter resets
        # per function).
        parent_name = self._current_fn.name if self._current_fn else ""
        fn_idx = self._lambda_by_dst.get((parent_name, instr.dst))
        if fn_idx is None:
            raise WasmEmissionError(
                f"MakeLambda for {instr.dst!r} not registered by the "
                f"discover pass; lifted-lambda table is out of sync"
            )
        lifted = self._lifted_lambdas[fn_idx]
        env_size = lifted["env_size"]
        env_layout = lifted["captures"]
        if env_size > 0:
            self._write(f"i32.const {env_size}")
            self._write("call $alloc")
            self._write("local.set $_lam_env_tmp")
            # Store each capture.
            for name, (offset, capa_ty) in env_layout.items():
                if capa_ty == "String":
                    self._write("local.get $_lam_env_tmp")
                    self._write(f"local.get ${name}_ptr")
                    self._write(f"i32.store offset={offset}")
                    self._write("local.get $_lam_env_tmp")
                    self._write(f"local.get ${name}_len")
                    self._write(f"i32.store offset={offset + 4}")
                else:
                    size = self._size_of(capa_ty)
                    self._write("local.get $_lam_env_tmp")
                    self._write(f"local.get ${name}")
                    self._write(f"{_store_op_for_size(size)} offset={offset}")
        else:
            self._write("i32.const 0")
            self._write("local.set $_lam_env_tmp")
        # Pack closure: (fn_idx_i64 << 32) | env_ptr_i64
        self._write(f"i64.const {fn_idx}")
        self._write("i64.const 32")
        self._write("i64.shl")
        self._write("local.get $_lam_env_tmp")
        self._write("i64.extend_i32_u")
        self._write("i64.or")
        self._write(f"local.set ${instr.dst}")

    def _emit_closure_call(self, instr: Call, callee_ty: str) -> None:
        """Invoke a closure value (i64) via call_indirect. The
        closure carries fn_idx (high 32) and env_ptr (low 32).
        Push env_ptr first, then user-level args, then fn_idx;
        call_indirect with the matching ``(type $sig_N)``."""
        # Look up the lambda's signature. We don't have the exact
        # sig_idx without referencing one of the lifted lambdas;
        # take the first lambda whose result_wasm_ty + param_wasm_tys
        # match the callee's Capa type. For Phase 6E we trust the
        # IR's typing: callee_ty is "Fun(<args>) -> <result>", so
        # we parse it back to a sig key.
        sig_key = self._fun_type_to_sig_key(callee_ty)
        sig_idx = self._closure_sig_keys.get(sig_key)
        if sig_idx is None:
            raise WasmEmissionError(
                f"closure call of type {callee_ty!r} has no matching "
                f"sig in the lifted-lambda table (key {sig_key!r})"
            )
        # Push env_ptr (first arg of the lifted lambda).
        self._push_value(Value(kind="local", name=instr.callee_name, ty=callee_ty))
        self._write("i32.wrap_i64")
        # Push the user-level args.
        for arg in instr.args:
            if arg.ty in _BUILTIN_CAPS:
                continue
            if arg.ty == "String":
                self._push_string_value_as_ptr_len(arg)
            else:
                self._push_value(arg)
        # Push fn_idx (top of stack for call_indirect).
        self._push_value(Value(kind="local", name=instr.callee_name, ty=callee_ty))
        self._write("i64.const 32")
        self._write("i64.shr_u")
        self._write("i32.wrap_i64")
        self._write(f"call_indirect (type $sig_{sig_idx})")
        if instr.dst is not None:
            dst_ty = self._dst_capa_ty(instr.dst)
            if dst_ty and dst_ty not in _BUILTIN_CAPS and dst_ty not in ("Unit",):
                if dst_ty == "String":
                    self._set_string_dst(instr.dst)
                else:
                    self._write(f"local.set ${instr.dst}")

    def _fun_type_to_sig_key(self, capa_ty: str) -> str:
        """Convert ``"Fun(Int, Int) -> Int"`` -> ``"(i32 i64 i64) -> i64"``.
        The leading i32 is for the env_ptr (always first param of
        a lifted lambda). Used at closure-call sites to find the
        matching sig_idx."""
        # Strip the leading "Fun" and outer parens.
        if not capa_ty.startswith("Fun"):
            raise WasmEmissionError(
                f"expected Fun type, got {capa_ty!r}"
            )
        rest = capa_ty[3:].strip()
        if not rest.startswith("("):
            raise WasmEmissionError(
                f"malformed Fun type {capa_ty!r}; expected ``Fun(...) -> R``"
            )
        # Find matching close paren accounting for nested parens.
        depth = 0
        close_idx = -1
        for i, ch in enumerate(rest):
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    close_idx = i
                    break
        if close_idx < 0:
            raise WasmEmissionError(
                f"unbalanced parens in Fun type {capa_ty!r}"
            )
        params_str = rest[1:close_idx]
        tail = rest[close_idx + 1:].strip()
        if tail.startswith("->"):
            ret_ty_str = tail[2:].strip()
        else:
            ret_ty_str = ""
        # Each param is a Capa type; split on top-level commas.
        param_capa_tys: list[str] = []
        if params_str.strip():
            buf = ""
            d = 0
            for ch in params_str:
                if ch in "(<":
                    d += 1
                elif ch in ")>":
                    d -= 1
                if ch == "," and d == 0:
                    param_capa_tys.append(buf.strip())
                    buf = ""
                    continue
                buf += ch
            if buf.strip():
                param_capa_tys.append(buf.strip())
        # Build wasm sig: env_ptr + each param + result.
        wasm_params = ["i32"]
        for pt in param_capa_tys:
            if pt == "String":
                wasm_params.append("i32")
                wasm_params.append("i32")
            else:
                wasm_params.append(self._wasm_type(pt))
        wasm_result = (
            self._wasm_type(ret_ty_str) if ret_ty_str else ""
        )
        return f"({' '.join(wasm_params)}) -> {wasm_result or '()'}"

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

    # ----- list HOFs (closures) ---------------------------------

    def _emit_list_hof(self, instr: MethodCall, elem_ty: str) -> None:
        """Emit a Phase 6E HOF (map / filter / fold) for a
        ``List<Int>`` receiver. The closure argument is unpacked
        per element and invoked via ``call_indirect``.

        Phase 6E ships only List<Int>; other element types raise."""
        if elem_ty != "Int":
            raise WasmEmissionError(
                f"Phase 6E: List<{elem_ty}>.{instr.method} not supported "
                f"(only List<Int> HOFs)"
            )
        if instr.method == "map":
            self._emit_list_map(instr)
            return
        if instr.method == "filter":
            self._emit_list_filter(instr)
            return
        if instr.method == "fold":
            self._emit_list_fold(instr)
            return
        raise WasmEmissionError(
            f"unhandled List HOF {instr.method!r}"
        )

    def _emit_invoke_closure(
        self, closure_value: Value, elem_pushes: list[str],
        sig_key: str,
    ) -> None:
        """Emit the (env, args, fn_idx) push + call_indirect for a
        closure value, given pre-emitted instruction strings for
        each non-env arg in ``elem_pushes``. The closure value
        ``closure_value`` is an i64; the sig is looked up by
        ``sig_key``.

        Lower-level helper used by the HOF dispatchers."""
        sig_idx = self._closure_sig_keys.get(sig_key)
        if sig_idx is None:
            raise WasmEmissionError(
                f"no closure sig {sig_key!r} registered"
            )
        # env_ptr (low 32 bits)
        self._push_value(closure_value)
        self._write("i32.wrap_i64")
        # args
        for s in elem_pushes:
            self._write(s)
        # fn_idx (high 32 bits)
        self._push_value(closure_value)
        self._write("i64.const 32")
        self._write("i64.shr_u")
        self._write("i32.wrap_i64")
        self._write(f"call_indirect (type $sig_{sig_idx})")

    def _emit_list_map(self, instr: MethodCall) -> None:
        """``xs.map(f) -> List<Int>``: allocate a new list of same
        length, iterate xs and store f(xs[i]) at new[i]."""
        recv = instr.receiver
        f_arg = instr.args[0]
        dst = instr.dst
        if dst is None:
            return
        # Sig: env_ptr (i32) + i64 -> i64
        sig_key = "(i32 i64) -> i64"
        if sig_key not in self._closure_sig_keys:
            raise WasmEmissionError(
                f"List.map: no lambda registered with sig {sig_key!r}"
            )
        # Save xs and the closure in scratch locals.
        self._push_value(recv)
        self._write("local.set $_m_scrut")
        self._push_value(f_arg)
        self._write("local.set $_lam_fn_tmp")
        # len = xs.length()
        self._write("local.get $_m_scrut")
        self._write(f"i32.load offset={_LIST_LEN_OFFSET}")
        self._write("local.set $_m_tag")
        # Allocate new list header.
        self._write(f"i32.const {_LIST_HEADER_SIZE}")
        self._write("call $alloc")
        self._write(f"local.set ${dst}")
        # Allocate data array = len * 8 bytes.
        self._write("local.get $_m_tag")
        self._write("i32.const 8")
        self._write("i32.mul")
        self._write("call $alloc")
        self._write("local.set $_alloc_tmp")
        # Store len, cap, data_ptr into header.
        self._write(f"local.get ${dst}")
        self._write("local.get $_m_tag")
        self._write(f"i32.store offset={_LIST_LEN_OFFSET}")
        self._write(f"local.get ${dst}")
        self._write("local.get $_m_tag")
        self._write(f"i32.store offset={_LIST_CAP_OFFSET}")
        self._write(f"local.get ${dst}")
        self._write("local.get $_alloc_tmp")
        self._write(f"i32.store offset={_LIST_DATA_OFFSET}")
        # Iterate i = 0 .. len.
        self._write("i32.const 0")
        self._write("local.set $_lam_idx")
        self._block_counter += 1
        loop = f"$Hmap{self._block_counter}_loop"
        exit_ = f"$Hmap{self._block_counter}_exit"
        self._write(f"block {exit_}")
        self._indent += 1
        self._write(f"loop {loop}")
        self._indent += 1
        self._write("local.get $_lam_idx")
        self._write("local.get $_m_tag")
        self._write("i32.ge_s")
        self._write(f"br_if {exit_}")
        # Load xs[i] (i64 element).
        self._write("local.get $_m_scrut")
        self._write(f"i32.load offset={_LIST_DATA_OFFSET}")
        self._write("local.get $_lam_idx")
        self._write("i32.const 8")
        self._write("i32.mul")
        self._write("i32.add")
        self._write("i64.load")
        self._write("local.set $_alloc_tmp_i64")
        # new[i] = f(env, xs[i]); compute address first.
        self._write("local.get $_alloc_tmp")  # data_ptr
        self._write("local.get $_lam_idx")
        self._write("i32.const 8")
        self._write("i32.mul")
        self._write("i32.add")
        # Push closure call args.
        sig_idx = self._closure_sig_keys[sig_key]
        # env_ptr
        self._write("local.get $_lam_fn_tmp")
        self._write("i32.wrap_i64")
        # the element (i64)
        self._write("local.get $_alloc_tmp_i64")
        # fn_idx
        self._write("local.get $_lam_fn_tmp")
        self._write("i64.const 32")
        self._write("i64.shr_u")
        self._write("i32.wrap_i64")
        self._write(f"call_indirect (type $sig_{sig_idx})")
        self._write("i64.store")
        # i++
        self._write("local.get $_lam_idx")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $_lam_idx")
        self._write(f"br {loop}")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")

    def _emit_list_filter(self, instr: MethodCall) -> None:
        """``xs.filter(p) -> List<Int>``: iterate xs, push elements
        where the predicate returns nonzero into a fresh list."""
        recv = instr.receiver
        p_arg = instr.args[0]
        dst = instr.dst
        if dst is None:
            return
        # Sig: env_ptr (i32) + i64 -> i32 (Bool result)
        sig_key = "(i32 i64) -> i32"
        if sig_key not in self._closure_sig_keys:
            raise WasmEmissionError(
                f"List.filter: no lambda registered with sig {sig_key!r}"
            )
        self._push_value(recv)
        self._write("local.set $_m_scrut")
        self._push_value(p_arg)
        self._write("local.set $_lam_fn_tmp")
        # New empty list with initial cap 8 -- _emit_list_push will
        # grow if needed.
        self._write(f"i32.const {_LIST_HEADER_SIZE}")
        self._write("call $alloc")
        self._write(f"local.set ${dst}")
        self._write(f"local.get ${dst}")
        self._write("i32.const 0")
        self._write(f"i32.store offset={_LIST_LEN_OFFSET}")
        self._write(f"local.get ${dst}")
        self._write("i32.const 8")
        self._write(f"i32.store offset={_LIST_CAP_OFFSET}")
        self._write("i32.const 64")  # 8 * 8 bytes
        self._write("call $alloc")
        self._write("local.set $_alloc_tmp")
        self._write(f"local.get ${dst}")
        self._write("local.get $_alloc_tmp")
        self._write(f"i32.store offset={_LIST_DATA_OFFSET}")
        # Iterate xs.
        self._write("i32.const 0")
        self._write("local.set $_lam_idx")
        self._write("local.get $_m_scrut")
        self._write(f"i32.load offset={_LIST_LEN_OFFSET}")
        self._write("local.set $_m_tag")
        self._block_counter += 1
        loop = f"$Hfilt{self._block_counter}_loop"
        exit_ = f"$Hfilt{self._block_counter}_exit"
        self._write(f"block {exit_}")
        self._indent += 1
        self._write(f"loop {loop}")
        self._indent += 1
        self._write("local.get $_lam_idx")
        self._write("local.get $_m_tag")
        self._write("i32.ge_s")
        self._write(f"br_if {exit_}")
        # Load element.
        self._write("local.get $_m_scrut")
        self._write(f"i32.load offset={_LIST_DATA_OFFSET}")
        self._write("local.get $_lam_idx")
        self._write("i32.const 8")
        self._write("i32.mul")
        self._write("i32.add")
        self._write("i64.load")
        self._write("local.set $_alloc_tmp_i64")
        # Call predicate.
        sig_idx = self._closure_sig_keys[sig_key]
        self._write("local.get $_lam_fn_tmp")
        self._write("i32.wrap_i64")
        self._write("local.get $_alloc_tmp_i64")
        self._write("local.get $_lam_fn_tmp")
        self._write("i64.const 32")
        self._write("i64.shr_u")
        self._write("i32.wrap_i64")
        self._write(f"call_indirect (type $sig_{sig_idx})")
        # If true, append to new list. Use the existing push helper
        # inline so grow + store happens correctly.
        self._write("if")
        self._indent += 1
        # Inline list.push: stash dst into _m_scrut briefly? The
        # push helper reads from receiver via _m_scrut, which we
        # have already used for xs. To avoid clobbering, we
        # inline a minimal push here that knows about i64 elems.
        self._emit_inline_int_list_push(dst, "_alloc_tmp_i64")
        self._indent -= 1
        self._write("end")
        # i++
        self._write("local.get $_lam_idx")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $_lam_idx")
        self._write(f"br {loop}")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")

    def _emit_inline_int_list_push(
        self, list_local: str, value_local: str,
    ) -> None:
        """Append an i64 value (in ``$<value_local>``) to the list
        whose pointer is in ``$<list_local>``. Grows the data
        array via memory.copy if at capacity. Distinct from
        ``_emit_list_push`` which expects the receiver as a Value
        and uses different scratch locals; this version reads from
        named locals so the filter loop can reuse it without
        clobbering its own scrutinee scratch."""
        # Load len, cap.
        self._write(f"local.get ${list_local}")
        self._write(f"i32.load offset={_LIST_LEN_OFFSET}")
        self._write("local.set $_lam_grow_len")
        self._write(f"local.get ${list_local}")
        self._write(f"i32.load offset={_LIST_CAP_OFFSET}")
        self._write("local.set $_lam_grow_cap")
        # if len >= cap, grow.
        self._write("local.get $_lam_grow_len")
        self._write("local.get $_lam_grow_cap")
        self._write("i32.ge_s")
        self._write("if")
        self._indent += 1
        # new_cap = max(cap * 2, 8)
        self._write("local.get $_lam_grow_cap")
        self._write("i32.const 2")
        self._write("i32.mul")
        self._write("local.tee $_lam_grow_cap")
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        self._write("i32.const 8")
        self._write("local.set $_lam_grow_cap")
        self._indent -= 1
        self._write("end")
        # new_data = alloc(new_cap * 8)
        self._write("local.get $_lam_grow_cap")
        self._write("i32.const 8")
        self._write("i32.mul")
        self._write("call $alloc")
        self._write("local.set $_lam_new_data")
        # memcpy(new_data, old_data, len * 8)
        self._write("local.get $_lam_new_data")
        self._write(f"local.get ${list_local}")
        self._write(f"i32.load offset={_LIST_DATA_OFFSET}")
        self._write("local.get $_lam_grow_len")
        self._write("i32.const 8")
        self._write("i32.mul")
        self._write("memory.copy")
        # store new data_ptr + cap
        self._write(f"local.get ${list_local}")
        self._write("local.get $_lam_new_data")
        self._write(f"i32.store offset={_LIST_DATA_OFFSET}")
        self._write(f"local.get ${list_local}")
        self._write("local.get $_lam_grow_cap")
        self._write(f"i32.store offset={_LIST_CAP_OFFSET}")
        self._indent -= 1
        self._write("end")
        # store at data[len]
        self._write(f"local.get ${list_local}")
        self._write(f"i32.load offset={_LIST_DATA_OFFSET}")
        self._write("local.get $_lam_grow_len")
        self._write("i32.const 8")
        self._write("i32.mul")
        self._write("i32.add")
        self._write(f"local.get ${value_local}")
        self._write("i64.store")
        # len++
        self._write(f"local.get ${list_local}")
        self._write("local.get $_lam_grow_len")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write(f"i32.store offset={_LIST_LEN_OFFSET}")

    def _emit_list_fold(self, instr: MethodCall) -> None:
        """``xs.fold(init, f) -> T`` (T = Int): start with init,
        for each element apply f(acc, x), bind dst to acc."""
        recv = instr.receiver
        init_arg = instr.args[0]
        f_arg = instr.args[1]
        dst = instr.dst
        if dst is None:
            return
        # Sig: env_ptr (i32) + i64 + i64 -> i64
        sig_key = "(i32 i64 i64) -> i64"
        if sig_key not in self._closure_sig_keys:
            raise WasmEmissionError(
                f"List.fold: no lambda registered with sig {sig_key!r}"
            )
        # acc = init
        self._push_value(init_arg)
        self._write(f"local.set ${dst}")
        # Save xs and closure.
        self._push_value(recv)
        self._write("local.set $_m_scrut")
        self._push_value(f_arg)
        self._write("local.set $_lam_fn_tmp")
        self._write("local.get $_m_scrut")
        self._write(f"i32.load offset={_LIST_LEN_OFFSET}")
        self._write("local.set $_m_tag")
        self._write("i32.const 0")
        self._write("local.set $_lam_idx")
        # Loop.
        self._block_counter += 1
        loop = f"$Hfold{self._block_counter}_loop"
        exit_ = f"$Hfold{self._block_counter}_exit"
        self._write(f"block {exit_}")
        self._indent += 1
        self._write(f"loop {loop}")
        self._indent += 1
        self._write("local.get $_lam_idx")
        self._write("local.get $_m_tag")
        self._write("i32.ge_s")
        self._write(f"br_if {exit_}")
        # Load element.
        self._write("local.get $_m_scrut")
        self._write(f"i32.load offset={_LIST_DATA_OFFSET}")
        self._write("local.get $_lam_idx")
        self._write("i32.const 8")
        self._write("i32.mul")
        self._write("i32.add")
        self._write("i64.load")
        self._write("local.set $_alloc_tmp_i64")
        # acc = f(env, acc, x)
        sig_idx = self._closure_sig_keys[sig_key]
        self._write("local.get $_lam_fn_tmp")
        self._write("i32.wrap_i64")
        self._write(f"local.get ${dst}")  # acc
        self._write("local.get $_alloc_tmp_i64")  # x
        self._write("local.get $_lam_fn_tmp")
        self._write("i64.const 32")
        self._write("i64.shr_u")
        self._write("i32.wrap_i64")
        self._write(f"call_indirect (type $sig_{sig_idx})")
        self._write(f"local.set ${dst}")
        # i++
        self._write("local.get $_lam_idx")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $_lam_idx")
        self._write(f"br {loop}")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")

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
        # Closures are packed i64: (fn_idx << 32) | env_ptr.
        if capa_ty.startswith("Fun"):
            return "i64"
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
