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
)
from ._emit_wit import _WIT_SIGNATURES, _KNOWN_CAPABILITIES


# Capa built-in capabilities. Receivers of these types route
# MethodCall instructions to imported Wasm functions rather than
# core method dispatch; their parameters carry no Wasm value.
_BUILTIN_CAPS = {"Stdio", "Fs", "Env", "Clock", "Net", "Random", "Proc", "Db", "Unsafe"}


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

    # ----- public ------------------------------------------------

    def emit(self, module: Module) -> str:
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
        if self._strings:
            self._write('(memory (export "memory") 1)')
            for text, (offset, _len) in sorted(
                self._strings.items(), key=lambda kv: kv[1][0],
            ):
                escaped = self._escape_wat_string(text)
                self._write(f'(data (i32.const {offset}) "{escaped}")')
        elif self._has_any_caps():
            # Even without literals, a capability that takes string
            # args may receive empty strings; export an empty memory
            # so the host's Linker can resolve the import shape.
            self._write('(memory (export "memory") 1)')
        # Stage 2: emit each function.
        for fn in module.functions:
            self._emit_function(fn)
        self._indent -= 1
        self._write(")")
        return "\n".join(self._lines) + "\n"

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
                # String-typed args must come from literals in this
                # phase; intern each one.
                for arg in instr.args:
                    if arg.kind == "lit_str":
                        self._intern_string(arg.literal)
            if isinstance(instr, AssignConst) and instr.src.kind == "lit_str":
                # Intern, but defer using-this-local to Phase 6D.
                self._intern_string(instr.src.literal)
            if isinstance(instr, If):
                self._discover_instrs(instr.then_body)
                self._discover_instrs(instr.else_body)
            elif isinstance(instr, While):
                self._discover_instrs(instr.cond_setup)
                self._discover_instrs(instr.body)

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
        # carries no runtime value.
        param_clauses = []
        for p in fn.params:
            if p.ty in _BUILTIN_CAPS:
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

        self._indent -= 1
        self._write(")")

    def _collect_locals(
        self, fn: Function, param_names: set[str],
    ) -> dict[str, str]:
        """Walk every instruction in the function body and gather
        the set of local names (with their Wasm types) that need
        to be declared at the top of the function. Param names are
        excluded because Wasm treats params as locals already."""
        out: dict[str, str] = {}

        def visit(instrs: list[Instr]) -> None:
            for instr in instrs:
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
                    # String locals exist in Phase 6B only as a
                    # by-product of intermediate-result locals from
                    # MethodCall instructions whose dst is later
                    # discarded; they have no Wasm representation
                    # yet, so we skip them here. Using a String
                    # local as a method argument would have already
                    # tripped ``_push_value`` in the discovery pass.
                    if capa_ty == "String":
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
        return out

    # ----- per-instruction --------------------------------------

    def _emit_instr(self, instr: Instr) -> None:
        if isinstance(instr, AssignConst):
            # Capability and String AssignConst targets are erased at
            # the Wasm level (see ``_collect_locals``); skip the emit
            # so we don't reference a non-existent local. The source
            # value's side effects (none for literals) are also a
            # no-op.
            dst_ty = self._dst_capa_ty(instr.dst)
            if dst_ty in _BUILTIN_CAPS or dst_ty == "String":
                return
            self._push_value(instr.src)
            self._write(f"local.set ${instr.dst}")
            return
        if isinstance(instr, Reassign):
            dst_ty = self._dst_capa_ty(instr.dst)
            if dst_ty in _BUILTIN_CAPS or dst_ty == "String":
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
        """Lower a Capa-level function call. Capability-typed args
        are skipped (the callee's Wasm signature does not include
        them; capabilities flow through module-level imports). The
        return value, if any, is bound to ``instr.dst``."""
        for arg in instr.args:
            if arg.ty in _BUILTIN_CAPS:
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

    # ----- capability method calls ------------------------------

    def _emit_cap_method_call(self, instr: MethodCall) -> None:
        cap = instr.cap_used
        method = instr.method
        # Push each argument. String args expand to (ptr, len).
        # Scalar args use the regular push path.
        for arg in instr.args:
            if arg.kind == "lit_str":
                offset, length = self._intern_string(arg.literal)
                self._write(f"i32.const {offset}")
                self._write(f"i32.const {length}")
            elif arg.kind == "local" and self._is_string_local(arg.name):
                # String locals in Phase 6B come from intermediate
                # IR locals that the Python emitter would have used
                # as f-string container. The Wasm path does not yet
                # support them; raise so we don't silently mis-emit.
                raise WasmEmissionError(
                    f"Phase 6B: String local {arg.name!r} as cap arg "
                    f"is not yet supported; pass a string literal "
                    f"(Phase 6D covers String locals)"
                )
            else:
                self._push_value(arg)
        self._write(f"call ${cap}_{method}")
        # Result handling: Phase 6B methods all return Unit, so no
        # local.set is needed. When a method returns a value (Phase
        # 6C+), we will local.set $instr.dst here.

    def _is_string_local(self, name: str) -> bool:
        ty = self._current_fn.locals.get(name) if self._current_fn else None
        return ty == "String"

    def _dst_capa_ty(self, name: str) -> str:
        if self._current_fn is None:
            return ""
        return self._current_fn.locals.get(name, "")

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
        raise WasmEmissionError(
            f"Phase 6A: value kind {v.kind!r} not supported "
            f"(no Wasm encoding yet for {v!r})"
        )

    # ----- helpers ----------------------------------------------

    def _wasm_type(self, capa_ty: str) -> str:
        head = capa_ty.split("<", 1)[0]
        if head in _CAPA_TO_WASM:
            return _CAPA_TO_WASM[head]
        raise WasmEmissionError(
            f"Phase 6A: Capa type {capa_ty!r} has no Wasm encoding yet"
        )

    def _write(self, line: str) -> None:
        if line == "":
            self._lines.append("")
        else:
            self._lines.append(self._unit * self._indent + line)
