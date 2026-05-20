"""CIR -> WebAssembly text (WAT) emitter (Phase 6A).

Phase 6A scope: integer / boolean arithmetic, comparisons, locals,
``if`` / ``while`` / ``break`` / ``continue`` / ``return``. Strings,
collections, structs, sums, lambdas, capabilities, ``?``, and match
are deferred to subsequent Phase 6 sub-phases.

The emitter produces WAT (text) which the caller assembles to binary
``.wasm`` via ``wasm-tools parse``. WAT is preferred over direct
binary because it is human-readable and easy to debug; the binary
form is mechanically derived from it.

Type mapping (Phase 6A):

- Capa ``Int`` -> Wasm ``i64`` (signed 64-bit integer)
- Capa ``Bool`` -> Wasm ``i32`` (0 or 1; wasm has no native bool)
- Capa ``Unit`` -> no Wasm result (functions returning Unit omit
  the ``(result ...)`` clause)

Functions are emitted as core Wasm functions for now; the Component
Model wrapper that turns them into capability-importing components
lands in Phase 6B.
"""

from __future__ import annotations

from typing import List, Optional

from ._nodes import (
    Module, Function, Param, Value, Instr,
    AssignConst, Reassign, BinOp, UnaryOp, Call,
    If, While, Break, Continue, Return,
)


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

    # ----- public ------------------------------------------------

    def emit(self, module: Module) -> str:
        self._write("(module")
        self._indent += 1
        for fn in module.functions:
            self._emit_function(fn)
        self._indent -= 1
        self._write(")")
        return "\n".join(self._lines) + "\n"

    # ----- function-level ---------------------------------------

    def _emit_function(self, fn: Function) -> None:
        # Reset per-function state.
        self._block_counter = 0
        self._loop_labels = []

        # Build the function header: params and result.
        param_clauses = []
        for p in fn.params:
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
            self._push_value(instr.src)
            self._write(f"local.set ${instr.dst}")
            return
        if isinstance(instr, Reassign):
            self._push_value(instr.src)
            self._write(f"local.set ${instr.dst}")
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
            raise WasmEmissionError(
                "Phase 6A does not support function calls; defer to 6B+"
            )
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
