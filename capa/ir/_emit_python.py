"""CIR -> Python source emitter (Phase 1).

Walks a lowered CIR module and emits Python source close to what the
legacy transpiler produces, so the runtime behaviour is identical for
the subset the IR currently covers. The emitter is deliberately
minimal: literal values, identifier references, binary ops, function
calls, method calls, return statements. Anything richer (closures,
match, generics, capability discipline) is the legacy transpiler's
responsibility until the IR coverage catches up.

The emitter does *not* re-introduce the full prelude (`from
capa.runtime import *`, `_capa_try` helper, etc.) the legacy
transpiler emits. Tests using the IR path either compare the
emitted function bodies directly or wrap them in the legacy prelude.
This keeps the IR emitter focused on the per-function lowering and
out of the prelude-management business that the legacy transpiler
already handles.
"""

from __future__ import annotations

from typing import List

from ._nodes import (
    Module, Function, Value, Instr,
    AssignConst, Reassign, BinOp, UnaryOp, Call, MethodCall,
    If, While, Break, Continue, Return,
    MakeStruct, MakeList, MakeTuple, FieldAccess, Index, FormatStr, For,
    TryUnwrap, MakeLambda,
    Pattern, PatWildcard, PatIdent, PatLiteral, PatVariant, Match,
)


# Source-level operators that translate verbatim into Python. The few
# that need a rewrite (``and``/``or`` are the same, ``not`` adds a
# space) are handled in ``_format_binop`` / ``_format_unary``.
_PY_BINOPS = {
    "+", "-", "*", "/", "%", "==", "!=", "<", "<=", ">", ">=",
    "and", "or",
}


class PythonEmitter:
    def __init__(self, indent_unit: str = "    "):
        self._lines: List[str] = []
        self._indent = 0
        self._unit = indent_unit

    # ----- public ------------------------------------------------

    def emit(self, module: Module) -> str:
        for fn in module.functions:
            self._emit_function(fn)
            self._lines.append("")
        return "\n".join(self._lines).rstrip() + "\n"

    # ----- function-level ---------------------------------------

    def _emit_function(self, fn: Function) -> None:
        params = ", ".join(p.name for p in fn.params)
        self._write(f"def {fn.name}({params}):")
        self._indent += 1
        if not fn.body:
            self._write("pass")
        else:
            for instr in fn.body:
                self._emit_instr(instr)
        self._indent -= 1

    # ----- per-instruction --------------------------------------

    def _emit_instr(self, instr: Instr) -> None:
        if isinstance(instr, AssignConst):
            self._write(f"{instr.dst} = {self._format_value(instr.src)}")
            return
        if isinstance(instr, Reassign):
            self._write(f"{instr.dst} = {self._format_value(instr.src)}")
            return
        if isinstance(instr, BinOp):
            rhs = self._format_binop(instr.op, instr.left, instr.right)
            self._write(f"{instr.dst} = {rhs}")
            return
        if isinstance(instr, UnaryOp):
            rhs = self._format_unary(instr.op, instr.operand)
            self._write(f"{instr.dst} = {rhs}")
            return
        if isinstance(instr, Call):
            args = ", ".join(self._format_value(a) for a in instr.args)
            rhs = f"{instr.callee_name}({args})"
            self._write(self._with_optional_dst(instr.dst, rhs))
            return
        if isinstance(instr, MethodCall):
            args = ", ".join(self._format_value(a) for a in instr.args)
            recv = self._format_value(instr.receiver)
            rhs = f"{recv}.{instr.method}({args})"
            self._write(self._with_optional_dst(instr.dst, rhs))
            return
        if isinstance(instr, If):
            self._write(f"if {self._format_value(instr.cond)}:")
            self._indent += 1
            if not instr.then_body:
                self._write("pass")
            else:
                for sub in instr.then_body:
                    self._emit_instr(sub)
            self._indent -= 1
            if instr.else_body:
                self._write("else:")
                self._indent += 1
                for sub in instr.else_body:
                    self._emit_instr(sub)
                self._indent -= 1
            return
        if isinstance(instr, While):
            # Capa loops re-evaluate the condition each iteration.
            # Python's ``while <expr>:`` only re-evaluates a bare
            # expression; to re-run the cond_setup instructions
            # before each test we emit them at the top of the body
            # and a copy before the ``while``.
            for sub in instr.cond_setup:
                self._emit_instr(sub)
            self._write(f"while {self._format_value(instr.cond)}:")
            self._indent += 1
            if not instr.body and not instr.cond_setup:
                self._write("pass")
            else:
                for sub in instr.body:
                    self._emit_instr(sub)
                # Recompute the condition for the next iteration.
                for sub in instr.cond_setup:
                    self._emit_instr(sub)
            self._indent -= 1
            return
        if isinstance(instr, Break):
            self._write("break")
            return
        if isinstance(instr, Continue):
            self._write("continue")
            return
        if isinstance(instr, MakeStruct):
            args = ", ".join(
                f"{name}={self._format_value(v)}"
                for name, v in instr.fields
            )
            self._write(f"{instr.dst} = {instr.type_name}({args})")
            return
        if isinstance(instr, MakeList):
            elems = ", ".join(self._format_value(v) for v in instr.elements)
            self._write(f"{instr.dst} = [{elems}]")
            return
        if isinstance(instr, MakeTuple):
            elems = ", ".join(self._format_value(v) for v in instr.elements)
            if len(instr.elements) == 1:
                # Single-element tuple in Python needs the trailing
                # comma to distinguish from a parenthesised value.
                self._write(f"{instr.dst} = ({elems},)")
            else:
                self._write(f"{instr.dst} = ({elems})")
            return
        if isinstance(instr, FieldAccess):
            recv = self._format_value(instr.receiver)
            self._write(f"{instr.dst} = {recv}.{instr.field}")
            return
        if isinstance(instr, Index):
            recv = self._format_value(instr.receiver)
            idx = self._format_value(instr.index)
            self._write(f"{instr.dst} = {recv}[{idx}]")
            return
        if isinstance(instr, FormatStr):
            # Build a Python f-string. Literal parts are inserted
            # verbatim; Value parts become ``{name}`` placeholders.
            # Special characters inside the literal parts must be
            # escaped (Python f-string escapes ``{`` and ``}`` by
            # doubling).
            buf = []
            for p in instr.parts:
                if isinstance(p, str):
                    buf.append(p.replace("{", "{{").replace("}", "}}"))
                else:
                    buf.append("{" + self._format_value(p) + "}")
            body = "".join(buf)
            # Use the same string-literal repr the legacy transpiler
            # uses for consistency; escape backslashes and quotes.
            self._write(f"{instr.dst} = f{repr(body)}")
            return
        if isinstance(instr, For):
            self._write(
                f"for {instr.name} in {self._format_value(instr.iter)}:"
            )
            self._indent += 1
            if not instr.body:
                self._write("pass")
            else:
                for sub in instr.body:
                    self._emit_instr(sub)
            self._indent -= 1
            return
        if isinstance(instr, TryUnwrap):
            # Inline check: bind src to dst, early-return dst on
            # Err / None_, then rebind dst to the unwrapped value.
            # The two-step rebind mirrors the legacy transpiler's
            # hoisted form and avoids the slow _capa_try call path
            # entirely. The emitted code assumes ``Err`` and ``None_``
            # are in scope, which the runtime prelude (consumed by
            # the legacy transpiler) provides via ``from capa.runtime
            # import *``; IR-only tests load the symbols explicitly
            # into their exec namespace.
            src = self._format_value(instr.src)
            self._write(f"{instr.dst} = {src}")
            self._write(
                f"if isinstance({instr.dst}, Err) or {instr.dst} is None_:"
            )
            self._indent += 1
            self._write(f"return {instr.dst}")
            self._indent -= 1
            self._write(f"{instr.dst} = {instr.dst}.value")
            return
        if isinstance(instr, MakeLambda):
            # Emit a nested ``def`` whose name is the lambda's dst.
            # Python's closures capture surrounding locals by reference,
            # so no explicit capture wiring is needed here. Note we do
            # not use a Python ``lambda`` expression even for
            # expression-body source lambdas: the ANF lowering has
            # already split the body into statement-level instructions,
            # which a Python lambda (single expression only) cannot
            # host.
            params = ", ".join(p.name for p in instr.params)
            self._write(f"def {instr.dst}({params}):")
            self._indent += 1
            if not instr.body:
                self._write("pass")
            else:
                for sub in instr.body:
                    self._emit_instr(sub)
            self._indent -= 1
            return
        if isinstance(instr, Match):
            self._write(f"match {self._format_value(instr.scrutinee)}:")
            self._indent += 1
            for arm in instr.arms:
                pat_str = self._format_pattern(arm.pattern)
                self._write(f"case {pat_str}:")
                self._indent += 1
                if not arm.body:
                    self._write("pass")
                else:
                    for sub in arm.body:
                        self._emit_instr(sub)
                self._indent -= 1
            self._indent -= 1
            return
        if isinstance(instr, Return):
            if instr.value is None:
                self._write("return")
            else:
                self._write(f"return {self._format_value(instr.value)}")
            return
        raise NotImplementedError(
            f"IR Python emitter: instruction {type(instr).__name__} "
            f"is not yet implemented"
        )

    # ----- value rendering --------------------------------------

    def _format_value(self, v: Value) -> str:
        if v.kind in ("local", "param"):
            return v.name or ""
        if v.kind == "lit_int":
            return repr(v.literal)
        if v.kind == "lit_float":
            return repr(v.literal)
        if v.kind == "lit_str":
            return repr(v.literal)
        if v.kind == "lit_bool":
            return "True" if v.literal else "False"
        if v.kind == "lit_unit":
            return "None"
        if v.kind == "cap_const":
            # Built-in capability class used as a value: emit the
            # class instantiation. The legacy runtime exports the
            # class names.
            return f"{v.name}()"
        raise NotImplementedError(f"IR Python emitter: value kind {v.kind!r}")

    def _format_binop(self, op: str, left: Value, right: Value) -> str:
        l = self._format_value(left)
        r = self._format_value(right)
        if op in _PY_BINOPS:
            return f"({l} {op} {r})"
        raise NotImplementedError(f"IR Python emitter: binop {op!r}")

    def _format_unary(self, op: str, operand: Value) -> str:
        x = self._format_value(operand)
        if op == "-":
            return f"(-{x})"
        if op == "not":
            return f"(not {x})"
        raise NotImplementedError(f"IR Python emitter: unary {op!r}")

    def _format_pattern(self, p: Pattern) -> str:
        # Python 3.10+ structural-match syntax. The IR's PatVariant
        # uses the variant's source name; for a sum-type's nullary
        # variants the legacy runtime emits singleton dataclass
        # instances named ``<Variant>()``, so the same form works as
        # a class-pattern here. The one wrinkle is Option's ``None``,
        # whose runtime singleton is ``None_`` (the ``_`` suffix
        # avoids the Python keyword); the source-level pattern
        # ``None`` reaches IR as a PatVariant whose name is "None",
        # which we rewrite here.
        if isinstance(p, PatWildcard):
            return "_"
        if isinstance(p, PatIdent):
            return p.name
        if isinstance(p, PatLiteral):
            if p.kind == "bool":
                return "True" if p.value else "False"
            if p.kind == "unit":
                return "None"
            return repr(p.value)
        if isinstance(p, PatVariant):
            # Capa's ``None`` is the source-level singleton variant of
            # Option; in the runtime it's an instance ``None_`` of the
            # internal ``_NoneType`` class. Python's case-pattern
            # ``Cls()`` requires a class on the left, so we emit the
            # class name, not the singleton constant.
            cls = "_NoneType" if p.name == "None" else p.name
            if not p.payloads:
                return f"{cls}()"
            inner = ", ".join(self._format_pattern(sub) for sub in p.payloads)
            return f"{cls}({inner})"
        raise NotImplementedError(
            f"IR Python emitter: pattern {type(p).__name__} not supported"
        )

    def _with_optional_dst(self, dst, rhs: str) -> str:
        if dst is None:
            return rhs
        return f"{dst} = {rhs}"

    # ----- line buffer ------------------------------------------

    def _write(self, line: str) -> None:
        if line == "":
            self._lines.append("")
        else:
            self._lines.append(self._unit * self._indent + line)
