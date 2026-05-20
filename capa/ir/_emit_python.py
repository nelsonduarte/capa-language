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
    MakeStruct, MakeList, MakeTuple, MakeMap, MakeSet,
    FieldAccess, Index, FormatStr, For,
    TryUnwrap, MakeLambda,
    Pattern, PatWildcard, PatIdent, PatLiteral, PatVariant, Match,
    StructDecl, SumDecl, ImplBlock, TraitDecl, ConstDecl, ImportDecl,
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
        # The emitter's per-function lowering is the original Phase 1
        # focus, but once the module carries type declarations we also
        # need to introduce ``@dataclass`` at the top so the emitted
        # source is self-contained. Tests / pipelines that mix the IR
        # with the legacy prelude already have ``dataclass`` in scope,
        # so the import is harmless when redundant.
        if module.types:
            self._write("from dataclasses import dataclass")
            self._lines.append("")
        for imp in module.imports:
            self._emit_import(imp)
        if module.imports:
            self._lines.append("")
        for c in module.consts:
            self._emit_const(c)
        if module.consts:
            self._lines.append("")
        # Track sum-type variants so impl blocks can attach their
        # methods to every variant class (the union alias is not
        # patchable). Populated by ``_emit_sum`` and consumed by
        # ``_emit_impl``.
        self._sum_variants: dict[str, list[str]] = {}
        for ty in module.types:
            self._emit_type(ty)
            self._lines.append("")
        for tr in module.traits:
            self._emit_trait(tr)
            self._lines.append("")
        for fn in module.functions:
            self._emit_function(fn)
            self._lines.append("")
        for impl in module.impls:
            self._emit_impl(impl)
            self._lines.append("")
        return "\n".join(self._lines).rstrip() + "\n"

    # ----- type declarations -----------------------------------

    def _emit_type(self, ty) -> None:
        if isinstance(ty, StructDecl):
            self._emit_struct(ty)
            return
        if isinstance(ty, SumDecl):
            self._emit_sum(ty)
            return
        raise NotImplementedError(
            f"IR Python emitter: type decl {type(ty).__name__} not supported"
        )

    def _emit_struct(self, t: StructDecl) -> None:
        self._write("@dataclass")
        if not t.fields:
            self._write(f"class {t.name}:")
            self._indent += 1
            self._write("pass")
            self._indent -= 1
            return
        self._write(f"class {t.name}:")
        self._indent += 1
        for f in t.fields:
            # Legacy convention: every Python-level field is annotated
            # ``object`` rather than the source type. Python's dataclass
            # does nothing meaningful with the annotation at runtime,
            # so ``object`` keeps emission target-agnostic.
            self._write(f"{f.name}: object")
        self._indent -= 1

    def _emit_sum(self, t: SumDecl) -> None:
        # One class per variant. Zero payloads -> bare class with
        # ``pass``; one payload -> dataclass with ``value: object``;
        # N payloads -> dataclass with ``f0, f1, ...`` matching the
        # positional field convention the legacy emitter uses.
        self._sum_variants[t.name] = [v.name for v in t.variants]
        for v in t.variants:
            n = len(v.payload_tys)
            if n == 0:
                self._write(f"class {v.name}:")
                self._indent += 1
                self._write("pass")
                self._indent -= 1
            elif n == 1:
                self._write("@dataclass")
                self._write(f"class {v.name}:")
                self._indent += 1
                self._write("value: object")
                self._indent -= 1
            else:
                self._write("@dataclass")
                self._write(f"class {v.name}:")
                self._indent += 1
                for i in range(n):
                    self._write(f"f{i}: object")
                self._indent -= 1
            self._lines.append("")
        # The sum-type alias. Python ``|`` on classes builds a
        # ``typing.Union`` at module level; useful for annotations and
        # harmless at runtime.
        if t.variants:
            union = " | ".join(v.name for v in t.variants)
            self._write(f"{t.name} = {union}")

    # ----- const + import --------------------------------------

    def _emit_import(self, imp: ImportDecl) -> None:
        # Defence in depth: the analyzer rejects ``import`` in v1, so
        # the IR's normal pipeline never reaches here with a valid
        # module. We mirror the legacy transpiler's breadcrumb to
        # signal intent and avoid emitting a real Python import.
        path = ".".join(imp.path)
        alias = f" as {imp.alias}" if imp.alias else ""
        self._write(
            f"# capa: 'import {path}{alias}' rejected, "
            f"use py_import(unsafe, ...) instead"
        )

    def _emit_const(self, c: ConstDecl) -> None:
        # Emit the constant's prelude instructions at the module's
        # top indent (which is zero at this point), then the final
        # binding. The instruction list ends with the AssignConst the
        # lowerer appended, so the last line is ``name = <value>``.
        for instr in c.body:
            self._emit_instr(instr)

    # ----- trait / capability decls -----------------------------

    def _emit_trait(self, t: TraitDecl) -> None:
        # Mirror the legacy transpiler: emit a shell class
        # ``_Trait_<Name>`` with one stub per method, plus an alias
        # ``<Name> = _Trait_<Name>`` for use in annotations. The class
        # has no real role at runtime (the analyzer's trait check is
        # static); the alias lets generated annotations resolve.
        self._write(f"class _Trait_{t.name}:")
        self._indent += 1
        if not t.methods:
            self._write("pass")
        else:
            for m in t.methods:
                params = ", ".join(p.name for p in m.params)
                self._write(f"def {m.name}({params}):")
                self._indent += 1
                self._write("raise NotImplementedError")
                self._indent -= 1
        self._indent -= 1
        self._write(f"{t.name} = _Trait_{t.name}")

    # ----- impl blocks ------------------------------------------

    def _emit_impl(self, impl: ImplBlock) -> None:
        # Each impl method lowers to a top-level Python function whose
        # name is mangled with the target type, then attached to the
        # target class (and to every variant of a sum type) so
        # ``instance.method(args)`` dispatches at runtime. We do not
        # emit Python inheritance for traits: the analyzer has already
        # certified the trait-impl relationship statically, and Python
        # method resolution only needs the attribute to exist.
        attach_targets = self._sum_variants.get(
            impl.type_name, [impl.type_name],
        )
        for m in impl.methods:
            # Emit ``def _Target_method(...): body``. We reuse the
            # standard function emission so dst-renaming, indentation,
            # and instruction dispatch are identical to a top-level
            # function. The legacy transpiler prefixed the function
            # name with an underscore to avoid colliding with the
            # method name in the class namespace; we mirror that.
            mangled = f"_{impl.type_name}_{m.name}"
            params = ", ".join(p.name for p in m.params)
            self._write(f"def {mangled}({params}):")
            self._indent += 1
            if not m.body:
                self._write("pass")
            else:
                for instr in m.body:
                    self._emit_instr(instr)
            self._indent -= 1
            for at in attach_targets:
                self._write(f"{at}.{m.name} = {mangled}")
            self._lines.append("")

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
            # Capa's ``List<T>`` is backed by ``CapaList`` (a subclass
            # of ``list``) so that ``.length()`` / ``.map()`` /
            # ``.filter()`` / etc. resolve to real methods on the
            # wrapper. Emitting a bare ``[...]`` would give a plain
            # Python list, on which ``xs.length()`` is an
            # ``AttributeError``. Matching the legacy transpiler's
            # ``CapaList([...])`` keeps the IR and legacy paths
            # behaviourally equivalent.
            elems = ", ".join(self._format_value(v) for v in instr.elements)
            self._write(f"{instr.dst} = CapaList([{elems}])")
            return
        if isinstance(instr, MakeMap):
            self._write(f"{instr.dst} = {{}}")
            return
        if isinstance(instr, MakeSet):
            self._write(f"{instr.dst} = set()")
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
        if v.kind in ("local", "param", "global"):
            return v.name or ""
        if v.kind == "variant_ctor":
            # Payload-less sum-type variant used as a value. The
            # ``None`` variant is a singleton (no per-instance state),
            # so we reference its runtime constant directly; for any
            # other variant we construct a fresh instance.
            if v.name == "None":
                return "None_"
            return f"{v.name}()"
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
