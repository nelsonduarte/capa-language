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
    MakeStruct, MakeList, MakeTuple, MakeMap, MakeRange, MakeSet,
    FieldAccess, FieldStore, Index, FormatStr, For,
    TryUnwrap, MakeLambda,
    Pattern, PatWildcard, PatIdent, PatLiteral, PatVariant, PatTuple, Match,
    StructDecl, SumDecl, ImplBlock, TraitDecl, ConstDecl, ImportDecl,
)
from ._lower import UnsupportedInIR
from ._free_vars import analyze_lambda
from .._py_ident import _safe_ident
# PatOr / PatStruct are the two CIR pattern shapes the shared lowerer
# (``_lower_pattern.py``) builds but ``_nodes`` does not yet carry; the
# Wasm match emitter already imports them from there, and so does this
# renderer, so both backends read the one lowering's output rather than
# rebuilding pattern structure of their own.
from ._lower_pattern import PatOr, PatStruct


# Source-level operators that translate verbatim into Python. The few
# that need a rewrite (``and``/``or`` are the same, ``not`` adds a
# space) are handled in ``_format_binop`` / ``_format_unary``.
# Bitwise / shift ops pass through unchanged: Python's ``& | ^ << >>``
# on ``int`` line up with Capa's Int semantics (analyzer-gated to Int
# operands only, so no float-bit-pattern surprises).
_PY_BINOPS = {
    "+", "-", "*", "/", "%",
    "&", "|", "^", "<<", ">>",
    "==", "!=", "<", "<=", ">", ">=",
    "and", "or",
}


# Map from a Capa source op to the runtime safety helper that wraps
# it on the Python backend. The helpers (in ``capa.runtime._safety``)
# raise ``OverflowError`` / ``ZeroDivisionError`` at the same input
# the Wasm backend traps on, so both backends fail loud at the same
# point (audit fixes C2 and C3, plus the ``/`` floor-division fix).
# Int ``/`` additionally floors toward negative infinity (Python
# ``//`` via ``_capa_idiv``) to match the Wasm ``i64.div_s`` + floor
# correction, where plain Python ``/`` would yield a Float. Only Int
# operands route through these; Float / String / Bool stay on the
# plain Python operator path.
_CAPA_INT_HELPERS = {
    "+": "_capa_iadd",
    "-": "_capa_isub",
    "*": "_capa_imul",
    "/": "_capa_idiv",
    "<<": "_capa_shl",
    ">>": "_capa_shr",
}


#: The CIR instruction kinds ``_emit_instr`` renders, one per
#: ``isinstance`` branch. Declared handled-set for the M1 exhaustiveness
#: net, pinned against ``ir._nodes.Instr.__subclasses__()``
#: (``tests/test_node_exhaustiveness.py``). A new ``Instr`` this backend
#: forgets fails that test rather than reaching this emitter's
#: ``NotImplementedError`` only when some program happens to lower to it.
#: ``ExprStmt`` and ``ForeignCall`` are the deliberate non-members (the
#: test records them as excluded); keep this set in lockstep with the
#: branches below.
PYTHON_EMITTED_INSTRS = frozenset({
    AssignConst, Reassign, BinOp, UnaryOp, Call, MethodCall,
    If, While, Break, Continue,
    MakeStruct, MakeList, MakeMap, MakeRange, MakeSet, MakeTuple,
    FieldAccess, FieldStore, Index, FormatStr, For,
    TryUnwrap, MakeLambda, Match, Return,
})


#: The CIR pattern kinds ``_format_pattern`` renders. Declared handled-set
#: for the M1 exhaustiveness net, pinned against the concrete ``Pattern``
#: subclasses under ``capa.ir`` (the original five in ``_nodes`` plus
#: ``PatOr`` / ``PatStruct`` from the shared lowerer ``_lower_pattern``).
#: The renderer covers the full CIR pattern domain: a match arm carrying
#: any of these lowers to byte-identical Python under ``--ir`` as the
#: legacy transpiler emits (audit OBS-1, "--ir backend crashes on
#: PatStruct/PatOr", is closed). A new pattern kind this backend forgets
#: fails ``tests/test_node_exhaustiveness.py`` rather than reaching this
#: emitter's ``NotImplementedError`` only when some program happens to
#: lower to it; keep this set in lockstep with the branches below.
PYTHON_EMITTED_PATTERNS = frozenset({
    PatWildcard, PatIdent, PatLiteral, PatVariant, PatTuple,
    PatOr, PatStruct,
})


class PythonEmitter:
    def __init__(self, indent_unit: str = "    "):
        self._lines: List[str] = []
        self._indent = 0
        self._unit = indent_unit
        # Toggled by ``_format_binop`` the first time it routes an
        # Int op through a safety helper. ``emit()`` consults this
        # after walking the module so the import line lands at the
        # top alongside ``from dataclasses import dataclass``.
        self._needs_safety = False
        # Toggled by ``_emit_instr`` (Index over List) and the
        # ``substring`` rewrite the first time they emit a call to
        # the bounds-check runtime helpers (audit fix C1). Drives
        # the ``from capa.runtime import _capa_list_get,
        # _capa_substring`` line in ``emit()`` so the emitted
        # module is self-contained.
        self._needs_bounds = False
        # Names bound in the scope enclosing the lambda currently
        # being emitted: the enclosing function's params + flat
        # locals, plus the params of every lambda on the way down.
        # ``_emit_make_lambda`` consults it to decide whether a bare
        # ``Call`` callee inside a lambda body is a higher-order
        # function captured from that scope (so it must be rebound as
        # a default arg, by value) versus a top-level function (which
        # stays a free reference). Set per function / impl method.
        self._enclosing_names: set[str] = set()

    # ----- public ------------------------------------------------

    def emit(self, module: Module) -> str:
        # The emitter's per-function lowering is the original Phase 1
        # focus, but once the module carries type declarations we also
        # need to introduce ``@dataclass`` at the top so the emitted
        # source is self-contained. Tests / pipelines that mix the IR
        # with the legacy prelude already have ``dataclass`` in scope,
        # so the import is harmless when redundant.
        # Decide the safety-helper import up front by scanning every
        # function / impl / const body for an Int +/-/* / ``/`` / <</>>
        # BinOp; the matching ``from capa.runtime import _capa_iadd, ...``
        # line then lands at the top alongside ``from dataclasses
        # import dataclass``. The legacy transpiler's prelude already
        # imports the same names, so this is harmless when the IR
        # output is concatenated with the legacy prelude.
        self._needs_safety = _module_uses_int_safety(module)
        self._needs_bounds = _module_uses_bounds_safety(module)
        if module.types:
            self._write("from dataclasses import dataclass")
            self._lines.append("")
        if self._needs_safety:
            self._write(
                "from capa.runtime import "
                "_capa_iadd, _capa_isub, _capa_imul, _capa_idiv, "
                "_capa_shl, _capa_shr"
            )
            self._lines.append("")
        if self._needs_bounds:
            self._write(
                "from capa.runtime import _capa_list_get, _capa_substring"
            )
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
        # ``unsafe_hash=True`` generates a value-based ``__hash__``
        # (from the field values) while keeping the class mutable, so
        # a struct can be a ``Set`` element / ``Map`` key yet still
        # support ``var p = P{...}; p.x = 5`` field assignment. A
        # frozen dataclass would hash but forbid mutation; a plain
        # ``@dataclass`` is mutable but unhashable (cannot go in a
        # Set). This matches the Wasm backend, which dedups Set
        # elements by structural value at add-time.
        self._write("@dataclass(unsafe_hash=True)")
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
            self._write(f"{_safe_ident(f.name)}: object")
        self._indent -= 1

    def _emit_sum(self, t: SumDecl) -> None:
        # One class per variant. Zero payloads -> empty frozen
        # dataclass (so ``Red == Red`` is True by value, matching the
        # Wasm backend's structural sum equality; a plain ``class Red:
        # pass`` would compare by identity); one payload -> dataclass
        # with ``value: object``; N payloads -> dataclass with ``f0,
        # f1, ...`` matching the positional field convention the
        # legacy emitter uses.
        self._sum_variants[t.name] = [v.name for v in t.variants]
        for v in t.variants:
            n = len(v.payload_tys)
            if n == 0:
                self._write("@dataclass(frozen=True)")
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
                params = ", ".join(_safe_ident(p.name) for p in m.params)
                self._write(f"def {_safe_ident(m.name)}({params}):")
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
            params = ", ".join(_safe_ident(p.name) for p in m.params)
            self._write(f"def {mangled}({params}):")
            self._indent += 1
            self._enclosing_names = self._scope_names(m)
            if not m.body:
                self._write("pass")
            else:
                for instr in m.body:
                    self._emit_instr(instr)
            self._indent -= 1
            for at in attach_targets:
                self._write(f"{at}.{_safe_ident(m.name)} = {mangled}")
            self._lines.append("")

    # ----- function-level ---------------------------------------

    def _emit_function(self, fn: Function) -> None:
        params = ", ".join(_safe_ident(p.name) for p in fn.params)
        self._write(f"def {_safe_ident(fn.name)}({params}):")
        self._indent += 1
        self._enclosing_names = self._scope_names(fn)
        if not fn.body:
            self._write("pass")
        else:
            for instr in fn.body:
                self._emit_instr(instr)
        self._indent -= 1

    @staticmethod
    def _scope_names(fn: Function) -> set[str]:
        """Names bound by a function-like body owner: its params plus
        the lowerer's flat ``locals`` map (which already covers every
        local introduced anywhere under it, including inside lambda
        bodies). Used as the enclosing scope for a lambda's
        captured-callee decision."""
        names = {p.name for p in fn.params}
        names |= set(getattr(fn, "locals", {}) or {})
        return names

    # ----- per-instruction --------------------------------------

    def _emit_instr(self, instr: Instr) -> None:
        if isinstance(instr, AssignConst):
            self._write(f"{_safe_ident(instr.dst)} = {self._format_value(instr.src)}")
            return
        if isinstance(instr, Reassign):
            self._write(f"{_safe_ident(instr.dst)} = {self._format_value(instr.src)}")
            return
        if isinstance(instr, BinOp):
            rhs = self._format_binop(instr.op, instr.left, instr.right)
            self._write(f"{_safe_ident(instr.dst)} = {rhs}")
            return
        if isinstance(instr, UnaryOp):
            rhs = self._format_unary(instr.op, instr.operand)
            self._write(f"{_safe_ident(instr.dst)} = {rhs}")
            return
        if isinstance(instr, Call):
            args = ", ".join(self._format_value(a) for a in instr.args)
            rhs = f"{_safe_ident(instr.callee_name)}({args})"
            self._write(self._with_optional_dst(instr.dst, rhs))
            return
        if isinstance(instr, MethodCall):
            args = [self._format_value(a) for a in instr.args]
            recv = self._format_value(instr.receiver)
            rhs = self._rewrite_builtin_method(
                instr.receiver.ty or "", instr.method, recv, args,
            )
            if rhs is None:
                rhs = f"{recv}.{_safe_ident(instr.method)}({', '.join(args)})"
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
            # We use the ``while True / cond_setup / if not c: break``
            # pattern so the cond is recomputed at the top of every
            # iteration, including those entered via ``continue``.
            # The earlier "tail-recompute" shape (cond_setup emitted
            # before the while AND at the body's tail) silently
            # broke any loop whose body had a ``continue`` because
            # Python jumps straight to the while-cond check without
            # running the body's tail.
            self._write("while True:")
            self._indent += 1
            for sub in instr.cond_setup:
                self._emit_instr(sub)
            self._write(
                f"if not {self._format_value(instr.cond)}:"
            )
            self._indent += 1
            self._write("break")
            self._indent -= 1
            if not instr.body:
                # Empty body is fine; the ``break`` above is the only
                # loop exit, and the cond_setup keeps it correct.
                pass
            else:
                for sub in instr.body:
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
                f"{_safe_ident(name)}={self._format_value(v)}"
                for name, v in instr.fields
            )
            self._write(f"{_safe_ident(instr.dst)} = {instr.type_name}({args})")
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
            self._write(f"{_safe_ident(instr.dst)} = CapaList([{elems}])")
            return
        if isinstance(instr, MakeMap):
            self._write(f"{_safe_ident(instr.dst)} = {{}}")
            return
        if isinstance(instr, MakeRange):
            # ``CapaRange`` is the runtime wrapper that mirrors the
            # legacy transpiler's ``CapaRange(start, stop)`` shape so
            # ``for i in 0..N`` / ``for i in a..=b`` iterates the
            # same integer sequence on both backends. Inclusive
            # ranges add 1 to ``end`` to align with Python's
            # half-open ``range(...)`` convention.
            start = self._format_value(instr.start)
            end = self._format_value(instr.end)
            stop = f"({end}) + 1" if instr.inclusive else end
            self._write(f"{_safe_ident(instr.dst)} = CapaRange({start}, {stop})")
            return
        if isinstance(instr, MakeSet):
            # CapaSet is insertion-ordered (dict-backed); a raw Python
            # ``set`` iterates in hash order and would diverge from the
            # Wasm backend's linear element array.
            self._write(f"{_safe_ident(instr.dst)} = CapaSet()")
            return
        if isinstance(instr, MakeTuple):
            elems = ", ".join(self._format_value(v) for v in instr.elements)
            if len(instr.elements) == 1:
                # Single-element tuple in Python needs the trailing
                # comma to distinguish from a parenthesised value.
                self._write(f"{_safe_ident(instr.dst)} = ({elems},)")
            else:
                self._write(f"{_safe_ident(instr.dst)} = ({elems})")
            return
        if isinstance(instr, FieldAccess):
            recv = self._format_value(instr.receiver)
            self._write(f"{_safe_ident(instr.dst)} = {recv}.{_safe_ident(instr.field)}")
            return
        if isinstance(instr, FieldStore):
            recv = self._format_value(instr.receiver)
            val = self._format_value(instr.src)
            self._write(f"{recv}.{_safe_ident(instr.field)} = {val}")
            return
        if isinstance(instr, Index):
            recv = self._format_value(instr.receiver)
            idx = self._format_value(instr.index)
            # Safety (audit fix C1): List indexing routes through
            # ``_capa_list_get`` so the Python backend raises
            # ``IndexError`` at the same input the Wasm backend traps
            # on. Tuple / Map / String indexing keeps the native ``[]``
            # (tuple arity is statically checked by the analyzer; Map
            # raises KeyError natively; String indexing is not surface
            # syntax). Cf. the legacy transpiler's matching rewrite in
            # ``capa/transpiler/_expressions.py``.
            recv_head = (instr.receiver.ty or "").split("<", 1)[0]
            if recv_head == "List":
                self._needs_bounds = True
                self._write(f"{_safe_ident(instr.dst)} = _capa_list_get({recv}, {idx})")
                return
            self._write(f"{_safe_ident(instr.dst)} = {recv}[{idx}]")
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
                    val = self._format_value(p)
                    # Match the legacy transpiler: a Bool prints as
                    # ``true`` / ``false`` (lowercase), not Python's
                    # default ``True`` / ``False``, so the Wasm and
                    # Python backends emit the same text.
                    if (p.ty or "") == "Bool":
                        val = f"('true' if ({val}) else 'false')"
                    buf.append("{" + val + "}")
            body = "".join(buf)
            # Use the same string-literal repr the legacy transpiler
            # uses for consistency; escape backslashes and quotes.
            self._write(f"{_safe_ident(instr.dst)} = f{repr(body)}")
            return
        if isinstance(instr, For):
            self._write(
                f"for {_safe_ident(instr.name)} in {self._format_value(instr.iter)}:"
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
            dst = _safe_ident(instr.dst)
            self._write(f"{dst} = {src}")
            self._write(
                f"if isinstance({dst}, Err) or {dst} is None_:"
            )
            self._indent += 1
            self._write(f"return {dst}")
            self._indent -= 1
            self._write(f"{dst} = {dst}.value")
            return
        if isinstance(instr, MakeLambda):
            self._emit_make_lambda(instr)
            return
        if isinstance(instr, Match):
            self._write(f"match {self._format_value(instr.scrutinee)}:")
            self._indent += 1
            for arm in instr.arms:
                pat_str = self._format_pattern(arm.pattern)
                if arm.guard is not None:
                    guard_str = self._format_guard(arm.guard, arm.guard_setup)
                    self._write(f"case {pat_str} if {guard_str}:")
                else:
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

    def _emit_make_lambda(self, instr: MakeLambda) -> None:
        # Emit a nested ``def`` whose name is the lambda's dst. We do
        # not use a Python ``lambda`` expression even for
        # expression-body source lambdas: the ANF lowering has already
        # split the body into statement-level instructions, which a
        # Python ``lambda`` (single expression only) cannot host.
        #
        # Every captured name is rebound as a default argument
        # (``def _lam(x, i=i): ...``) so it binds by VALUE at
        # def-execution time. Without this, Python's late-binding
        # closure semantics read a captured loop variable at CALL time:
        # ``for i in 0..N: fs.push(fun () => i)`` would make every
        # closure return the loop's final value (``4 4 4 ...``) where
        # the Wasm backend captures each iteration's ``i`` at
        # MakeLambda time (``0 1 2 ...``). Default args bind at
        # def-execution time, matching Wasm; reference-typed captures
        # (lists / maps / strings) still share the same object, which
        # is also what Wasm does (it captures the pointer, not a copy).
        # The capture set comes from the shared ``analyze_lambda`` so
        # this backend and the Wasm closure emitter agree on it.
        free = analyze_lambda(
            instr,
            callee_is_capture=lambda n: n in self._enclosing_names,
        ).free
        own = [_safe_ident(p.name) for p in instr.params]
        caps = [f"{_safe_ident(n)}={_safe_ident(n)}" for n in sorted(free)]
        params = ", ".join(own + caps)
        self._write(f"def {_safe_ident(instr.dst)}({params}):")
        self._indent += 1
        # A nested lambda sees this lambda's params as part of the
        # enclosing scope for its own captured-callee decision. Restore
        # on the way back out so sibling lambdas do not inherit them.
        prev_enclosing = self._enclosing_names
        self._enclosing_names = prev_enclosing | {p.name for p in instr.params}
        try:
            if not instr.body:
                self._write("pass")
            else:
                for sub in instr.body:
                    self._emit_instr(sub)
        finally:
            self._enclosing_names = prev_enclosing
        self._indent -= 1

    # ----- value rendering --------------------------------------

    def _format_value(self, v: Value) -> str:
        if v.kind in ("local", "param", "global"):
            return _safe_ident(v.name or "")
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
        if op not in _PY_BINOPS:
            raise NotImplementedError(f"IR Python emitter: binop {op!r}")
        l = self._format_value(left)
        r = self._format_value(right)
        return self._binop_expr(op, l, r, left.ty, right.ty)

    def _binop_expr(
        self, op: str, l: str, r: str, left_ty: str, right_ty: str,
    ) -> str:
        """Render a binary operation from pre-formatted operand strings.

        ``l`` / ``r`` are the already-rendered operands; ``left_ty`` /
        ``right_ty`` are their Capa source types. Int/Int operands route
        through the runtime safety helpers so the Python backend matches
        the Wasm backend at the same input: overflow-checked ``+`` /
        ``-`` / ``*`` and ``<<`` / ``>>`` (audit fixes C2 + C3), and
        floored, trap-on-``/0``-and-``MIN/-1`` division via
        ``_capa_idiv`` (where plain Python ``/`` would yield a Float and
        never trap). Float / String / Bool operands stay on the plain
        operator path. Mirrors the legacy transpiler's rewrite in
        ``capa/transpiler/_expressions.py``. Shared by ``_format_binop``
        (instruction stream) and the match-guard prelude inliner in
        ``_format_guard`` so both emit identical arithmetic.
        """
        if left_ty == "Int" and right_ty == "Int":
            helper = _CAPA_INT_HELPERS.get(op)
            if helper is not None:
                self._needs_safety = True
                return f"{helper}({l}, {r})"
        return f"({l} {op} {r})"

    def _format_unary(self, op: str, operand: Value) -> str:
        x = self._format_value(operand)
        if op == "-":
            return f"(-{x})"
        if op == "not":
            return f"(not {x})"
        raise NotImplementedError(f"IR Python emitter: unary {op!r}")

    def _format_guard(
        self, guard: Value, setup: list[Instr],
    ) -> str:
        """Render a match-arm guard back into a single Python
        expression for emission inside ``case PAT if EXPR:``.

        When ``setup`` is empty the guard is already a trivial
        Value (a bare local, literal, or capability constant) and
        renders directly. When it is non-empty the lowerer's ANF
        decomposition split a richer expression into intermediate
        instructions whose destination locals only feed back into
        the guard Value; this method walks the setup in order,
        builds a ``local_name -> python_expression`` substitution
        map for each intermediate, then renders the final guard
        with substitutions applied.

        Only side-effect-free shapes are inlineable: FieldAccess,
        Index, UnaryOp, BinOp. Method calls and free-function
        calls may legitimately appear in source-level guards but
        the inlining cannot prove their purity, so this method
        raises ``UnsupportedInIR`` for them and lets the caller
        (the CLI's ``--ir`` path) fall back to the legacy
        direct-to-Python transpiler, which handles guards via
        plain expression emission and does not need ANF lowering.
        """
        if not setup:
            return self._format_value(guard)

        subst: dict[str, str] = {}

        def render(v: Value) -> str:
            if v.kind in ("local", "param") and v.name in subst:
                return subst[v.name]
            return self._format_value(v)

        for ins in setup:
            if isinstance(ins, FieldAccess):
                expr = f"{render(ins.receiver)}.{_safe_ident(ins.field)}"
            elif isinstance(ins, Index):
                expr = f"{render(ins.receiver)}[{render(ins.index)}]"
            elif isinstance(ins, UnaryOp):
                operand = render(ins.operand)
                if ins.op == "-":
                    expr = f"(-{operand})"
                elif ins.op == "not":
                    expr = f"(not {operand})"
                else:
                    raise UnsupportedInIR(
                        f"guard prelude UnaryOp with op {ins.op!r} cannot "
                        f"be inlined into a Python `case ... if EXPR:` clause"
                    )
            elif isinstance(ins, BinOp):
                if ins.op not in _PY_BINOPS:
                    raise UnsupportedInIR(
                        f"guard prelude BinOp with op {ins.op!r} cannot "
                        f"be inlined into a Python `case ... if EXPR:` clause"
                    )
                # Route through the same core as the instruction stream
                # so an Int op inside a guard gets the identical
                # floored/trapping ``/`` and overflow-checked +/-/*/<<
                # />> treatment; otherwise a guard division would emit a
                # plain ``/`` and diverge from the other two backends.
                expr = self._binop_expr(
                    ins.op, render(ins.left), render(ins.right),
                    ins.left.ty, ins.right.ty,
                )
            else:
                raise UnsupportedInIR(
                    f"guard prelude instruction {type(ins).__name__} "
                    f"cannot be inlined into a Python `case ... if EXPR:` "
                    f"clause; either rewrite the guard as a bare "
                    f"identifier / direct comparison, or hoist the "
                    f"computation into a let-binding above the match"
                )
            subst[ins.dst] = expr

        return render(guard)

    def _rewrite_builtin_method(
        self, recv_ty: str, method: str, recv: str, args: list[str],
    ) -> str | None:
        """Rewrite a method call on a built-in receiver type to its
        Python idiom. Returns ``None`` if no rewrite applies (the
        caller falls back to a plain ``recv.method(args)`` emission).

        Mirrors the legacy transpiler's ``_emit_string_method`` /
        ``_emit_list_method`` / ``_emit_map_method`` / ``_emit_set_method``
        tables. We dispatch on the receiver type's source-level head
        (``String``, ``List``, ``Map``, ``Set``, ``Range``) which the
        IR stores as a string; type-argument suffixes (``List<Int>``)
        are normalised by chopping at the first ``<``.
        """
        head = recv_ty.split("<", 1)[0]
        if head == "String":
            return self._string_method(method, recv, args)
        if head == "List":
            return self._list_method(method, recv, args)
        if head == "Map":
            return self._map_method(method, recv, args)
        if head == "Set":
            return self._set_method(method, recv, args)
        return None

    def _string_method(self, m: str, r: str, a: list[str]) -> str | None:
        if m == "length":      return f"len({r})"
        if m == "contains":    return f"({a[0]} in {r})"
        if m == "starts_with": return f"{r}.startswith({a[0]})"
        if m == "ends_with":   return f"{r}.endswith({a[0]})"
        # ASCII-only case folding (parity slice): the runtime helpers
        # fold only A-Z <-> a-z and leave every other code point intact,
        # byte-identical with the Wasm backend. Python's native
        # ``str.upper()`` / ``str.lower()`` would case-fold non-ASCII
        # letters too and diverge silently.
        if m == "to_upper":    return f"_capa_to_upper({r})"
        if m == "to_lower":    return f"_capa_to_lower({r})"
        if m == "trim":        return f"{r}.strip()"
        if m == "trim_start":  return f"{r}.lstrip()"
        if m == "trim_end":    return f"{r}.rstrip()"
        if m == "is_empty":    return f"({r} == '')"
        if m == "split":       return f"CapaList({r}.split({a[0]}))"
        if m == "replace":
            # Empty-needle policy (D3 slice 4, 2026-05): both backends
            # return the receiver unchanged when ``old`` is empty,
            # rather than Python's native ``"abc".replace("", "X") ==
            # "XaXbXcX"``. Avoids the empty-needle inf-loop trap and
            # keeps the Wasm and Python paths bit-identical.
            return (
                f"(lambda _o, _n: {r}.replace(_o, _n) if _o else {r})"
                f"({a[0]}, {a[1]})"
            )
        if m == "substring":
            # Safety (audit fix C1): route through ``_capa_substring``
            # so the Python backend raises ``ValueError`` at the same
            # input the Wasm backend traps on. Cf. the legacy
            # transpiler's matching rewrite in ``_methods.py``.
            self._needs_bounds = True
            return f"_capa_substring({r}, {a[0]}, {a[1]})"
        if m == "char_at":
            # Option<String>: Some(s[i]) when 0 <= i < len(s).
            return (
                f"(Some({r}[{a[0]}]) "
                f"if 0 <= {a[0]} < len({r}) else None_)"
            )
        if m == "index_of":
            return (
                f"(lambda _i: Some(_i) if _i >= 0 else None_)"
                f"({r}.find({a[0]}))"
            )
        if m == "bytes":
            # List<Int> of UTF-8 bytes (each 0..255). ``surrogatepass``
            # keeps a lone surrogate as its 3-byte WTF-8 form (matching
            # the Wasm backend's internal string bytes) rather than
            # raising; identical to strict UTF-8 for well-formed text.
            return f"CapaList({r}.encode('utf-8', 'surrogatepass'))"
        return None

    def _list_method(self, m: str, r: str, a: list[str]) -> str | None:
        # The IR wraps list literals in CapaList(...) (a list subclass
        # whose methods cover most of the API); the rewrites here are
        # the ones the legacy bypasses for efficiency.
        if m == "length":   return f"len({r})"
        if m == "push":     return f"{r}.append({a[0]})"
        if m == "contains": return f"({a[0]} in {r})"
        if m == "is_empty": return f"(len({r}) == 0)"
        if m == "get":
            return (
                f"(lambda _xs, _i: "
                f"Some(_xs[_i]) if 0 <= _i < len(_xs) else None_)"
                f"({r}, {a[0]})"
            )
        return None

    def _map_method(self, m: str, r: str, a: list[str]) -> str | None:
        if m == "length":       return f"len({r})"
        if m == "contains_key": return f"({a[0]} in {r})"
        if m == "get":
            return f"(Some({r}[{a[0]}]) if {a[0]} in {r} else None_)"
        if m == "set":
            return f"{r}.__setitem__({a[0]}, {a[1]})"
        if m == "keys":   return f"CapaList({r}.keys())"
        if m == "values": return f"CapaList({r}.values())"
        if m == "pairs":  return f"CapaList({r}.items())"
        if m == "is_empty": return f"(len({r}) == 0)"
        return None

    def _set_method(self, m: str, r: str, a: list[str]) -> str | None:
        # Receiver is a CapaSet (insertion-ordered, dict-backed).
        if m == "length":   return f"len({r})"
        if m == "contains": return f"({a[0]} in {r})"
        if m == "add":      return f"{r}.add({a[0]})"
        if m == "remove":   return f"{r}.remove({a[0]})"  # discard-safe
        if m == "is_empty": return f"(len({r}) == 0)"
        if m == "to_list":  return f"{r}.to_list()"
        return None

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
            return _safe_ident(p.name)
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
        if isinstance(p, PatTuple):
            # Python's match accepts ``(a, b)`` as a sequence pattern;
            # one-element tuples need the trailing comma so Python
            # reads them as a tuple rather than a parenthesised
            # sub-pattern.
            parts = [self._format_pattern(sub) for sub in p.elements]
            if len(parts) == 1:
                return f"({parts[0]},)"
            return f"({', '.join(parts)})"
        if isinstance(p, PatStruct):
            # Struct-destructuring in match position. The dataclass
            # generated for the struct exposes its fields by name, so a
            # Python class-pattern with keyword sub-patterns
            # (``Type(field=subpat, ...)``) binds each field. Shorthand
            # ``{ x }`` already lowered to ``("x", PatIdent("x"))`` in
            # ``_lower_struct_pattern``, so it renders as ``x=x`` here,
            # matching the legacy transpiler.
            parts = [
                f"{_safe_ident(fname)}={self._format_pattern(sub)}"
                for fname, sub in p.fields
            ]
            return f"{p.type_name}({', '.join(parts)})"
        if isinstance(p, PatOr):
            # Python's match accepts ``a | b | c`` directly; the shared
            # body runs once for whichever alternative matched.
            alts = [self._format_pattern(sub) for sub in p.alternatives]
            return " | ".join(alts)
        raise NotImplementedError(
            f"IR Python emitter: pattern {type(p).__name__} not supported"
        )

    def _with_optional_dst(self, dst, rhs: str) -> str:
        if dst is None:
            return rhs
        return f"{_safe_ident(dst)} = {rhs}"

    # ----- line buffer ------------------------------------------

    def _write(self, line: str) -> None:
        if line == "":
            self._lines.append("")
        else:
            self._lines.append(self._unit * self._indent + line)


def _module_uses_int_safety(module: Module) -> bool:
    """Whether any function / impl / const body contains an Int
    +/-/*/ ``/`` or <</>> BinOp (every op in ``_CAPA_INT_HELPERS``).
    Drives the ``from capa.runtime import _capa_iadd, ...`` line at
    the top of the emitted Python so the safety helpers resolve at
    exec time without leaking the import into modules that have no
    Int arithmetic.

    Walks every instruction list reachable from the module: top-level
    function bodies, impl method bodies, const bodies, and the nested
    bodies of If / While / For / Match / MakeLambda. Returns ``True``
    on the first match for short-circuiting; structural recursion is
    intentional rather than reusing a generic walker because the
    Match arm shape is bespoke.
    """
    def walk_value(v) -> bool:
        return (
            v is not None
            and isinstance(v, Value)
            and getattr(v, "ty", "") == "Int"
        )

    def walk_instrs(instrs) -> bool:
        for ins in instrs or []:
            if isinstance(ins, BinOp) and ins.op in _CAPA_INT_HELPERS:
                if walk_value(ins.left) and walk_value(ins.right):
                    return True
            if isinstance(ins, If):
                if walk_instrs(ins.then_body) or walk_instrs(ins.else_body):
                    return True
            if isinstance(ins, While):
                if walk_instrs(ins.cond_setup) or walk_instrs(ins.body):
                    return True
            if isinstance(ins, For):
                if walk_instrs(ins.body):
                    return True
            if isinstance(ins, MakeLambda):
                if walk_instrs(ins.body):
                    return True
            if isinstance(ins, Match):
                for arm in ins.arms:
                    if walk_instrs(arm.body):
                        return True
                    if arm.guard_setup and walk_instrs(arm.guard_setup):
                        return True
        return False

    for fn in module.functions:
        if walk_instrs(fn.body):
            return True
    for impl in module.impls:
        for m in impl.methods:
            if walk_instrs(m.body):
                return True
    for c in module.consts:
        if walk_instrs(c.body):
            return True
    return False


def _module_uses_bounds_safety(module: Module) -> bool:
    """Whether any function / impl / const body needs the
    bounds-check runtime helpers ``_capa_list_get`` /
    ``_capa_substring`` (audit fix C1). Drives the matching
    ``from capa.runtime import ...`` line in ``PythonEmitter.emit``
    so the emitted module is self-contained.

    Matches:
    - ``Index`` over a ``List<...>`` receiver, which the emitter
      lowers to ``_capa_list_get(recv, idx)``.
    - ``MethodCall`` of ``substring`` on a ``String`` receiver,
      which the emitter lowers to ``_capa_substring(recv, start,
      end)``.

    Walks the same set of instruction lists as
    ``_module_uses_int_safety`` (function bodies, impl method
    bodies, const bodies, and the nested bodies of If / While /
    For / Match / MakeLambda) and short-circuits on the first
    match. Tuple / Map / String / Range indexing keep the native
    ``[]`` and do not need the helpers.
    """
    def walk_instrs(instrs) -> bool:
        for ins in instrs or []:
            if isinstance(ins, Index):
                recv_head = (ins.receiver.ty or "").split("<", 1)[0]
                if recv_head == "List":
                    return True
            if isinstance(ins, MethodCall):
                recv_head = (ins.receiver.ty or "").split("<", 1)[0]
                if recv_head == "String" and ins.method == "substring":
                    return True
            if isinstance(ins, If):
                if walk_instrs(ins.then_body) or walk_instrs(ins.else_body):
                    return True
            if isinstance(ins, While):
                if walk_instrs(ins.cond_setup) or walk_instrs(ins.body):
                    return True
            if isinstance(ins, For):
                if walk_instrs(ins.body):
                    return True
            if isinstance(ins, MakeLambda):
                if walk_instrs(ins.body):
                    return True
            if isinstance(ins, Match):
                for arm in ins.arms:
                    if walk_instrs(arm.body):
                        return True
                    if arm.guard_setup and walk_instrs(arm.guard_setup):
                        return True
        return False

    for fn in module.functions:
        if walk_instrs(fn.body):
            return True
    for impl in module.impls:
        for m in impl.methods:
            if walk_instrs(m.body):
                return True
    for c in module.consts:
        if walk_instrs(c.body):
            return True
    return False
