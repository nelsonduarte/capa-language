"""AST -> CIR lowering pass (Phase 1).

Walks a typed AST module and produces a CIR module covering the
subset listed in ``capa/ir/__init__.py``. Any construct outside the
subset raises ``UnsupportedInIR`` so the caller can fall back to the
legacy transpiler path.

The lowerer is ANF-flavoured: every sub-expression is bound to a
fresh local before its parent uses it. The Python emitter could
fold these back into nested expressions if it wanted; the cost of
the extra locals is one ``x = ...`` line per intermediate, which
Python's optimiser absorbs.
"""

from __future__ import annotations

from typing import Optional

from .. import capa_ast as A
from ._nodes import (
    Module, Function, Param, Value, Instr,
    AssignConst, Reassign, BinOp, UnaryOp, Call, MethodCall,
    If, While, Break, Continue, Return,
    MakeStruct, MakeList, MakeTuple, FieldAccess, Index, FormatStr, For,
    fresh_local,
)


# Built-in capabilities the analyzer recognises by type name. Used
# to set ``Param.is_capability``. Kept in sync with capa/builtins.py
# capability class list.
_BUILTIN_CAPS = {
    "Stdio", "Fs", "Net", "Env", "Clock", "Random", "Proc", "Db", "Unsafe",
}


class UnsupportedInIR(Exception):
    """Raised when the lowerer hits an AST node it does not yet
    handle. The caller (typically ``capa.ir.compile`` or a test) is
    expected to catch this and fall back to the legacy transpiler.
    The message identifies the unsupported shape so coverage can be
    extended incrementally."""

    def __init__(self, shape: str):
        super().__init__(f"CIR lowering does not yet support: {shape}")
        self.shape = shape


class Lowerer:
    def __init__(self, types: Optional[dict] = None):
        self.types = types or {}
        # Per-function state, reset on entry to each FunDecl.
        self._counter: dict = {"n": 0}
        self._instrs: list[Instr] = []
        self._locals: dict[str, str] = {}
        # Parameters of the function currently being lowered, used by
        # ``_lower_ident`` to decide between ``kind="param"`` and
        # ``kind="local"``.
        self._params: set[str] = set()
        # Capability classes declared in the current function's
        # signature, used by ``_lower_method_call`` to flag
        # ``cap_used``. The set tracks parameter names that are
        # capability-typed (built-in caps for now; user-defined caps
        # are added in a later phase).
        self._cap_params: dict[str, str] = {}

    # ------------------------------------------------------------
    # Module / function entry points.
    # ------------------------------------------------------------

    def lower_module(self, module: A.Module) -> Module:
        functions: list[Function] = []
        for item in module.items:
            if isinstance(item, A.FunDecl):
                functions.append(self.lower_function(item))
            else:
                raise UnsupportedInIR(
                    f"top-level item {type(item).__name__}"
                )
        return Module(functions=functions, ast_module=module)

    def lower_function(self, fn: A.FunDecl) -> Function:
        # Reset per-function state.
        self._counter = {"n": 0}
        self._instrs = []
        self._locals = {}
        self._params = set()
        self._cap_params = {}

        params: list[Param] = []
        for p in fn.params:
            ty_name = _type_name(p.type_expr) if p.type_expr else "Unknown"
            is_cap = ty_name in _BUILTIN_CAPS
            params.append(Param(name=p.name, ty=ty_name, is_capability=is_cap))
            self._params.add(p.name)
            if is_cap:
                self._cap_params[p.name] = ty_name

        ret_ty = _type_name(fn.return_type) if fn.return_type else "Unit"
        declared_caps = sorted(set(self._cap_params.values()))

        self._lower_block(fn.body)

        return Function(
            name=fn.name,
            params=params,
            return_type=ret_ty,
            declared_caps=declared_caps,
            body=self._instrs,
            locals=dict(self._locals),
        )

    # ------------------------------------------------------------
    # Blocks and statements.
    # ------------------------------------------------------------

    def _lower_block(self, block: A.Block) -> None:
        for stmt in block.stmts:
            self._lower_stmt(stmt)

    def _lower_stmt(self, s: A.Stmt) -> None:
        if isinstance(s, A.LetStmt):
            return self._lower_let(s)
        if isinstance(s, A.VarStmt):
            return self._lower_var(s)
        if isinstance(s, A.AssignStmt):
            return self._lower_assign(s)
        if isinstance(s, A.IfStmt):
            return self._lower_if(s)
        if isinstance(s, A.WhileStmt):
            return self._lower_while(s)
        if isinstance(s, A.BreakStmt):
            self._instrs.append(Break())
            return
        if isinstance(s, A.ContinueStmt):
            self._instrs.append(Continue())
            return
        if isinstance(s, A.ForStmt):
            return self._lower_for(s)
        if isinstance(s, A.ReturnStmt):
            return self._lower_return(s)
        if isinstance(s, A.ExprStmt):
            return self._lower_expr_stmt(s)
        raise UnsupportedInIR(f"statement {type(s).__name__}")

    def _lower_let(self, s: A.LetStmt) -> None:
        # Phase 1 supports only Ident patterns on the left side.
        if not isinstance(s.pattern, A.IdentPat):
            raise UnsupportedInIR(
                f"let-pattern {type(s.pattern).__name__}"
            )
        name = s.pattern.name
        value = self._lower_expr(s.value)
        # If the source value is already a single Value, bind directly.
        # Otherwise the expression lowering will have produced
        # instructions that ended with the result in a temp; chain
        # an extra AssignConst to give that result the user's name.
        self._locals[name] = value.ty
        self._instrs.append(AssignConst(dst=name, src=value))

    def _lower_var(self, s: A.VarStmt) -> None:
        # ``var x = expr``: same Python emission as ``let``, but the
        # IR records both kinds so future backends can enforce
        # immutability of let-bindings. Phase 2 collapses both to
        # AssignConst for simplicity; a follow-up may add a
        # ``mutable`` flag to AssignConst when a Wasm or LLVM target
        # cares.
        value = self._lower_expr(s.value)
        self._locals[s.name] = value.ty
        self._instrs.append(AssignConst(dst=s.name, src=value))

    def _lower_assign(self, s: A.AssignStmt) -> None:
        # Phase 2 only handles plain ``x = expr`` on a bare ident.
        # Compound assignment (``x += y``) and lhs-as-FieldAccess /
        # Index targets are deferred.
        if s.op != "=":
            raise UnsupportedInIR(
                f"compound assignment operator {s.op!r}"
            )
        if not isinstance(s.target, A.Ident):
            raise UnsupportedInIR(
                f"assignment target {type(s.target).__name__}"
            )
        value = self._lower_expr(s.value)
        self._instrs.append(Reassign(dst=s.target.name, src=value))

    def _lower_if(self, s: A.IfStmt) -> None:
        # Lower ``if cond { then } elif c1 { b1 } ... else { e }`` by
        # nesting elif chains in the else branch. The IR's ``If`` is
        # strictly binary (then / else). The condition's intermediate
        # instructions (e.g., method calls that build a Bool) need to
        # be emitted before the ``If`` itself; we capture them by
        # snapshotting the current instruction list, lowering the
        # condition, then splicing.
        outer_instrs = self._instrs

        # Condition: lower into a side buffer, then move into the
        # main instruction list before the ``If``.
        self._instrs = []
        cond_value = self._lower_expr(s.cond)
        cond_setup = self._instrs
        outer_instrs.extend(cond_setup)

        # Then body.
        self._instrs = []
        self._lower_block(s.then_block)
        then_body = self._instrs

        # Else chain: fold elifs into nested ifs, terminating with
        # the actual else block (or empty list if none).
        else_body: list[Instr] = self._fold_elif_chain(
            s.elif_arms, s.else_block,
        )

        self._instrs = outer_instrs
        self._instrs.append(
            If(cond=cond_value, then_body=then_body, else_body=else_body)
        )

    def _fold_elif_chain(self, elif_arms, else_block) -> list[Instr]:
        if not elif_arms:
            if else_block is None:
                return []
            buf = self._instrs
            self._instrs = []
            self._lower_block(else_block)
            out = self._instrs
            self._instrs = buf
            return out
        # First elif becomes ``if`` at this nesting level; remaining
        # elifs + the original else become its else-body.
        cond_expr, body = elif_arms[0]
        rest = elif_arms[1:]

        # Lower condition into a side buffer; its setup instructions
        # need to precede the nested ``If`` in the else_body.
        outer = self._instrs
        self._instrs = []
        cond_value = self._lower_expr(cond_expr)
        cond_setup = self._instrs

        self._instrs = []
        self._lower_block(body)
        then_body = self._instrs

        nested_else = self._fold_elif_chain(rest, else_block)

        self._instrs = outer
        return cond_setup + [
            If(cond=cond_value, then_body=then_body, else_body=nested_else)
        ]

    def _lower_while(self, s: A.WhileStmt) -> None:
        outer = self._instrs

        # Lower the condition into a setup buffer + a final Value.
        self._instrs = []
        cond_value = self._lower_expr(s.cond)
        cond_setup = self._instrs

        # Body.
        self._instrs = []
        self._lower_block(s.body)
        body = self._instrs

        self._instrs = outer
        self._instrs.append(
            While(cond_setup=cond_setup, cond=cond_value, body=body)
        )

    def _lower_for(self, s: A.ForStmt) -> None:
        # Phase 2 only supports Ident patterns. Tuple destructuring
        # (``for (a, b) in pairs``) is deferred.
        if not isinstance(s.pattern, A.IdentPat):
            raise UnsupportedInIR(
                f"for-pattern {type(s.pattern).__name__}"
            )
        iter_value = self._lower_expr(s.iter)
        self._locals[s.pattern.name] = "Unknown"
        outer = self._instrs
        self._instrs = []
        self._lower_block(s.body)
        body = self._instrs
        self._instrs = outer
        self._instrs.append(
            For(name=s.pattern.name, iter=iter_value, body=body)
        )

    def _lower_return(self, s: A.ReturnStmt) -> None:
        if s.value is None:
            self._instrs.append(Return(value=None))
            return
        v = self._lower_expr(s.value)
        self._instrs.append(Return(value=v))

    def _lower_expr_stmt(self, s: A.ExprStmt) -> None:
        # Discard the value of the expression; the side-effecting work
        # has already been emitted by ``_lower_expr``. For a call /
        # method-call we rewrite the last emitted instruction to drop
        # its ``dst`` so the emitter does not bind a useless local.
        v = self._lower_expr(s.expr)
        if self._instrs and isinstance(self._instrs[-1], (Call, MethodCall)):
            last = self._instrs[-1]
            if isinstance(v, Value) and v.kind == "local" and v.name == last.dst:
                last.dst = None
                self._locals.pop(v.name, None)
                return
        # No instruction-level rewrite possible (e.g., a bare literal
        # used as a statement). Just drop it; the emitter has nothing
        # to write.

    # ------------------------------------------------------------
    # Expressions: each returns a Value.
    # ------------------------------------------------------------

    def _lower_expr(self, e: A.Expr) -> Value:
        if isinstance(e, A.IntLit):
            return Value(kind="lit_int", literal=e.value, ty="Int")
        if isinstance(e, A.FloatLit):
            return Value(kind="lit_float", literal=e.value, ty="Float")
        if isinstance(e, A.StringLit):
            return Value(kind="lit_str", literal=e.value, ty="String")
        if isinstance(e, A.BoolLit):
            return Value(kind="lit_bool", literal=e.value, ty="Bool")
        if isinstance(e, A.UnitLit):
            return Value(kind="lit_unit", literal=None, ty="Unit")
        if isinstance(e, A.Ident):
            return self._lower_ident(e)
        if isinstance(e, A.BinOp):
            return self._lower_binop(e)
        if isinstance(e, A.UnaryOp):
            return self._lower_unary(e)
        if isinstance(e, A.Call):
            return self._lower_call(e)
        if isinstance(e, A.MethodCall):
            return self._lower_method_call(e)
        if isinstance(e, A.FieldAccess):
            return self._lower_field_access(e)
        if isinstance(e, A.Index):
            return self._lower_index(e)
        if isinstance(e, A.StructLit):
            return self._lower_struct_lit(e)
        if isinstance(e, A.ListLit):
            return self._lower_list_lit(e)
        if isinstance(e, A.TupleLit):
            return self._lower_tuple_lit(e)
        if isinstance(e, A.InterpolatedString):
            return self._lower_interpolated_string(e)
        raise UnsupportedInIR(f"expression {type(e).__name__}")

    def _lower_ident(self, e: A.Ident) -> Value:
        if e.name in self._params:
            ty = self._cap_params.get(e.name) or self._locals.get(e.name) or "Unknown"
            return Value(kind="param", name=e.name, ty=ty)
        if e.name in self._locals:
            return Value(kind="local", name=e.name, ty=self._locals[e.name])
        # Unknown identifier: could be a top-level function name, a
        # constant, a built-in capability class. Phase 1 only supports
        # built-in capability classes used as a value (rare) and
        # defers everything else.
        if e.name in _BUILTIN_CAPS:
            return Value(kind="cap_const", name=e.name, ty=e.name)
        raise UnsupportedInIR(f"identifier reference {e.name!r}")

    def _lower_binop(self, e: A.BinOp) -> Value:
        left = self._lower_expr(e.left)
        right = self._lower_expr(e.right)
        # Result type: trust the type map if present; otherwise default
        # to the left operand's type. Phase 1 does not need precise
        # inference here because the Python emitter does not specialise
        # on type.
        result_ty = self.types.get(id(e), left.ty) if self.types else left.ty
        if hasattr(result_ty, "__class__") and result_ty.__class__.__name__ != "str":
            result_ty = _ty_to_str(result_ty)
        dst = fresh_local(self._counter)
        self._locals[dst] = str(result_ty)
        self._instrs.append(BinOp(dst=dst, op=e.op, left=left, right=right))
        return Value(kind="local", name=dst, ty=str(result_ty))

    def _lower_unary(self, e: A.UnaryOp) -> Value:
        operand = self._lower_expr(e.operand)
        result_ty = operand.ty
        dst = fresh_local(self._counter)
        self._locals[dst] = result_ty
        self._instrs.append(UnaryOp(dst=dst, op=e.op, operand=operand))
        return Value(kind="local", name=dst, ty=result_ty)

    def _lower_call(self, e: A.Call) -> Value:
        # Phase 1: only supports direct identifier-callee calls (not
        # method-on-value or function-in-variable forms). Resolves the
        # callee by its source name.
        if not isinstance(e.callee, A.Ident):
            raise UnsupportedInIR(
                f"call with callee {type(e.callee).__name__}"
            )
        callee_name = e.callee.name
        args = [self._lower_expr(arg) for arg in e.args]
        result_ty = "Unknown"
        if self.types:
            t = self.types.get(id(e))
            if t is not None:
                result_ty = _ty_to_str(t)
        dst = fresh_local(self._counter)
        self._locals[dst] = result_ty
        self._instrs.append(Call(dst=dst, callee_name=callee_name, args=args))
        return Value(kind="local", name=dst, ty=result_ty)

    def _lower_field_access(self, e: A.FieldAccess) -> Value:
        recv = self._lower_expr(e.receiver)
        result_ty = "Unknown"
        if self.types:
            t = self.types.get(id(e))
            if t is not None:
                result_ty = _ty_to_str(t)
        dst = fresh_local(self._counter)
        self._locals[dst] = result_ty
        self._instrs.append(
            FieldAccess(dst=dst, receiver=recv, field=e.field_name)
        )
        return Value(kind="local", name=dst, ty=result_ty)

    def _lower_index(self, e: A.Index) -> Value:
        recv = self._lower_expr(e.receiver)
        idx = self._lower_expr(e.index)
        result_ty = "Unknown"
        if self.types:
            t = self.types.get(id(e))
            if t is not None:
                result_ty = _ty_to_str(t)
        dst = fresh_local(self._counter)
        self._locals[dst] = result_ty
        self._instrs.append(Index(dst=dst, receiver=recv, index=idx))
        return Value(kind="local", name=dst, ty=result_ty)

    def _lower_struct_lit(self, e: A.StructLit) -> Value:
        # Each field's value is lowered into the instruction list
        # first; the MakeStruct then references the produced locals.
        fields: list[tuple[str, Value]] = []
        for fname, fexpr in e.fields:
            fields.append((fname, self._lower_expr(fexpr)))
        dst = fresh_local(self._counter)
        self._locals[dst] = e.type_name
        self._instrs.append(
            MakeStruct(dst=dst, type_name=e.type_name, fields=fields)
        )
        return Value(kind="local", name=dst, ty=e.type_name)

    def _lower_list_lit(self, e: A.ListLit) -> Value:
        elements = [self._lower_expr(x) for x in e.elements]
        result_ty = "List"
        if self.types:
            t = self.types.get(id(e))
            if t is not None:
                result_ty = _ty_to_str(t)
        dst = fresh_local(self._counter)
        self._locals[dst] = result_ty
        self._instrs.append(MakeList(dst=dst, elements=elements))
        return Value(kind="local", name=dst, ty=result_ty)

    def _lower_tuple_lit(self, e: A.TupleLit) -> Value:
        if not e.elements:
            return Value(kind="lit_unit", literal=None, ty="Unit")
        elements = [self._lower_expr(x) for x in e.elements]
        result_ty = "Tuple"
        dst = fresh_local(self._counter)
        self._locals[dst] = result_ty
        self._instrs.append(MakeTuple(dst=dst, elements=elements))
        return Value(kind="local", name=dst, ty=result_ty)

    def _lower_interpolated_string(self, e: A.InterpolatedString) -> Value:
        # InterpolatedString carries a list of segments; each is
        # either a literal string fragment or an embedded expression.
        # We collect the parts into the FormatStr instruction's
        # ``parts`` list (alternating str / Value), lowering each
        # embedded expression into instructions first.
        parts: list = []
        for seg in e.parts:
            if isinstance(seg, str):
                parts.append(seg)
            else:
                parts.append(self._lower_expr(seg))
        dst = fresh_local(self._counter)
        self._locals[dst] = "String"
        self._instrs.append(FormatStr(dst=dst, parts=parts))
        return Value(kind="local", name=dst, ty="String")

    def _lower_method_call(self, e: A.MethodCall) -> Value:
        receiver = self._lower_expr(e.receiver)
        args = [self._lower_expr(arg) for arg in e.args]
        cap_used: Optional[str] = None
        # If the receiver is a capability-typed parameter, record the
        # capability class so the manifest builder can attribute this
        # method invocation.
        if receiver.kind == "param" and receiver.name in self._cap_params:
            cap_used = self._cap_params[receiver.name]
        result_ty = "Unknown"
        if self.types:
            t = self.types.get(id(e))
            if t is not None:
                result_ty = _ty_to_str(t)
        dst = fresh_local(self._counter)
        self._locals[dst] = result_ty
        self._instrs.append(
            MethodCall(
                dst=dst, receiver=receiver, method=e.method,
                args=args, cap_used=cap_used,
            )
        )
        return Value(kind="local", name=dst, ty=result_ty)


# ----------------------------------------------------------------
# Helpers.
# ----------------------------------------------------------------

def _type_name(te: object) -> str:
    """Best-effort name for a TypeExpr or Ty. Phase 1 only needs the
    string form for the Python emitter; structured Ty access can come
    later via the type map."""
    if te is None:
        return "Unknown"
    if isinstance(te, str):
        return te
    if hasattr(te, "name"):
        return getattr(te, "name")
    return _ty_to_str(te)


def _ty_to_str(t: object) -> str:
    """Convert a typesys Ty to a string. Falls back to ``repr`` for
    unknown shapes; the Python emitter does not consume this string."""
    try:
        from ..typesys import ty_str
        return ty_str(t)
    except Exception:
        return repr(t)
