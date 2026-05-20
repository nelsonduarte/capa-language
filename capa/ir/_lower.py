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
    AssignConst, BinOp, UnaryOp, Call, MethodCall, Return,
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
