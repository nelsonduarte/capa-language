"""Wasm-path-only pass: normalize the Capa type token ``Char`` to
``String`` throughout a lowered CIR module.

A Capa ``Char`` is a single-codepoint String: the CIR lowerer already
represents a char literal value as a string-shaped ``Value(kind=
"lit_str", ty="Char")`` (see ``_lower_expr.py``). At the Wasm level a
``Char`` is therefore laid out exactly like a ``String`` -- the same
(ptr, len) pair / packed-i64 slot conventions. The Wasm emitter has
full String machinery (params, returns, locals, interpolation,
equality, tuple / struct / list / map slots, match); the only reason
``Char`` fails is that the ~128 ``== "String"`` checks miss the literal
type token ``"Char"``.

This pass rewrites the whole-word type token ``Char`` to ``String`` in
every type-string-bearing field of the module, so the emitter never
sees ``"Char"``. It runs on the Wasm path only (wired into
``compile_wat`` right before emission); the Python transpiler path and
the AST-derived manifest / SBOM are untouched.

Whole-word replacement (regex ``\bChar\b``) means nested forms are
handled (``List<Char>``, ``(Char, Int)``, ``Map<Char, V>``,
``Option<Char>``) while a user type whose name merely contains "Char"
as a substring (``CharBuffer``) is left alone.

CIR ``Value`` is a frozen dataclass, so this pass rebuilds nodes with
``dataclasses.replace`` rather than mutating in place. The mutable
top-level / instruction nodes are updated field-by-field.
"""

from __future__ import annotations

import re
from dataclasses import replace

from . import _nodes as N
from ._lower_pattern import PatOr, PatStruct

# Whole-word ``Char`` -> ``String``. ``\b`` boundaries keep nested
# forms in scope (``List<Char>``) while leaving substring matches
# (``CharBuffer``) untouched.
_CHAR_TOKEN_RE = re.compile(r"\bChar\b")


def _norm(ty: str | None) -> str | None:
    """Rewrite every whole-word ``Char`` token in a type string to
    ``String``. Passes ``None`` / empty through unchanged."""
    if not ty:
        return ty
    return _CHAR_TOKEN_RE.sub("String", ty)


def normalize_char_to_string(module: N.Module) -> N.Module:
    """Rewrite the type token ``Char`` to ``String`` across every
    type-string-bearing field of ``module``. Mutates the module in
    place (rebuilding frozen ``Value`` nodes) and returns it."""
    for fn in module.functions:
        _normalize_function(fn)
    for impl in module.impls:
        for fn in impl.methods:
            _normalize_function(fn)
    for decl in module.types:
        _normalize_type_decl(decl)
    for trait in module.traits:
        _normalize_trait(trait)
    for const in module.consts:
        const.ty = _norm(const.ty)
        _normalize_instrs(const.body)
    return module


def _normalize_function(fn: N.Function) -> None:
    for p in fn.params:
        p.ty = _norm(p.ty)
    fn.return_type = _norm(fn.return_type)
    fn.locals = {name: _norm(ty) for name, ty in fn.locals.items()}
    # ``type_params`` are type-variable names, not Capa type strings;
    # leave them alone (a tyvar literally named ``Char`` would be
    # pathological and is out of scope).
    _normalize_instrs(fn.body)


def _normalize_type_decl(decl) -> None:
    if isinstance(decl, N.StructDecl):
        for f in decl.fields:
            f.ty = _norm(f.ty)
    elif isinstance(decl, N.SumDecl):
        for v in decl.variants:
            v.payload_tys = [_norm(t) for t in v.payload_tys]


def _normalize_trait(trait: N.TraitDecl) -> None:
    for m in trait.methods:
        for p in m.params:
            p.ty = _norm(p.ty)
        m.return_type = _norm(m.return_type)


def _normalize_value(v: N.Value) -> N.Value:
    """Rebuild a frozen ``Value`` with a normalized ``ty``. Returns the
    same instance when nothing changed so callers can detect no-ops."""
    new_ty = _norm(v.ty)
    if new_ty == v.ty:
        return v
    return replace(v, ty=new_ty)


def _normalize_instrs(instrs: list) -> None:
    """Rewrite every ``Value.ty`` operand and nested ``ty`` field in an
    instruction list, recursing into control-flow children."""
    for instr in instrs:
        _normalize_instr(instr)


def _normalize_instr(instr) -> None:
    # Operand Values (frozen) get rebuilt in place on their parent.
    if isinstance(instr, N.AssignConst):
        instr.src = _normalize_value(instr.src)
    elif isinstance(instr, N.Reassign):
        instr.src = _normalize_value(instr.src)
    elif isinstance(instr, N.BinOp):
        instr.left = _normalize_value(instr.left)
        instr.right = _normalize_value(instr.right)
    elif isinstance(instr, N.UnaryOp):
        instr.operand = _normalize_value(instr.operand)
    elif isinstance(instr, N.Call):
        instr.args = [_normalize_value(a) for a in instr.args]
    elif isinstance(instr, N.MethodCall):
        instr.receiver = _normalize_value(instr.receiver)
        instr.args = [_normalize_value(a) for a in instr.args]
    elif isinstance(instr, N.If):
        instr.cond = _normalize_value(instr.cond)
        _normalize_instrs(instr.then_body)
        _normalize_instrs(instr.else_body)
    elif isinstance(instr, N.While):
        _normalize_instrs(instr.cond_setup)
        instr.cond = _normalize_value(instr.cond)
        _normalize_instrs(instr.body)
    elif isinstance(instr, N.For):
        instr.iter = _normalize_value(instr.iter)
        _normalize_instrs(instr.body)
    elif isinstance(instr, N.MakeStruct):
        instr.fields = [
            (name, _normalize_value(val)) for name, val in instr.fields
        ]
    elif isinstance(instr, N.MakeList):
        instr.elements = [_normalize_value(e) for e in instr.elements]
    elif isinstance(instr, N.MakeTuple):
        instr.elements = [_normalize_value(e) for e in instr.elements]
    elif isinstance(instr, N.MakeRange):
        instr.start = _normalize_value(instr.start)
        instr.end = _normalize_value(instr.end)
    elif isinstance(instr, N.FieldAccess):
        instr.receiver = _normalize_value(instr.receiver)
    elif isinstance(instr, N.FieldStore):
        instr.receiver = _normalize_value(instr.receiver)
        instr.src = _normalize_value(instr.src)
    elif isinstance(instr, N.Index):
        instr.receiver = _normalize_value(instr.receiver)
        instr.index = _normalize_value(instr.index)
    elif isinstance(instr, N.FormatStr):
        instr.parts = [
            _normalize_value(p) if isinstance(p, N.Value) else p
            for p in instr.parts
        ]
    elif isinstance(instr, N.TryUnwrap):
        instr.src = _normalize_value(instr.src)
    elif isinstance(instr, N.Return):
        if instr.value is not None:
            instr.value = _normalize_value(instr.value)
    elif isinstance(instr, N.ExprStmt):
        instr.value = _normalize_value(instr.value)
    elif isinstance(instr, N.MakeLambda):
        for p in instr.params:
            p.ty = _norm(p.ty)
        instr.return_type = _norm(instr.return_type)
        _normalize_instrs(instr.body)
    elif isinstance(instr, N.Match):
        instr.scrutinee = _normalize_value(instr.scrutinee)
        for arm in instr.arms:
            _normalize_pattern(arm.pattern)
            if arm.guard is not None:
                arm.guard = _normalize_value(arm.guard)
            _normalize_instrs(arm.guard_setup)
            _normalize_instrs(arm.body)
    # MakeMap / MakeSet / Break / Continue carry no type-string field.


def _normalize_pattern(pat) -> None:
    """Patterns carry no Capa type string today (PatLiteral kinds are
    runtime-shape tags, PatStruct.type_name is a type *name* not a
    parametric type string). Recurse into nested patterns for
    completeness so a future type-bearing pattern field is reached."""
    if isinstance(pat, N.PatVariant):
        for sub in pat.payloads:
            _normalize_pattern(sub)
    elif isinstance(pat, N.PatTuple):
        for sub in pat.elements:
            _normalize_pattern(sub)
    elif isinstance(pat, PatOr):
        for sub in pat.alternatives:
            _normalize_pattern(sub)
    elif isinstance(pat, PatStruct):
        for _name, sub in pat.fields:
            _normalize_pattern(sub)
