"""Abstract syntax tree (AST) of the Capa language.

Each node has an associated position (the `pos` field) that points to the
start of the construct in the source — useful for type checker error
messages and for IDE tooling.

Design conventions:
- All nodes inherit from Node and use @dataclass(kw_only=True) to avoid
  field-ordering issues with defaults across the hierarchy.
- Abstract categories (Item, Stmt, Expr, Pattern, TypeExpr) are only
  for typing; they have no fields of their own beyond `pos`.
- Empty lists are preferred over None for fields like type_params, args.
- None is used for genuine semantic optionality (no return type, no
  guard in a match arm, etc.).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .tokens import Pos


# ===========================================================
# Base categories
# ===========================================================


@dataclass(kw_only=True)
class Node:
    """Base of the entire AST hierarchy. `pos` points to the starting token."""
    pos: Pos


@dataclass(kw_only=True)
class Item(Node):
    """Top-level declaration: import, type, trait, impl, fun, const."""
    pass


@dataclass(kw_only=True)
class Stmt(Node):
    """Statement inside a block."""
    pass


@dataclass(kw_only=True)
class Expr(Node):
    """Value-producing expression."""
    pass


@dataclass(kw_only=True)
class Pattern(Node):
    """Pattern used in let, for and match arms."""
    pass


@dataclass(kw_only=True)
class TypeExpr(Node):
    """Type expression (annotations, returns, generic parameters)."""
    pass


# ===========================================================
# Program top-level
# ===========================================================


@dataclass(kw_only=True)
class Module(Node):
    """A Capa file is a Module."""
    items: list[Item]


# ===========================================================
# Top-level items
# ===========================================================


@dataclass(kw_only=True)
class Import(Item):
    """import X            -> path=['X'], alias=None
    import X.Y          -> path=['X','Y'], alias=None
    import X as Z       -> path=['X'], alias='Z'
    """
    path: list[str]
    alias: Optional[str] = None


@dataclass(kw_only=True)
class ConstDecl(Item):
    name: str
    type_expr: TypeExpr
    value: Expr
    is_pub: bool = False


@dataclass(kw_only=True)
class Field(Node):
    """Field of a struct."""
    name: str
    type_expr: TypeExpr


@dataclass(kw_only=True)
class TypeStruct(Item):
    """type Name { field: T, ... }"""
    name: str
    type_params: list[str] = field(default_factory=list)
    fields: list[Field]
    is_pub: bool = False


@dataclass(kw_only=True)
class Variant(Node):
    """Variant of a sum type; payload optional."""
    name: str
    payload: Optional[TypeExpr] = None


@dataclass(kw_only=True)
class TypeSum(Item):
    """type Name =
        Variant1
        Variant2(T)
    """
    name: str
    type_params: list[str] = field(default_factory=list)
    variants: list[Variant]
    is_pub: bool = False


@dataclass(kw_only=True)
class Param(Node):
    """Function or method parameter.

    For `self`, name='self' and type_expr=None.
    `consuming=True` indicates that the function consumes the argument (moves ownership).
    """
    name: str
    type_expr: Optional[TypeExpr] = None
    consuming: bool = False


@dataclass(kw_only=True)
class MethodSig(Node):
    """Method signature inside a trait."""
    name: str
    type_params: list[str] = field(default_factory=list)
    params: list[Param]
    return_type: Optional[TypeExpr] = None


@dataclass(kw_only=True)
class TraitDecl(Item):
    """A trait declaration. If ``is_capability`` is True, the declaration
    used the ``capability`` keyword instead of ``trait``: the declared
    name is registered as a capability (subject to the capability
    discipline), and types that implement it can be used as receivers
    of capability-typed parameters.
    """
    name: str
    type_params: list[str] = field(default_factory=list)
    methods: list[MethodSig]
    is_pub: bool = False
    is_capability: bool = False


@dataclass(kw_only=True)
class FunDecl(Item):
    """Function declaration (top-level or method inside an impl)."""
    name: str
    type_params: list[str] = field(default_factory=list)
    params: list[Param]
    return_type: Optional[TypeExpr] = None
    body: Block
    is_pub: bool = False


@dataclass(kw_only=True)
class ImplBlock(Item):
    """impl Trait for Type<...>   or   impl Type<...>"""
    trait_name: Optional[str]   # None = inherent impl
    type_name: str
    type_args: list[TypeExpr] = field(default_factory=list)
    methods: list[FunDecl]


# ===========================================================
# Statements
# ===========================================================


@dataclass(kw_only=True)
class Block(Node):
    """Indented sequence of statements."""
    stmts: list[Stmt]


@dataclass(kw_only=True)
class LetStmt(Stmt):
    """let pattern: T = value   (T optional)"""
    pattern: Pattern
    type_expr: Optional[TypeExpr] = None
    value: Expr


@dataclass(kw_only=True)
class VarStmt(Stmt):
    """var name: T = value   (mutable)"""
    name: str
    type_expr: Optional[TypeExpr] = None
    value: Expr


@dataclass(kw_only=True)
class AssignStmt(Stmt):
    """target op= value, where target is ident, field access or index."""
    target: Expr
    op: str  # '=', '+=', '-=', '*=', '/=', '%='
    value: Expr


@dataclass(kw_only=True)
class IfStmt(Stmt):
    cond: Expr
    then_block: Block
    elif_arms: list[tuple[Expr, Block]] = field(default_factory=list)
    else_block: Optional[Block] = None


@dataclass(kw_only=True)
class WhileStmt(Stmt):
    cond: Expr
    body: Block


@dataclass(kw_only=True)
class ForStmt(Stmt):
    pattern: Pattern
    iter: Expr
    body: Block


@dataclass(kw_only=True)
class MatchArm(Node):
    """A match arm: pattern (if guard)? -> body

    body is an expression (common case, single-line) or a Block (multi-line).
    When match is used as an expression, an Expr body produces the value
    of the arm; a Block body produces Unit (unless it ends in return).
    """
    pattern: Pattern
    guard: Optional[Expr] = None
    body: Block | Expr  # Block for multi-line arms, Expr for single-line


@dataclass(kw_only=True)
class MatchExpr(Expr):
    """``match`` as an expression. In statement context, it is wrapped in
    ``ExprStmt``; in expression context (RHS of let/var, return, etc.),
    the value of each arm with an expression body becomes the match value."""
    scrutinee: Expr
    arms: list[MatchArm]


@dataclass(kw_only=True)
class IfExpr(Expr):
    """``if cond then e1 else e2`` — Capa ternary operator.

    Inline syntax for choosing a value between two expressions. Useful
    in single-line closures and in the RHS of let/var. The two branches
    must have compatible types. ``elif`` is not supported in this form —
    use match or an if-statement instead.
    """
    cond: Expr
    then_expr: Expr
    else_expr: Expr


@dataclass(kw_only=True)
class ReturnStmt(Stmt):
    value: Optional[Expr] = None


@dataclass(kw_only=True)
class BreakStmt(Stmt):
    pass


@dataclass(kw_only=True)
class ContinueStmt(Stmt):
    pass


@dataclass(kw_only=True)
class ExprStmt(Stmt):
    """Expression used as a statement (typically, a function call)."""
    expr: Expr


# ===========================================================
# Expressions — literals and identifiers
# ===========================================================


@dataclass(kw_only=True)
class IntLit(Expr):
    value: int


@dataclass(kw_only=True)
class FloatLit(Expr):
    value: float


@dataclass(kw_only=True)
class StringLit(Expr):
    value: str


@dataclass(kw_only=True)
class InterpolatedString(Expr):
    """String literal with ``${expr}`` interpolations.

    ``parts`` alternates literal text (``str``) and expressions (``Expr``).
    Empty text is allowed but redundant. For example,
    ``"a${x}b"`` produces ``parts=["a", Ident("x"), "b"]``;
    ``"${x}${y}"`` produces ``parts=["", Ident("x"), "", Ident("y"), ""]``.
    """
    parts: list  # list[str | Expr]


@dataclass(kw_only=True)
class CharLit(Expr):
    value: str


@dataclass(kw_only=True)
class BoolLit(Expr):
    value: bool


@dataclass(kw_only=True)
class UnitLit(Expr):
    """The () expression of type Unit."""
    pass


@dataclass(kw_only=True)
class Ident(Expr):
    name: str


# ===========================================================
# Expressions — operators
# ===========================================================


@dataclass(kw_only=True)
class BinOp(Expr):
    op: str
    left: Expr
    right: Expr


@dataclass(kw_only=True)
class UnaryOp(Expr):
    op: str  # 'not', '-'
    operand: Expr


# ===========================================================
# Expressions — postfix
# ===========================================================


@dataclass(kw_only=True)
class Call(Expr):
    callee: Expr
    type_args: list[TypeExpr] = field(default_factory=list)  # turbofish ::<T>
    args: list[Expr]


@dataclass(kw_only=True)
class MethodCall(Expr):
    receiver: Expr
    method: str
    type_args: list[TypeExpr] = field(default_factory=list)
    args: list[Expr]


@dataclass(kw_only=True)
class FieldAccess(Expr):
    receiver: Expr
    field_name: str


@dataclass(kw_only=True)
class Index(Expr):
    receiver: Expr
    index: Expr


@dataclass(kw_only=True)
class Try(Expr):
    """expr? — propagates the error if it is Err."""
    expr: Expr


# ===========================================================
# Expressions — aggregates
# ===========================================================


@dataclass(kw_only=True)
class StructLit(Expr):
    """Type { field: value, ... }"""
    type_name: str
    type_args: list[TypeExpr] = field(default_factory=list)
    fields: list[tuple[str, Expr]]


@dataclass(kw_only=True)
class ListLit(Expr):
    elements: list[Expr]


@dataclass(kw_only=True)
class TupleLit(Expr):
    """Tuple with 0+ elements. (1,) is a 1-tuple, () is unit."""
    elements: list[Expr]


@dataclass(kw_only=True)
class LambdaExpr(Expr):
    """Closure (lambda expression): ``fun (params) -> Ret => body``.

    The body can be:
    - A single expression (single-expr): ``fun (x) => x + 1``
    - An indented block (multi-line): ``fun (x) =>\\n    ...\\n    return x``

    A block body allows multiple statements and explicit returns.
    Without ``return``, a block-body returns ``Unit``.
    """
    params: list[Param]
    return_type: Optional[TypeExpr] = None
    body: "Expr | Block"


# ===========================================================
# Patterns
# ===========================================================


@dataclass(kw_only=True)
class WildcardPat(Pattern):
    """_"""
    pass


@dataclass(kw_only=True)
class IdentPat(Pattern):
    """Binds the value to a name."""
    name: str


@dataclass(kw_only=True)
class LiteralPat(Pattern):
    """Literal pattern (int, float, string, char, bool)."""
    value: Expr


@dataclass(kw_only=True)
class VariantPat(Pattern):
    """Sum-type variant with optional payload.

    Red             -> name='Red', payload=None
    Some(x)         -> name='Some', payload=IdentPat('x')
    Some(Red)       -> name='Some', payload=VariantPat('Red', None)
    """
    name: str
    payload: Optional[Pattern] = None


@dataclass(kw_only=True)
class StructPat(Pattern):
    """Type { field: pat, ... }   (just `field` is shorthand for `field: field`)"""
    type_name: str
    fields: list[tuple[str, Optional[Pattern]]]


@dataclass(kw_only=True)
class TuplePat(Pattern):
    """``(pat1, pat2, ...)`` — deconstructs a tuple into its components.

    Each element is itself a pattern, allowing nesting such as
    ``(Some(x), y)``. Empty tuples ``()`` match the ``Unit`` type.
    """
    elements: list[Pattern]


@dataclass(kw_only=True)
class OrPat(Pattern):
    """``pat1 | pat2 | ... | patN`` — pattern alternatives.

    Matches if *any* of the alternatives matches. For v0, we do not
    support bindings inside or-patterns (each alternative must be a
    pattern without bound variables: literal, wildcard, variant without
    payload). This restriction exists because allowing bindings would
    require ensuring that all alternatives bind the same names with the
    same types.
    """
    alternatives: list[Pattern]


# ===========================================================
# Types
# ===========================================================


@dataclass(kw_only=True)
class TypeName(TypeExpr):
    """Type name, possibly with generic arguments."""
    name: str
    args: list[TypeExpr] = field(default_factory=list)


@dataclass(kw_only=True)
class FunType(TypeExpr):
    """fun(T1, T2) -> T3"""
    param_types: list[TypeExpr]
    return_type: TypeExpr


@dataclass(kw_only=True)
class TupleType(TypeExpr):
    elements: list[TypeExpr]


@dataclass(kw_only=True)
class UnitType(TypeExpr):
    """The Unit type, written ()."""
    pass


# ===========================================================
# Pretty-printing utility (debug / CLI)
# ===========================================================


def dump(node, indent: int = 0) -> str:
    """Returns a multi-line representation of the AST, useful for debugging."""
    pad = "  " * indent
    if isinstance(node, list):
        if not node:
            return "[]"
        body = "\n".join(pad + "  - " + dump(n, indent + 1).lstrip() for n in node)
        return f"[\n{body}\n{pad}]"
    if not isinstance(node, Node):
        return repr(node)
    cls = type(node).__name__
    fields_repr = []
    for f in node.__dataclass_fields__.values():
        if f.name == "pos":
            continue
        v = getattr(node, f.name)
        if v is None or v == [] or v is False:
            # Omit empty defaults to avoid clutter.
            continue
        fields_repr.append((f.name, v))
    if not fields_repr:
        return f"{cls}"
    parts = []
    for name, v in fields_repr:
        if isinstance(v, list) and v and isinstance(v[0], Node):
            parts.append(f"{pad}  {name}={dump(v, indent + 1)}")
        elif isinstance(v, Node):
            parts.append(f"{pad}  {name}={dump(v, indent + 1)}")
        else:
            parts.append(f"{pad}  {name}={v!r}")
    return f"{cls}(\n" + "\n".join(parts) + f"\n{pad})"
