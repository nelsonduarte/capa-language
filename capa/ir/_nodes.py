"""CIR data classes.

Naming: ``Value`` is an operand (literal or a reference to a local /
param); ``Instr`` is an instruction that lives in a function body.
Every instruction either binds its result to a local (``dst``) or
performs a side effect (call discarded, control flow, return).

The IR is intentionally typeless at the structural level (no inheritance
tree of typed instructions) so that pattern-matching on
``isinstance(instr, ...)`` stays cheap for the emitters. Each instruction
carries the minimum information its target backend needs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


# ----------------------------------------------------------------
# Values: operands referenced by instructions.
# ----------------------------------------------------------------

@dataclass(frozen=True)
class Value:
    """An operand. ``kind`` selects which payload field is meaningful.

    ``kind="local"`` / ``"param"``: ``name`` holds the identifier.
    ``kind="lit_int"`` / ``"lit_float"`` / ``"lit_str"`` /
    ``"lit_bool"`` / ``"lit_unit"``: ``literal`` holds the value.
    ``kind="cap_const"``: ``name`` holds the capability class name
    (e.g. "Stdio").

    ``ty`` is the Capa type of the value as a string for now (the
    string representation used by ``typesys.ty_str``). Backends that
    need the structured Ty can re-resolve from the type map; the
    string form is enough for the Phase 1 Python emitter.
    """
    kind: str
    name: Optional[str] = None
    literal: object = None
    ty: str = ""


# ----------------------------------------------------------------
# Locals + params.
# ----------------------------------------------------------------

@dataclass
class Local:
    """A function-local binding: declared once, assigned to by an
    ``Assign`` instruction. The type is the Capa type as a string.
    """
    name: str
    ty: str


@dataclass
class Param:
    """A function parameter. ``is_capability`` flags parameters whose
    type is a capability (built-in or user-defined); the manifest
    emitter and any capability-aware backend (Wasm CM) consume this.
    """
    name: str
    ty: str
    is_capability: bool = False


# ----------------------------------------------------------------
# Instructions. Each is a dataclass; emitters dispatch via isinstance.
# ----------------------------------------------------------------

@dataclass
class Instr:
    """Base type. Subclasses are the concrete instruction shapes."""
    pass


@dataclass
class AssignConst(Instr):
    """``dst = <value>`` where the right-hand side is a single Value."""
    dst: str
    src: Value


@dataclass
class BinOp(Instr):
    """``dst = left <op> right``. ``op`` is the source-level operator
    spelling (``+``, ``-``, ``==``, ``and``, etc.). Type promotion is
    not done at the IR level; the Python emitter relies on Python's
    runtime semantics for now.
    """
    dst: str
    op: str
    left: Value
    right: Value


@dataclass
class UnaryOp(Instr):
    """``dst = <op> operand`` where ``op`` is a source-level unary."""
    dst: str
    op: str
    operand: Value


@dataclass
class Call(Instr):
    """``dst = callee(args...)``. ``callee_name`` is the resolved
    function name (after qualified-call rewriting). ``dst`` is None
    when the call's value is discarded.

    ``cap_flow`` lists the capability classes that flow through this
    call's parameter list (the static manifest's per-call-site
    contribution). Phase 1 leaves it empty; the manifest emitter does
    not yet read CIR, so the field is preserved for future use.
    """
    dst: Optional[str]
    callee_name: str
    args: list[Value]
    cap_flow: list[str] = field(default_factory=list)


@dataclass
class MethodCall(Instr):
    """``dst = receiver.method(args...)``. ``cap_used`` is set when
    the receiver's type is a capability; it names the capability
    class so the manifest builder can record this method invocation.
    """
    dst: Optional[str]
    receiver: Value
    method: str
    args: list[Value]
    cap_used: Optional[str] = None


@dataclass
class Return(Instr):
    """``return value``; ``value`` is None for a bare ``return``."""
    value: Optional[Value]


@dataclass
class ExprStmt(Instr):
    """An expression evaluated for side effects; the value (if any) is
    discarded. In CIR this is just the underlying Call / MethodCall
    instruction with ``dst=None``; this wrapper exists only when the
    expression itself was a Value (rare: a bare literal or identifier
    as a statement). Phase 1 may not emit any of these but it is here
    for completeness."""
    value: Value


# ----------------------------------------------------------------
# Top-level: functions and modules.
# ----------------------------------------------------------------

@dataclass
class Function:
    """A lowered function. ``locals`` is the mapping of every
    fresh local name introduced by the lowering pass to its CIR type
    (used by emitters that need to declare locals up front).
    """
    name: str
    params: list[Param]
    return_type: str
    declared_caps: list[str]
    body: list[Instr]
    locals: dict[str, str] = field(default_factory=dict)


@dataclass
class Module:
    """A lowered module. Phase 1 only carries function declarations;
    later phases will add structs, sums, traits, capabilities, impls,
    constants, and imports. The legacy AST is preserved in
    ``ast_module`` so the Python emitter can defer back to the legacy
    transpiler for items the IR does not yet cover.
    """
    functions: list[Function]
    ast_module: object = None  # capa_ast.Module; opaque to the IR


# Sentinel local-name generator helper.
def fresh_local(counter: dict, prefix: str = "t") -> str:
    """Allocate a unique local name using the supplied counter dict
    (single-key ``{"n": int}``)."""
    n = counter["n"]
    counter["n"] = n + 1
    return f"_ir_{prefix}{n}"
