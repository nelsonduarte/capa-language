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
class Reassign(Instr):
    """``dst = src`` for a previously-declared variable, where ``src``
    is a single ``Value``. Used to lower both ``AssignStmt`` with
    plain ``=`` and ``VarStmt`` rebindings; the difference from
    ``AssignConst`` is that ``Reassign`` does NOT introduce a new
    local. Python emits the same line either way; future backends
    that distinguish let-immutable from var-mutable consume the
    Instr type to decide."""
    dst: str
    src: Value


@dataclass
class If(Instr):
    """``if cond: then_body else: else_body``. Elif chains are
    lowered into nested ``If`` instructions inside ``else_body``;
    keeping the IR binary (then / else only) keeps the emitter
    simple and matches what every target backend wants."""
    cond: Value
    then_body: list[Instr]
    else_body: list[Instr]


@dataclass
class While(Instr):
    """``while cond: body``. The condition is recomputed each
    iteration; lowering responsibility for that recomputation falls
    on the lowerer, which inserts the condition-computing
    instructions inside the body's prelude on the first pass and
    again after each ``continue``. Phase 2 implementation keeps the
    cond as a single ``Value`` after evaluating any condition-side
    instructions before the loop and re-evaluating them at the end
    of the body; this matches the legacy transpiler's emission and
    is what Python's ``while`` semantics expect."""
    cond_setup: list[Instr]
    cond: Value
    body: list[Instr]


@dataclass
class Break(Instr):
    """``break`` inside a loop body."""
    pass


@dataclass
class Continue(Instr):
    """``continue`` inside a loop body."""
    pass


@dataclass
class MakeStruct(Instr):
    """``dst = TypeName(field=value, ...)``. The struct type is
    looked up by name at emit time; the IR carries only the name
    and the ordered (field, value) pairs as written at the source."""
    dst: str
    type_name: str
    fields: list[tuple[str, Value]]


@dataclass
class MakeList(Instr):
    """``dst = [v1, v2, ...]``. The element type lives in
    ``Function.locals[dst]``; lists in Capa are List<T> at the type
    level and Python lists at runtime."""
    dst: str
    elements: list[Value]


@dataclass
class MakeTuple(Instr):
    """``dst = (v1, v2, ...)``. Python tuples. Capa's TupleLit with
    zero elements lowers to a ``lit_unit`` Value instead."""
    dst: str
    elements: list[Value]


@dataclass
class FieldAccess(Instr):
    """``dst = receiver.field``. Receiver must be a struct value; the
    type check is the analyzer's responsibility, the IR trusts it."""
    dst: str
    receiver: Value
    field: str


@dataclass
class Index(Instr):
    """``dst = receiver[index]``. List indexing only for Phase 2;
    Map / Set indexing routes through dedicated method calls
    (``.get(k)``) at the analyzer level."""
    dst: str
    receiver: Value
    index: Value


@dataclass
class FormatStr(Instr):
    """``dst = f"...{v1}...{v2}..."``. Parts is a list of strings
    interleaved with Values; the literal parts before, between, and
    after each value. For a source-level ``"hello ${name}"`` the
    parts list is ``["hello ", v_name, ""]`` (always ends and
    begins with a literal, possibly empty)."""
    dst: str
    parts: list  # list[str | Value]


@dataclass
class For(Instr):
    """``for name in iter: body``. Pattern lowering is limited to
    single Ident targets in Phase 2; tuple destructuring patterns
    raise ``UnsupportedInIR``."""
    name: str
    iter: Value
    body: list[Instr]


@dataclass
class Pattern:
    """Base IR pattern. Concrete shapes below. Each backend's emitter
    decides how to render the pattern (Python ``match`` / ``case``
    syntax; Wasm CM ``record.match`` etc.)."""
    pass


@dataclass
class PatWildcard(Pattern):
    """``_`` — matches anything, binds nothing."""
    pass


@dataclass
class PatIdent(Pattern):
    """A bare identifier in pattern position — binds the scrutinee
    (or sub-scrutinee for nested patterns) to ``name`` in the arm
    body's scope."""
    name: str


@dataclass
class PatLiteral(Pattern):
    """A literal pattern. ``kind`` is one of ``"int"``, ``"str"``,
    ``"bool"``, ``"unit"``. ``value`` is the Python-side literal
    that the pattern compares against by equality."""
    kind: str
    value: object


@dataclass
class PatVariant(Pattern):
    """A sum-type variant pattern: ``VariantName(payload_pattern, ...)``
    for a variant with payloads, or ``VariantName()`` for a
    payload-less variant. Capa's ``None`` (Option's singleton)
    lowers to a PatVariant with name ``"None"`` and no payloads;
    the Python emitter has a special rule for it."""
    name: str
    payloads: list[Pattern]


@dataclass
class MatchArm:
    """A single arm of a Match. ``guard`` may be a Value that the
    emitter renders as a ``case ... if guard:`` clause; Phase 2D
    leaves ``guard=None`` for every arm because the lowerer rejects
    guard-bearing arms as UnsupportedInIR."""
    pattern: Pattern
    body: list[Instr]
    guard: Optional[Value] = None


@dataclass
class Match(Instr):
    """``match scrutinee: case pat -> body ...``.

    Statement-form only in Phase 2D: ``result_dst`` is None. A
    later phase that lifts MatchExpr (match in expression position)
    will populate ``result_dst`` and arrange for each arm body to
    write its produced value into it."""
    scrutinee: Value
    arms: list[MatchArm]
    result_dst: Optional[str] = None


@dataclass
class TryUnwrap(Instr):
    """The ``?`` operator. Reads ``src`` (a value of type
    ``Result<T, E>`` or ``Option<T>``); if it is ``Err`` or
    ``None_``, returns it from the enclosing function early.
    Otherwise binds the unwrapped payload (the ``Ok``'s or
    ``Some``'s ``.value``) to ``dst``.

    Three-address IR sidesteps the legacy expression-position vs.
    statement-position distinction: every ``?`` becomes a
    statement-level ``TryUnwrap`` because the surrounding
    expression has already been flattened into locals. The Python
    emitter expands this instruction to the same inline check
    pattern the legacy transpiler uses for the hoist-eligible
    positions; the slow ``_capa_try``/``_CapaTryEarlyReturn`` path
    is never reached from IR-emitted code."""
    dst: str
    src: Value


@dataclass
class MakeLambda(Instr):
    """``dst = fun(params) -> ret => body``. The lambda is emitted as
    a nested ``def`` whose name is ``dst``; Python closures handle
    capture-by-reference, so no explicit capture list is needed at
    this level. The body's last instruction for an expression-body
    lambda is a synthetic ``Return``; for a block-body lambda it is
    whatever the source's block produces. Wasm CM and LLVM backends
    will need to hoist this to a top-level function with an explicit
    capture record; Phase 2E leaves that lift to the backend."""
    dst: str
    params: list[Param]
    return_type: str
    body: list[Instr]


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
class StructField:
    """A field of a struct: name + Capa type as a string. The string
    form is what the Python emitter consumes; structured Ty access can
    be added later if a backend needs it."""
    name: str
    ty: str


@dataclass
class StructDecl:
    """A top-level ``type Name { field: T, ... }`` declaration. The
    Python emitter renders this as ``@dataclass class Name``."""
    name: str
    fields: list[StructField]


@dataclass
class SumVariant:
    """A variant of a sum type: ``Name`` (nullary) or
    ``Name(T1, T2, ...)`` (with payloads). For one payload the
    Python emitter emits a single ``value`` field on the dataclass;
    for N payloads it emits ``f0, f1, ..., f{N-1}`` to match the
    legacy transpiler's positional access convention."""
    name: str
    payload_tys: list[str]


@dataclass
class SumDecl:
    """A top-level ``type Name = V1 | V2(T) | ...`` declaration.
    Lowered to a sequence of dataclasses (one per variant) plus a
    union-type alias the analyzer's type-checker uses."""
    name: str
    variants: list[SumVariant]


@dataclass
class MethodSig:
    """A method signature inside a trait or capability declaration.
    No body; backends that emit interface-like targets (Wasm CM's
    WIT, for instance) consume these directly."""
    name: str
    params: list[Param]
    return_type: str


@dataclass
class TraitDecl:
    """A top-level ``trait Name { method-sigs }`` declaration.

    ``is_capability`` distinguishes Capa's two trait flavours: a
    plain trait (``trait``) is an interface; a capability trait
    (``capability``) is a user-defined capability that the manifest
    builder must track. Wasm CM emission cares about both because
    capabilities become WIT imports and traits become typed records.

    The Python emitter renders both alike (a class shell with each
    method raising ``NotImplementedError``); the runtime check that
    the impl actually exists is the analyzer's job."""
    name: str
    methods: list[MethodSig]
    is_capability: bool


@dataclass
class ImplBlock:
    """A top-level ``impl Type { ... }`` (inherent) or ``impl Trait for Type``
    block. ``methods`` is the list of lowered method functions; each
    Function carries its own params (including ``self``) and body.

    ``trait_name`` is the name of the trait being implemented, or
    ``None`` for an inherent impl. The Python emitter does not lift
    Capa traits to Python ABCs; the analyzer's static check is what
    makes the trait-impl relationship meaningful. The field is here
    because future backends (Wasm CM in particular) need to know
    which capability/trait each method realises."""
    type_name: str
    trait_name: Optional[str]
    methods: list[Function]


@dataclass
class Module:
    """A lowered module. Phase 1 carried only function declarations;
    Phase 3A adds top-level struct and sum type declarations.
    Phase 3B adds impl blocks. Subsequent phases will add traits,
    capabilities, constants, and imports. The legacy AST is preserved
    in ``ast_module`` so the Python emitter can defer back to the
    legacy transpiler for items the IR does not yet cover.
    """
    functions: list[Function]
    types: list = field(default_factory=list)  # list[StructDecl | SumDecl]
    impls: list = field(default_factory=list)  # list[ImplBlock]
    traits: list = field(default_factory=list)  # list[TraitDecl]
    ast_module: object = None  # capa_ast.Module; opaque to the IR


# Sentinel local-name generator helper.
def fresh_local(counter: dict, prefix: str = "t") -> str:
    """Allocate a unique local name using the supplied counter dict
    (single-key ``{"n": int}``)."""
    n = counter["n"]
    counter["n"] = n + 1
    return f"_ir_{prefix}{n}"
