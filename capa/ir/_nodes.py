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

    ``route`` records the direct-vs-closure routing decision made at
    LOWERING time (``"direct"`` -> ``call $name``; ``"closure"`` ->
    dispatch the callee value via ``call_indirect``). It is consulted
    ONLY by the Wasm emitter's closure-vs-direct routing (the ordinary
    path in ``_emit_wasm._emit_user_call`` and the tail-call peephole
    ``_is_tail_callable``), which honour the tag instead of re-deriving
    the decision from the flat ``Function.locals`` type map -- that map
    intentionally keeps a dead lambda-body local's ``Fun`` type for the
    closure emitter and so would mis-route a same-named enclosing call
    (a Python<->Wasm output divergence).

    ``route`` does NOT gate the emitter's by-name special-case branches.
    ``_emit_user_call`` reaches the routing check only AFTER those
    branches -- variant constructors (``self._variant_to_sum``),
    ``IoError``, ``Random``, ``parse_json`` / ``to_json``, ``parse_int``
    / ``parse_float``, ``panic``, ``to_int`` / ``to_float``, ``_capa_chr``,
    ``_capa_str_span`` -- have each already ``return``ed, keyed only on
    ``callee_name``; the lowerer likewise intercepts ``new_map`` /
    ``new_set`` into MakeMap / MakeSet with no Call (so no ``route``) at
    all. Hence ``None`` is merely the absence of the tag, NOT a claim
    that the callee is a built-in / intrinsic / variant, and those
    branches are NOT shadow-safe: a live-local or Fun-param shadow of one
    of those names (the lowerer tags it ``"closure"``) still runs as the
    built-in on Wasm while Python honours the shadow -- a silent wrong
    value, or a Wasm validation failure, from a ``--check``-clean
    program. That divergence is a KNOWN-OPEN, pre-existing residual this
    routing tag does not close. For an ordinary callee whose ``route`` is
    ``None``, the emitter falls back to the ``Function.locals`` lookup."""
    dst: Optional[str]
    callee_name: str
    args: list[Value]
    cap_flow: list[str] = field(default_factory=list)
    route: Optional[str] = None


@dataclass
class MethodCall(Instr):
    """``dst = receiver.method(args...)``. ``cap_used`` is set when
    the receiver's type is a capability; it names the capability
    class so the manifest builder can record this method invocation.

    ``attenuations`` carries the list of ``restrict_to`` /
    ``restrict_to_keys`` / ``restrict_to_after`` calls that were
    applied to this receiver before it reached the privileged
    method (e.g. ``let tmp = fs.restrict_to("/tmp/")`` then
    ``tmp.read(...)`` records ``[{"method": "restrict_to",
    "args": ["/tmp/"]}]`` here). The Wasm backend consumes this
    field to emit an inline runtime check before the host call so
    a guest cannot bypass attenuation by ignoring the discipline.
    Populated by the lowerer using ``_build_attenuation_map``;
    intra-function scope only in v1.
    """
    dst: Optional[str]
    receiver: Value
    method: str
    args: list[Value]
    cap_used: Optional[str] = None
    attenuations: Optional[list] = None


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
class MakeMap(Instr):
    """``dst = {}``. Capa's ``new_map()`` builtin is recognised by
    the lowerer and emitted as a dedicated instruction so the Python
    emitter can render a literal ``{}`` rather than a function call
    against a name that does not exist at runtime."""
    dst: str


@dataclass
class MakeSet(Instr):
    """``dst = set()``. Capa's ``new_set()`` builtin, dual to MakeMap."""
    dst: str


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
class FieldStore(Instr):
    """``receiver.field = src``. In-place mutation of a struct field
    slot. The receiver is the same heap-record value a ``FieldAccess``
    reads from; this writes ``src`` into that field's slot using the
    field's per-type encoding (the symmetric operation to a read).
    No ``dst``: the instruction is a pure side effect. The analyzer
    (capa/analyzer/_frozen.py) has already vetted that ``field`` is
    permitted to be mutated."""
    receiver: Value
    field: str
    src: Value


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
class MakeRange(Instr):
    """``dst = start..end`` (exclusive) or ``dst = start..=end``
    (inclusive). Mirrors :class:`capa.capa_ast.RangeExpr` at the
    IR level. The Python emitter renders this as a
    ``CapaRange(start, stop)`` wrapper; the Wasm emitter allocates
    a 24-byte heap record { start: i64, end: i64, inclusive: i32 }
    and, when consumed by a ``For`` iter whose type starts with
    ``Range``, emits a counted-loop fast-path without
    materialising the integer sequence."""
    dst: str
    start: Value
    end: Value
    inclusive: bool


@dataclass
class Pattern:
    """Base IR pattern. Concrete shapes below. Each backend's emitter
    decides how to render the pattern (Python ``match`` / ``case``
    syntax; Wasm CM ``record.match`` etc.)."""
    pass


@dataclass
class PatWildcard(Pattern):
    """``_`` - matches anything, binds nothing."""
    pass


@dataclass
class PatIdent(Pattern):
    """A bare identifier in pattern position - binds the scrutinee
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
class PatTuple(Pattern):
    """A tuple pattern: ``(pat0, pat1, ...)``. Each element is a
    nested pattern; the scrutinee at match time is a tuple value
    of matching arity. Lowered from ``A.TuplePat``; the Python
    emitter renders it as a Python ``(a, b)`` tuple pattern, the
    Wasm emitter loads each slot from the tuple heap record and
    matches the corresponding sub-pattern."""
    elements: list[Pattern]


@dataclass
class MatchArm:
    """A single arm of a Match.

    ``guard`` is the Value the emitter tests for the arm to fire;
    ``None`` for unconditional arms. ``guard_setup`` carries the
    ANF prelude instructions the guard expression lowered to
    (FieldAccess, UnaryOp, BinOp, ...) when the guard is not a
    trivial Value reference. Emitters either inline the prelude
    back into a single expression (Python ``case PAT if EXPR:``)
    or emit it as a fall-through control-flow block before testing
    ``guard`` (Wasm). For trivial guards (a bare identifier, a
    literal, a single binop on locals) ``guard_setup`` is empty
    and the guard renders directly as a Python expression."""
    pattern: Pattern
    body: list[Instr]
    guard: Optional[Value] = None
    guard_setup: list[Instr] = field(default_factory=list)


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


@dataclass
class ForeignCall(Instr):
    """``dst = Component.method(args...)`` across a typed foreign-
    component boundary (feature #4, F2a).

    Unlike a :class:`MethodCall`, the receiver is NOT a value: it is the
    source-level name of an ``extern component`` declaration, a callable
    namespace. The call crosses into an external Wasm Component Model
    artifact that the Wasm runtime sandboxes to exactly the capabilities
    passed here (the ``cap`` params). It lowers to a single host import
    call on the core ``--wasm`` path (``capa:foreign/<component>`` /
    ``<method>``): the guest pushes each capability argument's i32 handle
    plus each scalar argument, and the host closure resolves the handles
    to the caller's pre-attenuated caps, instantiates the child component
    with a restricted linker that binds ONLY those caps, calls the child's
    scalar export, and returns the scalar result.

    ``args`` are the lowered operands in declared-parameter order.
    ``param_kinds`` is a parallel list of ``("cap", CapName)`` or
    ``("scalar", SourceTy)`` tags describing each argument, so the emitter
    knows which operand is a handle (i32), which is a scalar, and which is
    a String (``("scalar", "String")`` -> a (ptr, len) pair), and the host
    knows which caps to bind. ``return_type`` is the source-level return
    type (``Int`` / ``Bool`` / ``Float`` / ``String`` / ``Unit``).
    ``artifact`` is the declared path to the child ``.wasm``.

    F2a marshals scalar crossing types (Int / Bool / Float); F2b adds the
    String crossing type (a (ptr, len) arg + an 8-byte indirect return
    area). An aggregate crossing type is rejected earlier (the CLI's
    aggregate guard, a further sub-phase), so this node only ever carries
    scalar / String params + return."""
    dst: Optional[str]
    component: str
    method: str
    artifact: str
    args: list[Value]
    param_kinds: list
    return_type: str


# ----------------------------------------------------------------
# Top-level: functions and modules.
# ----------------------------------------------------------------

@dataclass
class Function:
    """A lowered function. ``locals`` is the mapping of every
    fresh local name introduced by the lowering pass to its CIR type
    (used by emitters that need to declare locals up front).

    ``type_params`` carries the source's ``fun first<T, U>(...)``
    type-parameter names. The Python backend ignores them (duck
    typing handles substitution at runtime); the Wasm backend's
    monomorphisation pass uses them to identify generic functions
    that need per-instantiation specialisation before emit.
    """
    name: str
    params: list[Param]
    return_type: str
    declared_caps: list[str]
    body: list[Instr]
    locals: dict[str, str] = field(default_factory=dict)
    type_params: list[str] = field(default_factory=list)
    # ``@export``: marks this top-level function for the Wasm Component
    # Model export surface. The WIT generator advertises it in the
    # ``world`` alongside ``main`` (see
    # ``capa.ir._emit_wit._component_export_lines``). Set by the lowerer
    # from the source ``@export`` attribute; ignored by the Python
    # backend.
    is_export: bool = False


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
    Python emitter renders this as ``@dataclass class Name``.

    ``type_params`` carries the source's ``type Pair<T> { ... }``
    type-parameter names. The Python backend ignores them (duck
    typing); the Wasm backend's monomorphisation pass uses them to
    specialise a generic struct per concrete instantiation
    (``Pair<Char>`` -> a ``Pair__Char`` clone whose field ``a`` has
    the concrete type) so the layout machinery sizes / decodes each
    field correctly. Empty for non-generic structs."""
    name: str
    fields: list[StructField]
    type_params: list[str] = field(default_factory=list)


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
    union-type alias the analyzer's type-checker uses.

    ``type_params`` mirrors :class:`StructDecl.type_params`: the
    source's ``type Either<L, R> = ...`` type-parameter names, used
    by the Wasm monomorphisation pass to specialise a generic sum
    per concrete instantiation. Empty for non-generic sums."""
    name: str
    variants: list[SumVariant]
    type_params: list[str] = field(default_factory=list)


@dataclass
class ConstDecl:
    """A top-level ``const NAME: T = expr``. The right-hand side is
    represented as a sequence of CIR instructions terminating in an
    instruction that binds ``dst`` to the constant's name. This keeps
    constants three-address-uniform with function bodies; the Python
    emitter renders the prelude instructions inline before the binding."""
    name: str
    ty: str
    body: list[Instr]


@dataclass
class ImportDecl:
    """An ``import`` declaration. The analyzer rejects ``import`` in
    v1 (it would punch through Capa's capability discipline); the IR
    only records it so the emitter can leave a breadcrumb comment in
    sync with the legacy transpiler. No real Python import is ever
    emitted from this node."""
    path: list[str]
    alias: Optional[str]


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
    which capability/trait each method realises.

    ``type_params`` carries the source's ``impl Box<T> { ... }``
    type-parameter names (the binders from the impl header's
    ``type_args``). The Python backend ignores them (duck typing);
    the Wasm monomorphisation pass uses them to specialise a generic
    type's methods per concrete instantiation (``impl Box<T>`` ->
    a ``Box__Int`` impl whose ``get`` returns ``Int``) so the
    method-dispatch table is keyed on the mangled type name. Empty
    for non-generic impls."""
    type_name: str
    trait_name: Optional[str]
    methods: list[Function]
    type_params: list[str] = field(default_factory=list)


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
    consts: list = field(default_factory=list)  # list[ConstDecl]
    imports: list = field(default_factory=list)  # list[ImportDecl]
    ast_module: object = None  # capa_ast.Module; opaque to the IR


# Sentinel local-name generator helper.
def fresh_local(counter: dict, prefix: str = "t") -> str:
    """Allocate a unique local name using the supplied counter dict
    (single-key ``{"n": int}``)."""
    n = counter["n"]
    counter["n"] = n + 1
    return f"_ir_{prefix}{n}"
