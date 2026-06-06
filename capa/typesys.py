"""Type representation for the Capa compiler.

This is the **internal** representation of types manipulated by the type
checker, distinct from the AST's ``TypeExpr`` nodes (which represent the
**syntax** of types written by the programmer). The relationship between the
two: the checker takes a ``TypeExpr`` and produces a ``Ty``, resolving names
against the symbol table.

Types represented:

- ``TyName(name, args)``: named type with possible generic arguments.
  Covers primitives (``TyName("Int")``), constructor applications
  (``TyName("List", (TyName("Int"),))``), and user-defined types
  (``TyName("Task")``).
- ``TyVar(name)``: type variable, bound to a generic parameter in scope
  (e.g., the ``T`` inside ``fun first<T>(xs: List<T>) -> T``).
- ``TyFun(params, ret)``: function type.
- ``TyTuple(elements)``: tuple type.
- ``TyUnit``: the unit type (empty tuple). Singleton.
- ``TyUnknown``: marker for "the checker couldn't type this, but it isn't
  necessarily an error". Used when the v1 type checker does not yet support
  some construct (e.g., method dispatch on capabilities). Comparisons against
  TyUnknown silently succeed, it is an *escape hatch* to keep the checker
  useful without being overly pedantic.

Conventions:

- Types are *frozen dataclasses*, they compare by structure.
- Tuples are used instead of lists for args so they are hashable.
- The ``ty_str`` function produces a friendly representation used in error
  messages.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Ty:
    """Abstract base for types."""
    pass


@dataclass(frozen=True)
class TyName(Ty):
    """Named type: ``Int``, ``List<T>``, ``Task``, ``Result<T, E>``...

    ``state`` is the typestate index written ``Name[State]`` (roadmap
    S3); ``None`` for an ordinary type. It participates in equality and
    hashing, so ``Socket[Created]`` and ``Socket[Connected]`` are
    distinct types, which is what enforces the protocol."""
    name: str
    args: tuple[Ty, ...] = ()
    state: "str | None" = None


@dataclass(frozen=True)
class TyVar(Ty):
    """Type variable. ``name`` is the textual name of the generic parameter."""
    name: str


@dataclass(frozen=True)
class TyFun(Ty):
    """Function type: ``fun(T1, T2) -> R``."""
    params: tuple[Ty, ...]
    ret: Ty


@dataclass(frozen=True)
class TyTuple(Ty):
    """Tuple type. 1-element tuples are distinct from the element alone."""
    elements: tuple[Ty, ...]


@dataclass(frozen=True)
class _TyUnitSingleton(Ty):
    """Internal implementation of the Unit type. Use the ``TyUnit`` constant."""
    pass


# The unit type is a singleton (no point in instantiating it multiple times).
TyUnit: Ty = _TyUnitSingleton()


@dataclass(frozen=True)
class _TyUnknownSingleton(Ty):
    """"Unknown" type, checker escape hatch. Singleton."""
    pass


TyUnknown: Ty = _TyUnknownSingleton()


# ===========================================================
# Predefined primitive types (frequently used shortcuts)
# ===========================================================

TyInt = TyName("Int")
TyFloat = TyName("Float")
TyString = TyName("String")
TyChar = TyName("Char")
TyBool = TyName("Bool")


# Set of names the checker recognizes as primitives. These cannot be
# redefined by the programmer.
PRIMITIVE_NAMES: frozenset[str] = frozenset({
    "Int", "Float", "String", "Char", "Bool",
})


# Capabilities recognized by the system. They are opaque types, the v1
# checker does not verify the methods called on them, but knows they exist
# so parameters of type Stdio, Fs, etc. are accepted as annotations.
CAPABILITY_NAMES: frozenset[str] = frozenset({
    "Stdio", "Fs", "Net", "Env", "Proc", "Clock", "Random", "Db",
    "Unsafe",
})


# ===========================================================
# Pretty-printing
# ===========================================================


def ty_str(t: Ty) -> str:
    """Returns a textual representation of the type, in Capa style."""
    if isinstance(t, _TyUnitSingleton):
        return "()"
    if isinstance(t, _TyUnknownSingleton):
        return "?"
    if isinstance(t, TyName):
        suffix = f"[{t.state}]" if t.state is not None else ""
        if not t.args:
            return f"{t.name}{suffix}"
        args = ", ".join(ty_str(a) for a in t.args)
        return f"{t.name}<{args}>{suffix}"
    if isinstance(t, TyVar):
        return t.name
    if isinstance(t, TyFun):
        params = ", ".join(ty_str(p) for p in t.params)
        return f"fun({params}) -> {ty_str(t.ret)}"
    if isinstance(t, TyTuple):
        if len(t.elements) == 1:
            return f"({ty_str(t.elements[0])},)"
        return "(" + ", ".join(ty_str(e) for e in t.elements) + ")"
    return repr(t)


# ===========================================================
# Substitution (for instantiating generic types)
# ===========================================================


def substitute(t: Ty, mapping: dict[str, Ty]) -> Ty:
    """Replaces occurrences of ``TyVar(name)`` in the type with the type
    given in ``mapping[name]``. Does not cross quantification boundaries
    (this checker doesn't handle first-class polymorphism, only
    instantiation at calls of generic functions and types).
    """
    if isinstance(t, TyVar):
        return mapping.get(t.name, t)
    if isinstance(t, TyName):
        if not t.args:
            return t
        return TyName(
            t.name,
            tuple(substitute(a, mapping) for a in t.args),
            state=t.state,
        )
    if isinstance(t, TyFun):
        return TyFun(
            tuple(substitute(p, mapping) for p in t.params),
            substitute(t.ret, mapping),
        )
    if isinstance(t, TyTuple):
        return TyTuple(tuple(substitute(e, mapping) for e in t.elements))
    return t


# ===========================================================
# Type compatibility (structural equality with TyUnknown wildcard)
# ===========================================================


def compatible(expected: Ty, actual: Ty) -> bool:
    """Returns True if ``actual`` is compatible with ``expected``.

    The rule is structural equality, with these exceptions:
    - ``TyUnknown`` is compatible with any other type (on either
      side). This relaxation avoids cascading errors from a
      single non-typable expression.
    - ``TyVar`` (not-instantiated) is compatible with any type, since
      it represents an inference placeholder still to be resolved
      (e.g., `[]` produces `List<TyVar>`).
    """
    if isinstance(expected, _TyUnknownSingleton) or isinstance(actual, _TyUnknownSingleton):
        return True
    if isinstance(expected, TyVar) or isinstance(actual, TyVar):
        return True
    if isinstance(expected, _TyUnitSingleton) and isinstance(actual, _TyUnitSingleton):
        return True
    if isinstance(expected, TyName) and isinstance(actual, TyName):
        if expected.name != actual.name:
            # A Capa ``Char`` is, by definition, exactly one code
            # point, so it is ALWAYS a valid ``String`` (a char literal
            # lowers to a one-character string, the runtime represents
            # both as Python ``str``, and the Wasm backend normalizes
            # the ``Char`` type token to ``String`` before emission).
            # The relationship is ASYMMETRIC: where a ``String`` is
            # expected a ``Char`` is accepted, but where a ``Char`` is
            # expected a general ``String`` is NOT -- an arbitrary or
            # multi-codepoint string cannot be stored in a Char slot.
            # This keeps ``let s: String = 'z'``, passing a char
            # literal where a String is wanted, and the
            # String-iteration element used as a String all working
            # (the loop variable is typed ``String`` and ``c == 'a'``
            # checks compatibility in both directions). The one safe
            # ``String``-into-``Char`` case -- a provably
            # one-code-point string *literal* -- needs the expression
            # to inspect, so it lives in the analyzer's assignment /
            # argument checker, not here. Both must be unparameterised
            # scalars.
            if (
                expected.name == "String" and actual.name == "Char"
                and not expected.args and not actual.args
            ):
                return expected.state == actual.state
            return False
        # Typestate index (roadmap S3): a value in one state is not
        # compatible with a parameter expecting another state, which is
        # what enforces the protocol at the type level.
        if expected.state != actual.state:
            return False
        if len(expected.args) != len(actual.args):
            return False
        return all(compatible(e, a) for e, a in zip(expected.args, actual.args))
    if isinstance(expected, TyFun) and isinstance(actual, TyFun):
        if len(expected.params) != len(actual.params):
            return False
        return (
            all(compatible(e, a) for e, a in zip(expected.params, actual.params))
            and compatible(expected.ret, actual.ret)
        )
    if isinstance(expected, TyTuple) and isinstance(actual, TyTuple):
        if len(expected.elements) != len(actual.elements):
            return False
        return all(
            compatible(e, a)
            for e, a in zip(expected.elements, actual.elements)
        )
    return False


def contains_capability(t: Ty) -> Ty | None:
    """Returns the first capability found in the type, or None.

    Traverses recursively: generic arguments, tuple elements.
    **Does not traverse ``TyFun``**, capabilities as parameter or return
    types of a stored function are merely the signature, not capabilities
    actually stored. The cap is only "real" when the function is called
    with a concrete cap value. This distinction lets closures take
    capabilities as parameters without violating the structural rule.

    Useful for enforcing capability-usage rules (they cannot appear in
    fields, payloads, returns, local bindings, or generic type args).

    Returns the capability's ``TyName``, not just its textual name, so the
    caller can format precise messages.
    """
    if isinstance(t, TyName):
        if t.name in CAPABILITY_NAMES:
            return t
        for a in t.args:
            found = contains_capability(a)
            if found is not None:
                return found
        return None
    if isinstance(t, TyTuple):
        for e in t.elements:
            found = contains_capability(e)
            if found is not None:
                return found
        return None
    # TyFun: signature, not storage. Doesn't propagate.
    return None


def occurs_in(name: str, t: Ty) -> bool:
    """Occurs-check: returns True if the type variable ``name`` appears
    anywhere inside ``t``. Used by :func:`unify` to refuse bindings that
    would build an infinite (non-finite) type, and to detect the reflexive
    ``X = X`` case so unification terminates.
    """
    if isinstance(t, TyVar):
        return t.name == name
    if isinstance(t, TyName):
        return any(occurs_in(name, a) for a in t.args)
    if isinstance(t, TyTuple):
        return any(occurs_in(name, e) for e in t.elements)
    if isinstance(t, TyFun):
        return any(occurs_in(name, p) for p in t.params) or occurs_in(
            name, t.ret
        )
    return False


def unify(expected: Ty, actual: Ty, mapping: dict[str, Ty]) -> bool:
    """Local inference: discovers TyVar→Ty substitutions that make
    ``expected`` compatible with ``actual``, accumulating them in ``mapping``.

    This is a limited version (not full Hindley-Milner) sufficient to
    infer type arguments in calls to generic functions and in constructors
    of variants of generic sum types. No generalization (let-polymorphism),
    no free variables in function scope.

    Convention: ``expected`` is the signature's type (may contain ``TyVar``);
    ``actual`` is the concrete type at the call site (should not contain free
    ``TyVar``, but may contain ``TyUnknown``). ``TyUnknown`` on either side
    is compatible with everything and does not bind.

    Returns ``True`` if unification is consistent (compatible with the
    existing mapping). Returns ``False`` on definitive structural
    incompatibility. In either case, ``mapping`` may have been updated
    with tentative bindings, it is up to the caller to decide what to do
    (typically report an error via ``compatible`` after applying the mapping).
    """
    # TyUnknown on either side: passes silently.
    if isinstance(expected, _TyUnknownSingleton) or isinstance(actual, _TyUnknownSingleton):
        return True

    # TyVar on the expected side: bind (or verify consistency if already bound).
    if isinstance(expected, TyVar):
        # Reflexive case (``X`` against ``X``): trivially consistent. This must
        # be handled before any binding/recursion, otherwise binding ``X`` to
        # ``X`` and then re-unifying that binding loops forever. It arises in
        # the common generic-accumulator pattern, e.g. ``out.push(x)`` on a
        # ``List<T>`` whose element variable shares a name with ``x``'s ``T``.
        if isinstance(actual, TyVar) and actual.name == expected.name:
            return True
        bound = mapping.get(expected.name)
        # A pre-existing self-referential binding (``X = X``, which callers may
        # seed when the owner's type parameter shares a name with the
        # argument's variable) carries no information. Treat it as unbound so we
        # can either accept a concrete refinement or stay reflexive, instead of
        # recursing on it forever.
        if isinstance(bound, TyVar) and bound.name == expected.name:
            bound = None
        if bound is None:
            # Occurs-check: refuse to build an infinite type (binding ``X`` to a
            # term that itself mentions ``X``). A bare reflexive binding is
            # already handled above; anything else that contains ``X`` has no
            # finite solution.
            if occurs_in(expected.name, actual):
                return False
            mapping[expected.name] = actual
            return True
        return unify(bound, actual, mapping)

    # TyVar on the actual side with no pairing, a rare case that occurs
    # when the caller hasn't yet inferred certain types. We don't bind.
    if isinstance(actual, TyVar):
        return True

    if isinstance(expected, _TyUnitSingleton):
        return isinstance(actual, _TyUnitSingleton)

    if isinstance(expected, TyName) and isinstance(actual, TyName):
        if expected.name != actual.name:
            return False
        if expected.state != actual.state:  # roadmap S3: state-exact
            return False
        if len(expected.args) != len(actual.args):
            return False
        return all(
            unify(e, a, mapping) for e, a in zip(expected.args, actual.args)
        )

    if isinstance(expected, TyTuple) and isinstance(actual, TyTuple):
        if len(expected.elements) != len(actual.elements):
            return False
        return all(
            unify(e, a, mapping)
            for e, a in zip(expected.elements, actual.elements)
        )

    if isinstance(expected, TyFun) and isinstance(actual, TyFun):
        if len(expected.params) != len(actual.params):
            return False
        params_ok = all(
            unify(e, a, mapping)
            for e, a in zip(expected.params, actual.params)
        )
        return params_ok and unify(expected.ret, actual.ret, mapping)

    return False


def instantiate(ty: Ty, type_params: list[str], mapping: dict[str, Ty]) -> Ty:
    """Applies ``mapping`` to the type, replacing ``TyVar``s. For type
    parameters declared in ``type_params`` that were not inferred (not in
    ``mapping``), substitutes ``TyUnknown``.

    This is the way to "close" a polymorphic type at the call site:
    inferred information becomes concrete, information yet to be inferred
    remains as ``TyUnknown`` (which is compatible with everything).
    """
    full = dict(mapping)
    for p in type_params:
        if p not in full:
            full[p] = TyUnknown
    return substitute(ty, full)
