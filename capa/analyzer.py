"""Semantic analysis of the Capa language.

This module combines **name resolution** (associating each reference with a
declaration) and **type checking** (validating compatibility) into a single
walk of the AST, after a pre-pass that records top-level declarations
(to support forward references).

This is a **pragmatic** implementation of the v1 checker:

- Each name is resolved against a structured scope (local variables,
  parameters, top-level declarations, builtin capabilities, imported modules).
  Errors: ``undefined name``, ``duplicate declaration``.

- Types are checked wherever the information is available: literals,
  arithmetic/logical operators, assignments, ``if``/``while`` conditions,
  arity and argument types in calls to top-level functions, fields in
  struct literals, returns against the declared return type.

- Where the v1 checker cannot yet reason, it returns ``TyUnknown``,
  which is compatible with any other type. Cases that produce ``TyUnknown``:

  * Method dispatch (``obj.method(...)``), dispatch resolution requires
    trait information that is not yet implemented.
  * Field access on generic types whose concrete type has not yet been inferred.
  * Access to attributes of imported modules (``json.parse(...)``).
  * The ``?`` (try) operator, requires inferring the error type from context.

- The v1 checker does *not* check:

  * Linearity of capabilities (single consumption, no aliasing). This is a
    central property of the language and requires an effects/borrow system -
    deferred to phase 2.
  * Exhaustiveness of ``match``.
  * Full polymorphic inference (Hindley-Milner).
  * Subtyping or implicit coercions, a future automatic ``Int -> Float``
    coercion will have to be added explicitly.

The public interface is the ``analyze(module, source, filename)`` function,
which returns an ``AnalysisResult`` containing errors found, inferred types
and resolved bindings.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional

from . import capa_ast as A
from .errors import LexerError
from .tokens import Pos
from .typesys import (
    CAPABILITY_NAMES,
    PRIMITIVE_NAMES,
    Ty,
    TyBool,
    TyChar,
    TyFloat,
    TyFun,
    TyInt,
    TyName,
    TyString,
    TyTuple,
    TyUnit,
    TyUnknown,
    TyVar,
    compatible,
    contains_capability,
    instantiate,
    substitute,
    ty_str,
    unify,
)


# ===========================================================
# Errors
# ===========================================================


class AnalysisError(LexerError):
    """Semantic error (resolution or type) detected during analysis."""
    pass


# ===========================================================
# Symbols and scopes
# ===========================================================


class SymbolKind(Enum):
    PARAM = auto()
    LOCAL = auto()
    LOCAL_VAR = auto()       # var (mutable) vs LOCAL for let (immutable)
    FUNCTION = auto()
    CONSTANT = auto()
    TYPE_STRUCT = auto()
    TYPE_SUM = auto()
    TRAIT = auto()
    VARIANT = auto()
    MODULE = auto()
    CAPABILITY = auto()
    TYPE_PARAM = auto()


@dataclass
class Symbol:
    """A named entity in the program.

    The extra fields depend on the kind:
    - FUNCTION/CONSTANT/PARAM/LOCAL[_VAR]: ty is the entity's type
    - TYPE_STRUCT: type_params, struct_fields, methods
    - TYPE_SUM: type_params, sum_variants, methods
    - TRAIT: trait_methods (names only for v1)
    - VARIANT: variant_owner (TYPE_SUM symbol), variant_payload_ty
    - MODULE/CAPABILITY: opaque name
    """
    name: str
    kind: SymbolKind
    pos: Pos
    ty: Optional[Ty] = None
    type_params: list[str] = field(default_factory=list)
    struct_fields: dict[str, Ty] = field(default_factory=dict)
    sum_variants: dict[str, "Symbol"] = field(default_factory=dict)
    trait_methods: set[str] = field(default_factory=set)
    # For TRAIT: signatures of declared methods (name -> TyFun).
    # Allows checking that impls provide methods with compatible types.
    trait_method_sigs: dict[str, "TyFun"] = field(default_factory=dict)
    variant_owner: Optional["Symbol"] = None
    variant_payload_ty: Optional[Ty] = None
    # Methods defined in impl blocks. Maps name -> Symbol (kind=FUNCTION),
    # whose Ty (TyFun) covers only the explicit parameters (no self).
    methods: dict[str, "Symbol"] = field(default_factory=dict)
    # For TYPE_STRUCT/TYPE_SUM: names of traits and user-defined
    # capabilities this type implements (via `impl TraitOrCap for X`).
    # Used by the compatibility check to accept the type wherever the
    # trait/cap is expected.
    implements: set[str] = field(default_factory=set)
    # For FUNCTION: list parallel to params indicating whether each parameter
    # consumes the argument (ownership move). For use in flow analysis.
    consuming_params: list[bool] = field(default_factory=list)
    # For FUNCTION: parameter names parallel to the TyFun's `params`.
    # Used to resolve named arguments (`f(age: 30)`) and to give nicer
    # error messages. Empty when the function comes from a builtin and
    # named-arg dispatch is not supported.
    param_names: list[str] = field(default_factory=list)


@dataclass
class Scope:
    """A lexical level. Performs chained lookup through the parent."""
    symbols: dict[str, Symbol] = field(default_factory=dict)
    parent: Optional["Scope"] = None

    def lookup(self, name: str) -> Optional[Symbol]:
        s = self.symbols.get(name)
        if s is not None:
            return s
        if self.parent is not None:
            return self.parent.lookup(name)
        return None

    def lookup_local(self, name: str) -> Optional[Symbol]:
        return self.symbols.get(name)

    def define(self, sym: Symbol) -> None:
        self.symbols[sym.name] = sym


# ===========================================================
# Analysis result
# ===========================================================


@dataclass
class AnalysisResult:
    errors: list[AnalysisError] = field(default_factory=list)
    types: dict[int, Ty] = field(default_factory=dict)        # id(node) -> Ty
    bindings: dict[int, Symbol] = field(default_factory=dict)  # id(Ident) -> Symbol
    # Module-level symbols (functions, types, traits, capabilities,
    # constants). Exposed so LSP tooling can resolve a declaration
    # site to its Symbol even when the declaration has no
    # references elsewhere in the file.
    global_symbols: dict[str, Symbol] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return not self.errors


# ===========================================================
# Main analyzer
# ===========================================================


class Analyzer:
    """Performs the semantic analysis of a Module.

    Typical usage:
        result = analyze(module, source, filename)
        if not result.ok:
            for err in result.errors:
                print(err.format())
    """

    def __init__(self, source: str = "", filename: str = "<input>"):
        self.source = source
        self.filename = filename
        self.global_scope = Scope()
        self.scope = self.global_scope
        self.errors: list[AnalysisError] = []
        self.types: dict[int, Ty] = {}
        self.bindings: dict[int, Symbol] = {}
        # Return type of the function currently being analyzed,
        # used to check return statements.
        self.current_return_type: Optional[Ty] = None
        # Stack of type params in scope (for generic functions/types).
        self.type_param_stack: list[set[str]] = [set()]
        # When inside an impl: the type of Self.
        self.self_type: Optional[Ty] = None
        # Set of capabilities consumed in the current flow of the
        # current function. Used to detect use after `consume`. Reset per
        # function. In branches (if/else, match arms), I fork/merge:
        # snapshot before each branch, conservative union after (any branch
        # possibly consuming -> considered consumed).
        self._consumed: set[str] = set()
        # Stack of "names local to the lambda" for flow analysis in
        # closures. When inside a lambda, consuming a name that is NOT
        # in this stack means we are consuming a cap captured from the
        # outside, that is an error because the lambda may be called
        # multiple times.
        self._lambda_local_names_stack: list[set[str]] = []
        # Substitutions of fresh TyVars (introduced by expressions
        # like ``[]`` whose element is unknown). Per-function state;
        # reset in ``_check_fun``. When a call binds a fresh TyVar,
        # the substitution is recorded here, on subsequent uses of
        # the same symbol, ``_resolve_ty`` applies it.
        self._ty_subs: dict[str, Ty] = {}
        self._fresh_counter: int = 0

    def _fresh_ty_var(self, prefix: str) -> TyVar:
        """Create a TyVar with a unique name. The prefix allows clearer
        reading in debug messages (``?lst_0``, ``?map_3``).
        """
        name = f"?{prefix}_{self._fresh_counter}"
        self._fresh_counter += 1
        return TyVar(name)

    def _resolve_ty(self, ty: Ty) -> Ty:
        """Apply ``_ty_subs`` recursively. For TyVars that are not
        bound, return the TyVar itself unchanged. The result is the
        type "as known so far", subsequent calls may refine it further.
        """
        if isinstance(ty, TyVar):
            sub = self._ty_subs.get(ty.name)
            if sub is None:
                return ty
            # Path compression: dereference recursively.
            return self._resolve_ty(sub)
        if isinstance(ty, TyName):
            if not ty.args:
                return ty
            return TyName(ty.name, tuple(self._resolve_ty(a) for a in ty.args))
        if isinstance(ty, TyTuple):
            return TyTuple(tuple(self._resolve_ty(e) for e in ty.elements))
        if isinstance(ty, TyFun):
            return TyFun(
                tuple(self._resolve_ty(p) for p in ty.params),
                self._resolve_ty(ty.ret),
            )
        return ty

    def _commit_fresh_substitutions(self, mapping: dict[str, Ty]) -> None:
        """After a call with inference, copy into ``_ty_subs`` the
        substitutions of fresh TyVars (prefix ``?``). TyVars that
        correspond to declared type params of a function are local
        to the call and should not persist.
        """
        for var_name, ty in mapping.items():
            if var_name.startswith("?"):
                # Apply the rest of the mapping to the type before saving,
                # to avoid TyVar->TyVar->Int chains.
                self._ty_subs[var_name] = self._apply_mapping(ty, mapping)

    def _apply_mapping(self, ty: Ty, mapping: dict[str, Ty]) -> Ty:
        """Like _resolve_ty but using ``mapping`` instead of ``_ty_subs``."""
        if isinstance(ty, TyVar):
            sub = mapping.get(ty.name)
            if sub is None:
                # Not in the mapping, may be in _ty_subs.
                return self._resolve_ty(ty)
            return self._apply_mapping(sub, mapping)
        if isinstance(ty, TyName):
            if not ty.args:
                return ty
            return TyName(
                ty.name,
                tuple(self._apply_mapping(a, mapping) for a in ty.args),
            )
        if isinstance(ty, TyTuple):
            return TyTuple(tuple(
                self._apply_mapping(e, mapping) for e in ty.elements
            ))
        if isinstance(ty, TyFun):
            return TyFun(
                tuple(self._apply_mapping(p, mapping) for p in ty.params),
                self._apply_mapping(ty.ret, mapping),
            )
        return ty

    # ===========================================================
    # Public API
    # ===========================================================

    def analyze(self, module: A.Module) -> AnalysisResult:
        # Pre-populate global scope with primitives and capabilities.
        self._install_builtins()
        # Phase 1: register all top-level declarations (forward refs).
        self._collect_globals(module)
        # Phase 2: visit bodies of functions, impls, etc.
        for item in module.items:
            self._check_item(item)
        return AnalysisResult(
            errors=self.errors,
            types=self.types,
            bindings=self.bindings,
            global_symbols=dict(self.global_scope.symbols),
        )

    # ===========================================================
    # Helpers
    # ===========================================================

    def _err(self, message: str, pos: Pos) -> None:
        """Record an error without raising an exception. The analyzer
        keeps checking to find as many errors as possible in a single run."""
        self.errors.append(
            AnalysisError(message, pos, self.source, self.filename)
        )

    def _push_scope(self) -> None:
        self.scope = Scope(parent=self.scope)

    def _pop_scope(self) -> None:
        assert self.scope.parent is not None
        self.scope = self.scope.parent

    # ----------------------------------------------------------
    # "Did you mean?" suggestions
    # ----------------------------------------------------------
    # The matching algorithm (Levenshtein + case-aware
    # tie-breaking) lives in :mod:`capa._suggest`; the methods
    # here only collect the haystack from the current scope.

    def _names_in_scope(self) -> list[str]:
        """Flatten the current scope chain into a list of names
        visible at the call site, for ``did you mean`` lookups
        against undefined-name errors."""
        seen: set[str] = set()
        scope = self.scope
        while scope is not None:
            seen.update(scope.symbols.keys())
            scope = scope.parent
        return list(seen)

    def _type_names(self) -> list[str]:
        """All type-like names known to the global scope: structs,
        sum types, traits, and capabilities. Used as the haystack
        for ``undefined type`` hints."""
        type_kinds = {
            SymbolKind.TYPE_STRUCT, SymbolKind.TYPE_SUM,
            SymbolKind.TRAIT, SymbolKind.CAPABILITY,
        }
        return [
            name
            for name, s in self.global_scope.symbols.items()
            if s.kind in type_kinds
        ]

    def _variant_names(self, scrutinee_ty: "Ty") -> list[str]:
        """Variants the user might have meant when an unknown
        variant pattern is encountered. Prefers variants of the
        scrutinee's sum type if known, otherwise falls back to
        every variant in the global scope."""
        from .typesys import TyName as _TyName  # local to avoid cycles
        if isinstance(scrutinee_ty, _TyName):
            owner = self.global_scope.lookup(scrutinee_ty.name)
            if owner is not None and owner.kind == SymbolKind.TYPE_SUM:
                return list(owner.sum_variants.keys())
        return [
            name
            for name, s in self.global_scope.symbols.items()
            if s.kind == SymbolKind.VARIANT
        ]

    def _hint_did_you_mean(
        self, needle: str, haystack: list[str],
    ) -> str:
        """Thin pass-through to :func:`capa._suggest.hint_did_you_mean`,
        kept on the class so existing call sites don't change."""
        from ._suggest import hint_did_you_mean
        return hint_did_you_mean(needle, haystack)

    def _push_type_params(self, names: list[str]) -> None:
        self.type_param_stack.append(set(names))

    def _pop_type_params(self) -> None:
        self.type_param_stack.pop()

    def _is_type_param_in_scope(self, name: str) -> bool:
        for frame in self.type_param_stack:
            if name in frame:
                return True
        return False

    def _mark_consumed_args(
        self, args: list[A.Expr], consuming_flags: list[bool]
    ) -> None:
        """For each arg that is a capability Ident and whose flag is True,
        mark the name as consumed. Called after evaluating the args so
        that the use of those idents in the args themselves (the first
        time they appear) does not trigger the error.

        **Capture in lambdas**: if we are inside a lambda and the
        consumed name does not belong to the local parameters (or to
        enclosing lambdas that contain us), it is a captured cap, and
        consuming a captured cap is an error because the lambda may be
        invoked multiple times.
        """
        for arg, consuming in zip(args, consuming_flags):
            if not consuming:
                continue
            if not isinstance(arg, A.Ident):
                continue
            sym = self.scope.lookup(arg.name)
            if sym is None or sym.ty is None:
                continue
            if isinstance(sym.ty, TyName) and sym.ty.name in CAPABILITY_NAMES:
                # Inside a lambda? The name must be local to some
                # frame on the stack (ours or that of an outer lambda).
                if self._lambda_local_names_stack:
                    is_local_to_some_lambda = any(
                        arg.name in frame
                        for frame in self._lambda_local_names_stack
                    )
                    if not is_local_to_some_lambda:
                        self._err(
                            f"cannot consume capability {arg.name!r} "
                            f"captured from enclosing scope; closures may "
                            f"be invoked multiple times, but a capability "
                            f"can only be consumed once",
                            arg.pos,
                        )
                        # Do not mark as consumed, to avoid cascading errors.
                        continue
                self._consumed.add(arg.name)

    def _substitute_self(self, ty: Ty, self_ty: Ty) -> Ty:
        """Substitute occurrences of ``TyName('Self')`` in ``ty`` with
        ``self_ty``. Useful for resolving trait method signatures in
        the context of a concrete impl.
        """
        if isinstance(ty, TyName):
            if ty.name == "Self":
                return self_ty
            if ty.args:
                new_args = tuple(self._substitute_self(a, self_ty) for a in ty.args)
                return TyName(ty.name, new_args)
            return ty
        if isinstance(ty, TyTuple):
            return TyTuple(tuple(
                self._substitute_self(e, self_ty) for e in ty.elements
            ))
        if isinstance(ty, TyFun):
            return TyFun(
                tuple(self._substitute_self(p, self_ty) for p in ty.params),
                self._substitute_self(ty.ret, self_ty),
            )
        return ty

    def _is_capability_ident(self, expr: A.Expr) -> Optional[str]:
        """If ``expr`` is an Ident whose symbol is a capability in scope,
        return the name. Otherwise, return None.

        Helper used by the aliasing check in calls: we are only
        interested in detecting repetitions of **direct identifiers**
        that reference capabilities. More complex expressions (calls
        that return something else, field accesses) do not generate
        aliasing, their effects are sequential.
        """
        if not isinstance(expr, A.Ident):
            return None
        sym = self.scope.lookup(expr.name)
        if sym is None or sym.ty is None:
            return None
        if isinstance(sym.ty, TyName) and sym.ty.name in CAPABILITY_NAMES:
            return expr.name
        return None

    def _check_no_aliasing(self, slots: list[tuple[A.Expr, str]]) -> None:
        """Check that no capability appears twice in the ``slots``.

        ``slots`` is a list of pairs ``(expr, role)`` where role is a
        description such as ``"receiver"`` or ``"argument 2"`` for error
        messages. Each slot represents a position in a call where a
        capability could be passed (method receiver, function argument).

        Capability aliasing, passing the same cap to two places in a
        single call, violates the single-flow property that gives
        meaning to Capa signatures. This check is the v2 of the
        discipline, complementary to v1 (which enforces where caps may
        appear structurally).
        """
        seen: dict[str, str] = {}  # name -> first role where it appeared
        for expr, role in slots:
            name = self._is_capability_ident(expr)
            if name is None:
                continue
            if name in seen:
                self._err(
                    f"capability {name!r} appears as {role} but was already "
                    f"used as {seen[name]} of the same call; capabilities "
                    f"cannot be aliased (each call uses each capability at "
                    f"most once)",
                    expr.pos,
                )
            else:
                seen[name] = role

    def _check_no_capability(self, ty: Ty, pos: Pos, context: str) -> None:
        """Enforce the capability discipline rules.

        Capabilities represent permissions for effects (IO, network, etc.)
        and their value lies in being **traceable through the program flow**
       , any part of the program that may perform IO must have a
        capability in its signatures. For this tracing to work,
        capabilities cannot be:

        - **hidden in data structures** (fields, payloads, generic type
          args). There they would be invisible to anyone inspecting only
          function signatures.
        - **returned by functions**. Capabilities are not "created" by
          Capa code; they are instantiated at the entry point and
          propagated downward. Allowing a fun to "produce" a capability
          would be permission forgery.
        - **bound in locals (`let`/`var`) or constants**. Restricting
          them to function parameters makes the flow visible in every
          signature and prevents trivial aliasing.

        This check is the v1 approximation to a full linear type system.
        It does not prevent all possible duplications (flow analysis
        would be needed for that), but it captures the common ways of
        violating the discipline and gives real meaning to Capa signatures.

        Recognises both built-in (``Stdio``, ``Net``, ...) and user-
        defined (declared with ``capability X { ... }``) capabilities.
        """
        cap = self._contains_any_capability(ty)
        if cap is None:
            return
        self._err(
            f"capability {cap.name!r} cannot appear in {context}; "
            f"capabilities only flow through function parameters",
            pos,
        )

    def _contains_any_capability(self, ty: Ty) -> Optional[TyName]:
        """Recursive walk that returns the first capability found in
        ``ty``. Three things count as capabilities for the structural
        discipline:

        - built-in caps (``Stdio``, ``Net``, ...), names in ``CAPABILITY_NAMES``
        - user-defined caps (Symbol with kind=CAPABILITY) declared via
          the ``capability`` keyword
        - cap-bearing structs (Symbol with kind=TYPE_STRUCT) that
          implement at least one user-defined capability. The struct
          value itself carries authority and must follow the same
          aliasing/use rules as the underlying cap.
        """
        if isinstance(ty, TyName):
            if ty.name in CAPABILITY_NAMES:
                return ty
            sym = self.global_scope.lookup(ty.name)
            if sym is not None:
                if sym.kind == SymbolKind.CAPABILITY:
                    return ty
                if (
                    sym.kind == SymbolKind.TYPE_STRUCT
                    and any(self._is_user_capability(t) for t in sym.implements)
                ):
                    return ty
            for a in ty.args:
                found = self._contains_any_capability(a)
                if found is not None:
                    return found
        if isinstance(ty, TyTuple):
            for elem in ty.elements:
                found = self._contains_any_capability(elem)
                if found is not None:
                    return found
        return None

    def _is_user_capability(self, name: str) -> bool:
        """True iff ``name`` resolves to a user-defined capability, i.e.
        a Symbol whose kind is CAPABILITY but whose name is not in the
        built-in capability set (``Stdio``, ``Net``, etc.). User-defined
        capabilities (declared with the ``capability`` keyword) are
        subject to most of the same rules as built-in capabilities, but
        with two relaxations to support the WhitePaper §4.6 pattern:
        they can be the return type of a regular function (factories
        produce fresh instances), and they can wrap built-in
        capabilities as struct fields when the struct implements a
        user-defined capability.
        """
        if name in CAPABILITY_NAMES:
            return False
        sym = self.global_scope.lookup(name)
        return sym is not None and sym.kind == SymbolKind.CAPABILITY

    def _contains_builtin_capability(self, ty: Ty) -> Optional[TyName]:
        """Like ``contains_capability``, but only flags **built-in**
        capabilities (Stdio, Fs, Net, Env, ...). User-defined capabilities
        are ignored, call sites that allow user-defined caps to flow
        through use this helper instead of ``contains_capability``.
        """
        if isinstance(ty, TyName):
            if ty.name in CAPABILITY_NAMES:
                return ty
            for a in ty.args:
                found = self._contains_builtin_capability(a)
                if found is not None:
                    return found
        if isinstance(ty, TyTuple):
            for elem in ty.elements:
                found = self._contains_builtin_capability(elem)
                if found is not None:
                    return found
        return None

    def _check_no_builtin_capability(
        self, ty: Ty, pos: Pos, context: str,
    ) -> None:
        """Variant of ``_check_no_capability`` that only rejects
        **built-in** capabilities. Used in contexts that legitimately
        accept user-defined capabilities (notably: the return type of
        a factory function).
        """
        cap = self._contains_builtin_capability(ty)
        if cap is None:
            return
        self._err(
            f"capability {cap.name!r} cannot appear in {context}; "
            f"built-in capabilities only flow through function parameters",
            pos,
        )

    def _compatible_with_impls(self, expected: Ty, actual: Ty) -> bool:
        """Like ``compatible`` from ``typesys``, plus nominal subtyping
        via trait/capability implementations.

        When the expected type is the name of a trait or user-defined
        capability, and the actual type is a struct/sum whose Symbol
        records an ``impl`` of that trait/capability, the two are
        compatible, the concrete type is a valid implementor.

        Generic type args on the expected side are not yet substituted
        here (v1 limitation): an `impl Trait for X` is matched
        regardless of the type args on Trait. This is conservative for
        non-generic traits (the common case) and slightly permissive
        for generic ones; a future version should align the args.
        """
        if compatible(expected, actual):
            return True
        if isinstance(expected, TyName) and isinstance(actual, TyName):
            exp_sym = self.global_scope.lookup(expected.name)
            act_sym = self.global_scope.lookup(actual.name)
            if (
                exp_sym is not None and act_sym is not None
                and exp_sym.kind in (SymbolKind.TRAIT, SymbolKind.CAPABILITY)
                and expected.name in act_sym.implements
            ):
                return True
        return False

    def _install_builtins(self) -> None:
        """Install the language-level built-ins.

        The actual table of types, methods, variants, and free
        functions lives in :mod:`capa.builtins`. This method just
        delegates so the analyzer stays focused on the checking
        work proper.
        """
        from .builtins import register_builtins
        register_builtins(self.global_scope.define, self.global_scope.lookup)

    # ===========================================================
    # Phase 1: top-level declarations
    # ===========================================================

    def _collect_globals(self, module: A.Module) -> None:
        for item in module.items:
            if isinstance(item, A.Import):
                # `import` is syntactically accepted (reserved for a future
                # Capa module system) but semantically forbidden in v1:
                # transpiling it to a Python `import` would punch a direct
                # hole through the capability discipline (any function could
                # call `os.system(...)` via an imported module, with no
                # `Unsafe`). To cross the Python boundary use
                # `py_import(unsafe, ...)` and `py_invoke(unsafe, ...)`,
                # both of which require the Unsafe capability.
                full_path = ".".join(item.path)
                self._err(
                    f"'import {full_path}' is not allowed in Capa v1: "
                    f"the module system is reserved for a future version, "
                    f"and Python interop must cross the Unsafe boundary. "
                    f"Use `py_import(unsafe, \"{full_path}\")` to import a "
                    f"Python module (requires the Unsafe capability)",
                    item.pos,
                )
                # Still register the name in scope to avoid a cascade of
                # "name not defined" errors at subsequent uses of the alias.
                self._declare_global(
                    Symbol(
                        name=item.alias or item.path[-1],
                        kind=SymbolKind.MODULE,
                        pos=item.pos,
                    )
                )
            elif isinstance(item, A.ConstDecl):
                # The type is resolved in Phase 2 (it needs other top-level
                # decls already registered). Here we only register the name.
                self._declare_global(
                    Symbol(
                        name=item.name, kind=SymbolKind.CONSTANT,
                        pos=item.pos,
                    )
                )
            elif isinstance(item, A.TypeStruct):
                sym = Symbol(
                    name=item.name, kind=SymbolKind.TYPE_STRUCT,
                    pos=item.pos, type_params=list(item.type_params),
                )
                self._declare_global(sym)
            elif isinstance(item, A.TypeSum):
                sym = Symbol(
                    name=item.name, kind=SymbolKind.TYPE_SUM,
                    pos=item.pos, type_params=list(item.type_params),
                )
                self._declare_global(sym)
                # Variants registered in the global scope as constructors.
                for v in item.variants:
                    if v.name in self.global_scope.symbols:
                        existing = self.global_scope.symbols[v.name]
                        # We accept the case of a user-type variant with
                        # the same name as a builtin variant (e.g., None) -
                        # it is not a problem as long as they are not used
                        # in the same context. To keep things simple, we
                        # ignore collisions with builtins, but we detect
                        # collisions between user types.
                        if existing.pos is not _BUILTIN_POS:
                            self._err(
                                f"variant {v.name!r} conflicts with another "
                                f"declaration at {existing.pos}",
                                v.pos,
                            )
                            continue
                    vsym = Symbol(
                        name=v.name, kind=SymbolKind.VARIANT, pos=v.pos,
                        variant_owner=sym,
                    )
                    sym.sum_variants[v.name] = vsym
                    self.global_scope.define(vsym)
            elif isinstance(item, A.TraitDecl):
                # `capability X` declarations register as SymbolKind.CAPABILITY
                # so that downstream capability-discipline checks treat them
                # identically to built-in caps (Stdio, Net, etc). `trait X`
                # declarations remain SymbolKind.TRAIT. The method dispatch
                # and impl checking are the same in both cases.
                kind = (
                    SymbolKind.CAPABILITY if item.is_capability
                    else SymbolKind.TRAIT
                )
                sym = Symbol(
                    name=item.name, kind=kind, pos=item.pos,
                    type_params=list(item.type_params),
                    trait_methods={m.name for m in item.methods},
                )
                self._declare_global(sym)
            elif isinstance(item, A.FunDecl):
                self._declare_global(
                    Symbol(
                        name=item.name, kind=SymbolKind.FUNCTION,
                        pos=item.pos, type_params=list(item.type_params),
                    )
                )
            elif isinstance(item, A.ImplBlock):
                # Impls do not declare top-level names, they only add
                # methods to the associated type.
                pass

        # Intermediate sub-pass: identify structs that implement a
        # user-defined capability. These structs are exempt from the
        # "no capability as struct field" rule, so they can encapsulate
        # built-in caps (the WhitePaper §4.6 pattern). The exemption
        # only applies to such cap-bearing structs; plain structs still
        # cannot have capability fields.
        self._cap_bearing_structs: set[str] = set()
        for item in module.items:
            if not isinstance(item, A.ImplBlock):
                continue
            if item.trait_name is None:
                continue
            if self._is_user_capability(item.trait_name):
                self._cap_bearing_structs.add(item.type_name)

        # Second sub-pass: now that all type names are in scope, we can
        # resolve the types of struct fields, variant payloads, and
        # types of constants/functions.
        for item in module.items:
            if isinstance(item, A.TypeStruct):
                sym = self.global_scope.lookup(item.name)
                if sym is None:
                    continue
                self._push_type_params(item.type_params)
                is_cap_bearing = item.name in self._cap_bearing_structs
                for fld in item.fields:
                    fty = self._resolve_type(fld.type_expr)
                    if not is_cap_bearing:
                        self._check_no_capability(
                            fty, fld.pos, f"struct field {fld.name!r}",
                        )
                    sym.struct_fields[fld.name] = fty
                self._pop_type_params()
            elif isinstance(item, A.TypeSum):
                sym = self.global_scope.lookup(item.name)
                if sym is None:
                    continue
                self._push_type_params(item.type_params)
                for v in item.variants:
                    vsym = sym.sum_variants.get(v.name)
                    if vsym is None:
                        continue
                    if v.payload is not None:
                        pty = self._resolve_type(v.payload)
                        self._check_no_capability(
                            pty, v.pos,
                            f"payload of variant {v.name!r}",
                        )
                        vsym.variant_payload_ty = pty
                self._pop_type_params()
            elif isinstance(item, A.ConstDecl):
                sym = self.global_scope.lookup(item.name)
                if sym is not None:
                    sym.ty = self._resolve_type(item.type_expr)
                    self._check_no_capability(
                        sym.ty, item.pos, f"constant {item.name!r}",
                    )
            elif isinstance(item, A.FunDecl):
                sym = self.global_scope.lookup(item.name)
                if sym is not None:
                    sym.ty = self._fun_type_from_decl(item)
                    sym.consuming_params = [
                        p.consuming for p in item.params if p.name != "self"
                    ]
                    sym.param_names = [
                        p.name for p in item.params if p.name != "self"
                    ]
                    if isinstance(sym.ty, TyFun):
                        # Only built-in capabilities are forbidden as
                        # function return types. User-defined capabilities
                        # can be returned by factory functions, they
                        # are not "permission forgery" because the factory
                        # consumed the underlying built-in caps to build
                        # the higher-level one.
                        self._check_no_builtin_capability(
                            sym.ty.ret, item.pos,
                            f"return type of function {item.name!r}",
                        )
            elif isinstance(item, A.TraitDecl):
                sym = self.global_scope.lookup(item.name)
                if sym is None:
                    continue
                # Resolve the trait method signatures, with the trait's
                # type params in scope. Self refers to the impl-er -
                # during trait registration, it stays as a TyVar
                # placeholder that will be substituted during impl checking.
                self._push_type_params(item.type_params)
                prev_self = self.self_type
                self.self_type = TyName("Self")  # placeholder
                for method in item.methods:
                    fty = self._method_type_from_decl(method)
                    if isinstance(fty, TyFun):
                        sym.trait_method_sigs[method.name] = fty
                self.self_type = prev_self
                self._pop_type_params()

        # Third sub-pass: register the impl methods on the target type
        # symbols. This must come after the second sub-pass because the
        # method-type computation may depend on fully resolved types.
        for item in module.items:
            if isinstance(item, A.ImplBlock):
                self._register_impl_methods(item)

    def _register_impl_methods(self, impl: A.ImplBlock) -> None:
        """Register the methods of an ``impl`` on the target type's Symbol.

        Compute the function type of each method (excluding ``self``),
        with the target type's ``type_params`` in scope. ``Self`` appears
        in the types via ``self_type``, set temporarily.

        Does not check bodies, that is for phase 2. Only signatures are
        registered so that ``_check_method_call`` can dispatch.

        Also records the trait/capability the target implements (if
        any) on ``target.implements`` so that the compatibility check
        accepts the target where the trait/cap is expected.
        """
        target = self.global_scope.lookup(impl.type_name)
        if target is None or target.kind not in (
            SymbolKind.TYPE_STRUCT, SymbolKind.TYPE_SUM,
        ):
            return
        # Record the implemented trait/capability for subtyping.
        if impl.trait_name is not None:
            target.implements.add(impl.trait_name)
        # Configure Self and the target type's type params for the duration of the registration.
        self_args = tuple(TyVar(p) for p in target.type_params)
        prev_self = self.self_type
        self.self_type = TyName(impl.type_name, self_args)
        self._push_type_params(target.type_params)

        for method in impl.methods:
            if method.name in target.methods:
                self._err(
                    f"duplicate method {method.name!r} in impl of "
                    f"{impl.type_name!r}",
                    method.pos,
                )
                continue
            fty = self._method_type_from_decl(method)
            m_sym = Symbol(
                name=method.name, kind=SymbolKind.FUNCTION,
                pos=method.pos, ty=fty,
                type_params=list(method.type_params),
                consuming_params=[
                    p.consuming for p in method.params if p.name != "self"
                ],
                param_names=[
                    p.name for p in method.params if p.name != "self"
                ],
            )
            target.methods[method.name] = m_sym

        self._pop_type_params()
        self.self_type = prev_self

    def _method_type_from_decl(self, method: A.FunDecl) -> Ty:
        """Compute the ``TyFun`` of a method, **excluding the ``self``
        parameter**. The method type covers only the explicit arguments
       , the receiver is handled separately in ``_check_method_call``.
        """
        self._push_type_params(method.type_params)
        params: list[Ty] = []
        for p in method.params:
            if p.name == "self":
                continue
            if p.type_expr is None:
                params.append(TyUnknown)
            else:
                params.append(self._resolve_type(p.type_expr))
        ret = self._resolve_type(method.return_type) if method.return_type else TyUnit
        self._pop_type_params()
        return TyFun(tuple(params), ret)

    def _declare_global(self, sym: Symbol) -> None:
        existing = self.global_scope.lookup_local(sym.name)
        if existing is not None and existing.pos is not _BUILTIN_POS:
            self._err(
                f"duplicate top-level declaration {sym.name!r}; previously "
                f"declared at {existing.pos}",
                sym.pos,
            )
            return
        self.global_scope.define(sym)

    def _fun_type_from_decl(self, fn: A.FunDecl) -> Ty:
        self._push_type_params(fn.type_params)
        params = []
        for p in fn.params:
            if p.name == "self" and p.type_expr is None:
                # Inside an impl, self has the impl's type. In a top-level
                # function, self should not appear, we assume TyUnknown.
                params.append(TyUnknown)
            elif p.type_expr is None:
                params.append(TyUnknown)
            else:
                params.append(self._resolve_type(p.type_expr))
        ret = self._resolve_type(fn.return_type) if fn.return_type else TyUnit
        self._pop_type_params()
        return TyFun(tuple(params), ret)

    # ===========================================================
    # Resolution of syntactic types to internal types
    # ===========================================================

    def _resolve_type(self, te: A.TypeExpr) -> Ty:
        if isinstance(te, A.UnitType):
            return TyUnit
        if isinstance(te, A.TupleType):
            return TyTuple(tuple(self._resolve_type(e) for e in te.elements))
        if isinstance(te, A.FunType):
            return TyFun(
                tuple(self._resolve_type(p) for p in te.param_types),
                self._resolve_type(te.return_type),
            )
        if isinstance(te, A.TypeName):
            name = te.name
            # 'Unit' is the canonical name of the unit type; we accept it as a synonym for ().
            if name == "Unit" and not te.args:
                return TyUnit
            if name == "Self":
                if self.self_type is None:
                    self._err(
                        "'Self' is only valid inside an impl or trait",
                        te.pos,
                    )
                    return TyUnknown
                return self.self_type
            if self._is_type_param_in_scope(name):
                if te.args:
                    self._err(
                        f"type parameter {name!r} cannot have type arguments",
                        te.pos,
                    )
                return TyVar(name)
            sym = self.global_scope.lookup(name)
            if sym is None:
                hint = self._hint_did_you_mean(name, self._type_names())
                self._err(f"undefined type {name!r}{hint}", te.pos)
                return TyUnknown
            if sym.kind not in (
                SymbolKind.TYPE_STRUCT, SymbolKind.TYPE_SUM,
                SymbolKind.TRAIT, SymbolKind.CAPABILITY,
            ):
                self._err(
                    f"{name!r} is not a type "
                    f"(it is a {sym.kind.name.lower().replace('_', ' ')})",
                    te.pos,
                )
                return TyUnknown
            args = tuple(self._resolve_type(a) for a in te.args)
            return TyName(name, args)
        return TyUnknown

    # ===========================================================
    # Phase 2: item checking
    # ===========================================================

    def _check_item(self, item: A.Item) -> None:
        if isinstance(item, A.Import):
            return
        if isinstance(item, A.ConstDecl):
            self._check_const(item)
            return
        if isinstance(item, A.FunDecl):
            self._check_fun(item)
            return
        if isinstance(item, A.ImplBlock):
            self._check_impl(item)
            return
        # TypeStruct, TypeSum, TraitDecl: already handled in Phase 1.

    def _check_const(self, c: A.ConstDecl) -> None:
        sym = self.global_scope.lookup(c.name)
        expected = sym.ty if sym is not None else TyUnknown
        actual = self._check_expr(c.value)
        if not compatible(expected, actual):
            self._err(
                f"constant {c.name!r}: expected {ty_str(expected)}, "
                f"got {ty_str(actual)}",
                c.value.pos,
            )

    # ===========================================================
    # Attribute validation
    #
    # Attributes are static metadata attached to function declarations
    # (``@security(...)``, ``@deprecated(...)``, ``@audited(...)``).
    # v1 ships a fixed catalogue of known attributes; the analyzer
    # rejects unknown names and unknown keys so that downstream
    # consumers (the ``--manifest`` builder, future audit tooling)
    # can rely on a stable schema.
    #
    # The parser already guarantees that argument values are string
    # literals; here we only need to validate names and keys.
    # ===========================================================

    _ATTRIBUTE_SCHEMA: dict[str, set[str]] = {
        "security":   {"cve", "cwe", "severity", "fixed_in", "description"},
        "deprecated": {"reason", "since", "use", "removed_in"},
        "audited":    {"date", "by", "scope", "notes"},
    }

    def _check_function_attributes(self, fn: A.FunDecl) -> None:
        """Validate the names and keys of attributes attached to ``fn``."""
        seen_names: set[str] = set()
        for attr in fn.attributes:
            allowed_keys = self._ATTRIBUTE_SCHEMA.get(attr.name)
            if allowed_keys is None:
                known = ", ".join(sorted(self._ATTRIBUTE_SCHEMA))
                self._err(
                    f"unknown attribute '@{attr.name}'; "
                    f"known attributes are: {known}",
                    attr.pos,
                )
                continue
            # Reject duplicate attribute names on the same function.
            if attr.name in seen_names:
                self._err(
                    f"attribute '@{attr.name}' appears more than once on "
                    f"function {fn.name!r}",
                    attr.pos,
                )
                continue
            seen_names.add(attr.name)
            # Validate every key against the schema for this attribute.
            seen_keys: set[str] = set()
            for key, _value in attr.args:
                if key not in allowed_keys:
                    keys_str = ", ".join(sorted(allowed_keys))
                    self._err(
                        f"unknown key '{key}' in '@{attr.name}'; "
                        f"allowed keys are: {keys_str}",
                        attr.pos,
                    )
                    continue
                if key in seen_keys:
                    self._err(
                        f"key '{key}' appears more than once in "
                        f"'@{attr.name}'",
                        attr.pos,
                    )
                seen_keys.add(key)

    def _check_fun(self, fn: A.FunDecl) -> None:
        # Validate any attribute metadata first, fast, scope-free,
        # and a precondition for ``--manifest`` to trust the AST.
        if fn.attributes:
            self._check_function_attributes(fn)

        self._push_type_params(fn.type_params)
        self._push_scope()

        # Accumulate symbols of parameters that are capabilities, to
        # check at the end whether they were used at least once in the body.
        cap_param_syms: list[Symbol] = []

        # Parameters enter the scope.
        for p in fn.params:
            if p.name == "self":
                # Top-level fun with self is odd; we treat it as an error.
                if self.self_type is None:
                    self._err(
                        "'self' parameter is only valid inside an impl",
                        p.pos,
                    )
                psym = Symbol(
                    name="self", kind=SymbolKind.PARAM, pos=p.pos,
                    ty=self.self_type if self.self_type is not None else TyUnknown,
                )
            else:
                pty = self._resolve_type(p.type_expr) if p.type_expr else TyUnknown
                psym = Symbol(
                    name=p.name, kind=SymbolKind.PARAM, pos=p.pos, ty=pty,
                )
                # Mark capabilities for required-use checking.
                if contains_capability(pty) is not None:
                    cap_param_syms.append(psym)
            if self.scope.lookup_local(p.name) is not None:
                self._err(
                    f"duplicate parameter name {p.name!r}", p.pos,
                )
            self.scope.define(psym)

        # Snapshot of the bindings before visiting the body, to detect
        # which cap parameters are used in the body (and not elsewhere).
        bindings_before = set(self.bindings.keys())

        # Reset the consumed set for this function. Nested functions
        # (not supported in v1) do not influence the boundary.
        prev_consumed = self._consumed
        self._consumed = set()
        # Reset the fresh-TyVar substitutions, each function has
        # its own cross-statement inference universe.
        prev_subs = self._ty_subs
        self._ty_subs = {}

        # Check the body with return type configured.
        prev_ret = self.current_return_type
        ret = self._resolve_type(fn.return_type) if fn.return_type else TyUnit
        self.current_return_type = ret
        self._check_block(fn.body)
        self.current_return_type = prev_ret

        self._consumed = prev_consumed
        self._ty_subs = prev_subs

        # Bindings added during the body check.
        new_bindings = {
            k: v for k, v in self.bindings.items() if k not in bindings_before
        }
        used_sym_ids = {id(s) for s in new_bindings.values()}

        # Check that each capability parameter is referenced in the body.
        # Convention: names starting with '_' silence the warning, in the
        # fine tradition of Rust and Haskell.
        for psym in cap_param_syms:
            if id(psym) in used_sym_ids:
                continue
            if psym.name.startswith("_"):
                continue
            self._err(
                f"capability parameter {psym.name!r} is declared but never "
                f"used; prefix the name with '_' to silence this check",
                psym.pos,
            )

        self._pop_scope()
        self._pop_type_params()

    def _check_impl(self, impl: A.ImplBlock) -> None:
        # Check that the target type exists.
        target = self.global_scope.lookup(impl.type_name)
        if target is None or target.kind not in (
            SymbolKind.TYPE_STRUCT, SymbolKind.TYPE_SUM
        ):
            self._err(
                f"impl target {impl.type_name!r} is not a known type",
                impl.pos,
            )
            return

        # Check trait, if applicable. Both `trait X` and `capability X`
        # declarations are valid targets here, both produce a Symbol
        # carrying `trait_methods` / `trait_method_sigs`; only the
        # SymbolKind differs (TRAIT vs CAPABILITY).
        if impl.trait_name is not None:
            trait = self.global_scope.lookup(impl.trait_name)
            if trait is None or trait.kind not in (
                SymbolKind.TRAIT, SymbolKind.CAPABILITY,
            ):
                self._err(
                    f"trait {impl.trait_name!r} is not defined",
                    impl.pos,
                )
            else:
                # Check that all trait methods are implemented.
                impl_method_names = {m.name for m in impl.methods}
                missing = trait.trait_methods - impl_method_names
                if missing:
                    self._err(
                        f"impl of trait {impl.trait_name!r} for "
                        f"{impl.type_name!r} is missing methods: "
                        f"{', '.join(sorted(missing))}",
                        impl.pos,
                    )
                # Check that each implemented method has a signature
                # compatible with the trait's (with Self substituted by
                # the target type).
                self_args_check = tuple(TyVar(p) for p in target.type_params)
                self_ty_concrete = TyName(impl.type_name, self_args_check)
                for method in impl.methods:
                    if method.name not in trait.trait_method_sigs:
                        # Extra method (not declared in the trait).
                        # Capa allows this, useful for helper methods.
                        continue
                    expected = trait.trait_method_sigs[method.name]
                    # Substitute Self in the trait signature with the
                    # concrete impl type.
                    expected_concrete = self._substitute_self(
                        expected, self_ty_concrete,
                    )
                    # Compute the impl method's signature.
                    self._push_type_params(target.type_params)
                    prev_self = self.self_type
                    self.self_type = self_ty_concrete
                    actual = self._method_type_from_decl(method)
                    self.self_type = prev_self
                    self._pop_type_params()
                    if isinstance(actual, TyFun) and isinstance(expected_concrete, TyFun):
                        if not _signatures_match(expected_concrete, actual):
                            self._err(
                                f"impl method {method.name!r} for trait "
                                f"{impl.trait_name!r}: expected signature "
                                f"{ty_str(expected_concrete)}, got "
                                f"{ty_str(actual)}",
                                method.pos,
                            )

        # Configure Self and the target type's type params.
        self_args = tuple(TyVar(p) for p in target.type_params)
        prev_self = self.self_type
        self.self_type = TyName(impl.type_name, self_args)
        self._push_type_params(target.type_params)

        for method in impl.methods:
            self._check_fun(method)

        self._pop_type_params()
        self.self_type = prev_self

    # ===========================================================
    # Statements
    # ===========================================================

    def _check_block(self, block: A.Block) -> None:
        self._push_scope()
        for stmt in block.stmts:
            self._check_stmt(stmt)
        self._pop_scope()

    def _check_stmt(self, stmt: A.Stmt) -> None:
        if isinstance(stmt, A.LetStmt):
            self._check_let(stmt)
        elif isinstance(stmt, A.VarStmt):
            self._check_var(stmt)
        elif isinstance(stmt, A.AssignStmt):
            self._check_assign(stmt)
        elif isinstance(stmt, A.IfStmt):
            self._check_if(stmt)
        elif isinstance(stmt, A.WhileStmt):
            self._check_while(stmt)
        elif isinstance(stmt, A.ForStmt):
            self._check_for(stmt)
        elif isinstance(stmt, A.ReturnStmt):
            self._check_return(stmt)
        elif isinstance(stmt, A.BreakStmt):
            pass  # only allow inside loops? leave for v1.1
        elif isinstance(stmt, A.ContinueStmt):
            pass
        elif isinstance(stmt, A.ExprStmt):
            self._check_expr(stmt.expr)
        else:
            self._err(f"unknown statement type {type(stmt).__name__}", stmt.pos)

    def _check_let(self, s: A.LetStmt) -> None:
        actual = self._check_expr(s.value)
        if s.type_expr is not None:
            declared = self._resolve_type(s.type_expr)
            if not compatible(declared, actual):
                self._err(
                    f"let binding: expected {ty_str(declared)}, "
                    f"got {ty_str(actual)}",
                    s.value.pos,
                )
            actual = declared
        # Capabilities are normally forbidden in let bindings to prevent
        # aliasing. Exception: a fresh capability produced by a call -
        # either a method call (built-in attenuation, e.g.
        # `net.restrict_to("a.com")`) or a regular function call
        # (user-defined cap factory, e.g. `make_smtp_mailer(net, ...)`).
        # Both are brand-new capability instances, not aliases of
        # existing ones. The flow-layer non-aliasing rule still applies
        # at call sites if the binding is later passed around.
        if not isinstance(s.value, (A.MethodCall, A.Call)):
            self._check_no_capability(actual, s.pos, "a 'let' binding")
        self._bind_pattern(s.pattern, actual, mutable=False)

    def _check_var(self, s: A.VarStmt) -> None:
        actual = self._check_expr(s.value)
        if s.type_expr is not None:
            declared = self._resolve_type(s.type_expr)
            if not compatible(declared, actual):
                self._err(
                    f"var declaration: expected {ty_str(declared)}, "
                    f"got {ty_str(actual)}",
                    s.value.pos,
                )
            actual = declared
        # See _check_let for the rationale: call/method-call RHS is a
        # fresh capability, not an alias, so let it through.
        if not isinstance(s.value, (A.MethodCall, A.Call)):
            self._check_no_capability(actual, s.pos, "a 'var' binding")
        if self.scope.lookup_local(s.name) is not None:
            self._err(f"duplicate declaration of {s.name!r}", s.pos)
        self.scope.define(
            Symbol(name=s.name, kind=SymbolKind.LOCAL_VAR, pos=s.pos, ty=actual)
        )

    def _check_assign(self, s: A.AssignStmt) -> None:
        target_ty = self._check_expr(s.target)
        value_ty = self._check_expr(s.value)
        # Validate the target's mutability, if it is a name.
        if isinstance(s.target, A.Ident):
            sym = self.bindings.get(id(s.target))
            if sym is not None and sym.kind == SymbolKind.LOCAL:
                self._err(
                    f"cannot assign to immutable binding {sym.name!r} "
                    f"(use 'var' instead of 'let' to make it mutable)",
                    s.pos,
                )
            elif sym is not None and sym.kind == SymbolKind.CONSTANT:
                self._err(
                    f"cannot assign to constant {sym.name!r}", s.pos,
                )
            elif sym is not None and sym.kind == SymbolKind.PARAM:
                self._err(
                    f"cannot assign to parameter {sym.name!r}", s.pos,
                )
        if not compatible(target_ty, value_ty):
            self._err(
                f"assignment: cannot assign {ty_str(value_ty)} to "
                f"{ty_str(target_ty)}",
                s.value.pos,
            )

    def _snapshot_for_dry_run(self) -> dict:
        """Capture the analyzer's mutable state before a speculative
        pass (dry-run). Allows discovering effects without keeping them.

        Used by loop analysis: we need to know which capabilities will
        be consumed in the body before checking the body for real, so
        we pre-mark those caps and catch uses from the next iteration.
        """
        return {
            "consumed": self._consumed.copy(),
            "errors_len": len(self.errors),
            "bindings_keys": set(self.bindings.keys()),
            "types_keys": set(self.types.keys()),
        }

    def _restore_after_dry_run(self, snap: dict) -> None:
        """Restore the state captured by ``_snapshot_for_dry_run``,
        discarding changes made during the dry-run.

        Added bindings/types are removed by key; new errors are
        truncated; ``_consumed`` returns to the captured state.
        """
        self._consumed = snap["consumed"]
        self.errors = self.errors[: snap["errors_len"]]
        for k in list(self.bindings.keys()):
            if k not in snap["bindings_keys"]:
                del self.bindings[k]
        for k in list(self.types.keys()):
            if k not in snap["types_keys"]:
                del self.types[k]

    def _check_if(self, s: A.IfStmt) -> None:
        cond_ty = self._check_expr(s.cond)
        if not compatible(TyBool, cond_ty):
            self._err(
                f"if condition must be Bool, got {ty_str(cond_ty)}",
                s.cond.pos,
            )
        # Flow analysis: snapshot _consumed before each branch, conservative
        # union after. If any possible branch consumes a cap, we consider
        # it consumed after the if.
        before = set(self._consumed)
        branch_results: list[set[str]] = []

        self._consumed = set(before)
        self._check_block(s.then_block)
        branch_results.append(self._consumed)

        for cond, blk in s.elif_arms:
            self._consumed = set(before)
            cty = self._check_expr(cond)
            if not compatible(TyBool, cty):
                self._err(
                    f"elif condition must be Bool, got {ty_str(cty)}",
                    cond.pos,
                )
            self._check_block(blk)
            branch_results.append(self._consumed)

        if s.else_block is not None:
            self._consumed = set(before)
            self._check_block(s.else_block)
            branch_results.append(self._consumed)
        else:
            # No else: the path where no branch runs does not consume
            # anything additional. But if an else exists, all conditions
            # may be false and fall through, equivalent to an empty else.
            branch_results.append(before)

        # Conservative union: if any branch consumes, we consider it
        # consumed from here on.
        merged: set[str] = set()
        for s_set in branch_results:
            merged |= s_set
        self._consumed = merged

    def _check_while(self, s: A.WhileStmt) -> None:
        cty = self._check_expr(s.cond)
        if not compatible(TyBool, cty):
            self._err(
                f"while condition must be Bool, got {ty_str(cty)}",
                s.cond.pos,
            )
        # Loop-aware analysis (2-pass fixed point):
        # Pass 1 (dry-run): visit the body silently to discover which
        # capabilities will be consumed. Errors and added bindings are
        # discarded.
        # Pass 2 (real): pre-mark those caps as consumed before
        # entering the body, and visit it for real now. Thus, any use
        # of a cap that would be consumed in later iterations is
        # caught already in the first static iteration.
        snap = self._snapshot_for_dry_run()
        self._check_block(s.body)
        consumed_in_body = self._consumed - snap["consumed"]
        self._restore_after_dry_run(snap)

        self._consumed |= consumed_in_body
        self._check_block(s.body)

    def _check_for(self, s: A.ForStmt) -> None:
        iter_ty = self._check_expr(s.iter)
        # We try to infer the element type if the iterable is List<T>.
        elem_ty: Ty = TyUnknown
        if isinstance(iter_ty, TyName) and iter_ty.name == "List" and iter_ty.args:
            elem_ty = iter_ty.args[0]

        # Loop-aware analysis (see comment in _check_while).
        snap = self._snapshot_for_dry_run()
        self._push_scope()
        self._bind_pattern(s.pattern, elem_ty, mutable=False)
        for stmt in s.body.stmts:
            self._check_stmt(stmt)
        self._pop_scope()
        consumed_in_body = self._consumed - snap["consumed"]
        self._restore_after_dry_run(snap)

        self._consumed |= consumed_in_body
        self._push_scope()
        self._bind_pattern(s.pattern, elem_ty, mutable=False)
        for stmt in s.body.stmts:
            self._check_stmt(stmt)
        self._pop_scope()

    def _check_lambda(self, e: A.LambdaExpr) -> Ty:
        """Type a lambda expression. The body is checked in a local
        scope with the parameters as bindings.

        **Linear restriction (v1)**: inside the body of a lambda, any
        call that consumes a capability **captured from the outside** is
        rejected. The reason is that the lambda may be invoked multiple
        times, each invocation would consume the cap, but the cap is
        unique. Caps that are parameters of the lambda itself may be
        consumed freely (each call receives its own).

        Implementation: we record which names belong to the lambda's
        inner scope (params); in ``_check_call``, before marking as
        consumed, we check whether the name is local, otherwise, it
        is a capture and is an error.
        """
        self._push_scope()
        param_tys: list[Ty] = []
        param_names: set[str] = set()
        for p in e.params:
            if p.name == "self":
                self._err("'self' is not allowed in lambda parameters", p.pos)
                continue
            pty = self._resolve_type(p.type_expr) if p.type_expr else TyUnknown
            param_tys.append(pty)
            sym = Symbol(
                name=p.name, kind=SymbolKind.PARAM, pos=p.pos, ty=pty,
            )
            if self.scope.lookup_local(p.name) is not None:
                self._err(
                    f"duplicate parameter name {p.name!r} in lambda", p.pos,
                )
            self.scope.define(sym)
            param_names.add(p.name)

        # Reset _consumed for the lambda's scope. Snapshot the previous
        # state; we restore at the end, the lambda itself does not
        # consume from the outside, it only has effects when called.
        prev_consumed = self._consumed
        self._consumed = set(prev_consumed)

        # Mark this scope as "inside a lambda" so that the call checker
        # knows that consumes are only valid for local names. Stack
        # to support nested lambdas (rare).
        self._lambda_local_names_stack.append(param_names)

        # The body may be a single expression or an indented block.
        # For a single-expr, the body's type is the return type.
        # For a block body, explicit return statements are checked
        # against current_return_type, without a return, it returns Unit.
        if isinstance(e.body, A.Block):
            # Block body: configure expected return type, check stmts.
            decl_ret_block: Ty
            if e.return_type is not None:
                decl_ret_block = self._resolve_type(e.return_type)
            else:
                decl_ret_block = TyUnit
            prev_ret = self.current_return_type
            self.current_return_type = decl_ret_block
            for stmt in e.body.stmts:
                self._check_stmt(stmt)
            self.current_return_type = prev_ret
            ret_ty: Ty = decl_ret_block
            body_ty = decl_ret_block  # for log/debug
        else:
            body_ty = self._check_expr(e.body)
            # If the return type was declared, check it.
            if e.return_type is not None:
                decl_ret_expr = self._resolve_type(e.return_type)
                if not compatible(decl_ret_expr, body_ty):
                    self._err(
                        f"lambda body has type {ty_str(body_ty)}, but "
                        f"declared return type is {ty_str(decl_ret_expr)}",
                        e.body.pos,
                    )
                ret_ty = decl_ret_expr
            else:
                ret_ty = body_ty

        self._lambda_local_names_stack.pop()

        # Restore _consumed: the lambda has no effect on the outer flow.
        self._consumed = prev_consumed
        self._pop_scope()

        return TyFun(tuple(param_tys), ret_ty)

    def _check_if_expr(self, e: A.IfExpr) -> Ty:
        """Type-check ``if cond then e1 else e2``.

        Cond must be Bool. The two branches must have compatible types
       , uses the type of then_expr as expected, and checks else
        against it. Returns the type of then.
        """
        cond_ty = self._check_expr(e.cond)
        if not compatible(TyBool, cond_ty):
            self._err(
                f"if-expression: condition must be Bool, got {ty_str(cond_ty)}",
                e.cond.pos,
            )
        then_ty = self._check_expr(e.then_expr)
        else_ty = self._check_expr(e.else_expr)
        if not compatible(then_ty, else_ty):
            self._err(
                f"if-expression: branches have incompatible types: "
                f"then is {ty_str(then_ty)}, else is {ty_str(else_ty)}",
                e.else_expr.pos,
            )
        # Return the more informative type (non-TyUnknown if one is).
        if then_ty is TyUnknown:
            return else_ty
        return then_ty

    def _check_match_expr(self, s: A.MatchExpr) -> Ty:
        scrutinee_ty = self._check_expr(s.scrutinee)
        arm_types: list[Ty] = []
        # Flow analysis: each arm is an alternative. Snapshot _consumed
        # before each one, union after.
        before = set(self._consumed)
        branch_results: list[set[str]] = []

        for arm in s.arms:
            self._consumed = set(before)
            self._push_scope()
            self._bind_pattern(arm.pattern, scrutinee_ty, mutable=False)
            if arm.guard is not None:
                gty = self._check_expr(arm.guard)
                if not compatible(TyBool, gty):
                    self._err(
                        f"match guard must be Bool, got {ty_str(gty)}",
                        arm.guard.pos,
                    )
            if isinstance(arm.body, A.Block):
                # Block body: check statements and assign Unit as the
                # arm's type. If the block ends with a return, that
                # return was already checked against the function's return type.
                for stmt in arm.body.stmts:
                    self._check_stmt(stmt)
                arm_types.append(TyUnit)
            else:
                arm_types.append(self._check_expr(arm.body))
            self._pop_scope()
            branch_results.append(self._consumed)

        # Conservative union of consumed sets in each arm.
        merged: set[str] = set()
        for r in branch_results:
            merged |= r
        self._consumed = merged

        # Exhaustiveness check, only applicable for sum types when the
        # scrutinee has a concrete type.
        self._check_match_exhaustiveness(s, scrutinee_ty)

        # Type of the match expression: common type of the arms. For v1,
        # we use the first concrete (non-Unknown) type as reference and
        # check the others against it.
        ref_ty: Ty = TyUnknown
        for t in arm_types:
            if not isinstance(t, type(TyUnknown)) and t != TyUnknown:
                ref_ty = t
                break
        for i, t in enumerate(arm_types):
            if not compatible(ref_ty, t):
                self._err(
                    f"match arm {i + 1} has type {ty_str(t)}, "
                    f"incompatible with previous arms ({ty_str(ref_ty)})",
                    s.arms[i].pos,
                )
        return ref_ty

    def _check_match_exhaustiveness(self, s: A.MatchExpr, scrutinee_ty: Ty) -> None:
        """Check that the match covers all possible cases.

        Conservative strategy for v1:
        - If some arm has ``WildcardPat`` or ``IdentPat`` *without a guard*,
          the match is exhaustive (that arm "captures" everything). OK.
        - If the scrutinee has type ``Bool``, require coverage of ``true``
          and ``false`` (via ``LiteralPat`` with ``BoolLit``).
        - If the scrutinee has a sum type (TYPE_SUM), check that all
          variants appear as ``VariantPat`` in some arm without a guard.
        - Other cases (Int, structs), we do not check for v1. The rule
          for Int would be intractable (Int has 2^64 values); structs do
          not have "alternatives".
        - Arms with a guard do not count toward "covering" a case (because
          the guard may fail).
        """
        # If some arm is "catch-all" (wildcard/ident without guard), exhaustive.
        # Or-patterns containing a catch-all also count.
        for arm in s.arms:
            if arm.guard is not None:
                continue
            if self._pattern_is_catchall(arm.pattern):
                return

        # Bool: requires coverage of true and false.
        if isinstance(scrutinee_ty, TyName) and scrutinee_ty.name == "Bool":
            covered_bool: set[bool] = set()
            for arm in s.arms:
                if arm.guard is not None:
                    continue
                # Collect BoolLit in LiteralPat or in OrPat alternatives.
                for sub in self._flatten_or_pat(arm.pattern):
                    if isinstance(sub, A.LiteralPat) and isinstance(
                        sub.value, A.BoolLit
                    ):
                        covered_bool.add(sub.value.value)
            missing_bool = {True, False} - covered_bool
            if missing_bool:
                missing_str = ", ".join(
                    "true" if m else "false" for m in sorted(missing_bool, reverse=True)
                )
                self._err(
                    f"non-exhaustive match on Bool: missing {missing_str} "
                    f"(add '_ -> ...' to handle remaining cases)",
                    s.pos,
                )
            return

        # Nominal sum types.
        if not isinstance(scrutinee_ty, TyName):
            return
        type_sym = self.global_scope.lookup(scrutinee_ty.name)
        if type_sym is None or type_sym.kind != SymbolKind.TYPE_SUM:
            return

        # Collect the variants covered by arms without a guard.
        # OrPat counts each alternative that is a VariantPat.
        covered: set[str] = set()
        for arm in s.arms:
            if arm.guard is not None:
                continue
            for sub in self._flatten_or_pat(arm.pattern):
                if isinstance(sub, A.VariantPat):
                    covered.add(sub.name)

        all_variants = set(type_sym.sum_variants.keys())
        missing = all_variants - covered
        if missing:
            self._err(
                f"non-exhaustive match on {scrutinee_ty.name!r}: missing "
                f"variants {', '.join(sorted(missing))} "
                f"(add '_ -> ...' to handle remaining cases)",
                s.pos,
            )

    def _pattern_is_catchall(self, p: A.Pattern) -> bool:
        """Return True if the pattern captures all possible values.

        Wildcard or IdentPat are direct catch-alls. OrPat is catch-all
        if *any* of its alternatives is.
        """
        if isinstance(p, (A.WildcardPat, A.IdentPat)):
            return True
        if isinstance(p, A.OrPat):
            return any(self._pattern_is_catchall(a) for a in p.alternatives)
        return False

    def _flatten_or_pat(self, p: A.Pattern) -> list[A.Pattern]:
        """Return all alternatives of an or-pattern recursively.
        For non-Or patterns, return a list containing the pattern itself.
        """
        if isinstance(p, A.OrPat):
            result: list[A.Pattern] = []
            for a in p.alternatives:
                result.extend(self._flatten_or_pat(a))
            return result
        return [p]

    def _check_return(self, s: A.ReturnStmt) -> None:
        if s.value is None:
            actual = TyUnit
        else:
            actual = self._check_expr(s.value)
        expected = self.current_return_type or TyUnit
        if not compatible(expected, actual):
            self._err(
                f"return: expected {ty_str(expected)}, got {ty_str(actual)}",
                s.pos,
            )

    # ===========================================================
    # Patterns
    # ===========================================================

    def _bind_pattern(self, p: A.Pattern, ty: Ty, mutable: bool) -> None:
        """Bind the pattern's names to the current scope, with the given type."""
        if isinstance(p, A.WildcardPat):
            return
        if isinstance(p, A.IdentPat):
            kind = SymbolKind.LOCAL_VAR if mutable else SymbolKind.LOCAL
            if self.scope.lookup_local(p.name) is not None:
                self._err(f"duplicate binding {p.name!r}", p.pos)
            self.scope.define(
                Symbol(name=p.name, kind=kind, pos=p.pos, ty=ty)
            )
            return
        if isinstance(p, A.LiteralPat):
            self._check_expr(p.value)
            return
        if isinstance(p, A.VariantPat):
            sym = self.scope.lookup(p.name)
            if sym is None:
                hint = self._hint_did_you_mean(
                    p.name, self._variant_names(ty),
                )
                self._err(f"unknown variant {p.name!r}{hint}", p.pos)
                if p.payload is not None:
                    self._bind_pattern(p.payload, TyUnknown, mutable)
                return
            if sym.kind != SymbolKind.VARIANT:
                self._err(f"{p.name!r} is not a variant", p.pos)
                if p.payload is not None:
                    self._bind_pattern(p.payload, TyUnknown, mutable)
                return
            payload_ty: Ty = sym.variant_payload_ty or TyUnknown
            # Substitute the owner's type params (e.g., T in Some<T>(T))
            # with the scrutinee's type args. If the scrutinee is Option<Int>
            # and the variant is Some with payload TyVar(T), the concrete
            # payload is Int.
            if (
                sym.variant_owner is not None
                and isinstance(ty, TyName)
                and ty.name == sym.variant_owner.name
                and len(ty.args) == len(sym.variant_owner.type_params)
            ):
                subst = dict(zip(sym.variant_owner.type_params, ty.args))
                payload_ty = substitute(payload_ty, subst)
            elif ty is TyUnknown:
                # If we have no info from the scrutinee, the payload is
                # TyUnknown (not an abstract TyVar, which would fail on
                # later calls).
                if isinstance(payload_ty, TyVar):
                    payload_ty = TyUnknown
            if p.payload is not None:
                self._bind_pattern(p.payload, payload_ty, mutable)
            elif sym.variant_payload_ty is not None:
                self._err(
                    f"variant {p.name!r} requires a payload", p.pos,
                )
            return
        if isinstance(p, A.StructPat):
            sym = self.scope.lookup(p.type_name)
            if sym is None or sym.kind != SymbolKind.TYPE_STRUCT:
                self._err(
                    f"{p.type_name!r} is not a struct type", p.pos,
                )
                return
            known = sym.struct_fields
            seen: set[str] = set()
            for fname, fpat in p.fields:
                if fname in seen:
                    self._err(f"duplicate field {fname!r} in pattern", p.pos)
                seen.add(fname)
                if fname not in known:
                    self._err(
                        f"struct {p.type_name!r} has no field {fname!r}",
                        p.pos,
                    )
                    fty: Ty = TyUnknown
                else:
                    fty = known[fname]
                if fpat is None:
                    # shorthand: field : same-named binding
                    if self.scope.lookup_local(fname) is not None:
                        self._err(f"duplicate binding {fname!r}", p.pos)
                    self.scope.define(
                        Symbol(
                            name=fname,
                            kind=SymbolKind.LOCAL,
                            pos=p.pos,
                            ty=fty,
                        )
                    )
                else:
                    self._bind_pattern(fpat, fty, mutable)
            return
        if isinstance(p, A.TuplePat):
            # Check that the scrutinee's type is a tuple of the same arity.
            # ``ty`` may be TyTuple or TyUnit (for the empty pattern).
            if len(p.elements) == 0:
                if ty is not TyUnit and ty is not TyUnknown:
                    self._err(
                        f"tuple pattern () expects Unit, got {ty_str(ty)}",
                        p.pos,
                    )
                return
            if isinstance(ty, TyTuple):
                if len(p.elements) != len(ty.elements):
                    self._err(
                        f"tuple pattern has {len(p.elements)} elements, "
                        f"but type is {ty_str(ty)}",
                        p.pos,
                    )
                    # Bind what we can, with TyUnknown for extras.
                    for i, sub in enumerate(p.elements):
                        sub_ty: Ty = (
                            ty.elements[i] if i < len(ty.elements)
                            else TyUnknown
                        )
                        self._bind_pattern(sub, sub_ty, mutable)
                    return
                for sub, sub_ty in zip(p.elements, ty.elements):
                    self._bind_pattern(sub, sub_ty, mutable)
                return
            # Unknown or compatible type, bind each sub to TyUnknown.
            for sub in p.elements:
                self._bind_pattern(sub, TyUnknown, mutable)
            return
        if isinstance(p, A.OrPat):
            # Or-patterns: each alternative must match the scrutinee's
            # type. Bindings are allowed *if* all alternatives bind the
            # same set of names with compatible types. Implementation:
            # do a trial bind in a temporary scope for each alternative,
            # then do the real bind with the first (all equivalent).
            if not p.alternatives:
                return
            trial_scopes = []
            for alt in p.alternatives:
                trial = Scope(parent=self.scope)
                saved = self.scope
                self.scope = trial
                try:
                    self._bind_pattern(alt, ty, mutable)
                finally:
                    self.scope = saved
                trial_scopes.append(trial.symbols)
            # Check consistency between alternatives.
            first_names = set(trial_scopes[0].keys())
            for i, others in enumerate(trial_scopes[1:], start=1):
                other_names = set(others.keys())
                if first_names != other_names:
                    missing = first_names - other_names
                    extra = other_names - first_names
                    parts = []
                    if missing:
                        parts.append(
                            f"missing {', '.join(sorted(missing))}"
                        )
                    if extra:
                        parts.append(f"extra {', '.join(sorted(extra))}")
                    self._err(
                        f"or-pattern: alternative {i} binds different "
                        f"names than alternative 0 ({'; '.join(parts)})",
                        p.alternatives[i].pos,
                    )
                    continue
                for name in first_names:
                    t1 = trial_scopes[0][name].ty
                    t2 = others[name].ty
                    if not compatible(t1, t2):
                        self._err(
                            f"or-pattern: name {name!r} has type "
                            f"{ty_str(t1)} in alternative 0 but "
                            f"{ty_str(t2)} in alternative {i}",
                            p.alternatives[i].pos,
                        )
            # Real bind in the current scope using the first alternative.
            self._bind_pattern(p.alternatives[0], ty, mutable)
            return
        self._err(f"unknown pattern type {type(p).__name__}", p.pos)

    def _pattern_has_binding(self, p: A.Pattern) -> bool:
        """Return True if the pattern binds some name (not just matches).

        Idents (not in match with PascalCase), TuplePats with bindings,
        StructPats with sub-bindings, VariantPats with binding payloads,
        all count. Wildcards, literals and variants without payload bind
        nothing.

        Used to enforce the v0 restriction: or-patterns without bindings.
        """
        if isinstance(p, A.WildcardPat):
            return False
        if isinstance(p, A.LiteralPat):
            return False
        if isinstance(p, A.IdentPat):
            # In match context, a PascalCase ident is a variant without
            # payload (does not bind). But the parser has already decided
            # this and returned VariantPat in that case. IdentPat here
            # is always a binding.
            return True
        if isinstance(p, A.VariantPat):
            return p.payload is not None and self._pattern_has_binding(p.payload)
        if isinstance(p, A.StructPat):
            return any(
                fp is None or self._pattern_has_binding(fp)
                for _, fp in p.fields
            )
        if isinstance(p, A.TuplePat):
            return any(self._pattern_has_binding(sub) for sub in p.elements)
        if isinstance(p, A.OrPat):
            return any(self._pattern_has_binding(a) for a in p.alternatives)
        return False

    # ===========================================================
    # Expressions, return the inferred type
    # ===========================================================

    def _check_expr(self, e: A.Expr) -> Ty:
        ty = self._check_expr_inner(e)
        self.types[id(e)] = ty
        return ty

    def _check_expr_inner(self, e: A.Expr) -> Ty:
        if isinstance(e, A.IntLit):
            return TyInt
        if isinstance(e, A.FloatLit):
            return TyFloat
        if isinstance(e, A.StringLit):
            return TyString
        if isinstance(e, A.InterpolatedString):
            # Type each Expr part, any type is acceptable (it will be
            # converted to string via str() at runtime). The final
            # result is always String.
            for part in e.parts:
                if not isinstance(part, str):
                    self._check_expr(part)
            return TyString
        if isinstance(e, A.CharLit):
            return TyChar
        if isinstance(e, A.BoolLit):
            return TyBool
        if isinstance(e, A.UnitLit):
            return TyUnit
        if isinstance(e, A.Ident):
            return self._check_ident(e)
        if isinstance(e, A.BinOp):
            return self._check_binop(e)
        if isinstance(e, A.UnaryOp):
            return self._check_unary(e)
        if isinstance(e, A.Call):
            return self._check_call(e)
        if isinstance(e, A.MethodCall):
            return self._check_method_call(e)
        if isinstance(e, A.FieldAccess):
            return self._check_field_access(e)
        if isinstance(e, A.Index):
            recv_ty = self._check_expr(e.receiver)
            self._check_expr(e.index)
            # List<T>[i] returns T. For other indexable types (Map, etc.)
            # we have no support yet, so we return TyUnknown.
            if isinstance(recv_ty, TyName) and recv_ty.name == "List" and recv_ty.args:
                return recv_ty.args[0]
            return TyUnknown
        if isinstance(e, A.Try):
            self._check_expr(e.expr)
            return TyUnknown
        if isinstance(e, A.StructLit):
            return self._check_struct_lit(e)
        if isinstance(e, A.ListLit):
            return self._check_list_lit(e)
        if isinstance(e, A.TupleLit):
            elems = tuple(self._check_expr(x) for x in e.elements)
            return TyTuple(elems)
        if isinstance(e, A.MatchExpr):
            return self._check_match_expr(e)
        if isinstance(e, A.IfExpr):
            return self._check_if_expr(e)
        if isinstance(e, A.LambdaExpr):
            return self._check_lambda(e)
        if isinstance(e, A.RangeExpr):
            return self._check_range(e)
        self._err(f"unknown expression {type(e).__name__}", e.pos)
        return TyUnknown

    def _check_range(self, e: A.RangeExpr) -> Ty:
        """Range expressions ``a..b`` / ``a..=b`` evaluate to a
        ``List<Int>`` in v1. Both endpoints must be ``Int`` (Float ranges
        are deliberately excluded because precision around the endpoint
        is awkward). The result is fully materialised by the transpiler
        so all ``List<T>`` methods apply.
        """
        start_ty = self._check_expr(e.start)
        end_ty = self._check_expr(e.end)
        op = "..=" if e.inclusive else ".."
        if not compatible(TyInt, start_ty):
            self._err(
                f"range '{op}' requires Int endpoints; "
                f"left side has type {ty_str(start_ty)}",
                e.start.pos,
            )
        if not compatible(TyInt, end_ty):
            self._err(
                f"range '{op}' requires Int endpoints; "
                f"right side has type {ty_str(end_ty)}",
                e.end.pos,
            )
        return TyName("List", (TyInt,))

    def _check_ident(self, e: A.Ident) -> Ty:
        sym = self.scope.lookup(e.name)
        if sym is None:
            hint = self._hint_did_you_mean(e.name, self._names_in_scope())
            self._err(f"undefined name {e.name!r}{hint}", e.pos)
            return TyUnknown
        self.bindings[id(e)] = sym
        # Use-after-consume check: if the name is a capability marked
        # as consumed, any further use is an error.
        if e.name in self._consumed:
            self._err(
                f"capability {e.name!r} was consumed earlier and cannot "
                f"be used again",
                e.pos,
            )
        if sym.kind == SymbolKind.MODULE:
            return TyUnknown   # module accesses are not typed in v1
        if sym.kind == SymbolKind.CAPABILITY:
            return TyName(sym.name)
        if sym.kind == SymbolKind.VARIANT:
            # Constructor without payload: the type is the owning sum type.
            # For generic types whose parameters we cannot infer from
            # context, we use TyUnknown, which is compatible with any
            # concrete instantiation (e.g., 'None' produces Option<?>,
            # compatible with Option<Int>).
            if sym.variant_payload_ty is None and sym.variant_owner is not None:
                owner = sym.variant_owner
                if owner.pos is _BUILTIN_POS:
                    args = tuple(TyUnknown for _ in owner.type_params)
                else:
                    args = tuple(TyVar(p) for p in owner.type_params)
                return TyName(owner.name, args)
            return TyUnknown
        if sym.ty is not None:
            return self._resolve_ty(sym.ty)
        return TyUnknown

    def _check_binop(self, e: A.BinOp) -> Ty:
        lt = self._check_expr(e.left)
        rt = self._check_expr(e.right)
        op = e.op
        if op in ("+", "-", "*", "/", "%"):
            # Arithmetic: both sides Int or both Float.
            if compatible(TyInt, lt) and compatible(TyInt, rt):
                return TyInt
            if compatible(TyFloat, lt) and compatible(TyFloat, rt):
                return TyFloat
            # `+` on strings is concatenation.
            if op == "+" and compatible(TyString, lt) and compatible(TyString, rt):
                return TyString
            self._err(
                f"operator {op!r}: incompatible operand types "
                f"{ty_str(lt)} and {ty_str(rt)}",
                e.pos,
            )
            return TyUnknown
        if op in ("==", "!="):
            if not compatible(lt, rt) and not compatible(rt, lt):
                self._err(
                    f"operator {op!r}: cannot compare {ty_str(lt)} with "
                    f"{ty_str(rt)}",
                    e.pos,
                )
            return TyBool
        if op in ("<", "<=", ">", ">="):
            if not (
                (compatible(TyInt, lt) and compatible(TyInt, rt))
                or (compatible(TyFloat, lt) and compatible(TyFloat, rt))
                or (compatible(TyString, lt) and compatible(TyString, rt))
            ):
                self._err(
                    f"operator {op!r}: incompatible operand types "
                    f"{ty_str(lt)} and {ty_str(rt)}",
                    e.pos,
                )
            return TyBool
        if op in ("and", "or"):
            if not compatible(TyBool, lt):
                self._err(
                    f"operator {op!r}: left operand must be Bool, "
                    f"got {ty_str(lt)}",
                    e.left.pos,
                )
            if not compatible(TyBool, rt):
                self._err(
                    f"operator {op!r}: right operand must be Bool, "
                    f"got {ty_str(rt)}",
                    e.right.pos,
                )
            return TyBool
        return TyUnknown

    def _check_unary(self, e: A.UnaryOp) -> Ty:
        ot = self._check_expr(e.operand)
        if e.op == "-":
            if compatible(TyInt, ot):
                return TyInt
            if compatible(TyFloat, ot):
                return TyFloat
            self._err(
                f"unary '-': operand must be numeric, got {ty_str(ot)}",
                e.pos,
            )
            return TyUnknown
        if e.op == "not":
            if not compatible(TyBool, ot):
                self._err(
                    f"'not': operand must be Bool, got {ty_str(ot)}",
                    e.pos,
                )
            return TyBool
        return TyUnknown

    def _resolve_named_args(
        self,
        e: "A.Call | A.MethodCall",
        param_names: list[str],
        callee_label: str,
    ) -> Optional[list[int]]:
        """Validate ``e.arg_names`` and return a permutation that puts
        the arguments into parameter order.

        The result is a list ``perm`` of length ``len(e.args)`` such
        that ``e.args[perm[i]]`` is the argument bound to the i-th
        parameter. Returns ``None`` and reports an error if the named
        arguments are not well-formed (positional after named, name
        does not match a parameter, duplicate name, missing or extra
        argument). When no name appears in ``e.arg_names`` (all
        positional), returns the identity permutation without
        consulting ``param_names`` (so plain calls work even for
        builtins where ``param_names`` is empty).
        """
        names = e.arg_names
        if not any(n is not None for n in names):
            return list(range(len(e.args)))

        if not param_names:
            self._err(
                f"call to {callee_label}: named arguments are not "
                f"supported here",
                e.pos,
            )
            return None

        # Positional arguments must all precede any named argument.
        seen_named = False
        for i, n in enumerate(names):
            if n is None:
                if seen_named:
                    self._err(
                        f"call to {callee_label}: positional argument "
                        f"cannot follow a named argument",
                        e.args[i].pos,
                    )
                    return None
            else:
                seen_named = True

        # Arity check.
        if len(e.args) != len(param_names):
            self._err(
                f"call to {callee_label}: expected {len(param_names)} "
                f"arguments, got {len(e.args)}",
                e.pos,
            )
            return None

        # Build the permutation: param index -> arg index.
        assigned: list[Optional[int]] = [None] * len(param_names)
        name_to_param = {p: i for i, p in enumerate(param_names)}

        # Positional first.
        for i, n in enumerate(names):
            if n is not None:
                break
            assigned[i] = i

        # Then named.
        for i, n in enumerate(names):
            if n is None:
                continue
            param_idx = name_to_param.get(n)
            if param_idx is None:
                self._err(
                    f"call to {callee_label}: unknown parameter name "
                    f"{n!r}",
                    e.args[i].pos,
                )
                return None
            if assigned[param_idx] is not None:
                self._err(
                    f"call to {callee_label}: parameter {n!r} given "
                    f"more than once",
                    e.args[i].pos,
                )
                return None
            assigned[param_idx] = i

        # No gaps allowed (every param must be assigned). Should be
        # guaranteed by the arity check + duplicate check, but defend.
        for i, a in enumerate(assigned):
            if a is None:
                self._err(
                    f"call to {callee_label}: missing argument for "
                    f"parameter {param_names[i]!r}",
                    e.pos,
                )
                return None

        return assigned  # type: ignore[return-value]

    def _check_call(self, e: A.Call) -> Ty:
        # Check aliasing between the arguments before evaluating types -
        # the error is independent of whether the callee is known or not.
        self._check_no_aliasing(
            [(a, f"argument {i + 1}") for i, a in enumerate(e.args)]
        )
        # Evaluate args first, to report independent errors even if the
        # callee fails.
        arg_tys = [self._check_expr(a) for a in e.args]

        # Special case: callee is an identifier -> top-level function
        # or constructor variant. We check arity and types.
        if isinstance(e.callee, A.Ident):
            sym = self.scope.lookup(e.callee.name)
            if sym is not None:
                self.bindings[id(e.callee)] = sym
                if sym.kind == SymbolKind.FUNCTION:
                    if isinstance(sym.ty, TyFun):
                        # Resolve named arguments (no-op if all positional).
                        perm = self._resolve_named_args(
                            e, sym.param_names, repr(sym.name),
                        )
                        if perm is None:
                            return instantiate(
                                sym.ty.ret, sym.type_params, {},
                            )
                        reordered_args = [e.args[j] for j in perm]
                        reordered_tys = [arg_tys[j] for j in perm]
                        ret_ty = self._check_call_with_inference(
                            e, sym.ty, reordered_tys, sym.name,
                            sym.type_params, reordered_args,
                        )
                        # Mark as consumed the args corresponding to
                        # consuming parameters. Done after checking so
                        # that type errors are reported first.
                        if sym.consuming_params:
                            self._mark_consumed_args(
                                reordered_args, sym.consuming_params,
                            )
                        return ret_ty
                    return TyUnknown
                if sym.kind == SymbolKind.VARIANT:
                    # Constructor with payload: 1 argument.
                    if sym.variant_payload_ty is None:
                        self._err(
                            f"variant {sym.name!r} takes no payload",
                            e.pos,
                        )
                        return TyUnknown
                    if len(arg_tys) != 1:
                        self._err(
                            f"variant {sym.name!r} takes 1 argument, "
                            f"got {len(arg_tys)}",
                            e.pos,
                        )
                    # Inference: unify payload_ty (which may be a TyVar)
                    # with the argument's type, and propagate to the owner sum type.
                    mapping: dict[str, Ty] = {}
                    if arg_tys:
                        unify(sym.variant_payload_ty, arg_tys[0], mapping)
                        # Check compatibility after substitution.
                        substituted_payload = substitute(
                            sym.variant_payload_ty, mapping
                        )
                        if not compatible(substituted_payload, arg_tys[0]):
                            self._err(
                                f"variant {sym.name!r}: expected payload "
                                f"{ty_str(substituted_payload)}, "
                                f"got {ty_str(arg_tys[0])}",
                                e.args[0].pos,
                            )
                    if sym.variant_owner is not None:
                        owner = sym.variant_owner
                        # Apply the mapping to the owner's type_params.
                        # Uninferred params become TyUnknown.
                        args = tuple(
                            mapping.get(p, TyUnknown)
                            for p in owner.type_params
                        )
                        return TyName(owner.name, args)
                    return TyUnknown
        # Other callee forms: the v1 checker does not check.
        self._check_expr(e.callee)
        return TyUnknown

    def _check_call_with_inference(
        self,
        e: A.Call,
        fun_ty: TyFun,
        arg_tys: list[Ty],
        name: str,
        type_params: list[str],
        reordered_args: Optional[list[A.Expr]] = None,
    ) -> Ty:
        """Check a function call, performing local inference of
        ``type_params`` when applicable.

        Strategy: unify each parameter type (which may contain
        ``TyVar`` referencing the ``type_params``) with the corresponding
        argument type, accumulating substitutions. Then check that each
        argument is compatible with the substituted parameter, and
        return the return type also substituted.

        ``TyVar``s not inferred (not appearing in any parameter) become
        ``TyUnknown`` in the result.

        ``reordered_args`` lets the caller pass arguments rearranged
        into parameter order (used by named-argument resolution). When
        ``None``, ``e.args`` is used directly.
        """
        args_in_order = reordered_args if reordered_args is not None else e.args

        if len(fun_ty.params) != len(arg_tys):
            self._err(
                f"call to {name!r}: expected {len(fun_ty.params)} arguments, "
                f"got {len(arg_tys)}",
                e.pos,
            )
            return instantiate(fun_ty.ret, type_params, {})

        # Phase 1: inference. Unify each (param, arg) accumulating bindings.
        mapping: dict[str, Ty] = {}
        for param_ty, arg_ty in zip(fun_ty.params, arg_tys):
            unify(param_ty, arg_ty, mapping)

        # Phase 2: checking. Substitute in the param and check compatibility.
        for i, (param_ty, arg_ty) in enumerate(zip(fun_ty.params, arg_tys)):
            substituted = substitute(param_ty, mapping)
            if not self._compatible_with_impls(substituted, arg_ty):
                self._err(
                    f"call to {name!r}: argument {i + 1} expects "
                    f"{ty_str(substituted)}, got {ty_str(arg_ty)}",
                    args_in_order[i].pos,
                )

        # Persist substitutions of fresh TyVars (cross-statement).
        self._commit_fresh_substitutions(mapping)

        # Phase 3: substitute in the return type and close uninferred ones.
        return instantiate(fun_ty.ret, type_params, mapping)

    def _check_method_call(self, e: A.MethodCall) -> Ty:
        # The receiver of a method call occupies a call slot, a cap
        # passed as receiver and also as argument is aliasing.
        slots: list[tuple[A.Expr, str]] = [(e.receiver, "receiver")]
        slots.extend((a, f"argument {i + 1}") for i, a in enumerate(e.args))
        self._check_no_aliasing(slots)

        recv_ty = self._check_expr(e.receiver)
        arg_tys = [self._check_expr(a) for a in e.args]

        # Capabilities: consult registered methods for precise typing.
        # If the method is not registered, accept as TyUnknown (a
        # permissive fallback to preserve the capability's opacity).
        if isinstance(recv_ty, TyName) and recv_ty.name in CAPABILITY_NAMES:
            cap_sym = self.global_scope.lookup(recv_ty.name)
            if cap_sym is not None:
                method_sym = cap_sym.methods.get(e.method)
                if method_sym is not None and isinstance(method_sym.ty, TyFun):
                    return self._check_method_dispatch(
                        e, cap_sym, method_sym, recv_ty, arg_tys,
                    )
            return TyUnknown

        # Look up the method on the receiver type's Symbol.
        if isinstance(recv_ty, TyName):
            type_sym = self.global_scope.lookup(recv_ty.name)
            if type_sym is not None and type_sym.kind in (
                SymbolKind.TYPE_STRUCT, SymbolKind.TYPE_SUM,
            ):
                method_sym = type_sym.methods.get(e.method)
                if method_sym is None:
                    # No registered method, it may be an impl not yet
                    # processed or a non-existent method. To be precise,
                    # we report an error.
                    hint = self._hint_did_you_mean(
                        e.method, list(type_sym.methods.keys()),
                    )
                    self._err(
                        f"type {recv_ty.name!r} has no method "
                        f"{e.method!r}{hint}",
                        e.pos,
                    )
                    return TyUnknown
                return self._check_method_dispatch(
                    e, type_sym, method_sym, recv_ty, arg_tys,
                )

        # Non-nominal types (TyUnknown, TyVar, etc.), we cannot check.
        return TyUnknown

    def _check_method_dispatch(
        self,
        e: A.MethodCall,
        type_sym: Symbol,
        method_sym: Symbol,
        recv_ty: TyName,
        arg_tys: list[Ty],
    ) -> Ty:
        """Dispatch a method call: substitute the type's type params
        with the receiver's args, apply inference to the method's
        remaining type params, check args and return the return type.
        """
        if not isinstance(method_sym.ty, TyFun):
            return TyUnknown
        method_fun_ty = method_sym.ty

        # Initial mapping: the type's type_params -> concrete receiver args.
        # E.g., for Caixa<Int> the receiver has args=(Int,), and the type
        # has type_params=["T"]; the mapping becomes {"T": Int}.
        mapping: dict[str, Ty] = {}
        if len(type_sym.type_params) == len(recv_ty.args):
            for param, arg in zip(type_sym.type_params, recv_ty.args):
                mapping[param] = arg

        # Resolve named arguments (no-op if all positional).
        perm = self._resolve_named_args(
            e, method_sym.param_names, f"{recv_ty.name}.{e.method!r}",
        )
        if perm is None:
            all_type_params = type_sym.type_params + method_sym.type_params
            return instantiate(method_fun_ty.ret, all_type_params, mapping)
        reordered_args = [e.args[j] for j in perm]
        reordered_tys = [arg_tys[j] for j in perm]

        # Check arity of the explicit arguments.
        if len(method_fun_ty.params) != len(reordered_tys):
            self._err(
                f"call to {recv_ty.name}.{e.method!r}: expected "
                f"{len(method_fun_ty.params)} arguments, got "
                f"{len(reordered_tys)}",
                e.pos,
            )
            return instantiate(method_fun_ty.ret, method_sym.type_params, mapping)

        # Additional inference: some method type params may be inferred
        # from the explicit args (not from the receiver).
        for param_ty, arg_ty in zip(method_fun_ty.params, reordered_tys):
            substituted = substitute(param_ty, mapping)
            unify(substituted, arg_ty, mapping)

        # Check compatibility after substitution.
        for i, (param_ty, arg_ty) in enumerate(
            zip(method_fun_ty.params, reordered_tys)
        ):
            substituted = substitute(param_ty, mapping)
            if not self._compatible_with_impls(substituted, arg_ty):
                self._err(
                    f"call to {recv_ty.name}.{e.method!r}: argument "
                    f"{i + 1} expects {ty_str(substituted)}, got "
                    f"{ty_str(arg_ty)}",
                    reordered_args[i].pos,
                )

        # Persist substitutions of fresh TyVars (cross-statement).
        self._commit_fresh_substitutions(mapping)

        # Substitute in the return type, with uninferred type params becoming Unknown.
        all_type_params = type_sym.type_params + method_sym.type_params
        ret_ty = instantiate(method_fun_ty.ret, all_type_params, mapping)

        # Mark as consumed the args corresponding to consuming params.
        if method_sym.consuming_params:
            self._mark_consumed_args(reordered_args, method_sym.consuming_params)

        return ret_ty

    def _check_field_access(self, e: A.FieldAccess) -> Ty:
        rty = self._check_expr(e.receiver)
        if isinstance(rty, TyName):
            sym = self.global_scope.lookup(rty.name)
            if sym is not None and sym.kind == SymbolKind.TYPE_STRUCT:
                fty = sym.struct_fields.get(e.field_name)
                if fty is None:
                    hint = self._hint_did_you_mean(
                        e.field_name, list(sym.struct_fields.keys()),
                    )
                    self._err(
                        f"struct {rty.name!r} has no field "
                        f"{e.field_name!r}{hint}",
                        e.pos,
                    )
                    return TyUnknown
                if sym.type_params and rty.args:
                    mapping = dict(zip(sym.type_params, rty.args))
                    return substitute(fty, mapping)
                return fty
        return TyUnknown

    def _check_struct_lit(self, e: A.StructLit) -> Ty:
        sym = self.global_scope.lookup(e.type_name)
        if sym is None:
            hint = self._hint_did_you_mean(e.type_name, self._type_names())
            self._err(f"undefined type {e.type_name!r}{hint}", e.pos)
            for _, v in e.fields:
                self._check_expr(v)
            return TyUnknown
        if sym.kind != SymbolKind.TYPE_STRUCT:
            self._err(f"{e.type_name!r} is not a struct type", e.pos)
            for _, v in e.fields:
                self._check_expr(v)
            return TyUnknown
        # Inference: for generic types, we discover the args through
        # the types of the field values.
        mapping: dict[str, Ty] = {}
        seen: set[str] = set()
        # First pass: evaluate values and try to infer.
        for fname, fexpr in e.fields:
            if fname in seen:
                self._err(f"duplicate field {fname!r} in struct literal", e.pos)
            seen.add(fname)
            if fname not in sym.struct_fields:
                hint = self._hint_did_you_mean(
                    fname, list(sym.struct_fields.keys()),
                )
                self._err(
                    f"struct {e.type_name!r} has no field "
                    f"{fname!r}{hint}",
                    fexpr.pos,
                )
                self._check_expr(fexpr)
                continue
            expected = sym.struct_fields[fname]
            actual = self._check_expr(fexpr)
            unify(expected, actual, mapping)
        # Second pass: check compatibility after substitution.
        for fname, fexpr in e.fields:
            if fname not in sym.struct_fields:
                continue
            expected = sym.struct_fields[fname]
            substituted = substitute(expected, mapping)
            actual_ty = self.types.get(id(fexpr), TyUnknown)
            if not compatible(substituted, actual_ty):
                self._err(
                    f"struct {e.type_name!r}: field {fname!r} expects "
                    f"{ty_str(substituted)}, got {ty_str(actual_ty)}",
                    fexpr.pos,
                )
        missing = set(sym.struct_fields.keys()) - seen
        if missing:
            self._err(
                f"struct {e.type_name!r}: missing fields "
                f"{', '.join(sorted(missing))}",
                e.pos,
            )
        # Build the type with inferred args (TyUnknown for uninferred ones).
        type_args = tuple(
            mapping.get(p, TyUnknown) for p in sym.type_params
        )
        return TyName(sym.name, type_args)

    def _check_list_lit(self, e: A.ListLit) -> Ty:
        if not e.elements:
            # Fresh TyVar: the element type will be refined by later
            # uses (append calls, indexing, etc.).
            return TyName("List", (self._fresh_ty_var("lst"),))
        first_ty = self._check_expr(e.elements[0])
        for el in e.elements[1:]:
            ety = self._check_expr(el)
            if not compatible(first_ty, ety):
                self._err(
                    f"list literal: element has type {ty_str(ety)}, "
                    f"expected {ty_str(first_ty)}",
                    el.pos,
                )
        return TyName("List", (first_ty,))


# Position used for builtin symbols (which have no origin in the source).
_BUILTIN_POS = Pos(line=0, col=0, offset=0)


def _signatures_match(expected: TyFun, actual: TyFun) -> bool:
    """Check whether two function signatures are structurally compatible.

    For checking trait impls: the impl signature must match the trait's.
    ``TyUnknown`` on either side is permissive.
    """
    if len(expected.params) != len(actual.params):
        return False
    for ep, ap in zip(expected.params, actual.params):
        if not compatible(ep, ap):
            return False
    return compatible(expected.ret, actual.ret)


# ===========================================================
# Top-level API
# ===========================================================


def analyze(
    module: A.Module,
    source: str = "",
    filename: str = "<input>",
) -> AnalysisResult:
    """Analyze a Module and return the result."""
    return Analyzer(source=source, filename=filename).analyze(module)
