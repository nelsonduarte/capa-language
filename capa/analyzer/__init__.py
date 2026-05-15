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

from .. import capa_ast as A
from ..errors import LexerError
from ..tokens import Pos
from ..typesys import (
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


from ._declarations import _DeclarationsMixin
from ._discipline import _DisciplineMixin
from ._dispatch import _DispatchMixin
from ._expressions import _ExpressionsMixin
from ._items import _ItemsMixin
from ._patterns import _PatternsMixin
from ._statements import _StatementsMixin
from ._typing import _TypingMixin


class Analyzer(
    _TypingMixin, _DisciplineMixin, _DispatchMixin,
    _PatternsMixin, _DeclarationsMixin, _StatementsMixin,
    _ExpressionsMixin, _ItemsMixin,
):
    """Performs the semantic analysis of a Module.

    The implementation is split across mixin modules in this
    package: ``_typing.py`` for TyVar generation and
    substitution, this module for everything else. Each mixin
    documents which fields on ``self`` it needs; all of them are
    set up by ``__init__`` below.

    Typical usage:
        result = analyze(module, source, filename)
        if not result.ok:
            for err in result.errors:
                print(err.format())
    """

    def __init__(
        self,
        source: str = "",
        filename: str = "<input>",
        sources: Optional[dict[str, str]] = None,
        module_privates: Optional[dict[str, set[str]]] = None,
    ):
        self.source = source
        self.filename = filename
        # Per-file source map for the loader-linked case. When set,
        # _err looks up the source string for the position's
        # filename here so errors that originate in an imported
        # module render with the imported file's snippet, not the
        # root file's. Empty dict for the single-file path.
        self.sources: dict[str, str] = sources or {}
        # alias -> set of *private* names declared in that import's
        # target. Consulted when an "undefined name" lookup would
        # otherwise fall back to a typo hint: if the missing name
        # matches a private here, we surface the specialised
        # "private to module 'X'; mark it 'pub' to expose"
        # diagnostic instead.
        self.module_privates: dict[str, set[str]] = module_privates or {}
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

    # Type-substitution machinery (_fresh_ty_var, _resolve_ty,
    # _commit_fresh_substitutions, _apply_mapping) lives in
    # ``_typing.py`` and is folded in via :class:`_TypingMixin`.

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
        keeps checking to find as many errors as possible in a single run.

        When the analyzer was created with a ``sources`` map and the
        position carries a non-empty ``filename``, the source string
        for that filename is looked up so the rendered snippet comes
        from the right file (matters for imports). Falls back to
        ``self.source`` / ``self.filename`` otherwise.
        """
        src = self.source
        fname = self.filename
        if pos.filename and pos.filename in self.sources:
            src = self.sources[pos.filename]
            fname = pos.filename
        self.errors.append(AnalysisError(message, pos, src, fname))

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
        from ..typesys import TyName as _TyName  # local to avoid cycles
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
        kept on the class so existing call sites don't change.

        If the missing name is recorded as private to some imported
        module, that takes priority and we surface a "private to
        module 'X'" hint instead of the typo guess. The pub-vs-typo
        choice is a one-or-the-other call: if the user reached for
        a real declared name and got told it doesn't exist, the
        privacy reason is more actionable than any "did you mean".
        """
        priv_hint = self._hint_private_to_module(needle)
        if priv_hint:
            return priv_hint
        from .._suggest import hint_did_you_mean
        return hint_did_you_mean(needle, haystack)

    def _hint_private_to_module(self, name: str) -> str:
        """If ``name`` matches an entry in ``module_privates`` for
        any imported alias, return a hint suffix that points at the
        right module(s); otherwise return ``""``.
        """
        if not self.module_privates:
            return ""
        hits = [
            alias for alias, names in self.module_privates.items()
            if name in names
        ]
        if not hits:
            return ""
        if len(hits) == 1:
            return (
                f" (private to module {hits[0]!r}; "
                f"mark it 'pub' to expose)"
            )
        joined = ", ".join(repr(a) for a in sorted(hits))
        return (
            f" (private to modules {joined}; "
            f"mark it 'pub' in the right one to expose)"
        )

    def _push_type_params(self, names: list[str]) -> None:
        self.type_param_stack.append(set(names))

    def _pop_type_params(self) -> None:
        self.type_param_stack.pop()

    def _is_type_param_in_scope(self, name: str) -> bool:
        for frame in self.type_param_stack:
            if name in frame:
                return True
        return False

    # Capability discipline (``_mark_consumed_args``,
    # ``_substitute_self``, ``_is_capability_ident``,
    # ``_check_no_aliasing``, ``_check_no_capability``,
    # ``_contains_any_capability``, ``_is_user_capability``,
    # ``_contains_builtin_capability``,
    # ``_check_no_builtin_capability``, ``_compatible_with_impls``)
    # lives in ``_discipline.py`` and is folded in via
    # :class:`_DisciplineMixin`.

    def _install_builtins(self) -> None:
        """Install the language-level built-ins.

        The actual table of types, methods, variants, and free
        functions lives in :mod:`capa.builtins`. This method just
        delegates so the analyzer stays focused on the checking
        work proper.
        """
        from ..builtins import register_builtins
        register_builtins(self.global_scope.define, self.global_scope.lookup)


# Position used for builtin symbols (no origin in the source).
# Re-exported here under the private name so existing identity
# checks (``existing.pos is not _BUILTIN_POS``) keep working
# after the analyzer was split across mixin modules.
from ..builtins import BUILTIN_POS as _BUILTIN_POS


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
    sources: Optional[dict[str, str]] = None,
    module_privates: Optional[dict[str, set[str]]] = None,
) -> AnalysisResult:
    """Analyze a Module and return the result.

    ``sources``: optional per-file map (filename -> text) used by
    the loader-linked path so errors in imported modules render
    with the right source snippet. Single-file callers can leave
    it at its default.

    ``module_privates``: optional per-import-alias map of private
    top-level names contributed by each import. When set, an
    unresolved reference whose name appears in any of these sets
    produces a specialised "private to module 'X'" diagnostic
    instead of the generic "did you mean" hint.
    """
    return Analyzer(
        source=source, filename=filename, sources=sources,
        module_privates=module_privates,
    ).analyze(module)
