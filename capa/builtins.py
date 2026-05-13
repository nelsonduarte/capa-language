"""capa/builtins.py, declarative registration of built-in symbols.

The analyzer's previous ``_install_builtins`` was a ~600-line
imperative method that constructed roughly 70 ``Symbol`` objects
by hand. This module factors that work into tables: which
primitive types exist, which generic types and their type
parameters, which methods each built-in type/capability exposes,
which free functions live in the global scope, which variants
belong to which sum type, what the JSON sum type looks like.

A single function (``register_builtins``) walks the tables and
produces the same Symbols the analyzer used to assemble by hand,
so the analyzer's call site stays a one-liner. Keeping the data
in tables makes new built-ins a one-line addition and makes
auditing the built-in surface trivial (you read this file, not
600 lines of constructor calls).

Type-variable identity (``T``, ``U``, ``K``, ``V``, ``E``,
``F``) is by name (TyVar is a frozen dataclass keyed only on
``name``), so the literals in this file are interchangeable with
the ones the analyzer uses elsewhere.
"""

from __future__ import annotations

from typing import Optional

from .tokens import Pos
from .typesys import (
    CAPABILITY_NAMES, PRIMITIVE_NAMES,
    Ty, TyBool, TyFloat, TyFun, TyInt, TyName, TyString,
    TyUnit, TyUnknown, TyVar,
)


# Position assigned to every built-in symbol. ``Pos(0, 0)`` is the
# sentinel the LSP server uses to filter built-ins out of
# go-to-definition / find-references / rename.
BUILTIN_POS = Pos(line=0, col=0, offset=0)


# Built-in generic types with their type parameters.
# ``IoError`` has no type params but lives here for symmetry with
# the other types that ship method lists below.
PARAMETRIC_TYPES: tuple[tuple[str, list[str]], ...] = (
    ("List",    ["T"]),
    ("Option",  ["T"]),
    ("Result",  ["T", "E"]),
    ("Map",     ["K", "V"]),
    ("Set",     ["T"]),
    ("IoError", []),
)


# Type-var aliases used heavily in built-in method signatures
# below. TyVar identity is by ``name``, so these literals match
# what the analyzer uses elsewhere.
T = TyVar("T")
U = TyVar("U")
K = TyVar("K")
V = TyVar("V")
E = TyVar("E")
F = TyVar("F")


# Convenience type constructors so the tables read like the
# corresponding Capa source. ``opt(t)`` reads as ``Option<t>``.
def opt(t: Ty) -> TyName: return TyName("Option", (t,))
def res(t: Ty, e: Ty) -> TyName: return TyName("Result", (t, e))
def lst(t: Ty) -> TyName: return TyName("List", (t,))
def fun(*params_then_ret: Ty) -> TyFun:
    *params, ret = params_then_ret
    return TyFun(tuple(params), ret)


# Methods of each built-in type or capability. The owner is the
# key; each value is a list of (method_name, TyFun, extra_type_params).
# ``extra_type_params`` is the list of method-local type variables
# (those that do NOT come from the owner's type_params), used by
# the inference path.
#
# Some types (``String``, ``JsonValue``) are not parametric, but
# still get their own method tables here. The registration helper
# creates the owner Symbol if one does not exist yet.
_io_err = TyName("IoError")
_str_res = res(TyString, _io_err)
_unit_res = res(TyUnit, _io_err)
_json_ty = TyName("JsonValue")

METHODS: dict[str, list[tuple[str, TyFun, list[str]]]] = {
    "List": [
        ("length",   fun(TyInt),                                                   []),
        ("push",     fun(T, TyUnit),                                               []),
        ("contains", fun(T, TyBool),                                               []),
        ("map",      fun(fun(T, U), lst(U)),                                       ["U"]),
        ("filter",   fun(fun(T, TyBool), lst(T)),                                  []),
        ("fold",     fun(U, fun(U, T, U), U),                                      ["U"]),
        ("is_empty", fun(TyBool),                                                  []),
        ("first",    fun(opt(T)),                                                  []),
        ("last",     fun(opt(T)),                                                  []),
        ("get",      fun(TyInt, opt(T)),                                           []),
    ],
    "String": [
        ("length",      fun(TyInt),                                                []),
        ("contains",    fun(TyString, TyBool),                                     []),
        ("starts_with", fun(TyString, TyBool),                                     []),
        ("ends_with",   fun(TyString, TyBool),                                     []),
        ("to_upper",    fun(TyString),                                             []),
        ("to_lower",    fun(TyString),                                             []),
        ("trim",        fun(TyString),                                             []),
        ("split",       fun(TyString, lst(TyString)),                              []),
        ("replace",     fun(TyString, TyString, TyString),                         []),
        ("is_empty",    fun(TyBool),                                               []),
    ],
    "Map": [
        ("length",       fun(TyInt),                                               []),
        ("get",          fun(K, opt(V)),                                           []),
        ("set",          fun(K, V, TyUnit),                                        []),
        ("contains_key", fun(K, TyBool),                                           []),
        ("keys",         fun(lst(K)),                                              []),
        ("values",       fun(lst(V)),                                              []),
        ("is_empty",     fun(TyBool),                                              []),
    ],
    "Set": [
        ("length",   fun(TyInt),                                                   []),
        ("add",      fun(T, TyUnit),                                               []),
        ("remove",   fun(T, TyUnit),                                               []),
        ("contains", fun(T, TyBool),                                               []),
        ("to_list",  fun(lst(T)),                                                  []),
        ("is_empty", fun(TyBool),                                                  []),
    ],
    "Option": [
        ("is_some",   fun(TyBool),                                                 []),
        ("is_none",   fun(TyBool),                                                 []),
        ("unwrap_or", fun(T, T),                                                   []),
        ("map",       fun(fun(T, U), opt(U)),                                      ["U"]),
        ("and_then",  fun(fun(T, opt(U)), opt(U)),                                 ["U"]),
        ("ok_or",     fun(E, res(T, E)),                                           ["E"]),
    ],
    "Result": [
        ("is_ok",     fun(TyBool),                                                 []),
        ("is_err",    fun(TyBool),                                                 []),
        ("unwrap_or", fun(T, T),                                                   []),
        ("map",       fun(fun(T, U), res(U, E)),                                   ["U"]),
        ("and_then",  fun(fun(T, res(U, E)), res(U, E)),                           ["U"]),
        ("map_err",   fun(fun(E, F), res(T, F)),                                   ["F"]),
    ],
    "Stdio": [
        ("print",     fun(TyString, TyUnit),                                       []),
        ("println",   fun(TyString, TyUnit),                                       []),
        ("eprintln",  fun(TyString, TyUnit),                                       []),
        ("read_line", fun(_str_res),                                               []),
    ],
    "Fs": [
        ("restrict_to", fun(TyString, TyName("Fs")),                               []),
        ("allows",      fun(TyString, TyBool),                                     []),
        ("read",        fun(TyString, _str_res),                                   []),
        ("write",       fun(TyString, TyString, _unit_res),                        []),
        ("exists",      fun(TyString, TyBool),                                     []),
    ],
    "Env": [
        ("restrict_to_keys", fun(lst(TyString), TyName("Env")),                    []),
        ("allows",           fun(TyString, TyBool),                                []),
        ("get",              fun(TyString, opt(TyString)),                         []),
        ("args",             fun(lst(TyString)),                                   []),
    ],
    "Clock": [
        ("restrict_to_after", fun(TyFloat, TyName("Clock")),                       []),
        ("allows",            fun(TyBool),                                         []),
        ("now_secs",          fun(TyFloat),                                        []),
        ("now_monotonic",     fun(TyFloat),                                        []),
        ("sleep",             fun(TyFloat, TyUnit),                                []),
    ],
    "Net": [
        ("restrict_to", fun(TyString, TyName("Net")),                              []),
        ("allows",      fun(TyString, TyBool),                                     []),
        ("get",         fun(TyString, _str_res),                                   []),
    ],
    "Random": [
        ("with_seed",  fun(TyInt, TyName("Random")),                               []),
        ("int_range",  fun(TyInt, TyInt, TyInt),                                   []),
        ("float_unit", fun(TyFloat),                                               []),
    ],
    "JsonValue": [
        ("is_null",   fun(TyBool),                                                 []),
        ("as_bool",   fun(opt(TyBool)),                                            []),
        ("as_num",    fun(opt(TyFloat)),                                           []),
        ("as_string", fun(opt(TyString)),                                          []),
        ("as_array",  fun(opt(lst(_json_ty))),                                     []),
        ("as_object", fun(opt(TyName("Map", (TyString, _json_ty)))),               []),
    ],
}


# Free functions registered directly in the global scope.
# Format: name -> (TyFun, [extra_type_params]).
FREE_FUNCTIONS: dict[str, tuple[TyFun, list[str]]] = {
    "new_map":     (fun(TyName("Map", (TyUnknown, TyUnknown))),                    []),
    "new_set":     (fun(TyName("Set", (TyUnknown,))),                              []),
    "parse_int":   (fun(TyString, opt(TyInt)),                                     []),
    "parse_float": (fun(TyString, opt(TyFloat)),                                   []),
    "to_float":    (fun(TyInt, TyFloat),                                           []),
    "to_int":      (fun(TyFloat, TyInt),                                           []),
    "py_import":   (fun(TyName("Unsafe"), TyString, TyUnknown),                    []),
    "py_invoke":   (fun(TyName("Unsafe"), TyUnknown, lst(TyUnknown), TyUnknown),   []),
    "parse_json":  (fun(TyString, res(_json_ty, TyString)),                        []),
    "to_json":     (fun(_json_ty, TyString),                                       []),
}


# Variant constructors registered in the global scope. The payload
# type uses TyVar literals tied to the owning sum type's type
# params; ``None`` means the variant has no payload.
# Format: variant_name -> (owner_name, payload_ty | None)
VARIANTS: tuple[tuple[str, str, Optional[Ty]], ...] = (
    ("Some", "Option", T),
    ("None", "Option", None),
    ("Ok",   "Result", T),
    ("Err",  "Result", E),
    # JsonValue variants
    ("JNull", "JsonValue", None),
    ("JBool", "JsonValue", TyBool),
    ("JNum",  "JsonValue", TyFloat),
    ("JStr",  "JsonValue", TyString),
    ("JArr",  "JsonValue", lst(_json_ty)),
    ("JObj",  "JsonValue", TyName("Map", (TyString, _json_ty))),
)


def register_builtins(define, lookup) -> None:
    """Walk the tables above and create the built-in Symbols.

    ``define(sym)`` adds a Symbol to the global scope; ``lookup(name)``
    returns the existing Symbol for the given name (or None). Both
    are bound methods of the analyzer's Scope when this is called
    from ``Analyzer.analyze``.

    The function imports ``Symbol`` and ``SymbolKind`` from
    ``capa.analyzer`` lazily so this module stays usable without
    importing the analyzer (the LSP completion module wants to
    consult ``METHODS`` without analyzer startup cost).
    """
    from .analyzer import Symbol, SymbolKind

    # Primitives.
    for name in PRIMITIVE_NAMES:
        define(Symbol(name=name, kind=SymbolKind.TYPE_STRUCT, pos=BUILTIN_POS))

    # Capabilities.
    for name in CAPABILITY_NAMES:
        define(Symbol(name=name, kind=SymbolKind.CAPABILITY, pos=BUILTIN_POS))

    # Parametric types.
    for name, params in PARAMETRIC_TYPES:
        define(Symbol(
            name=name, kind=SymbolKind.TYPE_STRUCT,
            pos=BUILTIN_POS, type_params=list(params),
        ))

    # Methods (mutates the existing owner Symbol's ``methods`` dict).
    # ``String`` is one of the primitives above; the loop finds it
    # via ``lookup`` and adds the method table to that existing
    # Symbol rather than redefining a fresh one.
    for owner_name, methods in METHODS.items():
        owner = lookup(owner_name)
        if owner is None:
            # JsonValue is registered as a sum below; for any
            # other unknown owner, this is a programmer error.
            if owner_name == "JsonValue":
                continue
            raise RuntimeError(
                f"register_builtins: no Symbol named {owner_name!r}; "
                f"add it to PRIMITIVE_NAMES, CAPABILITY_NAMES or "
                f"PARAMETRIC_TYPES first"
            )
        for mname, mty, mty_params in methods:
            owner.methods[mname] = Symbol(
                name=mname, kind=SymbolKind.FUNCTION,
                pos=BUILTIN_POS, ty=mty,
                type_params=list(mty_params),
            )

    # JsonValue as a sum type.
    json_sym = Symbol(
        name="JsonValue", kind=SymbolKind.TYPE_SUM,
        pos=BUILTIN_POS, type_params=[],
    )
    define(json_sym)
    # Now populate JsonValue's methods (the loop above skipped it).
    for mname, mty, mty_params in METHODS.get("JsonValue", []):
        json_sym.methods[mname] = Symbol(
            name=mname, kind=SymbolKind.FUNCTION,
            pos=BUILTIN_POS, ty=mty,
            type_params=list(mty_params),
        )

    # Variants. Each is registered both as a top-level constructor
    # in the global scope and on the owner sum type's
    # ``sum_variants`` dict.
    for vname, owner_name, payload_ty in VARIANTS:
        owner = lookup(owner_name)
        if owner is None:
            raise RuntimeError(
                f"register_builtins: variant {vname!r} references unknown "
                f"owner {owner_name!r}"
            )
        vsym = Symbol(
            name=vname, kind=SymbolKind.VARIANT, pos=BUILTIN_POS,
            variant_owner=owner, variant_payload_ty=payload_ty,
        )
        define(vsym)
        owner.sum_variants[vname] = vsym

    # Free functions.
    for fname, (fty, ftparams) in FREE_FUNCTIONS.items():
        define(Symbol(
            name=fname, kind=SymbolKind.FUNCTION,
            pos=BUILTIN_POS, ty=fty,
            type_params=list(ftparams),
        ))
