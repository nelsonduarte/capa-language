"""Tests for the Capa semantic analyzer.

Covers name resolution (defined symbols, undefined, redefinitions)
and type checking (literals, operators, assignments, calls,
struct literals, returns, conditions). Also includes smoke tests of
the canonical examples.
"""

import unittest

from capa import Lexer, Parser, analyze

from tests.analyzer._helpers import check, errors_of


# =============================================================
# Valid programs
# =============================================================



# =============================================================
# Name resolution
# =============================================================



# =============================================================
# Type checking
# =============================================================



# =============================================================
# Variants and match
# =============================================================



# =============================================================
# Trait and impl
# =============================================================



# =============================================================
# Capability discipline
# =============================================================



# =============================================================
# Capability-container discipline: a capability may flow only as a
# bare, top-level function parameter, and can never be hidden inside a
# list / set / map / tuple (at any nesting depth). This closes the
# read-out / smuggle family: a container built with a capability
# element cannot be produced, stored, passed, or used, whatever the
# surrounding syntax.
# =============================================================



# =============================================================
# Capability forge: rejecting `Fs()`-style local construction.
# Surfaced 2026-05-24 by the empirical-study fuzz harness: the
# legacy --python backend transpiled `let fs = Fs()` to a literal
# `Fs()` instantiation that obtained unrestricted filesystem
# authority because the runtime `Fs` class defaults to an
# unrestricted instance. The analyzer must reject the call form
# so the static discipline holds across both backends.
# =============================================================



# =============================================================
# Generics inference
# =============================================================























# =============================================================
# Method dispatch
# =============================================================



# =============================================================
# Match exhaustiveness
# =============================================================



# =============================================================
# Closures (lambdas)
# =============================================================



# =============================================================
# Trait and impl verification
# =============================================================



# =============================================================
# Standard library: List<T> builtin methods
# =============================================================



# =============================================================
# Multi-line method chaining (implicit line continuation by '.')
# =============================================================



# =============================================================
# Standard library: String builtin methods
# =============================================================



# =============================================================
# Interpolated strings (InterpolatedString)
# =============================================================





# =============================================================
# Standard library: Map<K, V> and Set<T>
# =============================================================





# =============================================================
# Pattern matching with scrutinee type params
# =============================================================



# =============================================================
# Tuple patterns
# =============================================================



# =============================================================
# Struct-pattern bindings in let / for
# =============================================================



# =============================================================
# Or-patterns
# =============================================================



# =============================================================
# Stdio: read_line and typed methods
# =============================================================









# =============================================================
# Typed capabilities: Fs, Env, Clock, Random
# =============================================================









# =============================================================
# JSON: built-in JsonValue type and parse_json/to_json
# =============================================================











# =============================================================
# if-expression: ``if cond then e1 else e2``
# =============================================================



# =============================================================
# Full linearity: consume keyword + flow analysis
# =============================================================



# =============================================================
# Smoke tests of the canonical examples
# =============================================================



# =============================================================
# Named arguments
# =============================================================



# =============================================================
# "Did you mean?" suggestions
# =============================================================

































# =============================================================
# Reserved sum-type variant names (Ok / Err / Some / None)
# =============================================================































# =============================================================
# For-loop iterable validation (GAP 1)
#
# Capa's iterables are exactly List, Set, Range, and String. A
# Map (and any other non-iterable type) has no sound lowering on
# either backend: the Python backend would silently iterate a
# Map's keys or crash on the destructuring form, while the Wasm
# backend errors. The analyzer rejects them so both backends
# agree at compile time.
# =============================================================



# =============================================================
# Asymmetric Char / String compatibility.
#
# A Capa Char is, by definition, exactly one code point, so it is
# ALWAYS a valid String (one direction). A general String is NOT a
# Char: only a provably one-code-point string LITERAL is accepted
# where a Char is expected. A multi-char literal or a non-literal
# String value flowing into a Char slot is unsound and rejected.
# =============================================================



# =============================================================
# Index-element assignment rejection (GAP 2)
#
# ``xs[i] = v`` and the augmented ``xs[i] += 1`` have no sound
# lowering on either backend (the Python backend emits an
# assignment to a function call, a SyntaxError; the Wasm backend
# raises a CIR-lowering error). The analyzer rejects a bare Index
# assignment target. Assigning to a struct field reached THROUGH
# an index (``xs[0].field = v``) keeps working: its target is a
# FieldAccess whose receiver is the Index.
# =============================================================



# =============================================================
# Dead-Unsafe warning (migrate tooling slice 2)
# =============================================================



















if __name__ == "__main__":
    unittest.main()
