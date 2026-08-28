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























class TestLinearContainerLaundering(unittest.TestCase):
    """Soundness (already structurally closed): a linear / typestate value
    cannot be laundered into a non-linear container (tuple / list / struct
    field) to make its must-consume obligation disappear.

    The obligation on the inner value is discharged ONLY by a direct
    consume position -- a ``consume`` argument, a ``become`` operand, or a
    bare-identifier ``return``. Embedding the value in a container never
    discharges it, so the obligation stays live and is reported at scope
    exit no matter what happens to the container (dropped, returned,
    consumed). The language therefore admits no linear container, and no
    laundering escape exists. These tests lock that in."""

    _LIN = (
        "linear type Handle { id: Int }\n"
        "fun open() -> Handle\n"
        "    return Handle { id: 1 }\n"
        "fun close(consume h: Handle) -> Unit\n"
        "    return ()\n"
    )

    def _errs(self, body: str) -> list[str]:
        return [e for e in errors_of(body) if "never used" not in e]

    def test_launder_into_tuple_rejected(self):
        errs = self._errs(
            self._LIN
            + "fun main(_s: Stdio)\n"
            "    let h = open()\n"
            "    let t = (h, 1)\n"
        )
        self.assertTrue(
            any("dropped without being consumed" in e for e in errs), errs,
        )

    def test_launder_into_list_rejected(self):
        errs = self._errs(
            self._LIN
            + "fun main(_s: Stdio)\n"
            "    let h = open()\n"
            "    let xs = [h]\n"
        )
        self.assertTrue(
            any("dropped without being consumed" in e for e in errs), errs,
        )

    def test_launder_into_struct_field_rejected(self):
        errs = self._errs(
            "type Box { h: Handle }\n"
            + self._LIN
            + "fun main(_s: Stdio)\n"
            "    let h = open()\n"
            "    let b = Box { h: h }\n"
        )
        self.assertTrue(
            any("dropped without being consumed" in e for e in errs), errs,
        )

    def test_launder_into_returned_tuple_rejected(self):
        # A tuple carrying a linear value is now barred by the container-of-
        # linear invariant: the `-> (Handle, Int)` return type is rejected at
        # the declaration entry-gate and the `(h, 1)` expression at the use-
        # gate, both with the container message.
        errs = self._errs(
            self._LIN
            + "fun stash() -> (Handle, Int)\n"
            "    let h = open()\n"
            "    return (h, 1)\n"
            "fun main(_s: Stdio)\n"
            "    let t = stash()\n"
        )
        self.assertTrue(
            any("linear/typestate value cannot" in e for e in errs), errs,
        )


class TestBorrowedLinearNoEscape(unittest.TestCase):
    """Audit B-F1: a non-``consume`` (borrowed) linear / typestate
    parameter is owned by the CALLER, so the callee may read it and
    forward it to other borrow positions, but must not consume it,
    return it, alias-then-consume it, ``become`` it, call a ``consume
    self`` method on it, or pack it into an aggregate. Each of those
    transfers or duplicates ownership the caller still holds, so it would
    double-consume / double-free. Before this fix a borrowed param was
    untracked and every one of these slipped past with no diagnostic.

    The over-reject guard is as load-bearing as the rejects: a borrowed
    param must still be readable and forwardable, a ``consume`` param
    stays a terminal owner, and a factory / passthrough still compiles."""

    _LIN = (
        "linear type Handle { id: Int }\n"
        "fun open() -> Handle\n"
        "    return Handle { id: 1 }\n"
        "fun close(consume h: Handle) -> Unit\n"
        "    return ()\n"
        "fun peek(h: Handle) -> Int\n"
        "    return h.id\n"
    )
    _LINS = (
        "linear type Handle { id: Int }\n"
        "impl Handle\n"
        "    fun close(consume self) -> Unit\n"
        "        return ()\n"
        "    fun id_of(self) -> Int\n"
        "        return self.id\n"
        "fun open() -> Handle\n"
        "    return Handle { id: 1 }\n"
    )
    _TS = (
        "typestate Claim\n    Draft\n    Approved\n"
        "fun mk() -> Claim[Draft]\n"
        "    return Claim[Draft] {}\n"
        "fun settle(consume c: Claim[Approved]) -> Unit\n"
        "    return ()\n"
    )

    def _errs(self, body: str) -> list[str]:
        return [e for e in errors_of(body) if "never used" not in e]

    _BORROWED_MSG = "borrowed linear/typestate value"

    # ---- must REJECT ----

    def test_return_borrowed_rejected(self):
        errs = self._errs(
            self._LIN
            + "fun bad(h: Handle) -> Handle\n"
            "    return h\n"
        )
        self.assertTrue(
            any(self._BORROWED_MSG in e for e in errs), errs,
        )

    def test_consume_borrowed_in_callee_rejected(self):
        errs = self._errs(
            self._LIN
            + "fun bad(h: Handle)\n"
            "    close(h)\n"
        )
        self.assertTrue(
            any(self._BORROWED_MSG in e for e in errs), errs,
        )

    def test_alias_then_consume_borrowed_rejected(self):
        errs = self._errs(
            self._LIN
            + "fun bad(h: Handle)\n"
            "    let b = h\n"
            "    close(b)\n"
        )
        self.assertTrue(
            any(self._BORROWED_MSG in e for e in errs), errs,
        )

    def test_become_borrowed_typestate_rejected(self):
        errs = self._errs(
            self._TS
            + "fun bad(c: Claim[Draft]) -> Claim[Approved]\n"
            "    return become(c, Approved)\n"
        )
        self.assertTrue(
            any(self._BORROWED_MSG in e for e in errs), errs,
        )

    def test_consume_self_on_borrowed_receiver_rejected(self):
        errs = self._errs(
            self._LINS
            + "fun bad(h: Handle)\n"
            "    h.close()\n"
        )
        self.assertTrue(
            any(self._BORROWED_MSG in e for e in errs), errs,
        )

    def test_pack_borrowed_into_struct_rejected(self):
        errs = self._errs(
            "type Box { h: Handle }\n"
            + self._LIN
            + "fun bad(h: Handle)\n"
            "    let b = Box { h: h }\n"
        )
        self.assertTrue(
            any("into an aggregate" in e for e in errs), errs,
        )

    def test_pack_borrowed_into_list_rejected(self):
        errs = self._errs(
            self._LIN
            + "fun bad(h: Handle)\n"
            "    let xs = [h]\n"
        )
        self.assertTrue(
            any("into an aggregate" in e for e in errs), errs,
        )

    def test_pack_borrowed_into_tuple_rejected(self):
        errs = self._errs(
            self._LIN
            + "fun bad(h: Handle) -> (Handle, Int)\n"
            "    return (h, 1)\n"
        )
        self.assertTrue(
            any("into an aggregate" in e for e in errs), errs,
        )

    # ---- must COMPILE (over-reject guard) ----

    def test_borrow_and_read_compiles(self):
        r = check(
            self._LIN
            + "fun get_id(h: Handle) -> Int\n"
            "    return h.id\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_borrow_and_forward_compiles(self):
        r = check(
            self._LIN
            + "fun use2(h: Handle) -> Int\n"
            "    return peek(h)\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_alias_then_forward_no_consume_compiles(self):
        r = check(
            self._LIN
            + "fun use3(h: Handle) -> Int\n"
            "    let b = h\n"
            "    return peek(b)\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_non_consume_self_reads_field_compiles(self):
        r = check(
            self._LINS
            + "fun run(h: Handle) -> Int\n"
            "    return h.id_of()\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_factory_produced_value_returns_compiles(self):
        r = check(
            self._LIN
            + "fun make() -> Handle\n"
            "    let h = open()\n"
            "    return h\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_consume_param_passthrough_compiles(self):
        r = check(
            self._LIN
            + "fun passthrough(consume h: Handle) -> Handle\n"
            "    return h\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_consume_self_become_wrapper_compiles(self):
        r = check(
            "typestate Claim\n    Draft\n    Approved\n"
            "impl Claim[Draft]\n"
            "    fun approve(consume self) -> Claim[Approved]\n"
            "        return become(self, Approved)\n"
            "fun mk() -> Claim[Draft]\n"
            "    return Claim[Draft] {}\n"
        )
        self.assertTrue(r.ok, r.errors)






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













class TestLinearIntoContainerReject(unittest.TestCase):
    """Linearity decision 4b: a linear / typestate value (or a struct that
    OWNS one) cannot enter a container.

    A single-owner value packed into a List / Map / Set escapes name
    threading: a later read hands out an unbounded number of aliases to a
    value that must be consumed exactly once, a double-free / leak. Two
    seams enforce it:

    - the MUTATOR seam (``List.push`` / ``Set.add`` / ``Map.set``), which
      covers an owned, borrowed, fresh, or carrier value in any element /
      value / key position;
    - the LIST-LITERAL seam, which covers a fresh linear packed straight
      into ``[...]`` (it never passes through a mutator).

    Both facets (``linear type`` and ``typestate``) are exercised. This is
    analyzer-only and reject-only; nothing is stored, so no drain / codegen
    changes. The struct-literal factory (``return Session { conn: open()
    }``) stays legitimate and is NOT touched.

    The list-literal facet is now sealed by the container-of-linear use-gate
    (``_container_carries_linear`` in ``_check_expr``) rather than a special-
    case list rule, so its diagnostic is the shared container message; the
    mutator seam keeps its own precise insertion-site message. Both share the
    ``a linear/typestate value cannot ...`` prefix asserted below."""

    _LIN = (
        "linear type Conn { id: Int }\n"
        "fun open() -> Conn\n"
        "    return Conn { id: 1 }\n"
        "fun close(consume c: Conn) -> Unit\n"
        "    return ()\n"
    )
    # Non-linear struct that OWNS a linear field (a carrier).
    _CARRIER = _LIN + (
        "type S { conn: Conn, tag: Int }\n"
        "fun mks() -> S\n"
        "    return S { conn: open(), tag: 0 }\n"
    )
    # Typestate facet plus a non-linear carrier of a typestate field.
    _TS = (
        "typestate Claim\n    Draft\n    Settled\n"
        "fun mk() -> Claim[Draft]\n"
        "    return Claim[Draft] {}\n"
        "fun archive(consume c: Claim[Settled]) -> Unit\n"
        "    return ()\n"
        "type Record { claim: Claim[Settled], tag: Int }\n"
        "fun mkrec() -> Record\n"
        "    return Record { claim: become(mk(), Settled), tag: 0 }\n"
    )
    _MSG = "linear/typestate value cannot"

    def _rejects(self, body: str) -> None:
        errs = errors_of(body)
        self.assertTrue(
            any(self._MSG in e for e in errs), errs,
        )

    def _compiles(self, body: str) -> None:
        errs = [e for e in errors_of(body) if "never used" not in e]
        self.assertEqual(errs, [], errs)

    # ---- mutator seam, linear facet, every provenance ----

    def test_push_owned_linear_rejected(self):
        self._rejects(
            self._LIN + "fun main(_s: Stdio)\n    let c = open()\n"
            "    var xs: List<Conn> = []\n    xs.push(c)\n"
        )

    def test_push_borrowed_param_rejected(self):
        self._rejects(
            self._LIN + "fun stash(c: Conn, _s: Stdio)\n"
            "    var xs: List<Conn> = []\n    xs.push(c)\n"
        )

    def test_push_fresh_linear_rejected(self):
        self._rejects(
            self._LIN + "fun main(_s: Stdio)\n"
            "    var xs: List<Conn> = []\n    xs.push(open())\n"
        )

    def test_push_linear_carrier_struct_rejected(self):
        self._rejects(
            self._CARRIER + "fun main(_s: Stdio)\n    let sess = mks()\n"
            "    var xs: List<S> = []\n    xs.push(sess)\n"
        )

    def test_add_linear_into_set_rejected(self):
        self._rejects(
            self._LIN + "fun main(_s: Stdio)\n    let c = open()\n"
            "    var st = new_set()\n    st.add(c)\n"
        )

    def test_set_linear_value_into_map_rejected(self):
        self._rejects(
            self._LIN + "fun main(_s: Stdio)\n    let c = open()\n"
            "    var m = new_map()\n    m.set(\"k\", c)\n"
        )

    def test_set_linear_key_into_map_rejected(self):
        self._rejects(
            self._LIN + "fun main(_s: Stdio)\n    let c = open()\n"
            "    var m = new_map()\n    m.set(c, \"v\")\n"
        )

    # ---- list-literal seam (Part B, fresh path) ----

    def test_list_literal_fresh_linear_unannotated_rejected(self):
        self._rejects(
            self._LIN + "fun main(_s: Stdio)\n    let xs = [open()]\n"
        )

    def test_list_literal_fresh_linear_annotated_rejected(self):
        self._rejects(
            self._LIN + "fun main(_s: Stdio)\n"
            "    let xs: List<Conn> = [open()]\n"
        )

    # ---- typestate facet ----

    def test_push_typestate_value_rejected(self):
        self._rejects(
            self._TS + "fun main(_s: Stdio)\n"
            "    var xs: List<Claim[Settled]> = []\n"
            "    xs.push(become(mk(), Settled))\n"
        )

    def test_push_typestate_carrier_struct_rejected(self):
        self._rejects(
            self._TS + "fun main(_s: Stdio)\n    let rec = mkrec()\n"
            "    var xs: List<Record> = []\n    xs.push(rec)\n"
        )

    def test_list_literal_typestate_rejected(self):
        self._rejects(
            self._TS + "fun main(_s: Stdio)\n"
            "    let xs: List<Claim[Settled]> = [become(mk(), Settled)]\n"
        )

    # ---- must-compile: plain data + the legitimate factory ----

    def test_plain_data_container_ops_compile(self):
        self._compiles(
            "type LedgerEvent { amt: Int }\n"
            "fun main(_s: Stdio)\n"
            "    var xs: List<LedgerEvent> = []\n"
            "    xs.push(LedgerEvent { amt: 1 })\n"
            "    let n = xs.length()\n"
            "    let e = xs.get(0)\n"
            "    var m = new_map()\n"
            "    m.set(\"k\", \"s\")\n"
            "    let has = m.contains_key(\"k\")\n"
            "    var st = new_set()\n"
            "    st.add(3)\n"
            "    let flags = [LedgerEvent { amt: 2 }]\n"
        )

    def test_struct_literal_linear_factory_compiles(self):
        # The struct-literal factory is the legitimate way to build a
        # linear-carrying value; it must stay compiling (list literals only
        # are strengthened, never struct literals).
        self._compiles(
            self._LIN + "type Session { conn: Conn }\n"
            "fun open_session() -> Session\n"
            "    return Session { conn: open() }\n"
        )


class TestContainerOfLinearSeal(unittest.TestCase):
    """Container-of-linear seal (7th commit): a List / Map / Set / tuple type
    may not carry a linear/typestate value (nor a linear-carrying struct) at
    any nesting depth, mirroring the capability discipline's four mechanisms
    with one predicate (``_container_carries_linear``). A BARE linear value at
    top level stays legal (single-owner values flow by name, including through
    generics); only the below-a-container form is barred.

    Every route is rejected on both facets (``linear type`` + ``typestate``):
    the tuple literal (the corrected carve-out), nested containers, a producing
    higher-order ``map`` / ``flat_map``, a generic helper instantiated linear,
    and a direct signature (param / return / field / const / variant payload).
    The over-reject line is load-bearing: the generic non-linear-``T`` control,
    a bare linear through a generic, and every plain-data container must still
    compile."""

    _LIN = (
        "linear type Conn { id: Int }\n"
        "fun mkc() -> Conn\n"
        "    return Conn { id: 1 }\n"
        "fun close(consume c: Conn) -> Unit\n"
        "    return ()\n"
    )
    _CARRIER = _LIN + (
        "type Session { conn: Conn, tag: Int }\n"
        "fun mks() -> Session\n"
        "    return Session { conn: mkc(), tag: 0 }\n"
    )
    _TS = (
        "typestate Claim\n    Draft\n    Settled\n"
        "fun mk() -> Claim[Draft]\n"
        "    return Claim[Draft] {}\n"
        "fun archive(consume c: Claim[Settled]) -> Unit\n"
        "    return ()\n"
    )
    _MSG = "linear/typestate value cannot"

    def _rejects(self, body: str) -> None:
        errs = errors_of(body)
        self.assertTrue(any(self._MSG in e for e in errs), errs)

    def _compiles(self, body: str) -> None:
        errs = [e for e in errors_of(body) if "never used" not in e]
        self.assertEqual(errs, [], errs)

    # ---- tuple literal (the corrected carve-out) ----

    def test_tuple_literal_linear_rejected(self):
        self._rejects(
            self._LIN + "fun main(_s: Stdio)\n    let c = mkc()\n"
            "    let t = (c, 1)\n"
        )

    def test_tuple_literal_typestate_rejected(self):
        self._rejects(
            self._TS + "fun main(_s: Stdio)\n"
            "    let t = (become(mk(), Settled), 1)\n"
        )

    def test_tuple_literal_fresh_linear_rejected(self):
        self._rejects(
            self._LIN + "fun main(_s: Stdio)\n    let t = (mkc(), 1)\n"
        )

    # ---- nested containers ----

    def test_nested_list_of_list_linear_rejected(self):
        self._rejects(
            self._LIN + "fun main(_s: Stdio)\n"
            "    let xs: List<List<Conn>> = [[mkc()]]\n"
        )

    def test_list_of_tuple_linear_rejected(self):
        self._rejects(
            self._LIN + "fun main(_s: Stdio)\n"
            "    let xs: List<(Conn, Int)> = [(mkc(), 1)]\n"
        )

    # ---- producing higher-order map / flat_map ----

    def test_map_producer_linear_rejected(self):
        self._rejects(
            self._LIN + "fun main(_s: Stdio)\n"
            "    let xs = [1, 2, 3].map(fun(x) => mkc())\n"
        )

    def test_flat_map_producer_linear_rejected(self):
        self._rejects(
            self._LIN + "fun main(_s: Stdio)\n"
            "    let xs = [1, 2, 3].flat_map(fun(x) => [mkc()])\n"
        )

    # ---- generic helper instantiated linear ----

    _STASH = (
        "fun stash<T>(xs: List<T>, v: T) -> List<T>\n"
        "    xs.push(v)\n"
        "    return xs\n"
    )

    def test_generic_helper_instantiated_linear_rejected(self):
        self._rejects(
            self._LIN + self._STASH + "fun main(_s: Stdio)\n"
            "    var xs: List<Conn> = []\n"
            "    let ys = stash(xs, mkc())\n"
        )

    def test_generic_helper_instantiated_typestate_rejected(self):
        self._rejects(
            self._TS + self._STASH + "fun main(_s: Stdio)\n"
            "    var xs: List<Claim[Settled]> = []\n"
            "    let ys = stash(xs, become(mk(), Settled))\n"
        )

    # ---- direct signatures (entry-gates) ----

    def test_param_list_of_linear_rejected(self):
        self._rejects(
            self._LIN + "fun f(xs: List<Conn>) -> Unit\n    return ()\n"
        )

    def test_param_map_value_linear_rejected(self):
        self._rejects(
            self._LIN + "fun f(m: Map<String, Conn>) -> Unit\n    return ()\n"
        )

    def test_param_map_key_linear_rejected(self):
        self._rejects(
            self._LIN + "fun f(m: Map<Conn, String>) -> Unit\n    return ()\n"
        )

    def test_return_list_of_linear_rejected(self):
        self._rejects(
            self._LIN + "fun f() -> List<Conn>\n    return []\n"
        )

    def test_return_tuple_of_linear_rejected(self):
        self._rejects(
            self._LIN + "fun f(consume c: Conn) -> (Conn, Int)\n"
            "    return (c, 1)\n"
        )

    def test_struct_field_container_of_linear_rejected(self):
        self._rejects(
            self._LIN + "type Box { items: List<Conn> }\n"
        )

    def test_struct_field_container_of_carrier_rejected(self):
        self._rejects(
            self._CARRIER + "type Fleet { sessions: List<Session> }\n"
        )

    def test_typestate_field_container_of_linear_rejected(self):
        self._rejects(
            self._LIN + "typestate Pool { conns: List<Conn> }\n"
            "    Empty\n    Full\n"
        )

    def test_variant_payload_container_of_linear_rejected(self):
        self._rejects(
            self._LIN + "type Wrap =\n    Present(List<Conn>)\n    Nothing\n"
        )

    def test_typestate_param_list_rejected(self):
        self._rejects(
            self._TS + "fun f(xs: List<Claim[Settled]>) -> Unit\n"
            "    return ()\n"
        )

    # ---- over-reject line: must COMPILE ----

    def test_generic_helper_non_linear_t_compiles(self):
        self._compiles(
            self._STASH + "fun main(_s: Stdio)\n"
            "    var nums: List<Int> = []\n"
            "    let ys = stash(nums, 3)\n"
        )

    def test_bare_linear_through_generic_compiles(self):
        # A bare linear value threaded through a generic (id<T>(v: T) -> T at
        # T = Conn) is legal: single-owner values flow by name, including
        # through generics; only a container-of-linear substitution rejects.
        self._compiles(
            self._LIN + "fun id2<T>(consume v: T) -> T\n    return v\n"
            "fun main(_s: Stdio)\n    let c = id2(mkc())\n    close(c)\n"
        )

    def test_plain_data_containers_everywhere_compile(self):
        self._compiles(
            "type Money { cents: Int }\n"
            "fun sink(xs: List<Money>, m: Map<String, Money>) -> List<Money>\n"
            "    return xs\n"
            "fun main(_s: Stdio)\n"
            "    var xs: List<Money> = []\n"
            "    xs.push(Money { cents: 1 })\n"
            "    let doubled = [1, 2, 3].map(fun(x) => x + 1)\n"
            "    var m = new_map()\n"
            "    m.set(\"k\", Money { cents: 2 })\n"
            "    let ys = sink(xs, m)\n"
        )

    def test_bare_linear_signatures_compile(self):
        # The bare-linear flows: a consume param, a factory return, a linear
        # field of a carrier struct, and the struct-literal factory.
        self._compiles(
            self._CARRIER + "fun take(consume c: Conn) -> Conn\n"
            "    return c\n"
            "fun main(_s: Stdio)\n    let s = mks()\n"
            "    close(s.conn)\n"
        )




if __name__ == "__main__":
    unittest.main()
