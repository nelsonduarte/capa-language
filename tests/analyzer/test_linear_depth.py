"""Analyzer tests: the linear-obligation carrier walk is cycle-detecting,
not depth-capped.

The carrier must-consume predicate and its leaf enumerator used to share a
fail-open depth cap of 8 (``_MAX_DEPTH`` / ``_LINEAR_PATH_MAX_DEPTH``): a
carrier whose only linear/typestate leaf sat deeper than 8 field-hops was
judged a non-carrier, never armed, and its drop / pack silently accepted, and
the SBOM under-reported the obligation. The cap is replaced by cycle detection
(the predicate a global-``seen`` reachability, the enumerator a path-scoped DFS
with a fail-closed total-work budget), so a leaf at ANY depth is caught while a
by-value struct cycle (``type Node { next: Node }``, which the analyzer does
not reject independently) still terminates.

Each RED test below puts its linear leaf at dot-depth 9+ (past the old cap) so
it FAILS on the pre-fix analyzer and PASSES after. The diamond, termination,
budget, and predicate/enumerator-agreement cases are validated by mutation
(neutralize the fix and the right test goes red), documented per class.

OUT OF SCOPE (unchanged here): the pre-existing compiler-wide diamond
wall-clock DoS via ``capa/manifest/_reachability.py`` ``_contains_fun_via_structs``
and ``capa/analyzer/_declarations.py`` ``_ty_contains_fun_deep`` (path-scoped
fun-detection walks that blow up on a crafted deep diamond); this item closes
the LINEAR obligation walk only. Also out: Index target/receiver, the
borrow-read residual, E3 generic-return aliasing.
"""

import time
import unittest
from unittest import mock

from capa import Lexer, Parser, analyze
from capa._owned_obligation import linear_leaf_paths
from tests.analyzer._helpers import check, errors_of


_CONN = (
    "linear type Conn { id: Int }\n"
    "fun open() -> Conn\n"
    "    return Conn { id: 1 }\n"
    "fun close(consume c: Conn) -> Unit\n"
    "    return ()\n"
)
_SOCK = (
    "typestate Sock\n    Created\n    Closed\n"
    "fun mksock() -> Sock[Created]\n"
    "    return Sock[Created] {}\n"
)


def _chain_types(n: int, leaf_field: str, leaf_type: str) -> str:
    """L0.f -> L1.f -> ... -> L(n-1).f -> Ln.<leaf_field>: <leaf_type>.
    The leaf sits at field-hop n+1 from an L0 value, so n>=9 clears the old
    depth-8 cap."""
    lines = [f"type L{i} {{ f: L{i+1} }}" for i in range(n)]
    lines.append(f"type L{n} {{ {leaf_field}: {leaf_type} }}")
    return "\n".join(lines) + "\n"


def _chain_literal(n: int, leaf_field: str, leaf_expr: str) -> str:
    inner = f"L{n} {{ {leaf_field}: {leaf_expr} }}"
    for i in range(n - 1, -1, -1):
        inner = f"L{i} {{ f: {inner} }}"
    return inner


class TestDeepCarrierDrop(unittest.TestCase):
    """A carrier whose linear/typestate leaf is deeper than the old cap is
    still armed and its unconsumed drop / pack rejected (fail-open closed)."""

    def test_deep_linear_drop_rejected(self):
        # Leaf L10.h: Conn at field-hop 11 (old cap 8 -> pre-fix accepted).
        src = (
            _CONN
            + _chain_types(10, "h", "Conn")
            + "fun leak() -> Unit\n"
            + f"    let x = {_chain_literal(10, 'h', 'open()')}\n"
            + "    return ()\n"
        )
        errs = errors_of(src)
        self.assertTrue(
            any("linear value 'x' is dropped without being consumed" in e
                for e in errs),
            errs,
        )

    def test_deep_typestate_drop_rejected(self):
        # Typestate leaf at field-hop 11.
        src = (
            _SOCK
            + _chain_types(10, "h", "Sock[Created]")
            + "fun leak() -> Unit\n"
            + f"    let x = {_chain_literal(10, 'h', 'mksock()')}\n"
            + "    return ()\n"
        )
        errs = errors_of(src)
        self.assertTrue(
            any("linear value 'x' is dropped without being consumed" in e
                for e in errs),
            errs,
        )

    def test_deep_pack_into_outer_rejected(self):
        # The deep carrier is packed into an OUTER struct that is then
        # dropped; the outer must leak (pre-fix accepted).
        src = (
            _CONN
            + _chain_types(10, "h", "Conn")
            + "type Outer { inner: L0 }\n"
            + "fun leak() -> Unit\n"
            + f"    let o = Outer {{ inner: {_chain_literal(10, 'h', 'open()')} }}\n"
            + "    return ()\n"
        )
        errs = errors_of(src)
        self.assertTrue(
            any("linear value 'o' is dropped without being consumed" in e
                for e in errs),
            errs,
        )

    def test_deep_carrier_consumed_in_full_accepted(self):
        # Consuming the single deep leaf in full satisfies the obligation:
        # no leak. Mutation-guard: a predicate-only fix (arm the carrier but
        # leave the enumerator capped, so it yields no leaf) would report a
        # spurious whole-value leak here.
        deep_path = "x." + ".".join(["f"] * 10) + ".h"
        src = (
            _CONN
            + _chain_types(10, "h", "Conn")
            + "fun ok() -> Unit\n"
            + f"    let x = {_chain_literal(10, 'h', 'open()')}\n"
            + f"    close({deep_path})\n"
            + "    return ()\n"
        )
        self.assertEqual(errors_of(src), [])

    def test_shallow_carrier_drop_still_rejected(self):
        # Legit-forms-stay: a shallow carrier (leaf within the old cap) was
        # always caught and still is, so the fold did not regress it.
        src = (
            _CONN
            + _chain_types(2, "h", "Conn")
            + "fun leak() -> Unit\n"
            + f"    let x = {_chain_literal(2, 'h', 'open()')}\n"
            + "    return ()\n"
        )
        errs = errors_of(src)
        self.assertTrue(
            any("linear value 'x' is dropped without being consumed" in e
                for e in errs),
            errs,
        )


class TestDiamondPathScoped(unittest.TestCase):
    """The leaf enumerator is PATH-SCOPED, not globally memoized: a diamond
    ``P { a: S, b: S }`` owns BOTH ``p.a``'s and ``p.b``'s leaf. Mutation:
    globally memoizing the enumerator (dedup by struct name) drops the second
    branch, and ``test_diamond_consume_one_branch_reports_other`` goes red
    (nothing reported after ``p.a.h`` is consumed)."""

    _SRC = (
        _CONN
        + "type S { h: Conn }\n"
        + "type P { a: S, b: S }\n"
    )

    def _leak(self, *consume: str) -> list[str]:
        body = "".join(f"    close(p.{c}.h)\n" for c in consume)
        src = (
            self._SRC
            + "fun leak() -> Unit\n"
            + "    let p = P { a: S { h: open() }, b: S { h: open() } }\n"
            + body
            + "    return ()\n"
        )
        return errors_of(src)

    def test_diamond_consume_one_branch_reports_other(self):
        errs = self._leak("a")
        self.assertTrue(
            any("linear field 'p.b.h' is dropped without being consumed" in e
                for e in errs),
            errs,
        )

    def test_diamond_consume_both_accepted(self):
        self.assertEqual(self._leak("a", "b"), [])

    def test_diamond_consume_none_reports_whole_value(self):
        errs = self._leak()
        self.assertTrue(
            any("linear value 'p' is dropped without being consumed" in e
                for e in errs),
            errs,
        )


class TestCarrierWalkTerminates(unittest.TestCase):
    """A by-value struct cycle is NOT rejected independently, so the carrier
    walk itself must terminate on one. The old depth cap did that fail-open;
    cycle detection does it soundly. Mutation: dropping the ``seen`` /
    ``visited`` guard makes the predicate loop forever and the enumerator
    recurse without bound. The generous wall-clock bound is a hang tripwire."""

    _BUDGET_S = 15.0

    def test_recursive_struct_terminates_and_reports(self):
        src = (
            _CONN
            + "type Node { next: Node, h: Conn }\n"
            + "fun mk() -> Node\n"
            + "    return Node { next: mk(), h: open() }\n"
            + "fun leak() -> Unit\n"
            + "    let x = mk()\n"
            + "    return ()\n"
        )
        t0 = time.time()
        errs = errors_of(src)
        elapsed = time.time() - t0
        self.assertLess(elapsed, self._BUDGET_S, "carrier walk did not terminate")
        self.assertTrue(
            any("linear value 'x' is dropped without being consumed" in e
                for e in errs),
            errs,
        )

    def test_noncarrier_cycle_analyzes_clean_and_terminates(self):
        # A by-value struct cycle with NO linear leaf is not a carrier and is
        # not rejected independently, so the PREDICATE's global-``seen`` guard
        # must terminate on it -- the fail-closed single-source guard walks
        # ``carries_linear`` over every declared struct. Mutation: dropping
        # the ``seen`` skip makes the predicate loop forever here.
        src = "type Node { next: Node }\nfun f() -> Unit\n    return ()\n"
        t0 = time.time()
        result = check(src)
        self.assertLess(
            time.time() - t0, self._BUDGET_S, "predicate did not terminate",
        )
        self.assertTrue(result.ok)

    def test_mutual_recursion_terminates_and_reports(self):
        # A{b:B}, B{a:A, h:Conn}: the Conn leaf is reachable only after the
        # A->B->A cycle, so a broken cycle guard never finds it (or loops).
        src = (
            _CONN
            + "type A { b: B }\n"
            + "type B { a: A, h: Conn }\n"
            + "fun mkA() -> A\n"
            + "    return A { b: mkB() }\n"
            + "fun mkB() -> B\n"
            + "    return B { a: mkA(), h: open() }\n"
            + "fun leak() -> Unit\n"
            + "    let y = mkA()\n"
            + "    return ()\n"
        )
        t0 = time.time()
        errs = errors_of(src)
        elapsed = time.time() - t0
        self.assertLess(elapsed, self._BUDGET_S, "carrier walk did not terminate")
        self.assertTrue(
            any("linear value 'y' is dropped without being consumed" in e
                for e in errs),
            errs,
        )


class TestEnumeratorBudget(unittest.TestCase):
    """The path-scoped enumerator is inherently exponential in the
    path-distinct leaf count, so it carries a fail-CLOSED total-work budget.
    Under budget it enumerates every diamond leaf; over budget it collapses to
    the single whole-value place (never the empty list, which would fail OPEN
    on the move/pack path), so a crafted exponential-diamond type is never
    silently accepted and never hangs. Direct unit test: an end-to-end drop
    would need an exponential-size literal to construct the value."""

    @staticmethod
    def _diamond_roots(k: int):
        d = {f"L{i}": [("a", f"L{i+1}"), ("b", f"L{i+1}")] for i in range(k)}
        d[f"L{k}"] = [("h", "Conn")]
        return d

    def test_under_budget_enumerates_every_diamond_leaf(self):
        # k=6 diamond: 2**6 = 64 path-distinct leaves, all enumerated (proves
        # path-scoped: a global memo would yield far fewer).
        leaves = linear_leaf_paths(
            "x", "L0", {"Conn"}, self._diamond_roots(6).get,
        )
        self.assertEqual(len(leaves), 64)
        self.assertEqual(len(set(leaves)), 64)

    def test_over_budget_fails_closed_to_whole_value(self):
        # k=16 diamond: 2**16 = 65536 leaves, far past the budget. Fails
        # CLOSED to [place] (obligation retained), fast, non-empty. Mutation:
        # neutralizing the budget check makes this return 65536 leaves (and
        # eat CPU / memory building them), so the len==1 assertion goes red.
        t0 = time.time()
        result = linear_leaf_paths(
            "x", "L0", {"Conn"}, self._diamond_roots(16).get,
        )
        elapsed = time.time() - t0
        self.assertEqual(result, ["x"])
        self.assertLess(elapsed, 5.0, "budgeted enumerator did not fail fast")


class TestContainerSiblingCap(unittest.TestCase):
    """``_reaches_linear`` (the container-of-linear reject) read the same
    removed cap and failed open at deep nesting. Its cap is deleted (the
    resolved-Ty tree is finite and cannot cycle), so a deep ``List<...<Conn>>``
    is rejected at any nesting (pre-fix accepted at >= ~10)."""

    @staticmethod
    def _nest(n: int) -> str:
        ty = "Conn"
        for _ in range(n):
            ty = f"List<{ty}>"
        return ty

    def test_deep_container_param_rejected(self):
        src = _CONN + f"fun f(xs: {self._nest(12)}) -> Unit\n    return ()\n"
        errs = errors_of(src)
        self.assertTrue(
            any("a linear/typestate value cannot appear in the type of "
                "parameter 'xs'" in e for e in errs),
            errs,
        )

    def test_shallow_container_param_still_rejected(self):
        # Legit-forms-stay: a shallow container-of-linear was always rejected.
        src = _CONN + f"fun f(xs: {self._nest(2)}) -> Unit\n    return ()\n"
        errs = errors_of(src)
        self.assertTrue(
            any("a linear/typestate value cannot appear in the type of "
                "parameter 'xs'" in e for e in errs),
            errs,
        )


class TestPredicateEnumeratorAgreementPin(unittest.TestCase):
    """The fail-closed guard pins that every carrier the predicate arms yields
    at least one enumerated leaf, so the now-distinct predicate (global memo)
    and enumerator (path-scoped) cannot drift. A bare linear value is exempt
    (it is a whole-value leaf with no linear SUB-field)."""

    def _analyze(self, src: str):
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        return analyze(module, source=src)

    def test_pin_holds_on_a_real_deep_carrier(self):
        # FP guard: a genuine deep carrier passes the pin (no false raise);
        # analysis completes cleanly.
        src = (
            _CONN
            + _chain_types(10, "h", "Conn")
            + "fun noop() -> Unit\n    return ()\n"
        )
        self.assertTrue(self._analyze(src).ok)

    def test_pin_fires_when_enumerator_drops_a_carrier_leaf(self):
        # Mutation: neutralize the enumerator to yield nothing for an armed
        # carrier. The guard's predicate-implies-enumerable pin must fire.
        src = (
            _CONN
            + "type Box { h: Conn }\n"
            + "fun noop() -> Unit\n    return ()\n"
        )
        with mock.patch(
            "capa._owned_obligation.linear_leaf_paths", return_value=[],
        ):
            with self.assertRaises(AssertionError):
                self._analyze(src)


if __name__ == "__main__":
    unittest.main()
