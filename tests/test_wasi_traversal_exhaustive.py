"""META-TEST: the shared ``--wasi`` statement traversal
(:func:`capa.ir._wasi_const_prop._all_stmts` and its own-frame sibling
:func:`_own_frame_stmts`) must descend into EVERY AST sub-scope that
carries sub-statements or sub-blocks. This test exists to CLOSE the
scope-omission class permanently: it fails automatically if a node that
holds sub-statements (a new one added in the future, or one forgotten
today) is not reached by the traversal, so no analysis built on these
helpers can silently skip a sub-scope again.

The scope-omission class is the recurring bug where the statement-level
traversal descended into some sub-scopes by ad-hoc enumeration (if / while
/ for, then lambda bodies) and kept forgetting the next one (most recently
the ``Block`` body of a ``match`` arm). Ad-hoc enumeration can always miss
a case; an exhaustive, introspection-pinned check cannot.

Two independent guards:

* INVENTORY (introspection): enumerate every AST node class and every
  field whose declared type references ``Block`` / ``Stmt`` / ``MatchArm``
  (i.e. carries sub-statements or sub-blocks). Assert the set equals the
  KNOWN-COVERED inventory. A new sub-statement-bearing node, or a new such
  field, changes the set and fails here until the traversal is taught about
  it AND this inventory is updated -- forcing an explicit decision rather
  than a silent omission.

* REACHABILITY (behavioural): parse real Capa source that places a UNIQUE
  marker binding in each kind of sub-scope (control-flow blocks, a match-arm
  block, a lambda body, and nested combinations), then assert ``_all_stmts``
  from the frame root yields the ``LetStmt`` for every marker. A sub-scope
  the traversal does not descend into drops its marker and fails here.
"""

from __future__ import annotations

import dataclasses
import unittest

from capa import Lexer, Parser
from capa import capa_ast as A
from capa.ir._wasi_const_prop import (
    _all_stmts, _own_frame_stmts, _child_blocks, _lambda_body_blocks,
)


# The KNOWN-COVERED inventory of ``(node class, field)`` pairs whose type
# references a sub-statement / sub-block container (``Block`` / ``Stmt`` /
# ``MatchArm``). Each entry is annotated with WHICH traversal step reaches
# the sub-scope it introduces. If introspection finds a pair NOT in this
# set, a node carrying sub-statements is unaccounted for and the traversal
# may silently skip it -- the test fails until it is handled and listed.
#
# frame-root  : the callable body ``_all_stmts`` / ``_own_frame_stmts`` are
#               called ON (``FunDecl.body`` / a ``LambdaExpr.body`` block).
# container    : ``Block.stmts`` is the sequence the traversal iterates.
# child-block  : reached by ``_child_blocks`` (same frame): if / while / for
#               branches AND, via ``_same_frame_expr_blocks``, match-arm
#               block bodies reachable from a statement's expressions.
# lambda-body  : reached by ``_lambda_body_blocks`` (crosses into the lambda
#               frame; only ``_all_stmts`` descends here).
_KNOWN_COVERED: dict[tuple[str, str], str] = {
    ("Block", "stmts"): "container",
    ("FunDecl", "body"): "frame-root",
    ("IfStmt", "then_block"): "child-block",
    ("IfStmt", "elif_arms"): "child-block",
    ("IfStmt", "else_block"): "child-block",
    ("WhileStmt", "body"): "child-block",
    ("ForStmt", "body"): "child-block",
    ("MatchExpr", "arms"): "child-block",       # match-arm Block bodies
    ("MatchArm", "body"): "child-block",        # the Block | Expr arm body
    ("LambdaExpr", "body"): "lambda-body",
}


def _raw_annotations(cls) -> dict:
    """Every declared field annotation (raw string / type) for ``cls``,
    walking the MRO so inherited fields are included. Raw ``__annotations__``
    is used (not ``get_type_hints``) because several AST bodies use
    ``TYPE_CHECKING`` forward-ref strings (``"Block | Expr"``) that resolve
    only under type checking; the raw string still names ``Block``, which is
    all the inventory needs."""
    out: dict = {}
    for c in reversed(cls.__mro__):
        out.update(getattr(c, "__annotations__", {}))
    return out


def _substatement_fields() -> set[tuple[str, str]]:
    """Introspect the whole AST: every ``(class name, field)`` whose declared
    type references a sub-statement / sub-block container. This is the
    ground-truth inventory of nodes the statement traversal must account
    for."""
    found: set[tuple[str, str]] = set()
    for name in dir(A):
        obj = getattr(A, name)
        if not (isinstance(obj, type) and dataclasses.is_dataclass(obj)):
            continue
        for fname, ann in _raw_annotations(obj).items():
            if fname == "pos":
                continue
            s = str(ann)
            if "Block" in s or "MatchArm" in s or "Stmt" in s:
                found.add((name, fname))
    return found


def _module(src: str) -> A.Module:
    return Parser(Lexer(src).lex(), source=src).parse_module()


def _fun(module: A.Module, name: str) -> A.FunDecl:
    for item in module.items:
        if isinstance(item, A.FunDecl) and item.name == name:
            return item
    raise AssertionError(f"no fun {name!r}")


def _let_names(stmts) -> set[str]:
    """The bound names of every ``let``/``var`` ``IdentPat`` statement in an
    iterable of statements -- the markers used by the reachability guard."""
    names: set[str] = set()
    for s in stmts:
        if isinstance(s, A.LetStmt) and isinstance(s.pattern, A.IdentPat):
            names.add(s.pattern.name)
        elif isinstance(s, A.VarStmt):
            names.add(s.name)
    return names


class TestTraversalInventoryIsExhaustive(unittest.TestCase):
    def test_inventory_matches_known_covered(self) -> None:
        """The introspected set of sub-statement-bearing AST fields must
        EQUAL the known-covered inventory. A mismatch means a node carrying
        sub-statements is either unhandled by the traversal (missing from
        ``_KNOWN_COVERED`` -> the scope-omission bug re-appears) or the
        inventory is stale (a field was removed). Either way an explicit
        update is required; the traversal can never silently skip a new
        sub-scope."""
        found = _substatement_fields()
        known = set(_KNOWN_COVERED)
        missing = found - known
        stale = known - found
        msg = []
        if missing:
            msg.append(
                "AST nodes with sub-statements NOT in the known-covered "
                "inventory (the traversal may silently skip them -- teach "
                f"_child_blocks / _lambda_body_blocks about them): {sorted(missing)}"
            )
        if stale:
            msg.append(
                "known-covered entries no longer present in the AST "
                f"(inventory is stale, remove them): {sorted(stale)}"
            )
        if msg:
            self.fail("\n".join(msg))


class TestTraversalReachesEverySubScope(unittest.TestCase):
    """Behavioural proof: a unique marker binding in each sub-scope is
    reached by ``_all_stmts`` from the frame root. Each marker is a distinct
    ``let`` name; the traversal must yield the ``LetStmt`` for all of them."""

    def _all_names(self, src: str, fun: str = "main") -> set[str]:
        module = _module(src)
        return _let_names(_all_stmts(_fun(module, fun).body))

    def test_control_flow_blocks_reached(self) -> None:
        src = """
fun main(cond: Bool, xs: List<Int>)
    let m_top = 0
    if cond
        let m_then = 0
    else
        let m_else = 0
    while cond
        let m_while = 0
    for x in xs
        let m_for = 0
"""
        names = self._all_names(src)
        for marker in ("m_top", "m_then", "m_else", "m_while", "m_for"):
            self.assertIn(marker, names, f"{marker} not reached by _all_stmts")

    def test_elif_block_reached(self) -> None:
        src = """
fun main(a: Bool, b: Bool)
    if a
        let m_then = 0
    elif b
        let m_elif = 0
"""
        self.assertIn("m_elif", self._all_names(src))

    def test_match_arm_block_reached(self) -> None:
        """The regression this change closes: a ``let`` inside a multi-line
        ``match`` arm's ``Block`` body must be reached."""
        src = """
fun main(n: Int)
    match n
        _ ->
            let m_arm = 0
"""
        self.assertIn("m_arm", self._all_names(src))

    def test_lambda_body_block_reached(self) -> None:
        src = """
fun main()
    let f = fun (x: Int) -> Int =>
        let m_lambda = 0
        return x
    let _ = f(0)
"""
        self.assertIn("m_lambda", self._all_names(src))

    def test_match_arm_block_inside_lambda_reached(self) -> None:
        """A match-arm block nested inside a lambda body -- the two descents
        (lambda-body then match-arm) must compose."""
        src = """
fun main(n: Int)
    let f = fun (y: Int) -> Int =>
        match y
            _ ->
                let m_arm_in_lambda = 0
        return y
    let _ = f(0)
"""
        self.assertIn("m_arm_in_lambda", self._all_names(src))

    def test_lambda_inside_match_arm_block_reached(self) -> None:
        """A lambda body nested inside a match-arm block -- the reverse
        composition."""
        src = """
fun main(n: Int)
    match n
        _ ->
            let g = fun (z: Int) -> Int =>
                let m_lambda_in_arm = 0
                return z
            let _ = g(0)
"""
        self.assertIn("m_lambda_in_arm", self._all_names(src))

    def test_deeply_nested_control_flow_in_match_arm(self) -> None:
        """An ``if`` block inside a match-arm block: control-flow descent
        composes with match-arm descent."""
        src = """
fun main(n: Int, cond: Bool)
    match n
        _ ->
            if cond
                let m_if_in_arm = 0
"""
        self.assertIn("m_if_in_arm", self._all_names(src))


class TestOwnFrameTraversalScope(unittest.TestCase):
    """``_own_frame_stmts`` must descend into SAME-FRAME sub-scopes (control
    flow AND match-arm blocks) but NOT cross a lambda boundary."""

    def _own_names(self, src: str, fun: str = "main") -> set[str]:
        module = _module(src)
        return _let_names(_own_frame_stmts(_fun(module, fun).body))

    def test_match_arm_block_is_same_frame(self) -> None:
        """A binding in a match-arm block belongs to the enclosing frame, so
        the own-frame traversal reaches it (a ``return`` there is this
        callable's return, not a lambda's)."""
        src = """
fun main(n: Int)
    match n
        _ ->
            let m_arm = 0
"""
        self.assertIn("m_arm", self._own_names(src))

    def test_lambda_body_is_not_own_frame(self) -> None:
        """A binding inside a lambda body belongs to the LAMBDA's frame, so
        the own-frame traversal must NOT reach it (else a nested lambda's
        ``return`` would be mis-attributed to the enclosing callable)."""
        src = """
fun main()
    let f = fun (x: Int) -> Int =>
        let m_lambda = 0
        return x
    let _ = f(0)
"""
        self.assertNotIn("m_lambda", self._own_names(src))

    def test_match_arm_inside_lambda_is_not_own_frame(self) -> None:
        """A match-arm block that sits INSIDE a lambda body is the lambda's
        frame, not the enclosing callable's, so own-frame must not reach it.
        (The arm block is same-frame relative to the LAMBDA, but crossing
        into the lambda is what own-frame refuses.)"""
        src = """
fun main(n: Int)
    let f = fun (y: Int) -> Int =>
        match y
            _ ->
                let m_arm_in_lambda = 0
        return y
    let _ = f(0)
"""
        self.assertNotIn("m_arm_in_lambda", self._own_names(src))


class TestChildBlockHelpersDoNotCrossLambda(unittest.TestCase):
    """``_child_blocks`` collects same-frame sub-blocks (incl. match-arm
    blocks) but stops at a lambda boundary; ``_lambda_body_blocks`` collects
    exactly the lambda-body blocks. Together they partition the sub-scopes."""

    def test_child_blocks_finds_match_arm_but_not_lambda(self) -> None:
        src = """
fun main(n: Int)
    match n
        _ ->
            let m_arm = 0
    let f = fun (x: Int) -> Int =>
        let m_lambda = 0
        return x
    let _ = f(0)
"""
        body = _fun(_module(src), "main").body
        child_names: set[str] = set()
        for stmt in body.stmts:
            for blk in _child_blocks(stmt):
                child_names |= _let_names(_all_stmts(blk))
        self.assertIn("m_arm", child_names)
        self.assertNotIn("m_lambda", child_names)

    def test_lambda_body_blocks_finds_lambda(self) -> None:
        src = """
fun main()
    let f = fun (x: Int) -> Int =>
        let m_lambda = 0
        return x
    let _ = f(0)
"""
        body = _fun(_module(src), "main").body
        lam_names: set[str] = set()
        for stmt in body.stmts:
            for blk in _lambda_body_blocks(stmt):
                lam_names |= _let_names(_all_stmts(blk))
        self.assertIn("m_lambda", lam_names)


if __name__ == "__main__":
    unittest.main()
