"""Totality of the IFC label function over range and typestate nodes.

The confidentiality-label dispatch ``_compute_label`` (roadmap S2) had no
case for a RANGE expression (``a..b``) nor for the typestate transition
BECOME (``become(v, State)``); both fell through to a terminal PUBLIC
default. A secret routed through ``0..secret`` and read back via
``.length()`` or a loop over the range was therefore laundered to PUBLIC
and reached a public sink with no diagnostic -- a noninterference
violation accepted even under ``@strict_ifc``.

The fix gives each node a real rule (a range is the JOIN of its endpoint
labels; a become carries the label of the value it re-types) and then
makes the label function TOTAL: an expression node with no rule raises a
compiler-internal error rather than defaulting to PUBLIC, so a future
unhandled node can never again silently launder a secret.

These tests are fail-first: every range case below compiled CLEAN before
the fix (no warning, no strict error) and must now warn by default and
hard-error under ``@strict_ifc``.
"""

import unittest

from capa import Lexer, Parser, analyze
from capa import capa_ast as A
from capa import _labels as L
from capa.analyzer import Analyzer
from capa.tokens import Pos


def _analyze(src: str):
    return analyze(Parser(Lexer(src).lex(), source=src).parse_module(), source=src)


def _strict(src: str):
    return _analyze("@strict_ifc()\n" + src)


def _sink_warnings(r):
    return [w for w in r.warnings if "a @secret value reaches" in w.message]


def _sink_errors(r):
    return [e for e in r.errors if "a @secret value reaches" in e.message]


_P = Pos(line=1, col=1, offset=0)


class TestRangeExpressionLabel(unittest.TestCase):
    """A secret endpoint makes the whole range secret, so a length read or
    a loop over it cannot launder the secret to a public sink."""

    def test_range_length_read_warns_default(self):
        r = _analyze(
            "fun main(s: @secret Int, stdio: Stdio)\n"
            "    let r = 0..s\n"
            "    stdio.println(\"${r.length()}\")\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_sink_warnings(r)), 1, [w.message for w in r.warnings])

    def test_range_length_read_strict_error(self):
        r = _strict(
            "fun main(s: @secret Int, stdio: Stdio)\n"
            "    let r = 0..s\n"
            "    stdio.println(\"${r.length()}\")\n"
        )
        self.assertFalse(r.ok)
        self.assertEqual(len(_sink_errors(r)), 1, [e.message for e in r.errors])

    def test_range_length_inline_warns_default(self):
        r = _analyze(
            "fun main(s: @secret Int, stdio: Stdio)\n"
            "    stdio.println(\"${(0..s).length()}\")\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_sink_warnings(r)), 1, [w.message for w in r.warnings])

    def test_range_loop_variable_warns_default(self):
        r = _analyze(
            "fun main(s: @secret Int, stdio: Stdio)\n"
            "    for i in 0..s\n"
            "        stdio.println(\"${i}\")\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertGreaterEqual(len(_sink_warnings(r)), 1, [w.message for w in r.warnings])

    def test_range_loop_variable_strict_error(self):
        r = _strict(
            "fun main(s: @secret Int, stdio: Stdio)\n"
            "    for i in 0..s\n"
            "        stdio.println(\"${i}\")\n"
        )
        self.assertFalse(r.ok)
        self.assertGreaterEqual(len(_sink_errors(r)), 1, [e.message for e in r.errors])

    def test_public_range_stays_clean(self):
        r = _analyze(
            "fun main(n: Int, stdio: Stdio)\n"
            "    let r = 0..n\n"
            "    stdio.println(\"${r.length()}\")\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(_sink_warnings(r), [])

    def test_public_range_stays_clean_strict(self):
        r = _strict(
            "fun main(n: Int, stdio: Stdio)\n"
            "    for i in 0..n\n"
            "        stdio.println(\"${i}\")\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(_sink_errors(r), [])

    def test_direct_print_control_unchanged(self):
        # The direct-print control keeps its pre-existing behaviour: a
        # @secret Int printed directly warns by default and errors strict.
        r = _analyze(
            "fun main(s: @secret Int, stdio: Stdio)\n"
            "    stdio.println(\"${s}\")\n"
        )
        self.assertEqual(len(_sink_warnings(r)), 1, [w.message for w in r.warnings])
        rs = _strict(
            "fun main(s: @secret Int, stdio: Stdio)\n"
            "    stdio.println(\"${s}\")\n"
        )
        self.assertEqual(len(_sink_errors(rs)), 1, [e.message for e in rs.errors])


class TestBecomeLabel(unittest.TestCase):
    """``become(value, State)`` re-types a value in place; the result keeps
    the value's label. White-box, since a typestate program that carries a
    labelled value is verbose to spell out end to end."""

    def _az(self):
        return Analyzer(source="")

    def test_become_preserves_secret_label(self):
        az = self._az()
        child = A.IntLit(value=1, pos=_P)
        az._expr_labels[id(child)] = L.SECRET
        node = A.Become(value=child, state="Active", pos=_P)
        self.assertEqual(az._compute_label(node), L.SECRET)

    def test_become_public_value_stays_public(self):
        az = self._az()
        child = A.IntLit(value=1, pos=_P)
        az._expr_labels[id(child)] = L.PUBLIC
        node = A.Become(value=child, state="Active", pos=_P)
        self.assertEqual(az._compute_label(node), L.PUBLIC)


class TestRangeLabelWhiteBox(unittest.TestCase):
    """The range rule is the JOIN of its two endpoint labels."""

    def _node(self, start_label, end_label):
        az = Analyzer(source="")
        start = A.IntLit(value=0, pos=_P)
        end = A.Ident(name="x", pos=_P)
        az._expr_labels[id(start)] = start_label
        az._expr_labels[id(end)] = end_label
        node = A.RangeExpr(start=start, end=end, inclusive=False, pos=_P)
        return az._compute_label(node)

    def test_secret_end_makes_range_secret(self):
        self.assertEqual(self._node(L.PUBLIC, L.SECRET), L.SECRET)

    def test_secret_start_makes_range_secret(self):
        self.assertEqual(self._node(L.SECRET, L.PUBLIC), L.SECRET)

    def test_public_endpoints_stay_public(self):
        self.assertEqual(self._node(L.PUBLIC, L.PUBLIC), L.PUBLIC)


class _UnhandledExpr(A.Expr):
    """A stand-in for a future expression node with no label rule."""


class TestLabelFunctionIsTotal(unittest.TestCase):
    """The label function is total over the expression node kinds: a node
    with no rule must fail LOUD (compiler-internal error) rather than
    silently default to PUBLIC, which is what laundered the range secret."""

    def test_unhandled_node_raises_internal_error(self):
        az = Analyzer(source="")
        node = _UnhandledExpr(pos=_P)
        with self.assertRaises(AssertionError) as ctx:
            az._compute_label(node)
        self.assertIn("not total", str(ctx.exception))

    def test_range_and_become_are_the_only_two_that_needed_a_rule(self):
        # Guards the audit that RANGE and BECOME were the only expression
        # kinds missing a case: every concrete ``A.Expr`` subclass declared
        # in the AST is handled by ``_compute_label`` (a subclass added
        # without a rule trips ``test_unhandled_node_raises_internal_error``
        # the moment it reaches the walk). This test pins the inventory so a
        # newly added node is a conscious choice, not an accident.
        concrete = {
            cls.__name__
            for cls in _all_subclasses(A.Expr)
            if cls.__module__.startswith("capa.capa_ast")
        }
        # The 23 real expression kinds present when totality landed.
        self.assertIn("RangeExpr", concrete)
        self.assertIn("Become", concrete)
        self.assertEqual(len(concrete), 23, sorted(concrete))


def _all_subclasses(cls):
    out = set()
    for sub in cls.__subclasses__():
        out.add(sub)
        out |= _all_subclasses(sub)
    return out


if __name__ == "__main__":
    unittest.main()
