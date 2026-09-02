"""A completeness GUARD over the analyzer's own source: no single-use rule
may decide its operand by SYNTAX.

WHY THIS EXISTS, and why it is a source guard rather than a behaviour test.

The linear and capability disciplines both answer "is this value used at most
once?" by keying on a canonical PLACE: `_path_of` turns an expression into a
dotted path, and `_live_linear` / `_borrowed_linear` / `_consumed` are keyed
on that path. A rule that instead inspects the operand's SYNTAX -- typically
`isinstance(expr, A.Ident)` and then `expr.name` -- gets the right answer for
the two spellings it happens to enumerate and silently the wrong answer for
every other spelling of the same value. The language has two alias-introducing
forms (a pattern binder and an if/match selection) and they compose, so such a
rule rejects `close(c)` and accepts `close(if true then c else c)` on the same
borrowed `c`: a double-free that the direct spelling catches.

Three separate review rounds each found a defect of exactly this shape, at a
different rule:

* the `consume self` receiver, open-coding an `Ident` / `FieldAccess` branch
  list, so an unlisted receiver shape fell through every branch;
* `_linear_check_borrowed_escape`, testing `isinstance(expr, Ident)` at five
  aggregate-pack sites, accepting six laundered double-frees;
* `_linear_transfer_if_alias`'s borrowed propagation, testing
  `isinstance(value, Ident)` and `value.name` at four bind sites, accepting
  sixteen.

All three share ONE textual signature, which is what makes them machine
checkable rather than only sample-checkable: a function that both touches a
single-use state set and reaches an operand's `.name` (or narrows an operand
with `isinstance(..., Ident)` before doing so) is deciding by syntax. Behaviour
tests catch the members you thought to write; this catches the SHAPE, so the
fourth instance cannot be added without a test going red.

WHAT IT ALLOWS, and why each allowance is safe rather than convenient.

`_check_fun`'s parameter seeding is the one legitimate producer. A parameter's
NAME is its place -- there is no operand expression to resolve, and nothing
upstream could have aliased it -- so `self._live_linear[p.name] = ...` and
`self._borrowed_linear.add(p.name)` are position-independent by construction.
That allowance is pinned to the function name, so moving the seeding somewhere
else, or adding a second producer, fails this guard rather than inheriting it.

THIS GUARD IS ONLY WORTH ITS LINES IF IT BITES. `test_the_guard_bites` below
re-introduces a syntactic single-use test into the analyzer source in memory
and asserts the detector flags it, so the guard is proven to fail on the shape
it forbids and not merely to run. The negatives beside it prove it does not
flag the shapes that are fine, which is what keeps it from being disabled the
first time it cries wolf.
"""

import ast
import io
import os
import unittest

import capa.analyzer


# The state that answers "used at most once". A function that writes or reads
# one of these is deciding a single-use question.
SINGLE_USE_SETS = frozenset({
    "_live_linear",
    "_borrowed_linear",
    "_consumed",
    "_linear_names",
    "_linear_field_moved",
})

# THE resolver. A rule that goes through this is place-keyed by construction.
RESOLVER = "_path_of"

# The AST node classes an operand is narrowed to when a rule decides by
# syntax rather than by place.
OPERAND_NODES = frozenset({"Ident", "FieldAccess", "IfExpr", "MatchExpr"})

# (module, function) pairs allowed to key single-use state on a `.name`.
# One entry, and it is a PRODUCER, not a rule: see the module docstring.
ALLOWED = frozenset({
    ("_items.py", "_check_fun"),
})


def _analyzer_dir() -> str:
    return os.path.dirname(os.path.abspath(capa.analyzer.__file__))


def _read(path: str) -> str:
    with io.open(path, encoding="utf-8") as fh:
        return fh.read()


def _self_attr(node: ast.AST, names) -> bool:
    """True iff ``node`` is ``self.<one of names>``."""
    return (
        isinstance(node, ast.Attribute)
        and node.attr in names
        and isinstance(node.value, ast.Name)
        and node.value.id == "self"
    )


def _touches_single_use(tree: ast.AST) -> set:
    """The single-use sets referenced as ``self.<SET>`` in this subtree."""
    return {
        n.attr for n in ast.walk(tree)
        if _self_attr(n, SINGLE_USE_SETS)
    }


def _reads_operand_name(tree: ast.AST) -> bool:
    """True iff this subtree reads ``<something>.name`` off anything other
    than ``self``. That is how a rule spells "the identifier's text" when it
    should be spelling "the place this operand denotes"."""
    for n in ast.walk(tree):
        if (isinstance(n, ast.Attribute) and n.attr == "name"
                and not (isinstance(n.value, ast.Name)
                         and n.value.id == "self")):
            return True
    return False


def _isinstance_operand_classes(tree: ast.AST) -> bool:
    """True iff this subtree narrows a value with
    ``isinstance(x, <operand node class>)``. Kept separate from the ``.name``
    test because the receiver defect narrowed and branched on the operand's
    shape without ever reading ``.name``. The class may be spelled
    ``A.Ident``, ``_A.Ident`` or a tuple of them."""
    def cls_names(node):
        if isinstance(node, ast.Attribute):
            return [node.attr]
        if isinstance(node, ast.Name):
            return [node.id]
        if isinstance(node, ast.Tuple):
            out = []
            for e in node.elts:
                out.extend(cls_names(e))
            return out
        return []

    for n in ast.walk(tree):
        if (isinstance(n, ast.Call)
                and isinstance(n.func, ast.Name)
                and n.func.id == "isinstance"
                and len(n.args) == 2):
            if set(cls_names(n.args[1])) & OPERAND_NODES:
                return True
    return False


def _calls_resolver(tree: ast.AST) -> bool:
    """True iff this subtree calls ``self._path_of(...)``."""
    for n in ast.walk(tree):
        if isinstance(n, ast.Call) and _self_attr(n.func, {RESOLVER}):
            return True
    return False


# The statement kinds a single-use DECISION is spelled as. A decision keys
# the state on something, so it is a test, an assignment, a call or a return
# -- never a whole function body, which is why the scan is per statement.
_DECISION_STMTS = (
    ast.If, ast.While, ast.Assign, ast.AugAssign, ast.AnnAssign,
    ast.Expr, ast.Return, ast.Assert,
)


def find_syntactic_single_use_rules(analyzer_dir: str) -> list:
    """Every function that decides a single-use question by SYNTAX.

    A STATEMENT is flagged when it BOTH touches a single-use set AND, in the
    SAME statement, reaches an operand's ``.name`` or narrows a value with
    ``isinstance(x, A.Ident)``; the enclosing function is then reported
    unless it calls the resolver. Scoping the co-occurrence to one statement
    is what keeps the guard precise: a function that saves and restores
    ``_consumed`` around a scope, and separately reads ``.name`` to bind a
    pattern, is doing two unrelated things and is not deciding anything about
    an operand. Requiring all of it keeps the guard quiet on:

    * touching a set with no operand in the statement -- bookkeeping over a
      place string a caller already resolved, or set-level flow merging;
    * reading ``.name`` without touching a set -- a diagnostic, a symbol
      lookup, a type name;
    * doing both but calling ``_path_of`` somewhere in the function -- the
      resolve-then-decide shape this whole design is built on.

    Returns a sorted list of ``(module, function, lineno, sets)``.
    """
    findings = []
    for fname in sorted(os.listdir(analyzer_dir)):
        if not fname.endswith(".py"):
            continue
        with io.open(os.path.join(analyzer_dir, fname),
                     encoding="utf-8") as fh:
            src = fh.read()
        findings.extend(find_in_source(fname, src))
    return sorted(findings)


def _scan(body, narrowed: bool, hit: set) -> None:
    """Walk a statement list, carrying whether an enclosing ``if`` NARROWED a
    value to an operand node class.

    Narrowing propagates into the branch it guards, because that is how the
    receiver defect was written: ``if isinstance(recv, (Ident, FieldAccess))``
    and then the single-use work in the body, with ``.name`` never read. It
    does NOT propagate out of the function or across sibling statements, which
    is what stops a function that merely saves and restores a set from being
    confused with one that decides something about an operand.
    """
    for st in body:
        if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue  # scanned as its own unit
        if isinstance(st, (ast.If, ast.While)):
            here = narrowed or _isinstance_operand_classes(st.test)
            sets = _touches_single_use(st.test)
            if sets and (here or _reads_operand_name(st.test)):
                hit |= sets
            _scan(st.body, here, hit)
            _scan(st.orelse, narrowed, hit)
            continue
        if isinstance(st, (ast.For, ast.AsyncFor, ast.With, ast.AsyncWith,
                           ast.Try)):
            for attr in ("body", "orelse", "finalbody"):
                _scan(getattr(st, attr, []) or [], narrowed, hit)
            for h in getattr(st, "handlers", []) or []:
                _scan(h.body, narrowed, hit)
            continue
        if not isinstance(st, _DECISION_STMTS):
            continue
        sets = _touches_single_use(st)
        if sets and (narrowed or _reads_operand_name(st)
                     or _isinstance_operand_classes(st)):
            hit |= sets


def find_in_source(module_name: str, src: str) -> list:
    """The detector, over one module's SOURCE TEXT rather than a path, so the
    bite test can feed it a deliberately-broken variant without touching any
    file on disk."""
    findings = []
    for fn in ast.walk(ast.parse(src)):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if (module_name, fn.name) in ALLOWED:
            continue
        if _calls_resolver(fn):
            continue
        hit: set = set()
        _scan(fn.body, False, hit)
        if hit:
            findings.append(
                (module_name, fn.name, fn.lineno, tuple(sorted(hit))))
    return sorted(findings)


class TestSingleUseResolutionGuard(unittest.TestCase):

    def test_no_rule_decides_a_single_use_question_by_syntax(self):
        """THE guard. Every single-use decision resolves its operand."""
        findings = find_syntactic_single_use_rules(_analyzer_dir())
        self.assertEqual(
            findings, [],
            "these functions decide a single-use question by SYNTAX rather "
            "than through %s; resolve the operand to a place, or add the "
            "function to ALLOWED with a written reason if it is genuinely a "
            "position-independent producer:\n%s"
            % (RESOLVER, "\n".join("  %s:%d %s touches %s" % (m, ln, f, s)
                                   for m, f, ln, s in findings)),
        )

    # ---- the guard must BITE, not merely run --------------------------

    _BITE = '''
class _Fake:
    def _some_new_rule(self, expr, target):
        """A rule added later that decides by syntax."""
        if isinstance(expr, A.Ident) and expr.name in self._borrowed_linear:
            self._borrowed_linear.add(target)
            return True
        return False
'''

    def test_the_guard_bites_on_a_reintroduced_syntactic_rule(self):
        """Re-introduce the exact shape all three review rounds found, and
        confirm the detector flags it. Without this the guard would prove
        only that it RUNS."""
        found = find_in_source("_fake.py", self._BITE)
        self.assertEqual(len(found), 1, found)
        self.assertEqual(found[0][0], "_fake.py")
        self.assertEqual(found[0][1], "_some_new_rule")
        self.assertIn("_borrowed_linear", found[0][3])

    def test_the_guard_bites_on_a_branch_list_without_a_name_read(self):
        """The receiver defect narrowed the operand and branched on its shape
        WITHOUT reading ``.name``, so narrowing alone must be enough to
        flag."""
        src = '''
class _Fake:
    def _receiver_rule(self, recv):
        if isinstance(recv, (A.Ident, A.FieldAccess)):
            self._live_linear.pop("x", None)
'''
        found = find_in_source("_fake.py", src)
        self.assertEqual(len(found), 1, found)
        self.assertEqual(found[0][1], "_receiver_rule")

    def test_the_guard_bites_when_a_real_rule_is_reverted(self):
        """The strongest form: take the SHIPPED source of the rule the last
        round found, revert its resolution to the syntactic test it used to
        have, and confirm the guard flags it. This ties the guard to the
        actual defect rather than to a hand-written imitation of it."""
        path = os.path.join(_analyzer_dir(), "_linear.py")
        src = _read(path)
        self.assertEqual(find_in_source("_linear.py", src), [],
                         "shipped source must be clean before reverting")
        resolved = (
            "        place = self._path_of(value)\n"
            "        if place is None or not self._prefix_borrowed(place):\n"
            "            return False\n"
            "        self._borrowed_linear.add(target)\n"
            "        return True\n"
        )
        self.assertIn(resolved, src, "the rule's resolved body moved")
        syntactic = (
            "        from .. import capa_ast as _A\n"
            "        if not isinstance(value, _A.Ident):\n"
            "            return False\n"
            "        if value.name not in self._borrowed_linear:\n"
            "            return False\n"
            "        self._borrowed_linear.add(target)\n"
            "        return True\n"
        )
        found = find_in_source("_linear.py", src.replace(resolved, syntactic))
        self.assertTrue(
            any(f[1] == "_transfer_borrowed_marker" for f in found),
            "reverting the borrowed-marker rule to its syntactic form must "
            "be flagged; got %r" % (found,),
        )

    # ---- the guard must NOT over-flag ---------------------------------

    def test_resolving_first_is_not_flagged(self):
        """The shape the design is built on: resolve, then decide."""
        src = '''
class _Fake:
    def _resolved_rule(self, expr, target):
        place = self._path_of(expr)
        if place is not None and place in self._borrowed_linear:
            self._borrowed_linear.add(target)
'''
        self.assertEqual(find_in_source("_fake.py", src), [])

    def test_bookkeeping_over_a_place_string_is_not_flagged(self):
        """A helper handed an already-resolved place touches the sets and
        names no operand at all."""
        src = '''
class _Fake:
    def _discharge(self, place, pos):
        self._live_linear.pop(place, None)
        self._consumed.add(place)
'''
        self.assertEqual(find_in_source("_fake.py", src), [])

    def test_reading_a_name_without_single_use_state_is_not_flagged(self):
        """Diagnostics and symbol lookups read ``.name`` constantly."""
        src = '''
class _Fake:
    def _report(self, expr):
        if isinstance(expr, A.Ident):
            self._err("unknown name %r" % expr.name, expr.pos)
'''
        self.assertEqual(find_in_source("_fake.py", src), [])

    def test_the_allow_list_is_honoured_and_is_pinned_to_one_producer(self):
        """The seeding producer is allowed; the SAME body under any other
        name is not, so the allowance cannot be inherited by moving code."""
        src = '''
class _Fake:
    def _check_fun(self, fn):
        for p in fn.params:
            self._borrowed_linear.add(p.name)
'''
        self.assertEqual(find_in_source("_items.py", src), [])
        self.assertEqual(len(find_in_source("_other.py", src)), 1)
        renamed = src.replace("_check_fun", "_check_fun_v2")
        self.assertEqual(len(find_in_source("_items.py", renamed)), 1)

    def test_the_allow_list_entries_all_exist(self):
        """An ALLOWED entry naming a function that no longer exists is a
        silently dead exemption: the next function to take that name would
        inherit it. Fail closed instead."""
        adir = _analyzer_dir()
        for module_name, fn_name in sorted(ALLOWED):
            path = os.path.join(adir, module_name)
            self.assertTrue(os.path.exists(path), path)
            tree = ast.parse(_read(path))
            names = {
                n.name for n in ast.walk(tree)
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
            }
            self.assertIn(
                fn_name, names,
                "ALLOWED names %s.%s, which does not exist"
                % (module_name, fn_name),
            )

    def test_the_detector_sees_every_analyzer_module(self):
        """A guard that silently scanned nothing would pass forever. Pin that
        it parsed the real package and that the modules the class lives in
        are among them."""
        adir = _analyzer_dir()
        mods = [n for n in os.listdir(adir) if n.endswith(".py")]
        self.assertGreater(len(mods), 5, mods)
        for required in ("_linear.py", "_discipline.py", "_statements.py",
                         "_expressions.py", "_items.py"):
            self.assertIn(required, mods)
            src = _read(os.path.join(adir, required))
            ast.parse(src)


if __name__ == "__main__":
    unittest.main()
