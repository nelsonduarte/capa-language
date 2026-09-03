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
tests catch the members you thought to write; this catches a SHAPE.

A pentest then wrote a FOURTH spelling that shares the intent and not the
signature: `name.startswith('tmp')` beside a single-use set, deciding from a
name's TEXT with no operand node anywhere. It touches no `.name` attribute and
narrows nothing, so the three signatures above all miss it. Testing a string
against a LITERAL is now the fourth signature, and it is judged by the same
predicate as the other three (`_judge`), so the four cannot drift apart.

WHAT A GREEN RESULT HERE DOES NOT MEAN. The bound has three parts and all
three are load-bearing. A reader who takes a green guard for a closed class
will be wrong, and the failure would be silent.

1. IT SEES FOUR TEXTUAL SIGNATURES. A rule that decides a single-use question
   some other way is outside it entirely. This is a detector for how the known
   instances happened to be spelled, not a decision procedure for the property.

2. IT ONLY SEES RULES THAT TOUCH ONE OF THE NAMED STATE SETS. `SINGLE_USE_SETS`
   below is the whole of its reach. If either discipline grows new state -- a
   new map, a new poisoned-place set -- a rule keyed on it is invisible here
   until that name is added. Widening that set is the maintenance this guard
   requires and nothing enforces it.

   THAT MAINTENANCE HAS ALREADY BEEN OVERDUE ONCE, WITH A WORKING EXPLOIT. A
   pentest keyed a purely syntactic single-use rule on `_drop_exempt_linear`,
   which was not in the list. The build was unsound and this guard reported
   eleven passing tests on it, as did the whole 5899-test suite. Six sets are
   now watched that were not, including `_linear_alias`, which the release
   that added this guard introduced and left outside it. Part 2 of this bound
   is therefore not theoretical: it is the part that has already been paid.

3. NINE KNOWN SPELLINGS EVADE IT TODAY. 25 candidate evasions were constructed
   and run against this detector; 16 are flagged and 9 are not:

       hoisting the name into a local before keying state on it;
       `getattr(expr, "name", None)`;
       a helper method that returns the name;
       `match` / `case` pattern matching on the node class;
       resolving an UNRELATED operand first;
       resolving the operand and then ignoring the result;
       keying on a state set not in `SINGLE_USE_SETS`;
       a lambda body;
       a ternary that extracts the name conditionally.

   The module-level function and the `staticmethod` left this list because the
   analyzer receiver no longer has to be spelled `self`. The remaining nine
   were each checked against the shipped analyzer and NONE occurs, so they are
   latent rather than live. They are recorded because a guard whose holes are
   unwritten invites the belief that it has none. The reproducible list is
   `.claude/e3_v5_scripts/qa7_guard_attack.py`; run it after changing the
   detector, and treat a drop in the flagged count as a regression.

   "Keying on a state set not in `SINGLE_USE_SETS`" cannot be closed by any
   amount of list widening -- it is part 2 restated -- so it stays on this
   list permanently rather than being counted as progress.

So the honest claim is: this catches four spellings of the shape the known
instances share, across the modules it traverses, for the state it knows
about. It is one instrument among several, and the two most recent rules in
this class were found by constructing programs rather than by any detector.

WHAT IT ALLOWS, and why each allowance is safe rather than convenient.

`_check_fun`'s parameter seeding is the one legitimate producer. A parameter's
NAME is its place -- there is no operand expression to resolve, and nothing
upstream could have aliased it -- so `self._live_linear[p.name] = ...` and
`self._borrowed_linear.add(p.name)` are position-independent by construction.
That allowance is pinned to the function name, so moving the seeding somewhere
else, or adding a second producer, fails this guard rather than inheriting it.

A FOURTH instance was then found while implementing the fix, at the
laundering-call argument in `_move_linear_operand`, so the list above is
"known", not "all".

THIS GUARD IS ONLY WORTH ITS LINES IF IT BITES ON THE HARD CASE, and the
first version did not. It exempted a whole FUNCTION that called the resolver
anywhere, which is precisely wrong: the functions most likely to hide a stray
syntactic branch are the big resolve-then-decide seams, which by construction
resolve somewhere. A build with the laundering-call branch reverted ACCEPTS
three double-frees on all three backends, and that version of this guard
reported ten passing tests on it. The exemption is now scoped to the BRANCH,
and `test_the_guard_bites_on_the_case_that_defeated_it` is the primary proof;
the three hand-written bite tests are secondary, because all three used shapes
the broken exemption happened not to cover, which is how they passed while the
real defect walked through. The negatives beside them prove the guard does not
flag the shapes that are fine, which is what keeps it from being disabled the
first time it cries wolf.

There are now TWO primary bite proofs, and the second is
`test_the_guard_bites_on_the_pentest_exploit`. Both mutate SHIPPED source
rather than a hand-written imitation, and both are anchored to the exact text
they mutate, so a refactor that moves either site fails the test instead of
passing it vacuously. They fail for different reasons -- one for the scope of
the exemption, one for the reach of the watched state -- which is why both are
kept.
"""

import ast
import io
import os
import unittest

import capa.analyzer


# The state that answers "used at most once". A function that writes or reads
# one of these is deciding a single-use question.
#
# THE SECOND HALF OF THIS LIST WAS ADDED AFTER A WORKING EXPLOIT, not after a
# review. A pentest built a purely syntactic single-use rule keyed on
# ``_drop_exempt_linear`` -- a set NOT listed here at the time -- and the
# resulting analyzer was unsound (a ``let tmpa = open()`` never consumed was
# accepted) while THIS guard reported eleven passing tests and the whole
# 5899-test suite passed. The blindness is exactly the bound part 2 of the
# docstring states, so this is not a new kind of hole; it is the demonstration
# that the maintenance the bound calls for was overdue.
#
# ``_moved_subpath_sets`` is a METHOD, not an attribute: it returns the tuple
# of sub-path structures the move seam writes through. Naming it here is what
# lets the guard see a rule that reaches the state through the ACCESSOR rather
# than through the attributes, which is otherwise an evasion by one hop.
SINGLE_USE_SETS = frozenset({
    "_live_linear",
    "_borrowed_linear",
    "_consumed",
    "_linear_names",
    "_linear_field_moved",
    # added after the pentest, in the order the report enumerates them
    "_drop_exempt_linear",
    "_linear_alias",
    "_moved_subpath_sets",
    "_linear_conditional_reported",
    "_linear_container_reported",
    "_struct_aliases",
})

# String methods that inspect a name's TEXT. A single-use decision taken by
# comparing a place / name against a string LITERAL is syntactic in the purest
# sense -- no resolution at all -- and it is the shape the pentest's exploit
# took (``name.startswith('tmp')``). Splitting a place on ``"."`` to get its
# root, or prefix-scanning a moved-sub-path set, uses the same methods against
# a SEPARATOR, so the literal argument is what separates the two: measured
# against the shipped analyzer this signature has ZERO hits, and the exploit
# has one.
_TEXT_TESTS = frozenset({
    "startswith", "endswith", "find", "index", "count",
    "split", "rsplit", "partition", "rpartition",
    "lower", "upper", "strip", "lstrip", "rstrip", "removeprefix",
    "removesuffix",
})

# The separator a legitimate PLACE operation splits or scans on. A literal
# argument equal to it is path arithmetic on an already-resolved place
# (``place.split(".", 1)[0]`` is the root), not a decision about a name's
# text, so it does not count as a syntactic test.
_PLACE_SEPARATOR = "."

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


def _analyzer_attr(node: ast.AST, names) -> bool:
    """True iff ``node`` is ``<analyzer>.<one of names>``.

    The receiver may be ``self``, a local ALIAS of it (``me = self``), or a
    parameter a module-level helper was handed the analyzer through. Requiring
    the literal ``self.`` was an evasion the pentest measured, and widening it
    costs nothing in precision because the names in ``SINGLE_USE_SETS`` are
    analyzer-private and appear on no other object in the package -- verified
    by the shipped-source scan, which stays at zero findings."""
    if not (isinstance(node, ast.Attribute) and node.attr in names):
        return False
    return isinstance(node.value, (ast.Name, ast.Attribute))


def _text_test_on_a_literal(tree: ast.AST) -> bool:
    """True iff this subtree tests a string's TEXT against a string LITERAL.

    The purest syntactic decision there is: no operand node, no resolution,
    just the characters of a name. The pentest's exploit was exactly this
    (``name.startswith('tmp')`` beside ``self._drop_exempt_linear``), and it
    evaded every other signature here because it never touches an operand's
    ``.name`` and never narrows with ``isinstance``.

    The ``.``-separator argument is excluded because splitting a place on it
    is path arithmetic over an ALREADY-RESOLVED place, which is how every
    legitimate site in the analyzer uses these methods."""
    for n in ast.walk(tree):
        if not (isinstance(n, ast.Call)
                and isinstance(n.func, ast.Attribute)
                and n.func.attr in _TEXT_TESTS):
            continue
        for a in n.args:
            if (isinstance(a, ast.Constant) and isinstance(a.value, str)
                    and a.value != _PLACE_SEPARATOR):
                return True
    return False


def _touches_single_use(tree: ast.AST) -> set:
    """The single-use sets referenced as ``self.<SET>`` in this subtree."""
    return {
        n.attr for n in ast.walk(tree)
        if _analyzer_attr(n, SINGLE_USE_SETS)
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


# The statement kinds a single-use DECISION is spelled as. A decision keys
# the state on something, so it is a test, an assignment, a call, a return, a
# raise or a deletion -- never a whole function body, which is why the scan is
# per statement.
#
# ``Delete`` and ``Raise`` were absent and that was not exotic: ``del
# self._live_linear[expr.name]`` is a SHIPPED discharge spelling in
# ``_linear.py``, so a rule written in the language the analyzer already uses
# was invisible to the guard built to watch it.
_DECISION_STMTS = (
    ast.If, ast.While, ast.Assign, ast.AugAssign, ast.AnnAssign,
    ast.Expr, ast.Return, ast.Assert, ast.Raise, ast.Delete,
)


def find_syntactic_single_use_rules(analyzer_dir: str) -> list:
    """Every function that decides a single-use question by SYNTAX.

    A STATEMENT is flagged when it BOTH touches a single-use set AND, in the
    SAME statement or under an enclosing ``isinstance`` narrowing, reaches an
    operand's ``.name``; the enclosing function is then reported. The
    exemption for going through the resolver is scoped to the BRANCH, not to
    the function: see ``_scan``, where getting that wrong was a measured
    false negative. Scoping the co-occurrence this way keeps the guard
    precise, so a function that saves and restores ``_consumed`` around a
    scope and separately reads ``.name`` to bind a pattern is not confused
    with one that decides something about an operand. It keeps the guard
    quiet on:

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


def _resolves(node) -> bool:
    """True iff this subtree calls ``self._path_of(...)``."""
    for n in ast.walk(node):
        if isinstance(n, ast.Call) and _analyzer_attr(n.func, {RESOLVER}):
            return True
    return False


def _scan(body, narrowed: bool, resolved: bool, hit: set) -> None:
    """Walk a statement list, carrying two facts down the branch structure.

    ``narrowed``  an enclosing ``if`` narrowed a value to an operand node
                  class. It propagates INTO the branch it guards, because
                  that is how the receiver defect was written:
                  ``if isinstance(recv, (Ident, FieldAccess))`` and then the
                  single-use work in the body, with ``.name`` never read.

    ``resolved``  this statement, or a branch enclosing it, went through the
                  resolver. It is the EXEMPTION, and it is scoped to the
                  branch rather than to the function.

    THE SCOPE OF THE EXEMPTION IS THE WHOLE POINT, and getting it wrong was a
    measured false negative rather than a hypothetical one. Exempting the
    whole enclosing FUNCTION when it calls ``_path_of`` ANYWHERE let a
    syntactic branch at the top of ``_move_linear_operand`` pass unseen,
    because that function resolves further down its own body. The build with
    that branch re-introduced accepts three double-frees on all three
    backends, and the guard reported ten passing tests on it.

    A function-scoped exemption is aimed exactly at the hardest case: the
    functions most likely to hide a stray syntactic branch are the big
    resolve-then-decide seams, which by construction call the resolver
    somewhere. So the exemption follows the branch.

    HEADERS ARE SCANNED, NOT ONLY BODIES. ``for``/``with`` used to have their
    bodies recursed into and their ``iter`` / ``items`` HEADER ignored, so a
    rule spelled as a comprehension over the live set (``for k in [n for n in
    self._live_linear if n == expr.name]``) or as a context manager over it
    was invisible. The header is a sub-expression like any other and is now
    judged by the same predicate.
    """
    for st in body:
        if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue  # scanned as its own unit
        if isinstance(st, (ast.If, ast.While)):
            here_narrowed = narrowed or _syntactic_test(st.test)
            here_resolved = resolved or _resolves(st.test)
            _judge(st.test, here_narrowed, here_resolved, hit)
            _scan(st.body, here_narrowed, here_resolved, hit)
            # The else-branch does not inherit the test's narrowing, but it
            # does inherit a resolution that happened before the ``if``.
            _scan(st.orelse, narrowed, resolved, hit)
            continue
        if isinstance(st, (ast.For, ast.AsyncFor, ast.With, ast.AsyncWith,
                           ast.Try)):
            for header in _loop_headers(st):
                _judge(header, narrowed, resolved or _resolves(header), hit)
            for attr in ("body", "orelse", "finalbody"):
                _scan(getattr(st, attr, []) or [], narrowed, resolved, hit)
            for h in getattr(st, "handlers", []) or []:
                _scan(h.body, narrowed, resolved, hit)
            continue
        if not isinstance(st, _DECISION_STMTS):
            continue
        # A statement that resolves IN PLACE is the resolve-then-decide shape
        # and is fine; ``resolved`` inherited from an enclosing branch counts
        # too, so ``place = self._path_of(x)`` followed by decisions on
        # ``place`` in the same block is not flagged.
        if _resolves(st):
            resolved = True
            continue
        _judge(st, narrowed, resolved, hit)


def _loop_headers(st) -> list:
    """The HEADER sub-expressions of a compound statement: a ``for``'s
    iterable, a ``with``'s context managers. Enumerated in ONE place so the
    scan and any future caller agree on what a header is."""
    if isinstance(st, (ast.For, ast.AsyncFor)):
        return [st.iter]
    if isinstance(st, (ast.With, ast.AsyncWith)):
        return [item.context_expr for item in st.items]
    return []


def _syntactic_test(node) -> bool:
    """True iff ``node`` decides something about a value by SYNTAX rather than
    by the place it denotes: it narrows the value to an operand node class, or
    it tests a string's text against a literal.

    THE single list of syntactic-decision signatures that PROPAGATE into a
    branch, so a rule whose test is in the ``if`` header and whose single-use
    work is in the body is seen whichever signature the header used. Before
    this was one function, ``isinstance`` propagated and the text test did
    not, which meant the exploit was caught only in its one-statement spelling
    and its two-statement spelling walked through."""
    return _isinstance_operand_classes(node) or _text_test_on_a_literal(node)


def _judge(node, narrowed: bool, resolved: bool, hit: set) -> None:
    """THE single decision: does ``node`` decide a single-use question by
    SYNTAX, given the narrowing and resolution inherited from its branch?

    One body, called from every site that has a sub-expression to judge -- an
    ``if``/``while`` test, a ``for``/``with`` header, and a plain decision
    statement. The test and the statement each carried their own copy of this
    condition before, which is the duplicated-knowledge shape this whole
    release exists to remove; when the fourth signature was added it would
    have had to be written into both."""
    if resolved:
        return
    sets = _touches_single_use(node)
    if not sets:
        return
    if narrowed or _reads_operand_name(node) or _syntactic_test(node):
        hit |= sets


def find_in_source(module_name: str, src: str) -> list:
    """The detector, over one module's SOURCE TEXT rather than a path, so the
    bite test can feed it a deliberately-broken variant without touching any
    file on disk.

    There is deliberately NO function-level exemption here. Skipping a whole
    function because it calls the resolver somewhere is what let the
    laundering-call branch at the top of ``_move_linear_operand`` pass unseen
    while the build accepted three double-frees. ``_scan`` carries the
    exemption down the branch structure instead."""
    findings = []
    for fn in ast.walk(ast.parse(src)):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if (module_name, fn.name) in ALLOWED:
            continue
        hit: set = set()
        _scan(fn.body, False, False, hit)
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

    def test_the_guard_bites_on_the_case_that_defeated_it(self):
        """THE PRIMARY BITE PROOF. Everything else in this class is
        secondary to it.

        An earlier version of this guard exempted a whole FUNCTION when that
        function called the resolver anywhere. Reverting the laundering-call
        branch at the top of ``_move_linear_operand`` to its syntactic form
        therefore produced a build that ACCEPTS three double-frees on all
        three backends while this guard reported ten passing tests. The three
        hand-written bite tests below all happened to use shapes the
        function-scoped exemption did not cover, so they passed while the real
        defect walked through: the guard was proven to RUN, not to BITE.

        This reverts the SHIPPED source of the rule that defeated it, and the
        function it lives in resolves further down its own body, so it is a
        direct regression test for the exemption being branch-scoped rather
        than function-scoped. If someone widens the exemption again, this goes
        red and the three below do not.
        """
        path = os.path.join(_analyzer_dir(), "_discipline.py")
        src = _read(path)
        self.assertEqual(
            find_in_source("_discipline.py", src), [],
            "shipped source must be clean before reverting")
        resolved = (
            "                self._move_transfer_operand(origin_arg, origin_arg.pos)\n"
        )
        self.assertIn(resolved, src, "the laundering-call fold moved")
        syntactic = (
            "                if not self._move_linear_operand(origin_arg) and (\n"
            "                    isinstance(origin_arg, A.Ident)\n"
            "                    and origin_arg.name in self._borrowed_linear\n"
            "                ):\n"
            "                    self._linear_discharge(origin_arg.name, origin_arg.pos)\n"
        )
        found = find_in_source(
            "_discipline.py", src.replace(resolved, syntactic))
        self.assertTrue(
            any(f[1] == "_move_linear_operand" for f in found),
            "reverting the laundering-call fold must be flagged even though "
            "the enclosing function resolves elsewhere; got %r" % (found,),
        )

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

    def test_the_guard_bites_on_the_pentest_exploit(self):
        """THE SECOND PRIMARY BITE PROOF, and the reason this module's watched
        state grew.

        A pentest inserted one clause into the SHIPPED source of
        ``_linear_check_dropped``: a purely syntactic single-use rule deciding
        "is this drop a leak" from the operand name's TEXT, with no resolution
        at all. It was keyed on ``_drop_exempt_linear``, which was not in
        ``SINGLE_USE_SETS``.

        The resulting compiler was UNSOUND -- ``let tmpa = open()`` never
        consumed was accepted, where the branch rejects it -- and this guard
        reported EXIT 0, eleven tests OK, and the whole 5899-test suite passed.
        That is exactly the bound part 2 of the module docstring states, so it
        was not a new kind of hole; it was the demonstration that the
        maintenance the bound calls for had not been done.

        Both halves are asserted here: the shipped source stays clean, and the
        one-clause mutant is flagged at the function and set it was inserted
        into. Anchored to the SHIPPED text, so if that clause moves this goes
        red rather than passing vacuously against text that is no longer
        there.
        """
        path = os.path.join(_analyzer_dir(), "_linear.py")
        src = _read(path)
        self.assertEqual(find_in_source("_linear.py", src), [],
                         "shipped source must be clean before mutating")
        exempt = "            if name in self._drop_exempt_linear:\n"
        self.assertIn(exempt, src, "the drop-exempt clause moved")
        syntactic = (
            "            if name in self._drop_exempt_linear "
            "or name.startswith('tmp'):\n"
        )
        found = find_in_source("_linear.py", src.replace(exempt, syntactic, 1))
        self.assertTrue(
            any(f[1] == "_linear_check_dropped"
                and "_drop_exempt_linear" in f[3] for f in found),
            "a syntactic single-use rule keyed on _drop_exempt_linear must be "
            "flagged; got %r" % (found,),
        )

    def test_the_guard_bites_on_a_name_text_test_with_no_operand_node(self):
        """The FOURTH signature, isolated from the exploit it came from.

        Deciding a single-use question from a name's TEXT reads no `.name`
        attribute and narrows nothing, so the three older signatures all miss
        it. This is the smallest program with that shape, so the signature has
        a member of its own rather than being load-bearing only inside the
        shipped-source mutation.
        """
        src = (
            "class _Fake:\n"
            "    def _rule(self, name):\n"
            "        if name.startswith('tmp'):\n"
            "            self._live_linear.pop(name, None)\n"
            "            return True\n"
            "        return False\n"
        )
        found = find_in_source("_fake.py", src)
        self.assertEqual(len(found), 1, found)
        self.assertIn("_live_linear", found[0][3])

    # ---- the six state sets the pentest enumerated, each with a member ----

    def test_every_watched_state_set_is_reachable_by_the_detector(self):
        """Each name in ``SINGLE_USE_SETS`` must actually make the detector
        fire, or listing it is decoration.

        A set added to the list but never exercised is the failure mode this
        release keeps finding: a fact recorded in one place and believed in
        another, with nothing checking that they agree. Here the check is
        cheap, so there is no excuse for not having it.
        """
        for name in sorted(SINGLE_USE_SETS):
            src = (
                "class _Fake:\n"
                "    def _rule(self, expr):\n"
                "        if isinstance(expr, A.Ident):\n"
                "            self.%s\n" % name
            )
            with self.subTest(state=name):
                found = find_in_source("_fake.py", src)
                self.assertEqual(len(found), 1, (name, found))
                self.assertIn(name, found[0][3])

    def test_the_six_sets_the_pentest_named_are_watched(self):
        """Pinned by NAME, not by count, so widening the list cannot silently
        drop one of the six the pentest enumerated -- including
        ``_linear_alias``, the state this release itself introduced, which
        sat outside its own guard."""
        for name in ("_drop_exempt_linear", "_linear_alias",
                     "_moved_subpath_sets", "_linear_conditional_reported",
                     "_linear_container_reported", "_struct_aliases"):
            with self.subTest(state=name):
                self.assertIn(name, SINGLE_USE_SETS)

    def test_the_watched_state_names_all_exist_in_the_analyzer(self):
        """A watched name the analyzer no longer has is a dead entry that
        makes the list look wider than its reach. Fail closed on it, the same
        way ``ALLOWED`` is checked."""
        adir = _analyzer_dir()
        seen: set = set()
        for fname in sorted(os.listdir(adir)):
            if not fname.endswith(".py"):
                continue
            tree = ast.parse(_read(os.path.join(adir, fname)))
            seen |= {
                n.attr for n in ast.walk(tree)
                if isinstance(n, ast.Attribute) and n.attr in SINGLE_USE_SETS
            }
        self.assertEqual(
            sorted(SINGLE_USE_SETS - seen), [],
            "these watched names do not occur in the analyzer package")

    # ---- the three walk gaps the pentest measured ----

    def test_a_decision_spelled_as_a_del_is_seen(self):
        """``del self._live_linear[expr.name]`` is a SHIPPED discharge
        spelling, and ``ast.Delete`` was absent from the decision-statement
        set, so a rule written in the analyzer's own idiom was invisible."""
        src = (
            "class _Fake:\n"
            "    def _rule(self, expr):\n"
            "        del self._live_linear[expr.name]\n"
        )
        found = find_in_source("_fake.py", src)
        self.assertEqual(len(found), 1, found)
        self.assertEqual(found[0][1], "_rule")

    def test_a_decision_spelled_as_a_raise_is_seen(self):
        src = (
            "class _Fake:\n"
            "    def _rule(self, expr):\n"
            "        raise KeyError(self._live_linear[expr.name])\n"
        )
        self.assertEqual(len(find_in_source("_fake.py", src)), 1)

    def test_a_for_header_is_scanned_not_only_its_body(self):
        """The scan recursed into ``for`` bodies and never looked at the
        ``iter`` header, so a rule spelled as a comprehension over the live
        set was invisible."""
        src = (
            "class _Fake:\n"
            "    def _rule(self, expr):\n"
            "        for k in [n for n in self._live_linear "
            "if n == expr.name]:\n"
            "            pass\n"
        )
        found = find_in_source("_fake.py", src)
        self.assertEqual(len(found), 1, found)
        self.assertIn("_live_linear", found[0][3])

    def test_a_with_items_header_is_scanned(self):
        src = (
            "class _Fake:\n"
            "    def _rule(self, expr):\n"
            "        with open(self._live_linear[expr.name]) as fh:\n"
            "            pass\n"
        )
        self.assertEqual(len(find_in_source("_fake.py", src)), 1)

    def test_reaching_the_state_through_a_self_alias_is_seen(self):
        """``me = self`` then ``me._borrowed_linear`` evaded the literal
        ``self.<set>`` match."""
        src = (
            "class _Fake:\n"
            "    def _rule(self, expr):\n"
            "        me = self\n"
            "        if isinstance(expr, A.Ident) and "
            "expr.name in me._borrowed_linear:\n"
            "            me._borrowed_linear.add('x')\n"
        )
        self.assertEqual(len(find_in_source("_fake.py", src)), 1)

    def test_reaching_the_state_through_an_accessor_is_seen(self):
        """``_moved_subpath_sets()`` returns the sub-path structures the move
        seam writes through, so a rule going through it reaches watched state
        by one hop. Naming the accessor itself is what closes that hop."""
        src = (
            "class _Fake:\n"
            "    def _rule(self, expr):\n"
            "        if isinstance(expr, A.Ident):\n"
            "            for s in self._moved_subpath_sets():\n"
            "                s.add(expr.name)\n"
        )
        found = find_in_source("_fake.py", src)
        self.assertEqual(len(found), 1, found)
        self.assertIn("_moved_subpath_sets", found[0][3])

    # ---- the widening must NOT over-flag -----------------------------

    def test_splitting_a_place_on_its_separator_is_not_flagged(self):
        """``place.split(".", 1)[0]`` is path arithmetic over an already
        resolved place, not a decision about a name's text, and it occurs
        several times in the shipped analyzer."""
        src = (
            "class _Fake:\n"
            "    def _rule(self, place):\n"
            "        root = place.split('.', 1)[0]\n"
            "        self._consumed.add(root)\n"
        )
        self.assertEqual(find_in_source("_fake.py", src), [])

    def test_iterating_a_watched_set_with_no_operand_is_not_flagged(self):
        """Set-level flow merging names no operand at all, and the widened
        header scan must not start reporting it."""
        src = (
            "class _Fake:\n"
            "    def _merge(self):\n"
            "        for k in list(self._live_linear):\n"
            "            self._consumed.add(k)\n"
        )
        self.assertEqual(find_in_source("_fake.py", src), [])

    def test_resolving_first_then_using_new_state_is_not_flagged(self):
        """The resolve-then-decide shape must stay quiet for the NEWLY
        watched sets too, or the widening would be paid for in false alarms
        on the very rules it was added to watch."""
        src = (
            "class _Fake:\n"
            "    def _rule(self, expr, target):\n"
            "        place = self._path_of(expr)\n"
            "        if place is not None and place in self._linear_alias:\n"
            "            self._linear_alias[target] = place\n"
        )
        self.assertEqual(find_in_source("_fake.py", src), [])

    def test_the_place_separator_is_excluded_and_other_literals_are_not(self):
        """The literal-text signature keys on a literal that is NOT the path
        separator, so path arithmetic over a resolved place does not trip it
        while a text test on any other literal does.

        Both halves are asserted in ONE test because only the CONTRAST shows
        the exclusion is doing work: a "stays quiet" assertion on its own
        passes just as well when the whole signature is absent, which is how
        an earlier draft of this test measured nothing. The two bodies differ
        only in the literal.
        """
        quiet = (
            "class _Fake:\n"
            "    def _rule(self, place):\n"
            "        self._consumed.add(place.split('.', 1)[0])\n"
        )
        loud = (
            "class _Fake:\n"
            "    def _rule(self, place):\n"
            "        self._consumed.add(place.removeprefix('tmp'))\n"
        )
        self.assertEqual(find_in_source("_fake.py", quiet), [])
        self.assertEqual(len(find_in_source("_fake.py", loud)), 1)

    def test_the_shipped_depth_collapse_shape_is_not_flagged(self):
        """``_linear_place``'s depth collapse counts ``.`` in a resolved place
        beside a watched set. It is the closest shipped shape to the exploit
        signature, and it must stay quiet, or the widening would be paid for
        in a false alarm on real code."""
        src = (
            "class _Fake:\n"
            "    def _rule(self, place):\n"
            "        if place.count('.') > 3 and place in self._consumed:\n"
            "            return True\n"
        )
        self.assertEqual(find_in_source("_fake.py", src), [])

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

    def test_the_detector_visits_every_analyzer_module(self):
        """A guard that silently scanned nothing would pass forever, so this
        pins what the detector ACTUALLY traversed.

        The version this replaces re-implemented its own ``os.listdir`` and
        ``.py`` filter and compared that against itself, never touching the
        detector. It was a SECOND HAND-SYNCED COPY of the enumeration, which
        is the exact defect this release exists to remove, sitting inside the
        guard built against that defect. MEASURED vacuous rather than argued:
        narrowing the detector's own extension filter so it scanned ZERO
        modules left all eleven tests in this module GREEN, including that one.

        So the property here is OBSERVATION, not re-derivation. The per-file
        entry point is spied on, the top-level scan is invoked for real, and
        the set of module names it was actually called with must EQUAL the set
        of Python files in the analyzer directory. Nothing skipped, nothing
        invented, and the expected set is read from the directory rather than
        listed here, so adding a module to the package cannot silently leave
        it unscanned.
        """
        adir = _analyzer_dir()
        expected = {n for n in os.listdir(adir) if n.endswith(".py")}
        self.assertGreater(len(expected), 5, sorted(expected))

        import tests.analyzer.test_single_use_resolution_guard as _self
        visited = []
        real = _self.find_in_source

        def _spy(module_name, src):
            visited.append(module_name)
            return real(module_name, src)

        _self.find_in_source = _spy
        try:
            _self.find_syntactic_single_use_rules(adir)
        finally:
            _self.find_in_source = real

        self.assertEqual(
            sorted(visited), sorted(expected),
            "the detector did not traverse what it claims to: it visited %r, "
            "the analyzer package contains %r"
            % (sorted(visited), sorted(expected)),
        )
        # And the modules this defect class lives in are genuinely among them,
        # so a package that shrank to a couple of files could not pass either.
        for required in ("_linear.py", "_discipline.py", "_statements.py",
                         "_expressions.py", "_items.py"):
            self.assertIn(required, visited)


if __name__ == "__main__":
    unittest.main()
