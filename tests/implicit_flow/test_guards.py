"""Fail-closed guards for the implicit-flow walker and its loop fixpoint.

Each guard here is an INDEPENDENT construction of a set the compiler also
computes, so a member the compiler forgets appears as a disagreement
rather than staying invisible until someone builds the program that
exercises it:

- the LABEL CHANNELS the loop fixpoint observes, declared once in the
  label module, must equal the label-bearing state the analyzer package
  WRITES (derived from its source), and the accessor's snapshot must move
  when any declared channel moves (a runtime sensitivity check, so a body
  that stops reading a declared channel fails even with the declaration
  intact);
- the EXIT KINDS the walker attributes to a statement must equal what a
  reflective walk of the statement's subtree finds, for every statement of
  every fixture and shipped example, with the reference walk's leaf kinds
  and loop / lambda boundaries written here, not shared with the walker;
- the BODY POSITIONS (every AST field that holds a statement sequence) are
  derived from the AST dataclasses and must each have a refused member;
- there is ONE statement walker: every call of the statement dispatcher in
  the analyzer package is inside it;
- there is ONE exit enumeration: inside the analyzer package, no site
  outside the exit-syntax module reasons about the jump classes AS A SET,
  so no rule there can grow a private second opinion about what leaves a
  block. Naming ONE class is ordinary work and is not checked, and the
  scope is the analyzer package: modules that render or lower a statement
  name several classes to choose a syntax, which is not a claim about
  leaving a block;
- the exit kinds that END a loop, declared for the test package in
  ``_loop_ending`` so the head-pc pins can enumerate them, are the set the
  walker's head-pc rule quantifies over, so a kind added to one and not
  the other fails here instead of leaving the new kind unpinned;
- the fixpoint's per-analysis counters are surfaced on the result, read 0
  overruns on every pin, and read more than 0 when the cap is forced low.
"""

import ast
import re
import unittest
from unittest import mock

from capa import Lexer, Parser, analyze
from capa import _labels as L
from capa import capa_ast as A
from capa.analyzer import Analyzer, Symbol, SymbolKind
from capa.analyzer._exit_syntax import _ExitSyntaxMixin
from capa.analyzer._ifc import _IfcMixin
from capa.builtins import BUILTIN_POS
from capa.capa_ast._walk import children, walk
from capa.tokens import Pos
from capa.typesys import TyInt

from tests.implicit_flow._harness import FIXTURES, REPO, check_fixture, provenance_ok
from tests.implicit_flow._loop_ending import (
    EXIT_FORMS, LOOP_ENDING_KINDS, NON_ENDING_KINDS, loop_ending_probes,
)

ANALYZER_DIR = REPO / "capa" / "analyzer"


def _parse(source):
    return Parser(Lexer(source).lex(), source=source).parse_module()


def _all_fixture_files():
    files = sorted(FIXTURES.rglob("*.capa"))
    files += sorted((REPO / "examples").rglob("*.capa"))
    return files


# ---------------------------------------------------------------------
# Guard 1: the label channels
# ---------------------------------------------------------------------

#: The static derivation's grammar (its BOUND, stated): an assignment or
#: augmented / annotated assignment, or a subscript store, whose target is
#: ``<base>.<attr>`` with ``base`` one of the names below and ``attr``
#: naming a label, a taint or a split.
_LABELISH = re.compile(r"label|taint|split", re.I)
_BINDING_BASES = {"sym", "root", "new_sym"}
_ANALYZER_BASES = {"self"}


def _label_store_writes():
    """(owner, name) for every label-bearing attribute the analyzer
    package writes, by the grammar above."""
    out = set()
    for path in sorted(ANALYZER_DIR.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                targets = list(node.targets)
            elif isinstance(node, (ast.AugAssign, ast.AnnAssign)):
                targets = [node.target]
            else:
                continue
            for target in targets:
                if isinstance(target, ast.Subscript):
                    target = target.value
                if not (isinstance(target, ast.Attribute)
                        and isinstance(target.value, ast.Name)):
                    continue
                base, attr = target.value.id, target.attr
                if not _LABELISH.search(attr):
                    continue
                if base in _ANALYZER_BASES:
                    out.add(("analyzer", attr))
                elif base in _BINDING_BASES:
                    out.add(("binding", attr))
    return out


class _Probe:
    """A value no channel ever holds; its rendering is unique."""

    def __repr__(self):
        return "<label-channel-probe>"


class LabelChannelGuard(unittest.TestCase):
    """The fixpoint observes exactly the channels the store writes."""

    def test_declared_channels_equal_the_written_set(self):
        writes = _label_store_writes()
        declared = set(_IfcMixin._LABEL_CHANNELS)
        excluded = set(_IfcMixin._LABEL_CHANNEL_EXCLUSIONS)
        self.assertTrue(writes, "the static derivation found nothing")
        written_names = {name for _, name in writes}
        stale = excluded - written_names
        self.assertEqual(stale, set(), f"excluded channels nobody writes: {stale}")
        must_observe = {(o, n) for o, n in writes if n not in excluded}
        missing = must_observe - declared
        ghost = declared - writes
        self.assertEqual(missing, set(), f"written, not observed: {missing}")
        self.assertEqual(ghost, set(), f"observed, never written: {ghost}")

    def test_every_exclusion_carries_a_reason(self):
        for name, reason in _IfcMixin._LABEL_CHANNEL_EXCLUSIONS.items():
            self.assertTrue(reason.strip(), name)

    def _live_analyzer(self):
        an = Analyzer(source="")
        an._install_builtins()
        an._push_scope()
        sym = Symbol(name="probe", kind=SymbolKind.LOCAL_VAR,
                     pos=Pos(line=1, col=1, offset=0), ty=TyInt)
        an.scope.define(sym)
        return an, sym

    def test_snapshot_moves_with_every_declared_channel(self):
        an, sym = self._live_analyzer()
        an._container_taint_map()
        base = an._label_channels()
        self.assertEqual(base, an._label_channels(), "the snapshot is not stable")
        for owner, name in _IfcMixin._LABEL_CHANNELS:
            with self.subTest(channel=name):
                target = sym if owner == "binding" else an
                old = getattr(target, name, None)
                setattr(target, name, _Probe())
                try:
                    self.assertNotEqual(base, an._label_channels(),
                                        f"the snapshot does not read {name}")
                finally:
                    setattr(target, name, old)
                self.assertEqual(base, an._label_channels())

    def test_snapshot_moves_with_the_real_shapes(self):
        an, sym = self._live_analyzer()
        an._container_taint_map()
        base = an._label_channels()
        sym.label = "secret"
        raised = an._label_channels()
        self.assertNotEqual(base, raised)
        an._container_taint_map()[(id(sym), ())] = "secret"
        self.assertNotEqual(raised, an._label_channels())

    def test_snapshot_is_comparable_and_hashable(self):
        an, _ = self._live_analyzer()
        hash(an._label_channels())


# ---------------------------------------------------------------------
# Guard 2: the exit kinds, against an independent reflective walk
# ---------------------------------------------------------------------

def _is_builtin_panic(an, node):
    if not (isinstance(node, A.Call) and isinstance(node.callee, A.Ident)
            and node.callee.name == "panic"):
        return False
    sym = an.bindings.get(id(node.callee))
    return sym is not None and sym.pos == BUILTIN_POS


_LEAF_KINDS = {A.ReturnStmt: "return", A.BreakStmt: "break", A.ContinueStmt: "continue"}


def _reference_kinds(an, node, out, inner_loop=False):
    """Every exit kind syntactically reachable from ``node`` that leaves
    the body ``node`` sits in: a lambda is a frame boundary, a loop BODY
    consumes its own break / continue, a builtin ``panic`` is a return,
    and so is a ``?``, which leaves the frame when its operand is an
    ``Err``. ``_LEAF_KINDS`` stays statement-only because a ``?`` is not
    a leaf statement: it is an expression whose operand is walked on."""
    if node is None or isinstance(node, A.LambdaExpr):
        return
    leaf = _LEAF_KINDS.get(type(node))
    if leaf is not None:
        if leaf == "return" or not inner_loop:
            out.add(leaf)
    elif _is_builtin_panic(an, node) or isinstance(node, A.Try):
        out.add("return")
    if isinstance(node, (A.WhileStmt, A.ForStmt)):
        for child in children(node):
            _reference_kinds(an, child, out, inner_loop or child is node.body)
        return
    for child in children(node):
        _reference_kinds(an, child, out, inner_loop)


class ExitKindGuard(unittest.TestCase):
    """The walker's exit kinds agree with the reference walk on every
    statement of every fixture and shipped example."""

    def test_agreement_over_the_corpus(self):
        self.assertTrue(provenance_ok())
        checked = 0
        disagreements = []
        for path in _all_fixture_files():
            source = path.read_text(encoding="utf-8")
            try:
                module = _parse(source)
            except Exception:
                continue
            an = Analyzer(source=source)
            an.analyze(module)
            for node in walk(module):
                if not isinstance(node, A.Stmt):
                    continue
                checked += 1
                got = set(an._paths(node, an._ALL_KINDS).exits)
                want = set()
                _reference_kinds(an, node, want)
                if got != want:
                    disagreements.append(
                        (path.name, type(node).__name__, node.pos.line,
                         sorted(got), sorted(want)),
                    )
        self.assertGreater(checked, 1000, "the corpus is too small to mean anything")
        self.assertEqual(disagreements, [])

    def test_return_carried_match_arms_are_kinded_by_arm(self):
        source = (
            "@strict_ifc()\n"
            "fun f(env: Env) -> Int\n"
            '    let k = env.get("K").unwrap_or("")\n'
            "    for i in 0..3\n"
            '        return match k.starts_with("s")\n'
            "            v if v ->\n"
            "                break\n"
            "            _ ->\n"
            "                continue\n"
            "    return 0\n"
        )
        module = _parse(source)
        an = Analyzer(source=source)
        an.analyze(module)
        ret = next(n for n in walk(module) if isinstance(n, A.ReturnStmt) and n.value is not None)
        paths = an._paths(ret, an._ALL_KINDS)
        # The arms' own kinds reach the loop; ``return`` is still listed
        # (a return statement always may return, syntactically), and no
        # path terminates normally.
        self.assertLessEqual({"break", "continue"}, set(paths.exits))
        self.assertFalse(paths.may_normal)


# ---------------------------------------------------------------------
# Guard 3: the body positions
# ---------------------------------------------------------------------

def _block_fields():
    """Every AST dataclass field whose annotation names ``Block``."""
    out = set()
    for name in dir(A):
        obj = getattr(A, name)
        if not (isinstance(obj, type) and hasattr(obj, "__dataclass_fields__")):
            continue
        for f in obj.__dataclass_fields__.values():
            if "Block" in str(f.type):
                out.add(f"{obj.__name__}.{f.name}")
    return out


class BodyPositionGuard(unittest.TestCase):
    """A new Block-typed field fails here until a refused member exists."""

    def test_every_position_has_a_member(self):
        positions = _block_fields()
        self.assertEqual(len(positions), 8, positions)
        fixtures = {p.stem for p in (FIXTURES / "positions").glob("pos_*.capa")}
        want = {"pos_" + p.lower().replace(".", "_").replace("_block", "").replace("_arms", "")
                for p in positions}
        self.assertEqual(fixtures, want)
        for name in fixtures:
            with self.subTest(program=name):
                self.assertFalse(check_fixture("positions", name).ok, name)


# ---------------------------------------------------------------------
# Guard 4: one walker
# ---------------------------------------------------------------------

class WalkerIdentityGuard(unittest.TestCase):
    """Every call of the statement dispatcher in the analyzer package is
    inside the one walker, so no body position can be walked without the
    normal-termination label."""

    def test_the_dispatcher_has_one_caller(self):
        callers = set()
        for path in sorted(ANALYZER_DIR.glob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for fn in ast.walk(tree):
                if not isinstance(fn, ast.FunctionDef):
                    continue
                for node in ast.walk(fn):
                    if (isinstance(node, ast.Call)
                            and isinstance(node.func, ast.Attribute)
                            and node.func.attr == "_check_stmt"):
                        callers.add(f"{path.name}:{fn.name}")
        self.assertEqual(callers, {"_statements.py:_check_stmt_seq"})


# ---------------------------------------------------------------------
# Guard 5: one exit enumeration
# ---------------------------------------------------------------------

#: The AST classes that ARE an exit form. Written here, not imported from
#: the analyzer, so a class added to the analyzer's own list and to no
#: reference set is still checked.
_JUMP_CLASSES = {"ReturnStmt", "BreakStmt", "ContinueStmt"}

#: The places allowed to reason about the exit forms AS A SET: the
#: exit-syntax module, which answers the question, and the walker's own
#: per-shape dispatcher and its exhaustiveness table, which route a
#: statement to its checker and ask nothing about leaving.
_ALLOWED_SET_SITES = {
    "_statements.py:_check_stmt",
    "_statements.py:<module>",
}
_EXIT_SYNTAX_MODULE = "_exit_syntax.py"


def _jump_class_set_sites():
    """``file.py:function`` for every place in the analyzer package that
    names MORE THAN ONE of the jump classes.

    Naming one of them is ordinary work (a ``return``'s value is read at
    several sites, and its type is annotated). Naming SEVERAL is a claim
    about which forms leave a block: that is the enumeration, and it has
    one home."""
    out = {}
    for path in sorted(ANALYZER_DIR.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        owner = {}
        for fn in ast.walk(tree):
            if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for node in ast.walk(fn):
                    owner.setdefault(id(node), fn.name)
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Attribute)
                    and node.attr in _JUMP_CLASSES):
                continue
            site = f"{path.name}:{owner.get(id(node), '<module>')}"
            out.setdefault(site, set()).add(node.attr)
    return {site: kinds for site, kinds in out.items() if len(kinds) > 1}


class ExitEnumerationGuard(unittest.TestCase):
    """There is ONE enumeration of the forms that leave a block.

    Every rule that asks "does this block or statement leave, and by
    which kind" (the implicit-flow pc, the linear suspension, the branch
    merge, the arm typing of a ``match``, the falls-through check of a
    declared return type) asks ``_exit_syntax``. A second, private test
    re-introduced at any of those sites is a hand-synced copy that can
    silently disagree and that no verdict pin need notice.

    What is checked, exactly: a site INSIDE ``capa/analyzer`` that names
    MORE THAN ONE jump class, outside the exit-syntax module and the two
    allowances, fails. Naming one class is ordinary work (a ``return``'s
    value is read at several sites) and passes. The scope is the analyzer
    package because that is where the question is asked; sites elsewhere
    that name several classes choose a rendering or a lowering, not
    whether a block is left. A site that reaches the same second opinion
    without naming the classes together (three one-name helpers, an
    attribute fetched by name) is outside this derivation's reach and is
    covered by the behavioural pins instead."""

    def test_the_exit_forms_are_enumerated_in_one_module(self):
        sites = _jump_class_set_sites()
        self.assertTrue(sites, "the derivation found nothing")
        stray = {
            site: sorted(kinds) for site, kinds in sites.items()
            if not site.startswith(_EXIT_SYNTAX_MODULE)
            and site not in _ALLOWED_SET_SITES
        }
        self.assertEqual(stray, {}, f"a second exit enumeration: {stray}")

    def test_every_allowance_is_still_a_real_site(self):
        # An allowance nobody uses is a stale exemption that would hide
        # the next copy: it has to name a site the derivation finds.
        sites = set(_jump_class_set_sites())
        self.assertEqual(_ALLOWED_SET_SITES - sites, set())

    def test_the_seam_answers_every_consumer(self):
        # The four questions, asked of one analyzer on one program, so a
        # consumer that stopped routing through the seam shows up as a
        # disagreement rather than as a silent second opinion.
        source = (
            "fun f(c: Bool) -> Int\n"
            "    if c\n"
            "        return 1\n"
            "    else\n"
            '        panic("no")\n'
        )
        module = _parse(source)
        an = Analyzer(source=source)
        result = an.analyze(module)
        self.assertEqual([e.message for e in result.errors], [])
        fn = next(n for n in walk(module) if isinstance(n, A.FunDecl))
        self.assertFalse(an._paths(fn.body, an._ALL_KINDS).may_normal)
        then_block = next(
            n for n in walk(module) if isinstance(n, A.IfStmt)
        ).then_block
        self.assertTrue(an._block_leaves(then_block))
        self.assertEqual(an._jump_kind(then_block.stmts[-1]), "return")


# ---------------------------------------------------------------------
# Guard 6: the fixpoint counters
# ---------------------------------------------------------------------

class FixpointCounters(unittest.TestCase):
    """The per-analysis pass / overrun counters are on the result, read 0
    overruns on every pin, and observe an overrun when the cap is low."""

    CHAINS = [p.stem for p in sorted((FIXTURES / "loop_chains").glob("*.capa"))]

    def _result(self, source):
        return analyze(_parse(source), source=source)

    def test_no_overrun_on_any_fixture(self):
        worst = 0
        for path in sorted(FIXTURES.rglob("*.capa")):
            source = path.read_text(encoding="utf-8")
            try:
                module = _parse(source)
            except Exception:
                continue
            r = analyze(module, source=source)
            with self.subTest(program=path.name):
                self.assertEqual(r.fixpoint_overruns, 0)
            worst = max(worst, r.fixpoint_max_passes)
        self.assertGreater(worst, 2, "no fixture needed the fixpoint")
        self.assertLessEqual(worst, 12, "a chain needed more passes than links + 3")

    def test_counters_are_per_analysis(self):
        long_chain = (FIXTURES / "loop_chains" / "lc19_eightlink_break.capa").read_text(encoding="utf-8")
        r1 = self._result(long_chain)
        self.assertGreaterEqual(r1.fixpoint_max_passes, 8)
        r2 = self._result("fun main(stdio: Stdio)\n    stdio.println(\"x\")\n")
        self.assertEqual((r2.fixpoint_max_passes, r2.fixpoint_overruns), (0, 0))

    def test_low_cap_shows_overruns_and_fails_closed(self):
        overruns = 0
        with mock.patch.object(Analyzer, "_FIXPOINT_CAP", 2):
            for name in self.CHAINS:
                r = check_fixture("loop_chains", name)
                overruns += r.fixpoint_overruns
                self.assertLessEqual(r.fixpoint_max_passes, 2, name)
        self.assertGreater(overruns, 0)
        # The cap fails CLOSED: with every exit kind forced secret, a
        # chain member is still refused.
        with mock.patch.object(Analyzer, "_FIXPOINT_CAP", 2):
            r = check_fixture("loop_chains", "lc19_eightlink_break")
        self.assertFalse(r.ok)


# ---------------------------------------------------------------------
# Guard 7: the loop-ending kind set and the exit forms
# ---------------------------------------------------------------------

def _own_exit_node_types(sources):
    """The name of every AST node type the walker gives an exit of its
    OWN to, across the programs in ``sources``.

    An exit is the node's OWN when the walker attributes it to the node
    and no child of the node already carries it. That is a question about
    BEHAVIOUR, asked of the walker itself, so the derivation keeps no
    list of node names: a carrier fails it because every exit a carrier
    has came from inside it, a lambda fails it because the walk stops at
    a frame boundary and it has no exits at all, and the shapes that are
    left, among those the programs in ``sources`` spell, are the ones a
    generated program has to be able to spell. A program that does not
    parse is skipped, as elsewhere in this module: the corpus carries
    deliberately invalid fixtures."""
    found = set()
    for source in sources:
        try:
            module = _parse(source)
        except Exception:
            continue
        an = Analyzer(source=source)
        an.analyze(module)
        for node in walk(module):
            own = set(an._paths(node, an._ALL_KINDS).exits)
            if not own:
                continue
            for child in children(node):
                own -= set(an._paths(child, an._ALL_KINDS).exits)
                if not own:
                    break
            if own:
                found.add(type(node).__name__)
    return found


def _corpus_sources():
    """Every fixture and shipped example, as source text."""
    return [p.read_text(encoding="utf-8") for p in _all_fixture_files()]


class LoopEndingKindGuard(unittest.TestCase):
    """The kind set the head-pc pins enumerate is the one the walker uses,
    and every exit FORM they can spell is one the walker agrees about.

    The pins score programs that differ only in the exit a loop ends by,
    built from the sets ``_loop_ending`` declares. Declaring them there
    rather than importing them from the compiler keeps the expectation
    independent of the implementation it scores, and this guard is what
    makes that safe: a kind added to the walker's ``_LOOP_ENDING_KINDS``
    and not to the test package's set would otherwise be a hole in the
    net exactly where a new kind needs one, and a kind added to the test
    package alone would score a rule the walker does not have.

    A kind set alone does not bound that net, and the last two tests are
    what narrow the gap. The generator's real parameter is the SYNTAX of
    the exit, not its kind name: several forms share the kind ``return``,
    among them the keyword under an enclosing guard and ``?``, whose own
    operand can carry the dependence. Comparing sets of NAMES cannot see
    a form the generator is unable to spell, so the two directions are
    checked separately and against different sources.

    Outward, the walker is ASKED about each form the generator emits, and
    must end the loop exactly when the form's kind says so. Inward, the
    node types the walker gives an exit of its OWN to are collected by
    asking the walker about the fixture and example corpus, and each must
    have a form: that direction cannot be satisfied by the generator's
    own declaration, so DELETING a form whose shape the corpus spells
    fails here rather than silently shrinking the net (the bound is
    stated on that test). Both directions put behavioural questions to
    the walker and keep no list of node names to exempt, so there is
    nothing here that an edit to a list can narrow."""

    def test_the_declared_set_is_the_walker_set(self):
        self.assertEqual(
            set(LOOP_ENDING_KINDS), set(_ExitSyntaxMixin._LOOP_ENDING_KINDS),
        )

    def test_the_two_halves_partition_the_exit_kinds(self):
        # Every kind that can leave a body either ends a loop or does not,
        # so a kind added to the walker with no side chosen fails here.
        self.assertEqual(
            set(LOOP_ENDING_KINDS) | set(NON_ENDING_KINDS),
            set(_ExitSyntaxMixin._ALL_KINDS),
        )
        self.assertEqual(
            set(LOOP_ENDING_KINDS) & set(NON_ENDING_KINDS), set(),
        )

    def test_every_emitted_form_ends_a_loop_exactly_when_declared(self):
        # The walker is ASKED, on a program the generator itself built, so
        # a form it can spell but the walker does not recognise fails here
        # rather than scoring as an accepted program nobody looks at. The
        # question is put the way the loop rule puts it: the body's own
        # exit map (which includes the ``break`` the loop consumes), then
        # the one head-pc join, which rises above a public entry exactly
        # when that map gives a secret label to a kind that ends the loop.
        # Every probe takes its exit under the secret, so the join rises
        # exactly for the forms whose kind ends a loop.
        self.assertTrue(provenance_ok())
        asked = 0
        for form, source in loop_ending_probes():
            asked += 1
            with self.subTest(form=form.name):
                module = _parse(source)
                an = Analyzer(source=source)
                an.analyze(module)
                loop = next(n for n in walk(module)
                            if isinstance(n, (A.WhileStmt, A.ForStmt)))
                body = an._paths(loop.body, an._ALL_KINDS)
                ends = an._loop_head_pc(L.PUBLIC, body.exits) != L.PUBLIC
                self.assertEqual(
                    ends, form.kind in LOOP_ENDING_KINDS,
                    f"form {form.name!r} (kind {form.kind!r}) ends the loop: "
                    f"{ends}, declared {form.kind in LOOP_ENDING_KINDS}; "
                    f"the loop body's exits are {body.exits}",
                )
        self.assertEqual(asked, len(EXIT_FORMS), "a form was never asked about")

    def test_the_exit_node_types_of_the_corpus_each_have_a_form(self):
        # The other direction, and the one the generator cannot satisfy by
        # declaring it: every node type the walker gives an exit of its
        # OWN to somewhere in the corpus must be reachable by some form
        # the generator emits. A form deleted from the table therefore
        # fails here, which is what stops the net shrinking back to the
        # spellings it happens to have.
        #
        # BOTH sides are asked of the walker, through the one derivation,
        # so there is nothing to keep in step by hand: no list of carriers
        # to exempt, no list of names tested for another reason, and no
        # dependence on HOW the module spells a type test.
        #
        # The BOUND, stated rather than implied: the shapes are read off
        # the fixture tree and the shipped examples, so a shape the walker
        # could exit for that no program there spells is invisible here.
        # The size check keeps an EMPTIED corpus from reading as a pass;
        # it does not bound a corpus that merely stops spelling one shape,
        # which is why the hand-written members of each form stay.
        self.assertTrue(provenance_ok())
        corpus = _corpus_sources()
        self.assertGreater(
            len(corpus), 100, "the corpus is too small to mean anything",
        )
        producing = _own_exit_node_types(corpus)
        self.assertTrue(producing, "the derivation found nothing")
        covered = _own_exit_node_types(
            source for _form, source in loop_ending_probes()
        )
        self.assertEqual(
            producing - covered, set(),
            f"the walker gives these node types an exit of their own and no "
            f"generated form reaches one: {sorted(producing - covered)}",
        )


if __name__ == "__main__":
    unittest.main()
