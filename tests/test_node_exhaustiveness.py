"""M1: an additive, fail-closed node-kind exhaustiveness net.

Capa's AST (~61 concrete node kinds in ``capa.capa_ast``) and its CIR
(``capa.ir._nodes``) are dispatched by hand-written ``isinstance`` chains
in many consumers, with no compile-time exhaustiveness. A NEW node kind
can be added and SILENTLY fall through one such chain -- the
one-backend-silent-miscompile class of defect (a program that
``--check``s clean lowers correctly on one backend and wrongly, or not at
all, on the other).

This module generalises the proven ``capa._declassify._ITEM_ROOTS`` +
``__subclasses__()`` guard (see ``tests/test_declassification_sites.py``)
to the CORE dispatchers where a missed node is a real correctness /
soundness bug. Each covered dispatcher declares a handled-set constant
co-located with it in production; this test enumerates every concrete
subclass of that dispatcher's node base and asserts, fail-closed, that

    all_node_kinds == handled_set | deliberately_excluded_set

so a node kind that is neither handled nor explicitly excluded fails HERE,
at the seam, naming the node and the dispatcher, rather than by a silent
fall-through later.

That forward check alone is only half the agreement: it proves every node
kind is NAMED in a dispatcher's declared handled-set, not that the
dispatcher's ``isinstance`` ladder actually DISPATCHES each kind it names.
A kind could sit in the constant while its ``isinstance`` branch is missing
(or wired on only one backend) -- the exact one-backend-silent gap this net
advertises to guard. So this module also adds the REVERSE check: for each
covered dispatcher it DERIVES the dispatched set straight from the
function's source (the ``isinstance(x, Kind)`` branches read via
``inspect.getsource`` + a regex, the same technique
``tests/test_method_emit_agreement.py::_special_cased`` uses) and asserts it
equals the declared constant minus the deliberate exclusions. Forward plus
reverse is a genuine bidirectional constant<->code agreement.

COVERED dispatchers (chosen because a missed kind is a correctness bug):

- ``analyzer._expressions._check_expr_inner`` over AST ``Expr``
  (``CHECKED_EXPR_KINDS``) -- the type checker's expression dispatch.
- ``analyzer._statements._check_stmt`` over AST ``Stmt``
  (``CHECKED_STMT_KINDS``) -- the type checker's statement dispatch.
- ``ir._emit_python._emit_instr`` over CIR ``Instr``
  (``PYTHON_EMITTED_INSTRS``) -- the Python (CIR) backend.
- ``ir._emit_python._format_pattern`` over CIR ``Pattern``
  (``PYTHON_EMITTED_PATTERNS``) -- the Python (CIR) pattern renderer.
- ``ir._emit_wasm._dispatch._emit_instr`` over CIR ``Instr``
  (``WASM_EMITTED_INSTRS``) -- the Wasm backend. Paired with the Python
  ``Instr`` net, this is the direct guard for the one-backend-silent gap:
  an ``Instr`` wired into only one emitter fails the other's net.
- ``transpiler._expressions._emit_expr`` over AST ``Expr``
  (``TRANSPILED_EXPR_KINDS``) -- the legacy transpiler, the DEFAULT
  ``--run`` backend (it walks the AST directly, not the CIR).
- ``transpiler._statements._emit_stmt`` over AST ``Stmt``
  (``TRANSPILED_STMT_KINDS``) -- the legacy transpiler's statement
  dispatch.
- ``transpiler._statements._emit_pattern_match`` over AST ``Pattern``
  (``TRANSPILED_MATCH_PATTERNS``) -- the legacy transpiler's match-pattern
  renderer.

DELIBERATELY EXCLUDED dispatchers (faking a handled-set here would be
theater, per the M1 brief):

- ``ir._emit_wasm._match._emit_match`` dispatches STRUCTURALLY, by
  scrutinee TYPE (Bool / Int / Float / String / tuple / struct / sum),
  and each per-type handler covers a per-type VALID subset of pattern
  kinds (an Int match legitimately never sees a ``PatStruct``). There is
  no single honest "handles all ``Pattern`` subclasses" domain for it, so
  a declared handled-set cannot be kept honest. It is not a node-kind
  dispatcher.
- ``ir._emit_python._format_value`` dispatches on ``Value.kind`` (a
  string tag); ``Value`` has no subclass tree, so there are no node kinds
  to enumerate.
- The reflectively-walked consumers (``capa_ast.dump``, ``_borrow``,
  ``formatter/_comments``, the LSP walkers, ``manifest/_calls`` /
  ``_flow``, ``foreign`` / ``migrate`` / ``repl``) iterate
  ``__dataclass_fields__`` and so AUTO-ADAPT to a new node kind; they need
  no guard. NOTE: the transpiler's CODEGEN dispatchers (``_emit_expr`` /
  ``_emit_stmt`` / ``_emit_pattern_match``) are NOT reflective -- they are
  hand-written isinstance chains, and so are COVERED above; only the
  transpiler's incidental name-collection helpers walk reflectively.

This test is pure Python over class hierarchies (no wasm tooling, no
compilation), so it always collects. It is additive: it changes no
production behaviour.
"""

import inspect
import re
import unittest
from collections import namedtuple

from capa import capa_ast as A
from capa.ir import _nodes as I

from capa.analyzer._expressions import (
    CHECKED_EXPR_KINDS, _ExpressionsMixin as _AnalyzerExprMixin,
)
from capa.analyzer._statements import (
    CHECKED_STMT_KINDS, _StatementsMixin as _AnalyzerStmtMixin,
)
from capa.ir._emit_python import (
    PYTHON_EMITTED_INSTRS, PYTHON_EMITTED_PATTERNS, PythonEmitter,
)
from capa.ir._emit_wasm._dispatch import (
    WASM_EMITTED_INSTRS, _InstrDispatchMixin,
)
from capa.transpiler._expressions import (
    TRANSPILED_EXPR_KINDS, _ExpressionsMixin as _TranspilerExprMixin,
)
from capa.transpiler._statements import (
    TRANSPILED_STMT_KINDS, TRANSPILED_MATCH_PATTERNS,
    _StatementsMixin as _TranspilerStmtMixin,
)


def _concrete_subclasses(base, package):
    """Every concrete subclass of ``base`` declared under ``package``,
    transitively.

    The package filter keeps a throwaway subclass a sibling test may
    define (e.g. ``test_declassification_sites``'s ``NewFangledDecl``)
    from leaking into the real node inventory. Mirrors the enumeration in
    ``tests/test_declassification_sites.py``."""
    out = []
    stack = list(base.__subclasses__())
    while stack:
        cls = stack.pop()
        if cls.__module__.startswith(package):
            out.append(cls)
        stack.extend(cls.__subclasses__())
    return out


def _dispatched_kinds(fn, base, package):
    """The set of node-kind NAMES ``fn`` dispatches, read straight from its
    source: the ``isinstance(x, Kind)`` (and ``isinstance(x, (K1, K2))``)
    branches keyed on the function's own dispatch variable (its first
    parameter after ``self``).

    Reuses ``test_method_emit_agreement._special_cased``'s technique
    (``inspect.getsource`` + a regex over the branch guards) so a newly
    added or removed branch is picked up automatically rather than by a
    hand-list. The result is filtered to real concrete subclasses of
    ``base`` under ``package``, so a non-node ``isinstance`` on the same
    variable (``isinstance(p, str)``) and node names spelled with or without
    an ``A.`` / ``I.`` module prefix are both handled correctly."""
    params = [p for p in inspect.signature(fn).parameters if p != "self"]
    var = re.escape(params[0])
    names = {c.__name__ for c in _concrete_subclasses(base, package)}
    src = inspect.getsource(fn)
    tokens = re.findall(rf'isinstance\(\s*{var}\s*,\s*([\w.]+)\s*\)', src)
    for group in re.findall(
        rf'isinstance\(\s*{var}\s*,\s*\(([^)]*)\)\s*\)', src
    ):
        tokens += re.findall(r'[\w.]+', group)
    return {t.split(".")[-1] for t in tokens if t.split(".")[-1] in names}


#: One covered dispatcher. ``fn`` is the dispatch function itself (used by
#: the reverse check to derive its handled-set from source). ``handled`` is
#: the production-side declared handled-set constant; ``excluded`` is the set
#: this test asserts the dispatcher DELIBERATELY does not handle (each with a
#: reason below).
Dispatcher = namedtuple(
    "Dispatcher", "label fn base package handled excluded",
)


_COVERED = [
    Dispatcher(
        label="analyzer._expressions._check_expr_inner (AST Expr)",
        fn=_AnalyzerExprMixin._check_expr_inner,
        base=A.Expr, package="capa.capa_ast",
        handled=CHECKED_EXPR_KINDS,
        # The analyzer types every expression form; nothing is excluded.
        excluded=frozenset(),
    ),
    Dispatcher(
        label="analyzer._statements._check_stmt (AST Stmt)",
        fn=_AnalyzerStmtMixin._check_stmt,
        base=A.Stmt, package="capa.capa_ast",
        handled=CHECKED_STMT_KINDS,
        # The analyzer checks every statement form; nothing is excluded.
        excluded=frozenset(),
    ),
    Dispatcher(
        label="transpiler._expressions._emit_expr (AST Expr)",
        fn=_TranspilerExprMixin._emit_expr,
        base=A.Expr, package="capa.capa_ast",
        handled=TRANSPILED_EXPR_KINDS,
        # The legacy transpiler (default --run backend) renders every
        # expression form; nothing is excluded.
        excluded=frozenset(),
    ),
    Dispatcher(
        label="transpiler._statements._emit_stmt (AST Stmt)",
        fn=_TranspilerStmtMixin._emit_stmt,
        base=A.Stmt, package="capa.capa_ast",
        handled=TRANSPILED_STMT_KINDS,
        # The legacy transpiler renders every statement form; nothing is
        # excluded.
        excluded=frozenset(),
    ),
    Dispatcher(
        label="transpiler._statements._emit_pattern_match (AST Pattern)",
        fn=_TranspilerStmtMixin._emit_pattern_match,
        base=A.Pattern, package="capa.capa_ast",
        handled=TRANSPILED_MATCH_PATTERNS,
        # The match-pattern renderer covers the full pattern domain with a
        # loud TranspilerError fallthrough; nothing is excluded. (The
        # sibling _emit_pattern_lvalue handles only the let/for-lvalue
        # subset and is deliberately not part of this net.)
        excluded=frozenset(),
    ),
    Dispatcher(
        label="ir._emit_python._emit_instr (CIR Instr)",
        fn=PythonEmitter._emit_instr,
        base=I.Instr, package="capa.ir",
        handled=PYTHON_EMITTED_INSTRS,
        excluded=frozenset({
            # ExprStmt: a value evaluated for its side effect. The lowerer
            # emits the underlying Call / MethodCall with dst=None instead,
            # so this wrapper never reaches the Python emitter.
            I.ExprStmt,
            # ForeignCall: a typed foreign-component boundary crossing.
            # It lowers to a host import call on the Wasm backend only;
            # the Python (CIR) backend does not emit it.
            I.ForeignCall,
        }),
    ),
    Dispatcher(
        label="ir._emit_python._format_pattern (CIR Pattern)",
        fn=PythonEmitter._format_pattern,
        base=I.Pattern, package="capa.ir",
        handled=PYTHON_EMITTED_PATTERNS,
        # The renderer now covers the full CIR pattern domain, including
        # PatOr / PatStruct from the shared lowerer (audit OBS-1, "--ir
        # backend crashes on PatStruct/PatOr", is closed); nothing is
        # excluded.
        excluded=frozenset(),
    ),
    Dispatcher(
        label="ir._emit_wasm._dispatch._emit_instr (CIR Instr)",
        fn=_InstrDispatchMixin._emit_instr,
        base=I.Instr, package="capa.ir",
        handled=WASM_EMITTED_INSTRS,
        excluded=frozenset({
            # ExprStmt: as above, never produced by the lowerer.
            I.ExprStmt,
        }),
    ),
]


class TestNodeExhaustiveness(unittest.TestCase):
    def test_every_node_kind_is_handled_or_excluded(self):
        """The fail-closed net: for each covered dispatcher, every
        concrete node subclass of its base must be either handled or
        explicitly excluded. A new node kind that is neither fails here,
        named alongside the dispatcher that forgot it."""
        for d in _COVERED:
            with self.subTest(dispatcher=d.label):
                kinds = set(_concrete_subclasses(d.base, d.package))
                unaccounted = kinds - d.handled - d.excluded
                self.assertEqual(
                    sorted(c.__name__ for c in unaccounted), [],
                    f"node kind(s) neither handled nor excluded by "
                    f"{d.label}: "
                    f"{sorted(c.__name__ for c in unaccounted)}. Add each to "
                    f"that dispatcher's branch AND its declared handled-set, "
                    f"or record it as a deliberate exclusion in "
                    f"tests/test_node_exhaustiveness.py.",
                )

    def test_declared_constant_matches_the_dispatched_ladder(self):
        """The reverse half of the agreement: every kind NAMED in a
        dispatcher's declared handled-set must actually be dispatched by its
        ``isinstance`` ladder, and vice versa. A kind left in the constant
        while its branch is dropped (or wired on only one backend) fails
        here, naming the dispatcher and the drifted kind -- the
        one-backend-silent gap the forward check cannot see."""
        for d in _COVERED:
            with self.subTest(dispatcher=d.label):
                dispatched = _dispatched_kinds(d.fn, d.base, d.package)
                declared = {c.__name__ for c in (d.handled - d.excluded)}
                self.assertEqual(
                    dispatched, declared,
                    f"{d.label}: its source-derived isinstance ladder and "
                    f"its declared handled-set disagree. In the constant but "
                    f"not dispatched: {sorted(declared - dispatched)}; "
                    f"dispatched but not in the constant: "
                    f"{sorted(dispatched - declared)}. Re-sync the "
                    f"dispatcher's branches with its handled-set constant.",
                )

    def test_handled_and_excluded_are_disjoint(self):
        """A kind cannot be both handled and deliberately excluded; that
        would mask a real dispatch decision behind a stale exclusion."""
        for d in _COVERED:
            with self.subTest(dispatcher=d.label):
                overlap = sorted(
                    c.__name__ for c in (d.handled & d.excluded)
                )
                self.assertEqual(overlap, [])

    def test_no_stale_handled_or_excluded_entries(self):
        """Every class named in a handled-set or an exclusion is a real
        concrete node kind of that dispatcher's base. Renaming or removing
        a node without pruning the set fails here rather than silently
        widening the accepted domain."""
        for d in _COVERED:
            with self.subTest(dispatcher=d.label):
                kinds = set(_concrete_subclasses(d.base, d.package))
                stale = sorted(
                    c.__name__ for c in (d.handled | d.excluded) - kinds
                )
                self.assertEqual(stale, [])


if __name__ == "__main__":
    unittest.main()
