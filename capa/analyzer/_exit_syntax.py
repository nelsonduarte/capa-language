"""The exit syntax of the statement walker: the write-pure half.

Every question here is syntactic and answered over the AST after the
node was checked: by which kinds can this node leave the body it sits
in, under which guards, and what is its normal-termination label (Myers'
path labels). ``_paths`` is the ONE traversal that answers them; the
walker in ``_statements.py`` folds its answers along a body with
``_Paths.then`` (the one sequencing rule) and the loop rule reads the
``break`` entry of the folded exit map.

Write-pure, not pure: these methods write no analyzer state, but they
READ the labels the checker recorded for expressions (``_label_of``)
and the binding table (``_is_panic_call``), so they are correct only
once the node has been checked. The stateful half (the walker, the loop
rule, the fixpoint, the speculative-pass seam) stays with the state in
``_statements.py``.
"""

from __future__ import annotations

from typing import NamedTuple

from .. import capa_ast as A
from .. import _labels as L
from ..capa_ast._walk import children


class _Paths(NamedTuple):
    """Myers' path labels of one node, relative to the body it sits in.

    ``exits`` maps each kind by which the node may leave that body to the
    label of the guards it leaves under; an absent kind means the node
    cannot leave the body that way. ``norm`` is the normal-termination
    label: the information conveyed by control reaching the node's
    successor in the body. ``may_normal`` is False when no path through
    the node terminates normally, so nothing after it in the body runs.
    """

    exits: dict
    norm: str
    may_normal: bool

    def then(self, nxt: "_Paths") -> "_Paths":
        """Sequence ``self`` before ``nxt``: the ONE sequencing rule. The
        successor is reached only when ``self`` terminated normally, so
        its exits are taken under ``self.norm`` too, and the sequence
        terminates normally under the join of both labels."""
        exits = dict(self.exits)
        for kind, label in nxt.exits.items():
            exits[kind] = L.join(exits.get(kind), L.join(self.norm, label))
        return _Paths(
            exits, L.join(self.norm, nxt.norm),
            self.may_normal and nxt.may_normal,
        )


#: The paths of nothing: no exits, a public normal termination.
_NO_PATHS = _Paths({}, L.PUBLIC, True)



class _ExitSyntaxMixin:
    #: The kinds by which control can leave a body. A bare ``panic``
    #: leaves the frame, so it is kinded ``return``.
    _ALL_KINDS = frozenset({"return", "break", "continue"})
    #: The only kind that leaves a loop body for the enclosing body: a
    #: loop consumes its own ``break`` / ``continue``.
    _RETURN_KIND = frozenset({"return"})
    #: The kinds that END a loop, so the guards they are taken under
    #: decide HOW MANY TIMES the body and the controlling expression run:
    #: a ``break`` leaves the loop and a ``return`` leaves the whole
    #: frame, which ends the loop with it. A ``continue`` skips the rest
    #: of one iteration without changing how many there are, so it is not
    #: here. Declared once and read only through :meth:`_loop_head_pc`.
    _LOOP_ENDING_KINDS = frozenset({"break", "return"})

    def _loop_head_pc(self, pc_at_head, exits: dict) -> str:
        """THE ONE head pc of a loop: the pc at the loop's head joined
        with the label of every exit kind that ENDS the loop
        (``_LOOP_ENDING_KINDS``) in ``exits``. Everything whose number of
        executions the loop decides runs under it: the body, the counter
        a body statement increments, a container the loop mutates, and a
        ``while``'s controlling expression."""
        label = pc_at_head
        for kind in sorted(self._LOOP_ENDING_KINDS):
            label = L.join(label, exits.get(kind, L.PUBLIC))
        return label

    def _jump_kind(self, node):
        """The kind of an unconditional exit: a ``return`` / ``break`` /
        ``continue`` statement, or a call of the builtin ``panic`` (which
        leaves the frame), as an expression or as a bare statement.
        ``None`` for anything else, including a ``?`` / ``Try`` early
        return, which is not a recognised exit form (a disclosed
        residual: a branch that leaves through ``?`` reads as one that
        terminates normally)."""
        if isinstance(node, A.ReturnStmt):
            return "return"
        if isinstance(node, A.BreakStmt):
            return "break"
        if isinstance(node, A.ContinueStmt):
            return "continue"
        if isinstance(node, A.ExprStmt):
            return self._jump_kind(node.expr)
        if self._is_panic_call(node):
            return "return"
        return None

    def _block_leaves(self, block) -> bool:
        """True when a block's last statement is a jump (or a builtin
        ``panic``), so the block reaches no merge point after it: the
        one test the branch merges and the linear suspension share."""
        return bool(block.stmts) and self._jump_kind(block.stmts[-1]) is not None

    def _is_panic_call(self, e) -> bool:
        """True if ``e`` is a call to the built-in ``panic`` (a divergent
        abort that writes to stderr). Mirrors ``_is_declassify_call``'s
        builtin-position guard so a user function named ``panic`` is not
        treated as divergent here."""
        from ..builtins import BUILTIN_POS
        if not isinstance(e, A.Call):
            return False
        if not isinstance(e.callee, A.Ident) or e.callee.name != "panic":
            return False
        sym = self.bindings.get(id(e.callee))
        return sym is not None and sym.pos == BUILTIN_POS

    def _guarded_arms(self, node):
        """``(guard expressions, guard label, arm bodies)`` for a node that
        selects one of several bodies by a guard: an ``if`` statement (the
        implicit fall-through of a missing ``else`` is a ``None`` arm), a
        ``match`` expression, an ``if`` expression. The guard label is
        the join of every guard, the over-approximation the strict tier
        applies to every branching construct: it can only raise a pc,
        never lower one. ``None`` for any other node."""
        if isinstance(node, A.IfStmt):
            guards = [node.cond] + [c for c, _ in node.elif_arms]
            bodies = (
                [node.then_block] + [b for _, b in node.elif_arms]
                + [node.else_block]
            )
        elif isinstance(node, A.MatchExpr):
            guards = [node.scrutinee] + [
                a.guard for a in node.arms if a.guard is not None
            ]
            bodies = [a.body for a in node.arms]
        elif isinstance(node, A.IfExpr):
            guards = [node.cond]
            bodies = [node.then_expr, node.else_expr]
        else:
            return None
        return guards, L.join_all(self._label_of(g) for g in guards), bodies

    def _paths(self, node, kinds) -> _Paths:
        """THE ONE syntactic traversal behind the implicit-flow rules: the
        path labels of ``node`` relative to the body it sits in, where
        ``kinds`` are the exit kinds that leave that body (``_ALL_KINDS``
        for a statement of the body itself, ``_RETURN_KIND`` once the
        traversal has entered a loop, whose own ``break`` / ``continue``
        do not leave the enclosing body).

        A jump leaves by its kind; a guarded construct leaves by every
        kind an arm leaves by, under the guard, and terminates normally
        under the guard when some arm may leave and some arm may not
        (all-paths exclusion: an arm that leaves on every path does not
        make the construct's normal termination secret, because reaching
        the successor reveals only that the other arms ran); a loop
        leaves only by ``return`` from its body, under its controlling
        expression; a lambda is a frame of its own, so a definition
        leaves by nothing; every other node folds its children in
        evaluation order with ``_Paths.then``. A ``match`` or ``if``
        expression is found wherever it sits in an expression, not only
        when directly carried by a statement."""
        if node is None or isinstance(node, A.LambdaExpr):
            return _NO_PATHS
        if isinstance(node, A.Block):
            return self._paths_seq(node.stmts, kinds)
        kind = self._jump_kind(node)
        if kind is not None:
            # The operand (a returned value, a panic's arguments) runs
            # first and may itself leave the body; the jump fires when it
            # terminates normally.
            operand = self._paths_seq(list(children(node)), kinds)
            leaves = {kind: L.PUBLIC} if kind in kinds else {}
            return operand.then(_Paths(leaves, L.PUBLIC, False))
        if isinstance(node, (A.WhileStmt, A.ForStmt)):
            ctrl = node.cond if isinstance(node, A.WhileStmt) else node.iter
            before = self._paths(ctrl, kinds)
            body = self._paths(node.body, kinds & self._RETURN_KIND)
            ctrl_label = self._label_of(ctrl)
            exits = {k: L.join(ctrl_label, v) for k, v in body.exits.items()}
            norm = L.join(ctrl_label, body.norm) if exits else L.PUBLIC
            return before.then(_Paths(exits, norm, True))
        arms = self._guarded_arms(node)
        if arms is not None:
            guards, guard_label, bodies = arms
            before = self._paths_seq(guards, kinds)
            exits: dict = {}
            norm = L.PUBLIC
            may_normal = False
            for body in bodies:
                arm = self._paths(body, kinds)
                for k, v in arm.exits.items():
                    exits[k] = L.join(exits.get(k), L.join(guard_label, v))
                if arm.may_normal:
                    may_normal = True
                    norm = L.join(norm, arm.norm)
            if exits:
                norm = L.join(norm, guard_label)
            return before.then(_Paths(exits, norm, may_normal))
        return self._paths_seq(list(children(node)), kinds)

    def _paths_seq(self, nodes, kinds) -> _Paths:
        """The paths of ``nodes`` run in order."""
        acc = _NO_PATHS
        for node in nodes:
            acc = acc.then(self._paths(node, kinds))
        return acc

    def _exits_fingerprint(self, exits: dict) -> tuple:
        """A comparable rendering of an exit map, for the fixpoint."""
        return tuple(sorted((k, L.normalize(v)) for k, v in exits.items()))
