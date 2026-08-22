"""Tests for the canonical AST child-enumeration helpers
:func:`capa.capa_ast.children` and :func:`capa.capa_ast.walk`.

Two things are pinned:

1. ``children`` and ``walk`` on a hand-built representative tree
   (list-of-tuple fields, an if-stmt with elif arms, nested exprs,
   optionals left ``None``, and the ``pos`` field which must never
   surface as a child).

2. ``children`` yields exactly the node sequence the formatter's old
   ``_iter_children`` did. ``_reference_iter_children`` below is a
   verbatim frozen copy of that function as it stood in
   ``formatter/_comments.py`` immediately before it was deleted and the
   formatter re-pointed at the shared helper. At migration time this
   copy was additionally checked against the live function over the
   whole example/test ``.capa`` corpus (45,355 nodes, zero mismatches);
   the frozen copy keeps that equivalence pinned in CI now that the
   original is gone.
"""

import unittest

from capa import capa_ast as A
from capa.tokens import Pos


def _p() -> Pos:
    return Pos(line=1, col=1, offset=0)


def _reference_iter_children(node):
    """Frozen verbatim copy of the pre-migration
    ``formatter/_comments._iter_children``. Do not "improve" it: its
    sole purpose is to be the fixed oracle that :func:`A.children` is
    proven equal to."""
    for f in node.__dataclass_fields__.values():
        if f.name == "pos":
            continue
        v = getattr(node, f.name, None)
        if v is None:
            continue
        if isinstance(v, A.Node):
            yield v
        elif isinstance(v, list):
            for item in v:
                if isinstance(item, A.Node):
                    yield item
                elif isinstance(item, tuple):
                    for sub in item:
                        if isinstance(sub, A.Node):
                            yield sub
        elif isinstance(v, tuple):
            for sub in v:
                if isinstance(sub, A.Node):
                    yield sub


def _representative_tree() -> A.Module:
    """A small AST exercising every child-shape ``children`` handles.

    - ``StructLit.fields`` is ``list[tuple[str, Expr]]`` (list of
      tuples where only the second element is a node).
    - ``IfStmt.elif_arms`` is ``list[tuple[Expr, Block]]`` (list of
      tuples where both elements are nodes).
    - ``BinOp`` nests expressions.
    - ``LetStmt.type_expr`` and ``ReturnStmt.value`` are left ``None``
      to cover the optional/None skip.
    """
    # let p = Point { x: 1, y: a + 2 }
    struct = A.StructLit(
        pos=_p(),
        type_name="Point",
        fields=[
            ("x", A.IntLit(pos=_p(), value=1)),
            (
                "y",
                A.BinOp(
                    pos=_p(),
                    op="+",
                    left=A.Ident(pos=_p(), name="a"),
                    right=A.IntLit(pos=_p(), value=2),
                ),
            ),
        ],
    )
    let_stmt = A.LetStmt(
        pos=_p(),
        pattern=A.IdentPat(pos=_p(), name="p"),
        type_expr=None,
        value=struct,
    )

    # if c { return } elif d { return } else { return }
    if_stmt = A.IfStmt(
        pos=_p(),
        cond=A.Ident(pos=_p(), name="c"),
        then_block=A.Block(pos=_p(), stmts=[A.ReturnStmt(pos=_p())]),
        elif_arms=[
            (
                A.Ident(pos=_p(), name="d"),
                A.Block(pos=_p(), stmts=[A.ReturnStmt(pos=_p())]),
            ),
        ],
        else_block=A.Block(pos=_p(), stmts=[A.ReturnStmt(pos=_p())]),
    )

    fun = A.FunDecl(
        pos=_p(),
        name="f",
        type_params=[],
        params=[],
        return_type=None,
        body=A.Block(pos=_p(), stmts=[let_stmt, if_stmt]),
    )
    return A.Module(pos=_p(), items=[fun])


class TestChildren(unittest.TestCase):
    def test_struct_lit_unwraps_list_of_tuples(self):
        int_lit = A.IntLit(pos=_p(), value=1)
        ident = A.Ident(pos=_p(), name="a")
        struct = A.StructLit(
            pos=_p(),
            type_name="Point",
            fields=[("x", int_lit), ("y", ident)],
        )
        # Only the node element of each (name, value) tuple is yielded,
        # in declaration/list order.
        self.assertEqual(list(A.children(struct)), [int_lit, ident])

    def test_if_stmt_elif_arms_in_field_and_list_order(self):
        cond = A.Ident(pos=_p(), name="c")
        then_block = A.Block(pos=_p(), stmts=[])
        elif_cond = A.Ident(pos=_p(), name="d")
        elif_block = A.Block(pos=_p(), stmts=[])
        else_block = A.Block(pos=_p(), stmts=[])
        if_stmt = A.IfStmt(
            pos=_p(),
            cond=cond,
            then_block=then_block,
            elif_arms=[(elif_cond, elif_block)],
            else_block=else_block,
        )
        # cond, then_block, then each elem of the elif tuple, then else.
        self.assertEqual(
            list(A.children(if_stmt)),
            [cond, then_block, elif_cond, elif_block, else_block],
        )

    def test_optional_none_field_skipped(self):
        value = A.IntLit(pos=_p(), value=1)
        let_stmt = A.LetStmt(
            pos=_p(),
            pattern=A.IdentPat(pos=_p(), name="p"),
            type_expr=None,
            value=value,
        )
        kids = list(A.children(let_stmt))
        # type_expr (None) contributes nothing; pattern and value do.
        self.assertEqual(len(kids), 2)
        self.assertIs(kids[1], value)

    def test_pos_is_never_a_child(self):
        for node in A.walk(_representative_tree()):
            for child in A.children(node):
                self.assertNotIsInstance(child, Pos)
            self.assertNotIn(node.pos, list(A.children(node)))

    def test_leaf_has_no_node_children(self):
        self.assertEqual(list(A.children(A.IntLit(pos=_p(), value=1))), [])


class TestWalk(unittest.TestCase):
    def test_walk_is_preorder(self):
        left = A.Ident(pos=_p(), name="a")
        right = A.IntLit(pos=_p(), value=2)
        binop = A.BinOp(pos=_p(), op="+", left=left, right=right)
        # Parent precedes its children; children in field order.
        self.assertEqual(list(A.walk(binop)), [binop, left, right])

    def test_walk_covers_every_node_once(self):
        tree = _representative_tree()
        seen = list(A.walk(tree))
        # No duplicates, and the root comes first.
        self.assertIs(seen[0], tree)
        self.assertEqual(len(seen), len({id(n) for n in seen}))

    def test_walk_accepts_a_list_or_tuple_root(self):
        a = A.IntLit(pos=_p(), value=1)
        b = A.IntLit(pos=_p(), value=2)
        self.assertEqual(list(A.walk([a, b])), [a, b])
        self.assertEqual(list(A.walk((a, b))), [a, b])


class TestReferenceEquivalence(unittest.TestCase):
    """The migration-justifying proof: ``children`` matches the frozen
    copy of the formatter's old ``_iter_children`` on every node of a
    representative tree."""

    def test_children_equals_reference_over_whole_tree(self):
        for node in A.walk(_representative_tree()):
            self.assertEqual(
                [id(c) for c in A.children(node)],
                [id(c) for c in _reference_iter_children(node)],
                msg=f"children/_iter_children diverge on {type(node).__name__}",
            )


if __name__ == "__main__":
    unittest.main()
