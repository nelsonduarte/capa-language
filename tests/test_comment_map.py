"""Unit tests for the formatter v3 phase-2 CommentMap pass.

Cases mirror the ones laid out in
``docs/formatter-v3-comment-map-design.md`` section 6 (eight
positional cases plus the risk-mitigation case from section 7),
followed by a structural invariant: every comment that the lexer
captured ends up attached exactly once.
"""

import unittest

from capa import Lexer
from capa.parser import Parser
from capa import capa_ast as A
from capa.formatter._comments import (
    AttachedComments,
    CommentMap,
    build_comment_map,
)


def _parse(source: str):
    """Helper: lex + parse a source, return ``(module, tokens, comments)``."""
    lexer = Lexer(source)
    tokens = lexer.lex()
    parser = Parser(tokens, source=source, filename="<test>")
    module = parser.parse_module()
    return module, tokens, lexer.comments


def _only_entry(cmap: CommentMap):
    """Assert there is exactly one entry in the map and return it
    as ``(node_id, attached)``."""
    items = list(cmap._by_id.items())
    assert len(items) == 1, f"expected 1 attached node, got {len(items)}"
    return items[0]


class TestCommentMap(unittest.TestCase):

    # 1. Module leading (file header, separated from first item by
    # a blank line). A narrative comment that is NOT separated by a
    # blank line is treated as leading on the item, not on the
    # module - see test_adjacent_narrative_attaches_to_item below.
    def test_module_leading_comment(self):
        src = "// hello\n\nfun foo()\n    let x = 1\n"
        module, tokens, comments = _parse(src)
        cmap = build_comment_map(module, tokens, comments)
        self.assertEqual(len(comments), 1)
        attached = cmap.get(module)
        self.assertIsNotNone(attached)
        self.assertEqual(len(attached.leading), 1)
        self.assertEqual(attached.leading[0].text, "// hello")
        # The FunDecl itself must have nothing attached.
        fun = module.items[0]
        self.assertNotIn(fun, cmap)

    # 1b. Adjacent narrative (no blank line) attaches to the item,
    # not the module. The blank-line test in
    # ``_attach_standalone`` is what keeps section-divider-wrapped
    # comment blocks intact above the first item.
    def test_adjacent_narrative_attaches_to_item(self):
        src = "// hello\nfun foo()\n    let x = 1\n"
        module, tokens, comments = _parse(src)
        cmap = build_comment_map(module, tokens, comments)
        fun = module.items[0]
        attached = cmap.get(fun)
        self.assertIsNotNone(attached)
        self.assertEqual(len(attached.leading), 1)
        self.assertEqual(attached.leading[0].text, "// hello")
        # Module itself gets nothing in this case.
        self.assertNotIn(module, cmap)

    # 2. Item leading (section divider)
    def test_item_leading_section_divider(self):
        src = "// ====\nfun foo()\n    let x = 1\n"
        module, tokens, comments = _parse(src)
        cmap = build_comment_map(module, tokens, comments)
        fun = module.items[0]
        self.assertIsInstance(fun, A.FunDecl)
        attached = cmap.get(fun)
        self.assertIsNotNone(attached)
        self.assertEqual(len(attached.leading), 1)
        self.assertEqual(attached.leading[0].text, "// ====")
        # Module itself gets nothing.
        self.assertNotIn(module, cmap)

    # 3. Stmt trailing
    def test_stmt_trailing_comment(self):
        src = "fun foo()\n    let x = 1 // trailing\n"
        module, tokens, comments = _parse(src)
        cmap = build_comment_map(module, tokens, comments)
        fun = module.items[0]
        let_stmt = fun.body.stmts[0]
        self.assertIsInstance(let_stmt, A.LetStmt)
        attached = cmap.get(let_stmt)
        self.assertIsNotNone(attached)
        self.assertEqual(len(attached.trailing), 1)
        self.assertEqual(attached.trailing[0].text, "// trailing")

    # 4. Block floating
    def test_block_floating_comment(self):
        src = "fun foo()\n    let x = 1\n    // final\n"
        module, tokens, comments = _parse(src)
        cmap = build_comment_map(module, tokens, comments)
        fun = module.items[0]
        body = fun.body
        self.assertIsInstance(body, A.Block)
        attached = cmap.get(body)
        self.assertIsNotNone(attached)
        self.assertEqual(len(attached.trailing), 1)
        self.assertEqual(attached.trailing[0].text, "// final")

    # 5. Compound header trailing
    def test_compound_header_trailing(self):
        src = "fun foo()\n    if true // checked\n        let x = 1\n"
        module, tokens, comments = _parse(src)
        cmap = build_comment_map(module, tokens, comments)
        fun = module.items[0]
        if_stmt = fun.body.stmts[0]
        self.assertIsInstance(if_stmt, A.IfStmt)
        attached = cmap.get(if_stmt)
        self.assertIsNotNone(attached)
        self.assertEqual(len(attached.trailing_header), 1)
        self.assertEqual(attached.trailing_header[0].text, "// checked")
        # The inner let stmt has NOTHING attached.
        inner_let = if_stmt.then_block.stmts[0]
        self.assertNotIn(inner_let, cmap)

    # 6. Module trailing
    def test_module_trailing_comment(self):
        src = "fun foo()\n    let x = 1\n// end of file\n"
        module, tokens, comments = _parse(src)
        cmap = build_comment_map(module, tokens, comments)
        attached = cmap.get(module)
        self.assertIsNotNone(attached)
        self.assertEqual(len(attached.trailing), 1)
        self.assertEqual(attached.trailing[0].text, "// end of file")

    # 7. Interior block comment
    def test_interior_block_comment(self):
        src = "fun foo()\n    let x = 1 /* aside */ + 2\n    return x\n"
        module, tokens, comments = _parse(src)
        cmap = build_comment_map(module, tokens, comments)
        # Find the entry that holds an interior comment.
        interior_owners = [
            (nid, ac) for nid, ac in cmap._by_id.items() if ac.interior
        ]
        self.assertEqual(
            len(interior_owners), 1,
            f"expected exactly one interior comment, got {len(interior_owners)}",
        )
        _, ac = interior_owners[0]
        self.assertEqual(len(ac.interior), 1)
        self.assertEqual(ac.interior[0].text, "/* aside */")
        # Owner is an Expr node (per design).
        # Recover the node from id; walk the AST to find it.
        target_id = interior_owners[0][0]
        found = []

        def walk(n):
            if isinstance(n, A.Node):
                if id(n) == target_id:
                    found.append(n)
                for f in n.__dataclass_fields__.values():
                    if f.name == "pos":
                        continue
                    v = getattr(n, f.name, None)
                    if isinstance(v, A.Node):
                        walk(v)
                    elif isinstance(v, list):
                        for item in v:
                            walk(item)
                    elif isinstance(v, tuple):
                        for sub in v:
                            walk(sub)
        walk(module)
        self.assertEqual(len(found), 1)
        self.assertIsInstance(found[0], A.Expr)

    # 8. Doc comments are NOT in the map
    def test_doc_comment_not_in_map(self):
        src = "/// doc\nfun foo()\n    let x = 1\n"
        module, tokens, comments = _parse(src)
        # The lexer emits a DOC_COMMENT token, NOT a Comment, so
        # the sidecar must be empty.
        self.assertEqual(len(comments), 0)
        cmap = build_comment_map(module, tokens, comments)
        self.assertEqual(len(cmap), 0)
        # And the parser put the doc text on the FunDecl.
        fun = module.items[0]
        self.assertEqual(fun.doc, "doc")

    # 9. Section divider before a doc comment (risk from design 7)
    def test_section_divider_before_doc_comment(self):
        src = "// section\n/// doc\nfun foo()\n    let x = 1\n"
        module, tokens, comments = _parse(src)
        # The plain comment is the only entry in the sidecar.
        self.assertEqual(len(comments), 1)
        self.assertEqual(comments[0].text, "// section")
        cmap = build_comment_map(module, tokens, comments)
        fun = module.items[0]
        self.assertIsInstance(fun, A.FunDecl)
        self.assertEqual(fun.doc, "doc")
        # The section divider lands on FunDecl.leading, NOT on Module.
        self.assertNotIn(module, cmap)
        attached = cmap.get(fun)
        self.assertIsNotNone(attached)
        self.assertEqual(len(attached.leading), 1)
        self.assertEqual(attached.leading[0].text, "// section")

    # 10. Invariant: every captured comment is attached exactly once.
    def test_every_comment_attached_exactly_once(self):
        src = (
            "// file header\n"
            "// second header line\n"
            "\n"
            "/// real doc\n"
            "fun foo() // header trailing\n"
            "    // before x\n"
            "    let x = 1 // trailing x\n"
            "    let y = 2 /* aside */ + 3\n"
            "    // last in block\n"
            "\n"
            "// between items\n"
            "fun bar()\n"
            "    return 0\n"
            "// end of file\n"
        )
        module, tokens, comments = _parse(src)
        cmap = build_comment_map(module, tokens, comments)
        self.assertEqual(len(cmap), len(comments))
        # Sanity: at least every category is exercised.
        all_attached: list = []
        for ac in cmap:
            all_attached.extend(ac.leading)
            all_attached.extend(ac.trailing)
            all_attached.extend(ac.trailing_header)
            all_attached.extend(ac.interior)
        self.assertEqual(len(all_attached), len(comments))
        # Each Comment object appears exactly once across all slots.
        ids = [id(c) for c in all_attached]
        self.assertEqual(len(ids), len(set(ids)))


if __name__ == "__main__":
    unittest.main()
