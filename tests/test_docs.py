"""Tests for doc comments and the --doc HTML generator.

Three blocks:

  - lexer: ``///`` and ``/** */`` tokenise as ``DOC_COMMENT``, with
    leading-space stripping and Javadoc star-margin stripping
    applied; ``//`` and ``////+`` are still skipped silently.
  - parser: doc comments before fun / type / trait / capability /
    impl-method attach to the right declaration; rejected on
    const / import / impl.
  - docgen: the HTML output contains the doc text and the
    capability badges; the manifest carries the doc string too.
"""

import re
import unittest

from capa import Lexer, Parser, ParserError, analyze
from capa import ast as A
from capa.tokens import TokenKind
from capa.manifest import build_manifest
from capa.docgen import build_html


def lex(source: str):
    return Lexer(source).lex()


def parse(source: str) -> A.Module:
    return Parser(lex(source), source=source).parse_module()


def doc_tokens(source: str) -> list:
    return [t for t in lex(source) if t.kind == TokenKind.DOC_COMMENT]


# =============================================================
# Lexer
# =============================================================

class TestDocCommentLexing(unittest.TestCase):
    def test_triple_slash_emits_token(self):
        toks = doc_tokens("/// hello\nfun f()\n    return\n")
        self.assertEqual(len(toks), 1)
        self.assertEqual(toks[0].value, "hello")

    def test_quadruple_slash_is_regular_comment(self):
        toks = doc_tokens("//// not a doc\nfun f()\n    return\n")
        self.assertEqual(toks, [])

    def test_double_slash_is_regular_comment(self):
        toks = doc_tokens("// not a doc\nfun f()\n    return\n")
        self.assertEqual(toks, [])

    def test_leading_space_stripped_once(self):
        toks = doc_tokens("///   three spaces, only one stripped\n")
        self.assertEqual(toks[0].value, "  three spaces, only one stripped")

    def test_consecutive_triple_slash_two_tokens(self):
        toks = doc_tokens(
            "/// first\n"
            "/// second\n"
            "fun f()\n    return\n"
        )
        self.assertEqual(len(toks), 2)
        self.assertEqual([t.value for t in toks], ["first", "second"])

    def test_block_doc_strips_star_margin(self):
        toks = doc_tokens(
            "/** line one\n"
            " * line two\n"
            " * line three\n"
            " */\n"
            "fun f()\n    return\n"
        )
        self.assertEqual(len(toks), 1)
        self.assertEqual(toks[0].value, "line one\nline two\nline three")

    def test_block_regular_not_doc(self):
        toks = doc_tokens("/* not a doc */\nfun f()\n    return\n")
        self.assertEqual(toks, [])

    def test_empty_block_doc_not_emitted(self):
        # /**/ is a regular (empty) block comment, not a doc.
        toks = doc_tokens("/**/\nfun f()\n    return\n")
        self.assertEqual(toks, [])


# =============================================================
# Parser attachment
# =============================================================

class TestDocCommentAttachment(unittest.TestCase):
    def test_attaches_to_fun(self):
        m = parse(
            "/// my fun does X\n"
            "fun f()\n    return\n"
        )
        f = m.items[0]
        self.assertEqual(f.doc, "my fun does X")

    def test_attaches_to_struct_type(self):
        m = parse(
            "/// my struct\n"
            "type Foo { x: Int }\n"
        )
        t = m.items[0]
        self.assertIsInstance(t, A.TypeStruct)
        self.assertEqual(t.doc, "my struct")

    def test_attaches_to_sum_type(self):
        m = parse(
            "/// my sum\n"
            "type Color =\n"
            "    Red\n"
            "    Blue\n"
        )
        t = m.items[0]
        self.assertIsInstance(t, A.TypeSum)
        self.assertEqual(t.doc, "my sum")

    def test_attaches_to_capability(self):
        m = parse(
            "/// my cap\n"
            "capability X\n"
            "    fun do_it(self)\n"
        )
        c = m.items[0]
        self.assertIsInstance(c, A.TraitDecl)
        self.assertTrue(c.is_capability)
        self.assertEqual(c.doc, "my cap")

    def test_attaches_to_impl_method(self):
        m = parse(
            "type Foo {}\n"
            "impl Foo\n"
            "    /// the only method\n"
            "    fun bar(self)\n"
            "        return\n"
        )
        impl = m.items[1]
        self.assertEqual(impl.methods[0].doc, "the only method")

    def test_two_lines_joined_with_newline(self):
        m = parse(
            "/// first line\n"
            "/// second line\n"
            "fun f()\n    return\n"
        )
        self.assertEqual(m.items[0].doc, "first line\nsecond line")

    def test_rejected_on_const(self):
        with self.assertRaises(ParserError) as cm:
            parse("/// doc\nconst PI: Float = 3.14\n")
        self.assertIn("const", cm.exception.message)

    def test_rejected_on_import(self):
        with self.assertRaises(ParserError) as cm:
            parse("/// doc\nimport thing\n")
        self.assertIn("import", cm.exception.message)

    def test_rejected_on_impl(self):
        with self.assertRaises(ParserError) as cm:
            parse(
                "/// doc on the whole impl\n"
                "impl Foo\n"
                "    fun bar(self)\n        return\n"
            )
        self.assertIn("impl", cm.exception.message)

    def test_no_doc_means_none(self):
        m = parse("fun f()\n    return\n")
        self.assertIsNone(m.items[0].doc)


# =============================================================
# Manifest carries doc strings
# =============================================================

class TestManifestDoc(unittest.TestCase):
    def test_function_doc_in_manifest(self):
        m = parse(
            "/// my fun\n"
            "fun f()\n    return\n"
        )
        manifest = build_manifest(m, filename="t.capa")
        self.assertEqual(manifest["functions"][0]["doc"], "my fun")

    def test_capability_doc_in_manifest(self):
        m = parse(
            "/// my capability\n"
            "capability X\n"
            "    fun go(self)\n"
        )
        manifest = build_manifest(m, filename="t.capa")
        self.assertEqual(
            manifest["user_defined_capabilities"][0]["doc"],
            "my capability",
        )

    def test_no_doc_field_is_none(self):
        m = parse("fun f()\n    return\n")
        manifest = build_manifest(m, filename="t.capa")
        self.assertIsNone(manifest["functions"][0]["doc"])


# =============================================================
# Docgen output
# =============================================================

class TestDocgen(unittest.TestCase):
    def test_html_envelope(self):
        m = parse("fun f()\n    return\n")
        html = build_html(m, filename="t.capa")
        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn("</html>", html)
        # Function appears in the body.
        self.assertIn(">f<", html)

    def test_doc_text_renders_in_html(self):
        m = parse(
            "/// finds the unique characters\n"
            "fun unique_chars(s: String) -> Int\n"
            "    return 0\n"
        )
        html = build_html(m, filename="t.capa")
        self.assertIn("finds the unique characters", html)

    def test_paragraphs_become_p_tags(self):
        m = parse(
            "/// first paragraph\n"
            "/// \n"
            "/// second paragraph\n"
            "fun f()\n    return\n"
        )
        html = build_html(m, filename="t.capa")
        # Two paragraphs should yield two <p>s in the rendered output.
        paragraphs_in_doc = re.findall(
            r"<p>(?:first|second) paragraph</p>", html,
        )
        self.assertEqual(len(paragraphs_in_doc), 2)

    def test_backtick_renders_as_code(self):
        m = parse(
            "/// use `restrict_to` to narrow\n"
            "fun f()\n    return\n"
        )
        html = build_html(m, filename="t.capa")
        self.assertIn("<code>restrict_to</code>", html)

    def test_capability_badge_present(self):
        m = parse(
            "fun fetcher(net: Net)\n"
            "    let _ = net.allows(\"x\")\n"
        )
        html = build_html(m, filename="t.capa")
        # The Net cap badge appears as a span with "badge cap" classes.
        self.assertIn('class="badge cap', html)
        self.assertIn("Net", html)

    def test_attribute_section_present(self):
        m = parse(
            "@security(cve: \"CVE-2024-1\")\n"
            "fun f()\n    return\n"
        )
        html = build_html(m, filename="t.capa")
        self.assertIn("@security", html)
        self.assertIn("CVE-2024-1", html)

    def test_capability_section_appears(self):
        m = parse(
            "/// emails\n"
            "capability SendEmail\n"
            "    fun send(self, to: String) -> Bool\n"
        )
        html = build_html(m, filename="t.capa")
        self.assertIn("capability", html)
        self.assertIn("SendEmail", html)
        self.assertIn("emails", html)

    def test_html_escapes_special_characters(self):
        # If a doc contains literal '<' it must be escaped.
        m = parse(
            "/// use a < b for less-than\n"
            "fun f()\n    return\n"
        )
        html = build_html(m, filename="t.capa")
        self.assertIn("&lt;", html)
        self.assertNotIn("use a < b", html)

    def test_fenced_code_block_renders_as_pre(self):
        m = parse(
            "/// Example.\n"
            "///\n"
            "/// ```\n"
            "/// let x = 1\n"
            "/// let y = 2\n"
            "/// ```\n"
            "fun f()\n    return\n"
        )
        html = build_html(m, filename="t.capa")
        # Inner code lines preserved verbatim inside <pre><code>.
        self.assertIn("<pre><code>let x = 1\nlet y = 2</code></pre>", html)

    def test_fenced_code_block_language_tag(self):
        m = parse(
            "/// ```capa\n"
            "/// fun id(x: Int) -> Int\n"
            "/// ```\n"
            "fun f()\n    return\n"
        )
        html = build_html(m, filename="t.capa")
        # Language tag becomes a class on the inner <code>.
        self.assertIn('<code class="lang-capa">', html)

    def test_fenced_code_block_html_inside_is_escaped(self):
        m = parse(
            "/// ```\n"
            "/// <script>alert(1)</script>\n"
            "/// ```\n"
            "fun f()\n    return\n"
        )
        html = build_html(m, filename="t.capa")
        self.assertIn("&lt;script&gt;", html)
        self.assertNotIn("<script>alert(1)</script>", html)

    def test_bulleted_list_renders_as_ul(self):
        m = parse(
            "/// Caveats:\n"
            "///\n"
            "/// - blocks the caller\n"
            "/// - reads the whole file into memory\n"
            "/// - returns Err on permission denied\n"
            "fun f()\n    return\n"
        )
        html = build_html(m, filename="t.capa")
        self.assertIn("<ul>", html)
        self.assertIn("<li>blocks the caller</li>", html)
        self.assertIn(
            "<li>reads the whole file into memory</li>", html,
        )

    def test_trait_section_appears(self):
        m = parse(
            "/// Things that can be audited.\n"
            "trait Auditable\n"
            "    fun audit_label(self) -> String\n"
        )
        html = build_html(m, filename="t.capa")
        self.assertIn("<h2>Traits</h2>", html)
        self.assertIn("Auditable", html)
        self.assertIn("Things that can be audited.", html)
        # Method signature shows up under the trait.
        self.assertIn("audit_label", html)

    def test_trait_implementors_listed(self):
        m = parse(
            "trait Auditable\n"
            "    fun audit_label(self) -> String\n"
            "type Foo {\n"
            "    n: Int\n"
            "}\n"
            "impl Auditable for Foo\n"
            "    fun audit_label(self) -> String\n"
            "        return \"foo\"\n"
        )
        html = build_html(m, filename="t.capa")
        # The trait section lists Foo as an implementor.
        trait_section = re.search(
            r'<article id="tr-auditable".*?</article>', html, re.DOTALL,
        )
        self.assertIsNotNone(trait_section)
        self.assertIn("<code>Foo</code>", trait_section.group(0))


if __name__ == "__main__":
    unittest.main()
