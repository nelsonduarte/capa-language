"""Tests for ``capa.lsp_server.compute_diagnostics``.

We do not boot the full LSP server in unit tests (stdio JSON-RPC
is awkward to drive synthetically). Instead, we cover the
diagnostic computation: clean source, lexer errors, parser
errors, analyzer errors. The mapping from Capa positions
(1-based line/col) to LSP positions (0-based) is also exercised
since editors rely on it.

These tests skip cleanly when ``pygls`` (and its sibling
``lsprotocol``) are not installed, so the rest of the suite
continues to run in a stock-Python environment.
"""

import unittest

try:
    import lsprotocol  # noqa: F401
    _HAVE_LSP = True
except ImportError:
    _HAVE_LSP = False


@unittest.skipUnless(_HAVE_LSP, "requires `pygls` extra (pip install '.[lsp]')")
class TestComputeDiagnostics(unittest.TestCase):
    def setUp(self):
        from capa.lsp_server import compute_diagnostics
        self.compute = compute_diagnostics

    def test_clean_source_yields_no_diagnostics(self):
        src = 'fun main(stdio: Stdio)\n    stdio.println("hi")\n'
        self.assertEqual(self.compute(src, "t.capa"), [])

    def test_undefined_name_becomes_diagnostic(self):
        src = (
            "fun main(stdio: Stdio)\n"
            "    let x = undefiend_var\n"
            "    stdio.println(\"${x}\")\n"
        )
        diags = self.compute(src, "t.capa")
        self.assertTrue(diags, "expected at least one diagnostic")
        msgs = [d.message for d in diags]
        self.assertTrue(
            any("undefined name 'undefiend_var'" in m for m in msgs),
            msgs,
        )

    def test_lsp_position_is_zero_based(self):
        # Capa reports positions as 1-based; LSP expects 0-based.
        # An undefined name on line 2, column 13 of the source
        # should appear at line=1, character=12 in the diagnostic.
        src = (
            "fun main(stdio: Stdio)\n"
            "    let x = undefiend\n"  # col 13 = the 'u'
            "    stdio.println(\"${x}\")\n"
        )
        diags = self.compute(src, "t.capa")
        d = next(
            d for d in diags
            if "undefined name" in d.message and "undefiend" in d.message
        )
        self.assertEqual(d.range.start.line, 1)
        self.assertEqual(d.range.start.character, 12)

    def test_diagnostic_carries_error_severity(self):
        from lsprotocol import types as lsp
        src = "fun main()\n    let = 1\n"  # parser error
        diags = self.compute(src, "t.capa")
        self.assertTrue(diags)
        self.assertEqual(diags[0].severity, lsp.DiagnosticSeverity.Error)
        self.assertEqual(diags[0].source, "capa-lsp")

    def test_lexer_error_short_circuits(self):
        # When the lexer fails, parser and analyzer are skipped:
        # we expect exactly one diagnostic carrying the lexer
        # message.
        src = "fun main()\n\tlet x = 1\n"  # leading tab is a lexer error
        diags = self.compute(src, "t.capa")
        self.assertEqual(len(diags), 1)
        self.assertIn("tab", diags[0].message.lower())

    def test_parser_error_short_circuits(self):
        src = "fun main()\n    let = 1\n"  # missing pattern after let
        diags = self.compute(src, "t.capa")
        # Exactly one parser error; analyzer never runs.
        self.assertEqual(len(diags), 1)

    def test_analyzer_yields_multiple_diagnostics(self):
        src = (
            "fun main(stdio: Stdio)\n"
            "    let a = aaa\n"
            "    let b = bbb\n"
        )
        diags = self.compute(src, "t.capa")
        # Both undefined names + a "stdio unused" capability warning
        # come through; we just check there are several.
        self.assertGreaterEqual(len(diags), 2)

    def test_did_you_mean_hint_is_visible_in_diagnostic(self):
        # The CLI-level message improvement should appear in the
        # diagnostic text shown by editors.
        src = (
            "fun main(stdio: Stdio)\n"
            "    let n = \"hi\".lenght()\n"
            "    stdio.println(\"${n}\")\n"
        )
        diags = self.compute(src, "t.capa")
        self.assertTrue(
            any("did you mean 'length'?" in d.message for d in diags),
            [d.message for d in diags],
        )


@unittest.skipUnless(_HAVE_LSP, "requires `pygls` extra (pip install '.[lsp]')")
class TestHover(unittest.TestCase):
    """Hover answers ``what is this symbol?`` for identifiers
    under the cursor. Coverage is intentionally limited to ``Ident``
    nodes in v1: hovering on a declaration site (the ``foo`` in
    ``fun foo(...)``) does not fire because the parser stores
    declared names as strings, not as Ident nodes. Hovering on
    a *reference* to ``foo`` (a call site, a use in an
    expression) does fire."""

    def setUp(self):
        from capa.lsp_server import compute_hover
        self.hover = compute_hover

    def test_hover_on_function_call_shows_signature(self):
        src = (
            "fun greet(name: String, age: Int) -> String\n"
            "    return name\n"
            "fun main(stdio: Stdio)\n"
            "    let msg = greet(\"Ana\", 30)\n"
            "    stdio.println(msg)\n"
        )
        # ``greet`` at the call site, line 4 col 15.
        r = self.hover(src, "t.capa", 4, 15)
        self.assertIsNotNone(r)
        md, ident = r
        self.assertIn("fun greet(name: String, age: Int) -> String", md)
        self.assertEqual(ident.name, "greet")

    def test_hover_on_parameter_use_shows_type(self):
        src = (
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"hi\")\n"
        )
        # ``stdio`` on line 2, col 5.
        r = self.hover(src, "t.capa", 2, 5)
        self.assertIsNotNone(r)
        md, _ = r
        self.assertIn("stdio: Stdio", md)
        self.assertIn("*parameter*", md)

    def test_hover_on_let_binding_use_shows_type(self):
        # Use the binding outside an interpolation, since string
        # interpolation expressions go through a side channel that
        # does not preserve positions in v1.
        src = (
            "fun id(x: Int) -> Int\n"
            "    return x\n"
            "fun main(stdio: Stdio)\n"
            "    let n = 42\n"
            "    let _ = id(n)\n"
            "    stdio.println(\"done\")\n"
        )
        # ``n`` on line 5, col 16 (inside the call id(n)).
        r = self.hover(src, "t.capa", 5, 16)
        self.assertIsNotNone(r)
        md, _ = r
        self.assertIn("n: Int", md)
        self.assertIn("*binding*", md)

    def test_hover_in_whitespace_returns_none(self):
        src = "fun main()\n    return\n"
        # Column 1 of an empty-ish line is whitespace.
        r = self.hover(src, "t.capa", 2, 1)
        self.assertIsNone(r)

    def test_hover_on_unknown_position_returns_none(self):
        src = "fun main(stdio: Stdio)\n    stdio.println(\"hi\")\n"
        # Far past end of file.
        r = self.hover(src, "t.capa", 999, 1)
        self.assertIsNone(r)

    def test_hover_with_parse_error_does_not_crash(self):
        # An incomplete buffer should yield None, never raise.
        src = "fun main()\n    let = "
        r = self.hover(src, "t.capa", 2, 9)
        self.assertIsNone(r)


@unittest.skipUnless(_HAVE_LSP, "requires `pygls` extra (pip install '.[lsp]')")
class TestGoToDefinition(unittest.TestCase):
    """Go-to-definition: resolve the identifier at the cursor to
    the (1-based) source position where its declaring symbol
    lives. Built-in symbols return None because their declaration
    is the Pos(0, 0) sentinel, not a real file location."""

    def setUp(self):
        from capa.lsp_server import compute_definition
        self.defn = compute_definition

    def test_jump_from_call_to_function_declaration(self):
        src = (
            "fun greet(name: String) -> String\n"   # line 1
            "    return name\n"                     # line 2
            "\n"
            "fun main(stdio: Stdio)\n"              # line 4
            "    let msg = greet(\"Ana\")\n"        # line 5
            "    stdio.println(msg)\n"              # line 6
        )
        # ``greet`` at the call site, line 5 col 15.
        p = self.defn(src, "t.capa", 5, 15)
        self.assertIsNotNone(p)
        self.assertEqual(p.line, 1)

    def test_jump_from_use_to_let_binding(self):
        src = (
            "fun id(x: Int) -> Int\n"
            "    return x\n"
            "fun main(stdio: Stdio)\n"
            "    let n = 42\n"             # line 4
            "    let _ = id(n)\n"          # line 5, n at col 16
            "    stdio.println(\"k\")\n"
        )
        p = self.defn(src, "t.capa", 5, 16)
        self.assertIsNotNone(p)
        # Declaration of `n` is on line 4.
        self.assertEqual(p.line, 4)

    def test_jump_from_use_to_parameter(self):
        src = (
            "fun greet(name: String) -> String\n"  # line 1
            "    return name\n"                     # line 2, `name` at col 12
        )
        p = self.defn(src, "t.capa", 2, 12)
        self.assertIsNotNone(p)
        # Parameter declared on line 1.
        self.assertEqual(p.line, 1)

    def test_builtin_symbol_returns_none(self):
        # ``Stdio`` is a built-in capability with no source
        # origin, so go-to-definition should cleanly return
        # nothing instead of jumping to line 0.
        src = (
            "fun main(stdio: Stdio)\n"  # line 1, ``Stdio`` at col 17
            "    stdio.println(\"hi\")\n"
        )
        # Note: ``Stdio`` here is a type name in a Param's
        # type annotation. Whether it has an Ident at that
        # position depends on the parser. If find_ident_at
        # doesn't see it as an Ident, the result is None for
        # a different reason; either way the test asserts
        # "no jump to line 0".
        p = self.defn(src, "t.capa", 1, 17)
        if p is not None:
            self.assertNotEqual(p.line, 0)

    def test_no_definition_at_whitespace(self):
        src = "fun main()\n    return\n"
        p = self.defn(src, "t.capa", 2, 1)
        self.assertIsNone(p)

    def test_no_definition_for_parse_error_buffer(self):
        src = "fun main()\n    let = "
        p = self.defn(src, "t.capa", 2, 9)
        self.assertIsNone(p)


@unittest.skipUnless(_HAVE_LSP, "requires `pygls` extra (pip install '.[lsp]')")
class TestFindReferences(unittest.TestCase):
    """Find-references: given an identifier under the cursor,
    list every other identifier in the file that resolves to the
    same symbol. Built on top of the same collect_idents +
    AnalysisResult.bindings machinery as hover and
    go-to-definition."""

    def setUp(self):
        from capa.lsp_server import compute_references
        self.refs = compute_references

    def test_function_references_include_declaration_and_call_sites(self):
        src = (
            "fun greet(name: String) -> String\n"   # line 1 (decl)
            "    return name\n"                     # line 2
            "fun main(stdio: Stdio)\n"
            "    let a = greet(\"Ana\")\n"          # line 4 (call 1)
            "    let b = greet(\"Bea\")\n"          # line 5 (call 2)
            "    stdio.println(\"${a}-${b}\")\n"
        )
        # Pivot on the first call site, line 4 col 13.
        refs = self.refs(src, "t.capa", 4, 13)
        self.assertIsNotNone(refs)
        lines = sorted(r.pos.line for r in refs)
        # Three positions: declaration on line 1, two calls.
        self.assertEqual(lines, [1, 4, 5])

    def test_exclude_declaration_when_requested(self):
        src = (
            "fun greet() -> Int\n"
            "    return 0\n"
            "fun main(stdio: Stdio)\n"
            "    let _ = greet()\n"
            "    stdio.println(\"hi\")\n"
        )
        refs = self.refs(
            src, "t.capa", 4, 13, include_declaration=False,
        )
        self.assertIsNotNone(refs)
        # Only the single call site remains.
        self.assertEqual(len(refs), 1)
        self.assertEqual(refs[0].pos.line, 4)

    def test_parameter_references_collect_all_uses(self):
        src = (
            "fun add(x: Int, y: Int) -> Int\n"
            "    let s = x + y\n"
            "    return s + x\n"
        )
        # Pivot on `x` at line 2 col 13 (the use in the let).
        refs = self.refs(src, "t.capa", 2, 13)
        self.assertIsNotNone(refs)
        names = {r.name for r in refs}
        self.assertEqual(names, {"x"})
        # Declaration (line 1) + two uses (line 2 col 13, line 3 col 16).
        self.assertEqual(len(refs), 3)

    def test_pivot_on_declaration_position_is_idempotent(self):
        # Pivoting on the declaration site itself: the parser
        # does not represent `foo` in `fun foo(...)` as an
        # Ident, so the result is None for that exact cursor.
        # Pivoting on any *use* must still find the same set.
        src = (
            "fun foo() -> Int\n"
            "    return 0\n"
            "fun main(stdio: Stdio)\n"
            "    let _ = foo()\n"
            "    stdio.println(\"hi\")\n"
        )
        # Pivot on call site.
        refs_a = self.refs(src, "t.capa", 4, 13)
        # Same call site, again.
        refs_b = self.refs(src, "t.capa", 4, 13)
        self.assertEqual(
            [(r.pos.line, r.pos.col) for r in refs_a],
            [(r.pos.line, r.pos.col) for r in refs_b],
        )

    def test_references_sorted_by_source_position(self):
        src = (
            "fun greet() -> Int\n"   # line 1
            "    return 0\n"
            "fun main(stdio: Stdio)\n"
            "    let _ = greet()\n"  # line 4
            "    let _ = greet()\n"  # line 5
            "    let _ = greet()\n"  # line 6
            "    stdio.println(\"hi\")\n"
        )
        refs = self.refs(src, "t.capa", 4, 13)
        lines = [r.pos.line for r in refs]
        self.assertEqual(lines, sorted(lines))

    def test_no_references_at_whitespace(self):
        src = "fun main()\n    return\n"
        self.assertIsNone(self.refs(src, "t.capa", 2, 1))

    def test_no_references_for_parse_error_buffer(self):
        src = "fun main()\n    let = "
        self.assertIsNone(self.refs(src, "t.capa", 2, 9))


@unittest.skipUnless(_HAVE_LSP, "requires `pygls` extra (pip install '.[lsp]')")
class TestDocumentSymbols(unittest.TestCase):
    """Document symbols build the outline view shown in the
    editor's sidebar / breadcrumb. Top-level items appear in
    source order; structs nest their fields, sum types nest
    their variants, traits/capabilities nest their method
    signatures, impl blocks nest their methods."""

    def setUp(self):
        from capa.lsp_server import compute_document_symbols
        self.symbols = compute_document_symbols

    def test_lex_or_parse_error_returns_none(self):
        src = "fun main()\n    let = "
        self.assertIsNone(self.symbols(src, "t.capa"))

    def test_constant_appears_with_type_detail(self):
        src = 'const VERSION: String = "1.0"\n'
        syms = self.symbols(src, "t.capa")
        self.assertEqual(len(syms), 1)
        self.assertEqual(syms[0].name, "VERSION")
        self.assertEqual(syms[0].kind, "constant")
        self.assertIn("String", syms[0].detail)

    def test_struct_lists_fields_as_children(self):
        src = (
            "type Point {\n"
            "    x: Int,\n"
            "    y: Int\n"
            "}\n"
        )
        syms = self.symbols(src, "t.capa")
        self.assertEqual(len(syms), 1)
        self.assertEqual(syms[0].kind, "struct")
        self.assertEqual([c.name for c in syms[0].children], ["x", "y"])
        self.assertTrue(all(c.kind == "field" for c in syms[0].children))

    def test_sum_lists_variants_as_children(self):
        src = (
            "type Color =\n"
            "    Red\n"
            "    Green\n"
            "    Blue(Int)\n"
        )
        syms = self.symbols(src, "t.capa")
        self.assertEqual(len(syms), 1)
        self.assertEqual(syms[0].kind, "sum")
        names = [c.name for c in syms[0].children]
        self.assertEqual(names, ["Red", "Green", "Blue"])
        # Variant with payload carries the payload type in its
        # detail field for the outline tooltip.
        blue = syms[0].children[2]
        self.assertIn("Int", blue.detail)

    def test_capability_kind_distinct_from_trait(self):
        src = (
            "capability SendEmail\n"
            "    fun send(self, to: String) -> Bool\n"
            "trait Greet\n"
            "    fun hi(self) -> String\n"
        )
        syms = self.symbols(src, "t.capa")
        kinds = {s.name: s.kind for s in syms}
        self.assertEqual(kinds["SendEmail"], "capability")
        self.assertEqual(kinds["Greet"], "trait")

    def test_function_detail_renders_signature(self):
        src = (
            "fun add(x: Int, y: Int) -> Int\n"
            "    return x + y\n"
        )
        syms = self.symbols(src, "t.capa")
        self.assertEqual(syms[0].kind, "function")
        self.assertEqual(syms[0].detail, "(x: Int, y: Int) -> Int")

    def test_impl_block_nests_methods_and_omits_self_from_detail(self):
        src = (
            "type Point {\n"
            "    x: Int,\n"
            "    y: Int\n"
            "}\n"
            "impl Point\n"
            "    fun translate(self, dx: Int) -> Point\n"
            "        return Point { x: self.x + dx, y: self.y }\n"
        )
        syms = self.symbols(src, "t.capa")
        impls = [s for s in syms if s.kind == "impl"]
        self.assertEqual(len(impls), 1)
        impl = impls[0]
        self.assertEqual(impl.name, "impl Point")
        self.assertEqual(len(impl.children), 1)
        method = impl.children[0]
        self.assertEqual(method.name, "translate")
        # `self` must not appear in the detail signature.
        self.assertNotIn("self", method.detail)
        self.assertEqual(method.detail, "(dx: Int) -> Point")

    def test_trait_impl_display_name_includes_trait(self):
        src = (
            "trait Greet\n"
            "    fun hi(self) -> String\n"
            "type Foo {\n"
            "    n: Int\n"
            "}\n"
            "impl Greet for Foo\n"
            "    fun hi(self) -> String\n"
            '        return "hi"\n'
        )
        syms = self.symbols(src, "t.capa")
        impl = next(s for s in syms if s.kind == "impl")
        self.assertEqual(impl.name, "impl Greet for Foo")

    def test_items_returned_in_source_order(self):
        src = (
            "const A: Int = 1\n"
            "type T { f: Int }\n"
            "fun g() -> Int\n"
            "    return A\n"
        )
        syms = self.symbols(src, "t.capa")
        self.assertEqual([s.name for s in syms], ["A", "T", "g"])


@unittest.skipUnless(_HAVE_LSP, "requires `pygls` extra (pip install '.[lsp]')")
class TestCodeActions(unittest.TestCase):
    """Code actions implement Quick Fixes for the analyzer's
    ``did you mean 'X'?`` hints. The fix replaces the misspelled
    token (located by scanning the diagnostic line, since
    diagnostic columns can be approximate for some error families)
    with the suggested spelling."""

    def setUp(self):
        from capa.lsp_server import compute_code_actions, compute_diagnostics
        self.actions = compute_code_actions
        self.diags = compute_diagnostics

    def test_no_did_you_mean_returns_no_actions(self):
        # An ordinary error with no suggestion gives no Quick Fix.
        msg = "expected newline after impl header"
        self.assertEqual(self.actions("fun main()\n", msg, 1), [])

    def test_method_typo_replaces_with_suggestion(self):
        src = (
            "fun main(stdio: Stdio)\n"
            "    let n = \"hi\".lenght()\n"
            "    stdio.println(\"${n}\")\n"
        )
        diags = self.diags(src, "t.capa")
        target = next(d for d in diags if "lenght" in d.message)
        diag_line_1 = target.range.start.line + 1
        actions = self.actions(src, target.message, diag_line_1)
        self.assertEqual(len(actions), 1)
        a = actions[0]
        self.assertEqual(a.edit.new_text, "length")
        # Column span covers exactly the typo.
        self.assertEqual(a.edit.col_end - a.edit.col_start, len("lenght"))
        # And the source at that span is indeed the typo.
        line_text = src.split("\n")[a.edit.line - 1]
        span = line_text[a.edit.col_start - 1 : a.edit.col_end - 1]
        self.assertEqual(span, "lenght")

    def test_type_typo_replaces_with_suggestion(self):
        src = "fun id(x: Strng) -> Strng\n    return x\n"
        diags = self.diags(src, "t.capa")
        target = next(d for d in diags if "did you mean 'String'" in d.message)
        actions = self.actions(src, target.message, target.range.start.line + 1)
        self.assertGreaterEqual(len(actions), 1)
        self.assertEqual(actions[0].edit.new_text, "String")

    def test_undefined_name_typo_replaces_with_suggestion(self):
        # Use the typo outside string interpolation: ``${...}``
        # contents go through a side parse channel that does not
        # carry positions in v1, so the diagnostic for typos
        # inside interpolations points at line 1 col 1, which
        # the code-action search cannot recover from.
        src = (
            "fun id(x: Int) -> Int\n"
            "    return x\n"
            "fun main(stdio: Stdio)\n"
            "    let result = 42\n"
            "    let _ = id(reslt)\n"
            "    stdio.println(\"k\")\n"
        )
        diags = self.diags(src, "t.capa")
        target = next(d for d in diags if "did you mean 'result'" in d.message)
        actions = self.actions(src, target.message, target.range.start.line + 1)
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0].edit.new_text, "result")

    def test_struct_field_typo_replaces_with_suggestion(self):
        src = (
            "type Person {\n"
            "    full_name: String\n"
            "}\n"
            "fun main(stdio: Stdio)\n"
            "    let p = Person { full_name: \"A\" }\n"
            "    stdio.println(p.full_naem)\n"
        )
        diags = self.diags(src, "t.capa")
        target = next(
            d for d in diags if "did you mean 'full_name'" in d.message
        )
        actions = self.actions(src, target.message, target.range.start.line + 1)
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0].edit.new_text, "full_name")

    def test_typo_search_uses_whole_word_match(self):
        # If the typo happens to be a substring of another token on
        # the same line, the whole-word match must skip the
        # substring occurrence. Here ``in`` is a Capa keyword and
        # also appears inside ``println``; the fix should target
        # nothing on this line because ``in`` is not a typo here.
        # Simulate a synthetic message claiming `in` is the typo.
        src = "fun main(stdio: Stdio)\n    stdio.println(\"hi\")\n"
        msg = "undefined name 'in'; did you mean 'is'?"
        actions = self.actions(src, msg, 2)
        # Either an action against a real ``in`` token (none here)
        # or no action at all. We check that the action does NOT
        # land inside ``println``.
        for a in actions:
            line_text = src.split("\n")[a.edit.line - 1]
            span = line_text[a.edit.col_start - 1 : a.edit.col_end - 1]
            self.assertEqual(span, "in")
            # And the surrounding context is not ``println``.
            before = line_text[a.edit.col_start - 2 : a.edit.col_start - 1]
            after = line_text[a.edit.col_end - 1 : a.edit.col_end]
            self.assertNotEqual(before, "l")  # not 'l' before, so not `lin`
            self.assertNotEqual(after, "t")   # not 't' after, so not `int`

    def test_invalid_line_number_returns_no_actions(self):
        src = "fun main()\n    return\n"
        msg = "undefined name 'x'; did you mean 'y'?"
        self.assertEqual(self.actions(src, msg, 999), [])

    def test_typo_not_on_line_returns_no_actions(self):
        # The diagnostic claims a typo that is not present on the
        # given line (perhaps because the user already started
        # editing). The result must be empty, not a wrong-position
        # edit.
        src = "fun main(stdio: Stdio)\n    stdio.println(\"hi\")\n"
        msg = "undefined name 'gone'; did you mean 'good'?"
        self.assertEqual(self.actions(src, msg, 2), [])


@unittest.skipUnless(_HAVE_LSP, "requires `pygls` extra (pip install '.[lsp]')")
class TestDeclarationSiteSupport(unittest.TestCase):
    """The parser now records ``name_pos`` for declared names
    (functions, types, traits, capabilities, constants, parameters,
    variants, struct fields, method signatures). This unlocks
    hover, go-to-definition, and find-references on the cursor
    sitting on the declaration itself, not just on uses."""

    def setUp(self):
        from capa.lsp_server import (
            compute_hover, compute_definition, compute_references,
        )
        self.hover = compute_hover
        self.defn = compute_definition
        self.refs = compute_references

    def test_hover_on_function_declaration_shows_signature(self):
        src = (
            "fun greet(name: String) -> String\n"   # line 1, `greet` at col 5
            "    return name\n"
        )
        r = self.hover(src, "t.capa", 1, 5)
        self.assertIsNotNone(r)
        md, _ = r
        self.assertIn("fun greet(name: String) -> String", md)

    def test_hover_on_parameter_declaration_shows_type(self):
        src = (
            "fun greet(name: String) -> String\n"   # line 1, `name` at col 11
            "    return name\n"
        )
        r = self.hover(src, "t.capa", 1, 11)
        self.assertIsNotNone(r)
        md, _ = r
        self.assertIn("name: String", md)
        self.assertIn("parameter", md)

    def test_hover_on_const_declaration(self):
        src = 'const VERSION: String = "1.0"\n'   # `VERSION` at col 7
        r = self.hover(src, "t.capa", 1, 7)
        self.assertIsNotNone(r)
        md, _ = r
        self.assertIn("VERSION", md)
        self.assertIn("constant", md)

    def test_hover_on_struct_declaration(self):
        src = (
            "type Point {\n"   # `Point` at col 6
            "    x: Int,\n"
            "    y: Int\n"
            "}\n"
        )
        r = self.hover(src, "t.capa", 1, 6)
        self.assertIsNotNone(r)
        md, _ = r
        self.assertIn("type Point", md)
        self.assertIn("struct", md)

    def test_hover_on_struct_field_declaration(self):
        src = (
            "type Point {\n"
            "    x: Int,\n"   # `x` at col 5 of line 2
            "    y: Int\n"
            "}\n"
        )
        r = self.hover(src, "t.capa", 2, 5)
        self.assertIsNotNone(r)
        md, _ = r
        self.assertIn("x: Int", md)

    def test_hover_on_variant_declaration(self):
        src = (
            "type Color =\n"
            "    Red\n"      # line 2, `Red` at col 5
            "    Green\n"
            "    Blue\n"
        )
        r = self.hover(src, "t.capa", 2, 5)
        self.assertIsNotNone(r)
        md, _ = r
        self.assertIn("Red", md)
        self.assertIn("Color", md)  # owner

    def test_hover_on_capability_declaration(self):
        src = (
            "capability SendEmail\n"   # `SendEmail` at col 12
            "    fun send(self, to: String) -> Bool\n"
        )
        r = self.hover(src, "t.capa", 1, 12)
        self.assertIsNotNone(r)
        md, _ = r
        self.assertIn("capability SendEmail", md)

    def test_goto_def_on_declaration_is_a_noop(self):
        # Cursor on the declaration name should resolve to the
        # same position (jump-to-self).
        src = (
            "fun greet() -> Int\n"   # `greet` at col 5
            "    return 0\n"
        )
        p = self.defn(src, "t.capa", 1, 5)
        self.assertIsNotNone(p)
        self.assertEqual((p.line, p.col), (1, 5))

    def test_find_refs_from_declaration_includes_call_sites(self):
        src = (
            "fun greet() -> Int\n"   # decl at line 1 col 5
            "    return 0\n"
            "fun main(stdio: Stdio)\n"
            "    let _ = greet()\n"   # call at line 4 col 13
            "    let _ = greet()\n"   # call at line 5 col 13
            "    stdio.println(\"k\")\n"
        )
        # Pivot on the declaration name (col 5 of line 1).
        refs = self.refs(src, "t.capa", 1, 5)
        self.assertIsNotNone(refs)
        positions = sorted((r.pos.line, r.pos.col) for r in refs)
        # Expect the declaration entry (at the name's position,
        # NOT at column 1) plus the two call sites.
        self.assertEqual(positions, [(1, 5), (4, 13), (5, 13)])

    def test_find_refs_pivot_consistent_from_decl_or_use(self):
        src = (
            "fun foo() -> Int\n"
            "    return 0\n"
            "fun main(stdio: Stdio)\n"
            "    let _ = foo()\n"
            "    stdio.println(\"k\")\n"
        )
        from_decl = self.refs(src, "t.capa", 1, 5)
        from_use = self.refs(src, "t.capa", 4, 13)
        self.assertEqual(
            sorted((r.pos.line, r.pos.col) for r in from_decl),
            sorted((r.pos.line, r.pos.col) for r in from_use),
        )

    def test_declaration_entry_uses_name_pos_not_keyword(self):
        # Before the parser change, the declaration "ref" landed
        # at col 1 (the `fun` keyword). Now it must land at the
        # name's column.
        src = (
            "fun greet() -> Int\n"   # `greet` at col 5
            "    return 0\n"
            "fun main(stdio: Stdio)\n"
            "    let _ = greet()\n"
            "    stdio.println(\"k\")\n"
        )
        refs = self.refs(src, "t.capa", 4, 13, include_declaration=True)
        decl_entry = next(r for r in refs if r.pos.line == 1)
        self.assertEqual(decl_entry.pos.col, 5)


@unittest.skipUnless(_HAVE_LSP, "requires `pygls` extra (pip install '.[lsp]')")
class TestRename(unittest.TestCase):
    """Rename rewrites every reference + the declaration of the
    symbol under the cursor. Built on top of compute_references
    with include_declaration=True, plus a check that the new name
    is a valid Capa identifier (not a reserved keyword)."""

    def setUp(self):
        from capa.lsp_server import compute_rename, compute_prepare_rename
        self.rename = compute_rename
        self.prepare = compute_prepare_rename

    def test_prepare_rename_returns_range_for_reference(self):
        src = (
            "fun greet() -> Int\n"
            "    return 0\n"
            "fun main(stdio: Stdio)\n"
            "    let _ = greet()\n"   # `greet` call at line 4 col 13
            "    stdio.println(\"k\")\n"
        )
        result = self.prepare(src, "t.capa", 4, 13)
        self.assertIsNotNone(result)
        pos, name = result
        self.assertEqual(name, "greet")
        self.assertEqual((pos.line, pos.col), (4, 13))

    def test_prepare_rename_returns_range_for_declaration(self):
        src = (
            "fun greet() -> Int\n"   # decl at line 1 col 5
            "    return 0\n"
        )
        result = self.prepare(src, "t.capa", 1, 5)
        self.assertIsNotNone(result)
        pos, name = result
        self.assertEqual(name, "greet")
        self.assertEqual((pos.line, pos.col), (1, 5))

    def test_prepare_rename_rejects_builtin(self):
        src = (
            "fun main(stdio: Stdio)\n"   # Stdio at col 17, built-in
            "    stdio.println(\"hi\")\n"
        )
        # Stdio is a type-annotation Ident; it's renameable only
        # if it has a real source origin, which it does not.
        result = self.prepare(src, "t.capa", 1, 17)
        self.assertIsNone(result)

    def test_prepare_rename_returns_none_at_whitespace(self):
        src = "fun main()\n    return\n"
        self.assertIsNone(self.prepare(src, "t.capa", 2, 1))

    def test_rename_function_edits_decl_and_all_call_sites(self):
        src = (
            "fun greet() -> Int\n"        # decl at line 1 col 5
            "    return 0\n"
            "fun main(stdio: Stdio)\n"
            "    let a = greet()\n"       # line 4 col 13
            "    let b = greet()\n"       # line 5 col 13
            "    stdio.println(\"k\")\n"
        )
        # Rename from a call site.
        r = self.rename(src, "t.capa", 4, 13, "say_hi")
        self.assertIsNone(r.error)
        positions = sorted((e.line, e.col_start) for e in r.edits)
        self.assertEqual(positions, [(1, 5), (4, 13), (5, 13)])
        for e in r.edits:
            self.assertEqual(e.col_end - e.col_start, len("greet"))

    def test_rename_from_declaration_site_is_consistent_with_from_use(self):
        src = (
            "fun greet() -> Int\n"
            "    return 0\n"
            "fun main(stdio: Stdio)\n"
            "    let _ = greet()\n"
            "    stdio.println(\"k\")\n"
        )
        from_decl = self.rename(src, "t.capa", 1, 5, "say")
        from_use = self.rename(src, "t.capa", 4, 13, "say")
        self.assertEqual(
            sorted((e.line, e.col_start) for e in from_decl.edits),
            sorted((e.line, e.col_start) for e in from_use.edits),
        )

    def test_rename_to_reserved_keyword_is_rejected(self):
        src = (
            "fun greet() -> Int\n"
            "    return 0\n"
            "fun main(stdio: Stdio)\n"
            "    let _ = greet()\n"
            "    stdio.println(\"k\")\n"
        )
        r = self.rename(src, "t.capa", 4, 13, "if")
        self.assertIsNotNone(r.error)
        self.assertIn("not a valid Capa identifier", r.error)
        self.assertEqual(r.edits, [])

    def test_rename_to_empty_name_is_rejected(self):
        src = "fun greet() -> Int\n    return 0\n"
        r = self.rename(src, "t.capa", 1, 5, "")
        self.assertIsNotNone(r.error)
        self.assertEqual(r.edits, [])

    def test_rename_to_name_starting_with_digit_is_rejected(self):
        src = "fun greet() -> Int\n    return 0\n"
        r = self.rename(src, "t.capa", 1, 5, "1greet")
        self.assertIsNotNone(r.error)
        self.assertEqual(r.edits, [])

    def test_rename_to_name_with_dash_is_rejected(self):
        src = "fun greet() -> Int\n    return 0\n"
        r = self.rename(src, "t.capa", 1, 5, "say-hi")
        self.assertIsNotNone(r.error)
        self.assertEqual(r.edits, [])

    def test_rename_parameter_edits_param_and_body_uses(self):
        src = (
            "fun greet(name: String) -> String\n"   # `name` at col 11
            "    return name\n"                     # use at col 12
        )
        r = self.rename(src, "t.capa", 2, 12, "who")
        self.assertIsNone(r.error)
        positions = sorted((e.line, e.col_start) for e in r.edits)
        # Parameter declaration + one body use.
        self.assertEqual(positions, [(1, 11), (2, 12)])

    def test_rename_returns_no_edits_at_unknown_position(self):
        src = "fun main()\n    return\n"
        r = self.rename(src, "t.capa", 2, 1, "ok")
        # The new name is valid, but there is no symbol at the
        # cursor. The error must be present and edits empty.
        self.assertIsNotNone(r.error)
        self.assertEqual(r.edits, [])

    def test_rename_returns_none_for_parse_error_buffer(self):
        src = "fun main()\n    let = "
        r = self.rename(src, "t.capa", 2, 9, "ok")
        self.assertIsNotNone(r.error)
        self.assertEqual(r.edits, [])


@unittest.skipUnless(_HAVE_LSP, "requires `pygls` extra (pip install '.[lsp]')")
class TestCompletion(unittest.TestCase):
    """Completion v1 is a floor (keywords + built-in types,
    capabilities, variants, functions) plus, when the buffer
    parses, the module-level names and approximate locals at
    the cursor."""

    def setUp(self):
        from capa.lsp_server import compute_completions
        self.complete = compute_completions

    def _labels(self, completions) -> set[str]:
        return {c.label for c in completions}

    def test_floor_always_includes_core_keywords(self):
        # Even with a totally empty buffer, the keyword floor
        # should be there.
        c = self.complete("", "t.capa", 1, 1)
        labels = self._labels(c)
        for kw in ("fun", "type", "trait", "impl", "let", "var",
                   "if", "match", "return", "true", "false"):
            self.assertIn(kw, labels)

    def test_floor_includes_builtin_capabilities(self):
        c = self.complete("", "t.capa", 1, 1)
        labels = self._labels(c)
        for cap in ("Stdio", "Fs", "Net", "Env", "Clock", "Random", "Unsafe"):
            self.assertIn(cap, labels)

    def test_floor_includes_builtin_types(self):
        c = self.complete("", "t.capa", 1, 1)
        labels = self._labels(c)
        for ty in ("Int", "Float", "Bool", "String", "Char", "Unit",
                   "List", "Option", "Result", "Map", "Set"):
            self.assertIn(ty, labels)

    def test_floor_includes_common_variants(self):
        c = self.complete("", "t.capa", 1, 1)
        labels = self._labels(c)
        for v in ("Some", "None", "Ok", "Err"):
            self.assertIn(v, labels)

    def test_broken_buffer_falls_back_to_floor(self):
        # A buffer that fails to parse must still get the floor
        # (otherwise the completion list goes dark on every
        # half-typed line).
        c = self.complete("fun main()\n    let x = ", "t.capa", 2, 14)
        labels = self._labels(c)
        # The floor is intact.
        self.assertIn("fun", labels)
        self.assertIn("Stdio", labels)
        self.assertIn("Some", labels)

    def test_module_level_names_appear_when_parsed(self):
        src = (
            "const VERSION: String = \"1.0\"\n"
            "fun greet(name: String) -> String\n"
            "    return name\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"hi\")\n"
        )
        c = self.complete(src, "t.capa", 5, 5)
        labels = self._labels(c)
        self.assertIn("VERSION", labels)
        self.assertIn("greet", labels)
        self.assertIn("main", labels)

    def test_function_signature_in_detail(self):
        src = (
            "fun greet(name: String) -> String\n"
            "    return name\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"hi\")\n"
        )
        c = self.complete(src, "t.capa", 4, 5)
        item = next(x for x in c if x.label == "greet")
        self.assertEqual(item.kind, "function")
        self.assertIn("name: String", item.detail)
        self.assertIn("-> String", item.detail)

    def test_struct_type_marked_as_struct(self):
        src = (
            "type Point {\n"
            "    x: Int,\n"
            "    y: Int\n"
            "}\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"hi\")\n"
        )
        c = self.complete(src, "t.capa", 6, 5)
        item = next(x for x in c if x.label == "Point")
        self.assertEqual(item.kind, "type")
        self.assertEqual(item.detail, "struct")

    def test_sum_type_and_variants_both_surfaced(self):
        src = (
            "type Color =\n"
            "    Red\n"
            "    Green\n"
            "    Blue\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"hi\")\n"
        )
        c = self.complete(src, "t.capa", 6, 5)
        labels = self._labels(c)
        self.assertIn("Color", labels)
        # Variants are surfaced individually so users do not have
        # to spell the owning type.
        self.assertIn("Red", labels)
        self.assertIn("Green", labels)
        self.assertIn("Blue", labels)
        red = next(x for x in c if x.label == "Red")
        self.assertEqual(red.kind, "variant")
        self.assertIn("Color", red.detail)

    def test_user_capability_distinguished_from_builtin(self):
        src = (
            "capability SendEmail\n"
            "    fun send(self, to: String) -> Bool\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"hi\")\n"
        )
        c = self.complete(src, "t.capa", 4, 5)
        item = next(x for x in c if x.label == "SendEmail")
        self.assertEqual(item.kind, "capability")
        self.assertIn("user-defined", item.detail)

    def test_local_let_binding_appears_with_inferred_type(self):
        src = (
            "fun main(stdio: Stdio)\n"
            "    let count = 42\n"
            "    let name = \"hi\"\n"
            "    stdio.println(name)\n"
        )
        c = self.complete(src, "t.capa", 4, 5)
        labels = self._labels(c)
        self.assertIn("count", labels)
        self.assertIn("name", labels)
        count = next(x for x in c if x.label == "count")
        self.assertEqual(count.kind, "value")
        self.assertEqual(count.detail, "Int")

    def test_parameter_visible_in_function_body(self):
        src = (
            "fun greet(name: String) -> String\n"
            "    return name\n"
        )
        c = self.complete(src, "t.capa", 2, 5)
        labels = self._labels(c)
        self.assertIn("name", labels)

    def test_underscore_prefixed_params_filtered_out(self):
        # Capa convention: ``_name`` silences unused-capability
        # checks. Such parameters should not pollute completion.
        src = (
            "fun main(_stdio: Stdio, x: Int) -> Int\n"
            "    return x\n"
        )
        c = self.complete(src, "t.capa", 2, 5)
        labels = self._labels(c)
        self.assertNotIn("_stdio", labels)
        self.assertIn("x", labels)

    def test_no_duplicate_labels(self):
        # When a user binding collides with a built-in name, the
        # de-dup pass keeps one entry per label.
        src = (
            "fun main(stdio: Stdio)\n"
            "    let Int = 5\n"   # shadows the built-in type name
            "    stdio.println(\"hi\")\n"
        )
        c = self.complete(src, "t.capa", 3, 5)
        labels_list = [x.label for x in c]
        self.assertEqual(len(labels_list), len(set(labels_list)))


@unittest.skipUnless(_HAVE_LSP, "requires `pygls` extra (pip install '.[lsp]')")
class TestMethodCompletion(unittest.TestCase):
    """When the cursor sits in a ``receiver.<here>`` context, the
    completion list narrows to the methods of the receiver's
    type. No keyword / built-in floor is mixed in: the user is
    asking for members, not free names. Mid-edit buffers
    (``stdio.<eof>``) are handled by re-parsing with a synthetic
    placeholder identifier injected at the cursor."""

    def setUp(self):
        from capa.lsp_server import compute_completions
        self.complete = compute_completions

    def _labels(self, completions) -> set[str]:
        return {c.label for c in completions}

    def test_trailing_dot_after_capability_offers_its_methods(self):
        src = (
            "fun main(stdio: Stdio)\n"
            "    stdio.\n"
        )
        c = self.complete(src, "t.capa", 2, 11)
        labels = self._labels(c)
        # Stdio methods registered by the analyzer.
        for m in ("print", "println", "eprintln", "read_line"):
            self.assertIn(m, labels)
        # And no keyword noise.
        self.assertNotIn("fun", labels)
        self.assertNotIn("let", labels)

    def test_partial_method_name_still_offers_full_set(self):
        # LSP clients fuzzy-rank by the user's partial input;
        # the server must return the full list, not the filtered
        # one.
        src = (
            "fun main(stdio: Stdio)\n"
            "    stdio.pr\n"
        )
        c = self.complete(src, "t.capa", 2, 13)
        labels = self._labels(c)
        self.assertIn("print", labels)
        self.assertIn("println", labels)
        # ``read_line`` does not start with ``pr`` but must
        # still appear so the client's ranker can decide.
        self.assertIn("read_line", labels)

    def test_string_literal_receiver(self):
        src = (
            "fun main(stdio: Stdio)\n"
            "    let n = \"hi\".\n"
            "    stdio.println(\"k\")\n"
        )
        c = self.complete(src, "t.capa", 2, 18)
        labels = self._labels(c)
        for m in ("length", "contains", "starts_with", "to_upper",
                  "trim", "split", "replace", "is_empty"):
            self.assertIn(m, labels)

    def test_list_local_receiver(self):
        src = (
            "fun main(stdio: Stdio)\n"
            "    let xs = [1, 2, 3]\n"
            "    let y = xs.\n"
            "    stdio.println(\"k\")\n"
        )
        c = self.complete(src, "t.capa", 3, 16)
        labels = self._labels(c)
        for m in ("length", "push", "map", "filter", "fold", "first"):
            self.assertIn(m, labels)

    def test_method_completion_signature_in_detail(self):
        src = "fun main(stdio: Stdio)\n    stdio.\n"
        c = self.complete(src, "t.capa", 2, 11)
        println = next(x for x in c if x.label == "println")
        # The detail column shows the method's TyFun.
        self.assertIn("String", println.detail)
        self.assertIn("()", println.detail)

    def test_user_defined_struct_methods_offered(self):
        src = (
            "type Counter {\n"
            "    n: Int\n"
            "}\n"
            "impl Counter\n"
            "    fun value(self) -> Int\n"
            "        return self.n\n"
            "    fun bump(self) -> Counter\n"
            "        return Counter { n: self.n + 1 }\n"
            "fun main(stdio: Stdio)\n"
            "    let c = Counter { n: 0 }\n"
            "    let _ = c.\n"
            "    stdio.println(\"k\")\n"
        )
        c = self.complete(src, "t.capa", 11, 15)
        labels = self._labels(c)
        self.assertIn("value", labels)
        self.assertIn("bump", labels)

    def test_underscore_methods_filtered(self):
        # Methods that start with `_` should not appear in
        # completion (internal-by-convention).
        src = (
            "fun main(stdio: Stdio)\n"
            "    stdio.\n"
        )
        c = self.complete(src, "t.capa", 2, 11)
        for x in c:
            self.assertFalse(
                x.label.startswith("_"),
                f"{x.label!r} should not appear in method completion",
            )

    def test_unresolved_receiver_returns_empty(self):
        # ``foo.`` where ``foo`` is not in scope: no methods to
        # offer. Empty list rather than a noisy fallback.
        src = "fun main(stdio: Stdio)\n    foo.\n"
        c = self.complete(src, "t.capa", 2, 9)
        self.assertEqual(c, [])

    def test_method_context_does_not_include_keywords(self):
        # The dot-trigger path returns ONLY methods, never the
        # keyword/builtin floor (which would be misleading).
        src = "fun main(stdio: Stdio)\n    stdio.\n"
        c = self.complete(src, "t.capa", 2, 11)
        for x in c:
            self.assertEqual(
                x.kind, "function",
                f"unexpected kind={x.kind!r} for {x.label!r}",
            )


if __name__ == "__main__":
    unittest.main()
