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
from pathlib import Path

try:
    import lsprotocol  # noqa: F401
    _HAVE_LSP = True
except ImportError:
    _HAVE_LSP = False


try:
    import pygls  # noqa: F401
    _HAVE_PYGLS = True
except ImportError:
    _HAVE_PYGLS = False


@unittest.skipUnless(
    _HAVE_LSP and _HAVE_PYGLS,
    "requires pygls + lsprotocol (pip install '.[lsp]')",
)
class TestLspServerHandlersInProcess(unittest.TestCase):
    """In-process coverage for the handlers built inside
    ``capa.lsp.server._build_server()``. The earlier suites
    (``TestHover``, ``TestGoToDefinition``, ...) hit the
    ``compute_*`` helpers directly through the back-compat shim;
    that misses the server itself, which translates between
    pygls' LSP types and the compute helpers' Capa-native types.

    The harness builds the real LanguageServer, then stubs the
    workspace + publish_diagnostics + show_message so each
    feature handler can be invoked with mock LSP params without
    a JSON-RPC round-trip. Handlers are retrieved from
    ``server.protocol.fm.features`` (pygls 2.x's feature map).
    """

    def setUp(self):
        from unittest.mock import MagicMock
        from capa.lsp.server import _build_server
        self.server = _build_server()
        # Stub workspace: callers do ``ls.workspace.get_text_document(uri)``
        # then ``.source`` on the result.
        self.workspace = MagicMock()
        self.doc = MagicMock()
        self.workspace.get_text_document.return_value = self.doc
        self.server.protocol._workspace = self.workspace
        # Capture published diagnostics + show_message calls so tests
        # can assert against them without a JSON-RPC channel.
        self.published: list = []
        self.server.text_document_publish_diagnostics = (
            lambda params: self.published.append(params)
        )
        self.messages: list = []
        self.server.show_message = (
            lambda msg, kind=None: self.messages.append((msg, kind))
        )

    # ---- helpers ---------------------------------------------

    def _handler(self, method: str):
        """Fetch a registered handler by LSP method name. KeyError
        flags a regression (a handler was renamed or removed)."""
        return self.server.protocol.fm.features[method]

    def _set_source(self, source: str) -> None:
        """Replace the fake doc's source so the next handler call
        sees the new content."""
        self.doc.source = source

    def _params_position(self, line: int, char: int):
        from lsprotocol import types as lsp
        return lsp.Position(line=line, character=char)

    def _text_doc_id(self):
        from lsprotocol import types as lsp
        return lsp.TextDocumentIdentifier(uri="file:///t.capa")

    # ---- did_open / did_change / did_save / did_close --------

    def test_did_open_publishes_diagnostics(self):
        from lsprotocol import types as lsp
        params = lsp.DidOpenTextDocumentParams(
            text_document=lsp.TextDocumentItem(
                uri="file:///t.capa",
                language_id="capa",
                version=1,
                text="fun main(stdio: Stdio)\n    let x = undefined_thing\n",
            )
        )
        self._handler(lsp.TEXT_DOCUMENT_DID_OPEN)(params)
        self.assertEqual(len(self.published), 1)
        diags = self.published[0].diagnostics
        self.assertTrue(any("undefined" in d.message for d in diags))

    def test_did_change_re_publishes_from_workspace_doc(self):
        from lsprotocol import types as lsp
        self._set_source(
            "fun main(stdio: Stdio)\n    let y = oops\n"
        )
        params = lsp.DidChangeTextDocumentParams(
            text_document=lsp.VersionedTextDocumentIdentifier(
                uri="file:///t.capa", version=2,
            ),
            content_changes=[],
        )
        self._handler(lsp.TEXT_DOCUMENT_DID_CHANGE)(params)
        self.assertEqual(len(self.published), 1)
        self.assertTrue(any(
            "undefined" in d.message
            for d in self.published[0].diagnostics
        ))

    def test_did_save_re_publishes(self):
        from lsprotocol import types as lsp
        self._set_source(
            "fun main(stdio: Stdio)\n    stdio.println(\"ok\")\n"
        )
        params = lsp.DidSaveTextDocumentParams(
            text_document=self._text_doc_id(),
        )
        self._handler(lsp.TEXT_DOCUMENT_DID_SAVE)(params)
        self.assertEqual(len(self.published), 1)
        self.assertEqual(self.published[0].diagnostics, [])

    def test_did_close_clears_diagnostics(self):
        from lsprotocol import types as lsp
        params = lsp.DidCloseTextDocumentParams(
            text_document=self._text_doc_id(),
        )
        self._handler(lsp.TEXT_DOCUMENT_DID_CLOSE)(params)
        self.assertEqual(len(self.published), 1)
        self.assertEqual(self.published[0].diagnostics, [])

    # ---- hover -----------------------------------------------

    def test_hover_on_reference_returns_markdown(self):
        from lsprotocol import types as lsp
        self._set_source(
            "fun greet(name: String) -> String\n"
            "    return \"hi \" + name\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(greet(\"x\"))\n"
        )
        # Cursor over `greet` in `greet("x")` (line 4 col 19, 0-based 3/18).
        params = lsp.HoverParams(
            text_document=self._text_doc_id(),
            position=self._params_position(3, 18),
        )
        result = self._handler(lsp.TEXT_DOCUMENT_HOVER)(params)
        self.assertIsNotNone(result)
        self.assertIn("greet", result.contents.value)

    def test_hover_on_whitespace_returns_none(self):
        from lsprotocol import types as lsp
        self._set_source("fun main(stdio: Stdio)\n    stdio.println(\"x\")\n")
        params = lsp.HoverParams(
            text_document=self._text_doc_id(),
            position=self._params_position(0, 0),  # column 0, before `fun`
        )
        result = self._handler(lsp.TEXT_DOCUMENT_HOVER)(params)
        self.assertIsNone(result)

    # ---- definition + references -----------------------------

    def test_definition_resolves_to_decl_site(self):
        from lsprotocol import types as lsp
        self._set_source(
            "fun greet(name: String) -> String\n"
            "    return name\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(greet(\"x\"))\n"
        )
        # Cursor over the `greet` reference on line 4.
        params = lsp.DefinitionParams(
            text_document=self._text_doc_id(),
            position=self._params_position(3, 18),
        )
        result = self._handler(lsp.TEXT_DOCUMENT_DEFINITION)(params)
        self.assertIsNotNone(result)
        self.assertEqual(result.range.start.line, 0)  # `fun greet(...)` is line 1 (0-based 0)

    def test_definition_on_unknown_returns_none(self):
        from lsprotocol import types as lsp
        self._set_source("fun main(stdio: Stdio)\n    stdio.println(\"x\")\n")
        params = lsp.DefinitionParams(
            text_document=self._text_doc_id(),
            position=self._params_position(0, 0),
        )
        result = self._handler(lsp.TEXT_DOCUMENT_DEFINITION)(params)
        self.assertIsNone(result)

    def test_references_returns_locations(self):
        from lsprotocol import types as lsp
        self._set_source(
            "fun greet(name: String) -> String\n"
            "    return name\n"
            "fun main(stdio: Stdio)\n"
            "    let a = greet(\"x\")\n"
            "    let b = greet(\"y\")\n"
            "    stdio.println(a)\n"
            "    stdio.println(b)\n"
        )
        params = lsp.ReferenceParams(
            text_document=self._text_doc_id(),
            position=self._params_position(3, 12),
            context=lsp.ReferenceContext(include_declaration=False),
        )
        result = self._handler(lsp.TEXT_DOCUMENT_REFERENCES)(params)
        self.assertIsNotNone(result)
        self.assertGreaterEqual(len(result), 2)

    def test_references_default_includes_declaration(self):
        from lsprotocol import types as lsp
        self._set_source(
            "fun greet(name: String) -> String\n"
            "    return name\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(greet(\"x\"))\n"
        )
        # Construct ReferenceParams without context to hit the
        # `include_decl=True` default branch on line 191.
        params = lsp.ReferenceParams(
            text_document=self._text_doc_id(),
            position=self._params_position(3, 18),
            context=lsp.ReferenceContext(include_declaration=True),
        )
        # Force the include_declaration default branch by null-ing context.
        params.context = None
        result = self._handler(lsp.TEXT_DOCUMENT_REFERENCES)(params)
        self.assertIsNotNone(result)

    # ---- document_symbol -------------------------------------

    def test_document_symbol_lists_top_level_items(self):
        from lsprotocol import types as lsp
        self._set_source(
            "type Pair { x: Int, y: Int }\n"
            "fun add(a: Int, b: Int) -> Int\n"
            "    return a + b\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
        )
        params = lsp.DocumentSymbolParams(text_document=self._text_doc_id())
        syms = self._handler(lsp.TEXT_DOCUMENT_DOCUMENT_SYMBOL)(params)
        names = {s.name for s in syms}
        self.assertIn("Pair", names)
        self.assertIn("add", names)
        self.assertIn("main", names)

    # ---- code_action -----------------------------------------

    def test_code_action_offers_quickfix_for_did_you_mean(self):
        from lsprotocol import types as lsp
        self._set_source(
            "fun main(stdio: Stdio)\n"
            "    let n = \"hi\".lenght()\n"
            "    stdio.println(\"${n}\")\n"
        )
        # Provide a diagnostic mirroring what `_refresh` would publish
        # so `compute_code_actions` finds a matching quickfix.
        diag = lsp.Diagnostic(
            range=lsp.Range(
                start=lsp.Position(line=1, character=17),
                end=lsp.Position(line=1, character=24),
            ),
            severity=lsp.DiagnosticSeverity.Error,
            source="capa-lsp",
            message="unknown String method 'lenght'; did you mean 'length'?",
        )
        params = lsp.CodeActionParams(
            text_document=self._text_doc_id(),
            range=diag.range,
            context=lsp.CodeActionContext(diagnostics=[diag]),
        )
        result = self._handler(lsp.TEXT_DOCUMENT_CODE_ACTION)(params)
        self.assertIsNotNone(result)
        self.assertTrue(any("length" in a.title for a in result))

    def test_code_action_with_no_diagnostics_returns_none(self):
        from lsprotocol import types as lsp
        self._set_source("fun main(stdio: Stdio)\n    stdio.println(\"ok\")\n")
        params = lsp.CodeActionParams(
            text_document=self._text_doc_id(),
            range=lsp.Range(
                start=lsp.Position(line=0, character=0),
                end=lsp.Position(line=0, character=0),
            ),
            context=lsp.CodeActionContext(diagnostics=[]),
        )
        result = self._handler(lsp.TEXT_DOCUMENT_CODE_ACTION)(params)
        self.assertIsNone(result)

    # ---- semantic_tokens -------------------------------------

    def test_semantic_tokens_full_returns_data(self):
        from lsprotocol import types as lsp
        self._set_source(
            "fun main(stdio: Stdio)\n"
            "    let x = 42\n"
            "    stdio.println(\"${x}\")\n"
        )
        params = lsp.SemanticTokensParams(text_document=self._text_doc_id())
        result = self._handler(lsp.TEXT_DOCUMENT_SEMANTIC_TOKENS_FULL)(params)
        self.assertIsNotNone(result)
        # data is a flat list of ints; should be non-empty for this source.
        self.assertGreater(len(result.data), 0)

    # ---- completion ------------------------------------------

    def test_completion_returns_items(self):
        from lsprotocol import types as lsp
        self._set_source(
            "fun main(stdio: Stdio)\n"
            "    let x = \n"
        )
        params = lsp.CompletionParams(
            text_document=self._text_doc_id(),
            position=self._params_position(1, 12),
        )
        result = self._handler(lsp.TEXT_DOCUMENT_COMPLETION)(params)
        self.assertIsNotNone(result)
        # We at least get keyword completions like `true`, `false`, ...
        self.assertGreater(len(result), 0)

    # ---- prepare_rename / rename -----------------------------

    def test_prepare_rename_returns_range_for_valid_target(self):
        from lsprotocol import types as lsp
        self._set_source(
            "fun greet(name: String) -> String\n"
            "    return name\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(greet(\"x\"))\n"
        )
        params = lsp.PrepareRenameParams(
            text_document=self._text_doc_id(),
            position=self._params_position(3, 18),
        )
        result = self._handler(lsp.TEXT_DOCUMENT_PREPARE_RENAME)(params)
        self.assertIsNotNone(result)
        self.assertEqual(result.start.line, 3)

    def test_prepare_rename_on_invalid_returns_none(self):
        from lsprotocol import types as lsp
        self._set_source("fun main(stdio: Stdio)\n    stdio.println(\"ok\")\n")
        params = lsp.PrepareRenameParams(
            text_document=self._text_doc_id(),
            position=self._params_position(0, 0),
        )
        result = self._handler(lsp.TEXT_DOCUMENT_PREPARE_RENAME)(params)
        self.assertIsNone(result)

    def test_rename_produces_workspace_edit(self):
        from lsprotocol import types as lsp
        self._set_source(
            "fun greet(name: String) -> String\n"
            "    return name\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(greet(\"x\"))\n"
        )
        params = lsp.RenameParams(
            text_document=self._text_doc_id(),
            position=self._params_position(3, 18),
            new_name="hello",
        )
        result = self._handler(lsp.TEXT_DOCUMENT_RENAME)(params)
        self.assertIsNotNone(result)
        self.assertIn("file:///t.capa", result.changes)
        edits = result.changes["file:///t.capa"]
        self.assertTrue(all(e.new_text == "hello" for e in edits))
        self.assertGreaterEqual(len(edits), 2)  # decl + at least one use

    def test_rename_to_invalid_identifier_shows_warning(self):
        from lsprotocol import types as lsp
        self._set_source(
            "fun greet(name: String) -> String\n"
            "    return name\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(greet(\"x\"))\n"
        )
        params = lsp.RenameParams(
            text_document=self._text_doc_id(),
            position=self._params_position(3, 18),
            new_name="123_not_an_ident",
        )
        result = self._handler(lsp.TEXT_DOCUMENT_RENAME)(params)
        self.assertIsNone(result)
        self.assertEqual(len(self.messages), 1)
        msg, kind = self.messages[0]
        self.assertIn("123_not_an_ident", msg)

    # ---- P0: UTF-16 vs codepoint column at the wire boundary ----
    #
    # When a line contains an astral (supplementary-plane) char
    # before an identifier, the LSP wire ``character`` column is in
    # UTF-16 code units (pygls' Utf16 codec) while the compute_*
    # helpers work in codepoints. The server boundary must convert
    # both ways or rename silently corrupts the buffer.

    _ASTRAL_SRC = (
        "fun f(greeting: String) -> String\n"
        "    let z = \"\U0001F600\" + greeting\n"
    )
    # On line 2 (0-based 1): the emoji is one codepoint but two
    # UTF-16 units, so ``greeting`` sits at codepoint col 18 (0-based)
    # / UTF-16 col 19 (0-based). Verified via PositionCodec.
    _GREETING_CP_0BASED = 18
    _GREETING_UTF16_0BASED = 19

    def _greeting_client_col(self):
        from pygls.workspace import PositionCodec
        from lsprotocol import types as lsp
        lines = self._ASTRAL_SRC.splitlines(keepends=True)
        out = PositionCodec().position_to_client_units(
            lines, lsp.Position(line=1, character=self._GREETING_CP_0BASED),
        )
        return out.character

    def test_astral_client_col_matches_verified_value(self):
        # Guards the hard-coded expectation against codec drift.
        self.assertEqual(
            self._greeting_client_col(), self._GREETING_UTF16_0BASED,
        )

    def test_rename_on_astral_line_emits_utf16_columns(self):
        # P0 rename: the edit on the astral line must land on the
        # correct UTF-16 columns, not the (shifted) codepoint ones.
        from lsprotocol import types as lsp
        self._set_source(self._ASTRAL_SRC)
        client_col = self._greeting_client_col()
        params = lsp.RenameParams(
            text_document=self._text_doc_id(),
            position=self._params_position(1, client_col),
            new_name="hi",
        )
        result = self._handler(lsp.TEXT_DOCUMENT_RENAME)(params)
        self.assertIsNotNone(result)
        edits = result.changes["file:///t.capa"]
        use_edits = [e for e in edits if e.range.start.line == 1]
        self.assertEqual(len(use_edits), 1)
        rng = use_edits[0].range
        # UTF-16 start 19, end 19 + len("greeting") == 27.
        self.assertEqual(rng.start.character, self._GREETING_UTF16_0BASED)
        self.assertEqual(rng.end.character, self._GREETING_UTF16_0BASED + 8)
        # The declaration edit on the ASCII line is unshifted.
        decl_edits = [e for e in edits if e.range.start.line == 0]
        self.assertEqual(decl_edits[0].range.start.character, 6)

    def test_hover_on_astral_line_resolves_inbound_position(self):
        # P0 round-trip: a client UTF-16 position on the astral line
        # must resolve to the right codepoint col so hover/definition
        # find the identifier.
        from lsprotocol import types as lsp
        self._set_source(self._ASTRAL_SRC)
        client_col = self._greeting_client_col()
        params = lsp.HoverParams(
            text_document=self._text_doc_id(),
            position=self._params_position(1, client_col),
        )
        result = self._handler(lsp.TEXT_DOCUMENT_HOVER)(params)
        self.assertIsNotNone(result)
        # And the returned range comes back in UTF-16 client units.
        self.assertEqual(
            result.range.start.character, self._GREETING_UTF16_0BASED,
        )

    def test_ascii_rename_columns_unchanged_by_codec(self):
        # Regression guard: for ASCII, codepoint == UTF-16, so the
        # conversion must be a no-op.
        from lsprotocol import types as lsp
        self._set_source(
            "fun greet(name: String) -> String\n"
            "    return name\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(greet(\"x\"))\n"
        )
        params = lsp.RenameParams(
            text_document=self._text_doc_id(),
            position=self._params_position(3, 18),
            new_name="hello",
        )
        result = self._handler(lsp.TEXT_DOCUMENT_RENAME)(params)
        edits = result.changes["file:///t.capa"]
        # greet decl on line 0 starts at column 4.
        decl = [e for e in edits if e.range.start.line == 0][0]
        self.assertEqual(decl.range.start.character, 4)
        self.assertEqual(decl.range.end.character, 4 + 5)


@unittest.skipUnless(
    _HAVE_LSP,
    "requires lsprotocol (pip install '.[lsp]')",
)
class TestLspDocumentHighlightHandlers(unittest.TestCase):
    """Coverage for ``compute_document_highlights``: the
    same-binding occurrence walker that backs
    ``textDocument/documentHighlight``. We exercise the compute
    helper directly rather than the wire handler because the
    handler in ``server.py`` is a thin translation layer; the
    interesting logic lives in this module.
    """

    def setUp(self):
        from capa.lsp.document_highlight import (
            compute_document_highlights,
        )
        self.highlight = compute_document_highlights

    def test_highlight_on_identifier_returns_all_occurrences(self):
        src = (
            "fun foo(x: Int) -> Int\n"
            "    let y = x + x\n"
            "    return y + x\n"
        )
        # Cursor on the first body-occurrence of `x` (line 2, col 13).
        hits = self.highlight(src, "t.capa", 2, 13)
        self.assertIsNotNone(hits)
        # Param decl + three uses = four highlights.
        self.assertEqual(len(hits), 4)
        self.assertTrue(all(h.name == "x" for h in hits))

    def test_highlight_on_whitespace_returns_none(self):
        src = (
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"hi\")\n"
        )
        # Column 1 of line 2 is whitespace inside the indent.
        self.assertIsNone(self.highlight(src, "t.capa", 2, 1))

    def test_highlight_on_function_name_returns_decl_plus_calls(self):
        src = (
            "fun foo() -> Int\n"
            "    return 1\n"
            "fun main(stdio: Stdio)\n"
            "    let a = foo()\n"
            "    let b = foo()\n"
            "    stdio.println(\"${a}\")\n"
            "    stdio.println(\"${b}\")\n"
        )
        # Cursor on `foo` in the declaration `fun foo()` (line 1, col 5).
        hits = self.highlight(src, "t.capa", 1, 5)
        self.assertIsNotNone(hits)
        self.assertTrue(all(h.name == "foo" for h in hits))
        # Decl on line 1 + two call sites on lines 4 and 5.
        lines = sorted({h.line for h in hits})
        self.assertEqual(lines, [1, 4, 5])

    def test_highlight_kind_is_text_in_v1(self):
        from lsprotocol import types as lsp
        src = (
            "fun foo(x: Int) -> Int\n"
            "    return x + x\n"
        )
        hits = self.highlight(src, "t.capa", 2, 12)
        self.assertIsNotNone(hits)
        # v1: no read/write split, every kind is the wire `Text`.
        # The handler's mapping is `"text" -> DocumentHighlightKind.Text`,
        # so the module-level string must round-trip to that constant.
        kind_map = {
            "text":  lsp.DocumentHighlightKind.Text,
            "read":  lsp.DocumentHighlightKind.Read,
            "write": lsp.DocumentHighlightKind.Write,
        }
        for h in hits:
            self.assertEqual(h.kind, "text")
            self.assertEqual(
                kind_map[h.kind], lsp.DocumentHighlightKind.Text,
            )


@unittest.skipUnless(
    _HAVE_LSP and _HAVE_PYGLS,
    "requires pygls + lsprotocol (pip install '.[lsp]')",
)
class TestLspFormattingHandlers(unittest.TestCase):
    """Coverage for ``capa.lsp.formatting.compute_formatting`` and
    ``compute_range_formatting``. The handlers are not yet wired
    into ``_build_server()`` (that's a separate merge step), so
    these tests exercise the pure functions directly. They follow
    the same shape as ``TestLspServerHandlersInProcess`` so the
    handler-wired versions can drop in later without churn.
    """

    def _compute_formatting(self):
        from capa.lsp.formatting import compute_formatting
        return compute_formatting

    def _compute_range_formatting(self):
        from capa.lsp.formatting import compute_range_formatting
        return compute_range_formatting

    def test_formatting_canonical_source_returns_no_edits(self):
        from capa.formatter import format_source
        canonical = format_source(
            "fun main(stdio: Stdio)\n    let x = 1\n"
        )
        # Sanity: the formatter is idempotent on its own output.
        self.assertEqual(format_source(canonical), canonical)
        edits = self._compute_formatting()(canonical)
        self.assertEqual(edits, [])

    def test_formatting_non_canonical_source_returns_one_edit(self):
        from capa.formatter import format_source
        source = "fun main(stdio: Stdio)\n    let x  =  1\n"
        expected = format_source(source)
        self.assertNotEqual(source, expected)  # guard: input is non-canonical
        edits = self._compute_formatting()(source)
        self.assertEqual(len(edits), 1)
        edit = edits[0]
        self.assertEqual(edit.start_line, 1)
        self.assertEqual(edit.start_col, 1)
        # Range covers the whole document up to the past-end position.
        lines = source.split("\n")
        self.assertEqual(edit.end_line, len(lines))
        self.assertEqual(edit.end_col, len(lines[-1]) + 1)
        self.assertEqual(edit.new_text, expected)

    def test_formatting_invalid_source_falls_back_safely(self):
        # ``fun foo(`` is unterminated; the v3 AST round-trip will
        # raise on parse, the formatter falls back to v1+v2 line-
        # level, and the handler must surface whatever that returns
        # without raising.
        source = "fun foo("
        from capa.formatter import format_source
        expected = format_source(source)
        # The line-level fallback at minimum adds a trailing newline,
        # so the source is not canonical and we expect an edit.
        self.assertNotEqual(source, expected)
        try:
            edits = self._compute_formatting()(source)
        except Exception as exc:
            self.fail(
                f"compute_formatting must never raise; got {exc!r}"
            )
        self.assertEqual(len(edits), 1)
        self.assertEqual(edits[0].new_text, expected)

    def test_range_formatting_falls_back_to_whole_document(self):
        # Asking for lines 1-2 only still produces a whole-document
        # edit, per the scope cut documented in capa/lsp/formatting.py.
        from capa.formatter import format_source
        source = "fun main(stdio: Stdio)\n    let x  =  1\n"
        expected = format_source(source)
        edits = self._compute_range_formatting()(
            source,
            start_line=1, start_col=1,
            end_line=2, end_col=1,
        )
        self.assertEqual(len(edits), 1)
        edit = edits[0]
        self.assertEqual(edit.start_line, 1)
        self.assertEqual(edit.start_col, 1)
        lines = source.split("\n")
        self.assertEqual(edit.end_line, len(lines))
        self.assertEqual(edit.end_col, len(lines[-1]) + 1)
        self.assertEqual(edit.new_text, expected)


@unittest.skipUnless(
    _HAVE_LSP and _HAVE_PYGLS,
    "requires pygls + lsprotocol (pip install '.[lsp]')",
)
class TestLspServerHelpers(unittest.TestCase):
    """Direct coverage for the small helpers around the handler
    body: URI parsing, Pos -> LSP Range translation, and the
    `serve()` early-exit when pygls is missing."""

    def test_uri_to_filename_strips_file_prefix(self):
        from capa.lsp.server import _uri_to_filename
        self.assertEqual(
            _uri_to_filename("file:///tmp/a.capa"), "/tmp/a.capa",
        )

    def test_uri_to_filename_strips_windows_drive_slash(self):
        from capa.lsp.server import _uri_to_filename
        self.assertEqual(
            _uri_to_filename("file:///c:/x/y.capa"), "c:/x/y.capa",
        )

    def test_uri_to_filename_unquotes_percent_escapes(self):
        from capa.lsp.server import _uri_to_filename
        self.assertEqual(
            _uri_to_filename("file:///tmp/has%20space.capa"),
            "/tmp/has space.capa",
        )

    def test_uri_to_filename_passthrough_non_file_scheme(self):
        from capa.lsp.server import _uri_to_filename
        # untitled:* and other schemes pass through unchanged so
        # the editor's own identifier reaches the error message.
        self.assertEqual(
            _uri_to_filename("untitled:Untitled-1"), "untitled:Untitled-1",
        )

    def test_to_lsp_position_is_zero_based(self):
        from capa.lsp.server import _to_lsp_position
        from capa.tokens import Pos
        p = _to_lsp_position(Pos(line=3, col=5, offset=0, filename="t.capa"))
        self.assertEqual(p.line, 2)
        self.assertEqual(p.character, 4)

    def test_to_lsp_range_one_char_when_no_end(self):
        from capa.lsp.server import _to_lsp_range
        from capa.tokens import Pos
        r = _to_lsp_range(Pos(line=2, col=3, offset=0, filename="t.capa"))
        self.assertEqual(r.start.line, 1)
        self.assertEqual(r.start.character, 2)
        self.assertEqual(r.end.line, 1)
        self.assertEqual(r.end.character, 3)

    def test_to_lsp_range_uses_end_pos_when_given(self):
        from capa.lsp.server import _to_lsp_range
        from capa.tokens import Pos
        r = _to_lsp_range(
            Pos(line=2, col=3, offset=0, filename="t.capa"),
            Pos(line=2, col=10, offset=0, filename="t.capa"),
        )
        self.assertEqual(r.end.character, 9)

    def test_serve_returns_2_when_pygls_missing(self):
        # Force the ImportError branch of `serve()` by patching
        # `_build_server` to raise. The function's contract is
        # "exit code 2 + a stderr message" when pygls is absent;
        # the patch simulates that without uninstalling pygls.
        import io
        import sys
        from unittest.mock import patch
        from capa.lsp import server as server_mod

        def _raise_import_error():
            raise ImportError("pygls is not installed")

        captured = io.StringIO()
        with patch.object(server_mod, "_build_server", _raise_import_error):
            with patch.object(sys, "stderr", captured):
                rc = server_mod.serve()
        self.assertEqual(rc, 2)
        self.assertIn("pygls", captured.getvalue())


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


@unittest.skipUnless(_HAVE_LSP, "requires `pygls` extra (pip install '.[lsp]')")
class TestSemanticTokens(unittest.TestCase):
    """Semantic tokens deliver type-aware highlighting. The
    server returns a flat array of (deltaLine, deltaStart,
    length, tokenType, tokenModifiers) tuples relative to the
    previous token, plus the legend for the type and modifier
    indices. Helpers in this class decode the relative array
    back into absolute positions for readable assertions."""

    def setUp(self):
        from capa.lsp_server import compute_semantic_tokens
        self.compute = compute_semantic_tokens

    def _decode(self, types, mods, data):
        """Decode the relative-encoded array into a list of dicts
        with absolute 0-based positions and named type/modifier
        strings."""
        out = []
        cur_line = 0
        cur_col = 0
        for i in range(0, len(data), 5):
            dl, dc, length, ti, mm = data[i:i + 5]
            if dl == 0:
                cur_col += dc
            else:
                cur_line += dl
                cur_col = dc
            mod_names = {
                mods[b] for b in range(len(mods)) if mm & (1 << b)
            }
            out.append({
                "line": cur_line,
                "col": cur_col,
                "length": length,
                "type": types[ti],
                "mods": mod_names,
            })
        return out

    def test_legend_is_stable(self):
        # The legend is part of the protocol contract: clients
        # register it once at initialise time and reference token
        # types by index thereafter.
        types, mods, _ = self.compute(
            "fun main()\n    return\n", "t.capa",
        )
        self.assertEqual(
            types,
            ["function", "parameter", "variable",
             "interface", "type", "enumMember", "property"],
        )
        self.assertEqual(
            mods, ["defaultLibrary", "declaration", "readonly"],
        )

    def test_lex_or_parse_error_returns_empty_data(self):
        # The legend is always returned (clients want to register
        # it regardless), but the data array is empty.
        types, mods, data = self.compute(
            "fun main()\n    let = ", "t.capa",
        )
        self.assertEqual(data, [])

    def test_function_declaration_is_tagged_as_function(self):
        src = "fun greet(name: String) -> String\n    return name\n"
        types, mods, data = self.compute(src, "t.capa")
        decoded = self._decode(types, mods, data)
        greet = next(d for d in decoded if d["line"] == 0 and d["col"] == 4)
        self.assertEqual(greet["type"], "function")
        self.assertIn("declaration", greet["mods"])
        self.assertEqual(greet["length"], 5)

    def test_columns_are_utf16_units(self):
        # Audit slice 28 P3 (2026-06-01): the wire protocol counts
        # columns + token lengths in UTF-16 code units (pygls Utf16),
        # but the lexer works in codepoints. A token on a line that
        # contains an astral char (emoji in a string) before it must
        # be reported at its UTF-16 column, not its codepoint column.
        # Here the type annotation ``Int`` sits after a 2-UTF16-unit
        # emoji on its line; without the fix the decoded col would be
        # one short.
        emoji = "\U0001F600"  # 1 codepoint, 2 UTF-16 units
        src = (
            "fun main(stdio: Stdio)\n"
            f'    let s = "{emoji}"\n'
            "    let n: Int = 0\n"
        )
        types, mods, data = self.compute(src, "t.capa")
        decoded = self._decode(types, mods, data)
        # Find the Int type token on line 2 (0-based).
        int_tok = next(
            d for d in decoded if d["line"] == 2 and d["type"] == "type"
        )
        line2 = src.splitlines()[2]
        cp_col = line2.index("Int")
        utf16_col = len(line2[:cp_col].encode("utf-16-le")) // 2
        # 'Int' is on an ASCII-only line, so cp == utf16 here; the
        # real guard is the emoji line not shifting later tokens.
        self.assertEqual(int_tok["col"], utf16_col)
        # And a token whose own line carries the emoji before it:
        # add an identifier reference after the emoji on the SAME line.
        src2 = (
            "fun main(stdio: Stdio)\n"
            "    let greeting = 1\n"
            f'    let z = "{emoji}" == greeting\n'
        )
        # (greeting is referenced after the emoji on line 2)
        types2, mods2, data2 = self.compute(src2, "t.capa")
        decoded2 = self._decode(types2, mods2, data2)
        line2b = src2.splitlines()[2]
        cp = line2b.index("greeting", line2b.index("=="))
        expected_utf16 = len(line2b[:cp].encode("utf-16-le")) // 2
        ref = next(
            d for d in decoded2
            if d["line"] == 2 and d["col"] == expected_utf16
        )
        # The codepoint col would be expected_utf16 - 1 (emoji = 1 cp
        # but 2 utf16 units); assert we did NOT report that.
        self.assertNotEqual(ref["col"], cp)  # cp is the codepoint col

    def test_parameter_declaration_and_use_are_tagged_as_parameter(self):
        src = "fun greet(name: String) -> String\n    return name\n"
        types, mods, data = self.compute(src, "t.capa")
        decoded = self._decode(types, mods, data)
        # Param decl: line 0 col 10
        param_decl = next(
            d for d in decoded if d["line"] == 0 and d["col"] == 10
        )
        self.assertEqual(param_decl["type"], "parameter")
        self.assertIn("declaration", param_decl["mods"])
        # Param use: line 1 col 11
        param_use = next(
            d for d in decoded if d["line"] == 1 and d["col"] == 11
        )
        self.assertEqual(param_use["type"], "parameter")
        self.assertNotIn("declaration", param_use["mods"])

    def test_builtin_capability_is_interface_with_defaultLibrary(self):
        src = "fun main(stdio: Stdio)\n    stdio.println(\"k\")\n"
        types, mods, data = self.compute(src, "t.capa")
        decoded = self._decode(types, mods, data)
        # The `Stdio` type-annotation token sits at line 0 col 16.
        stdio_anno = next(
            d for d in decoded if d["line"] == 0 and d["col"] == 16
        )
        self.assertEqual(stdio_anno["type"], "interface")
        self.assertIn("defaultLibrary", stdio_anno["mods"])

    def test_user_capability_is_interface_without_defaultLibrary(self):
        src = (
            "capability SendEmail\n"
            "    fun send(self, to: String) -> Bool\n"
            "fun deliver(s: SendEmail)\n"
            "    return\n"
        )
        types, mods, data = self.compute(src, "t.capa")
        decoded = self._decode(types, mods, data)
        # The use of `SendEmail` as a parameter type annotation is
        # on line 2 col 15.
        use = next(
            d for d in decoded
            if d["line"] == 2 and d["col"] == 15 and d["length"] == 9
        )
        self.assertEqual(use["type"], "interface")
        self.assertNotIn("defaultLibrary", use["mods"])
        # And the declaration site is also tagged interface +
        # declaration.
        decl = next(
            d for d in decoded if d["line"] == 0 and d["col"] == 11
        )
        self.assertEqual(decl["type"], "interface")
        self.assertIn("declaration", decl["mods"])

    def test_let_binding_is_variable_readonly(self):
        src = (
            "fun main(stdio: Stdio)\n"
            "    let count = 42\n"
            "    stdio.println(\"k\")\n"
        )
        types, mods, data = self.compute(src, "t.capa")
        decoded = self._decode(types, mods, data)
        let_token = next(
            d for d in decoded if d["line"] == 1 and d["col"] == 8
        )
        self.assertEqual(let_token["type"], "variable")
        self.assertIn("readonly", let_token["mods"])
        self.assertIn("declaration", let_token["mods"])

    def test_var_binding_is_variable_not_readonly(self):
        src = (
            "fun main(stdio: Stdio)\n"
            "    var count = 0\n"
            "    stdio.println(\"k\")\n"
        )
        types, mods, data = self.compute(src, "t.capa")
        decoded = self._decode(types, mods, data)
        var_token = next(
            d for d in decoded if d["line"] == 1 and d["col"] == 8
        )
        self.assertEqual(var_token["type"], "variable")
        self.assertNotIn("readonly", var_token["mods"])

    def test_constant_is_variable_readonly_declaration(self):
        src = "const VERSION: String = \"1.0\"\n"
        types, mods, data = self.compute(src, "t.capa")
        decoded = self._decode(types, mods, data)
        version = next(
            d for d in decoded if d["line"] == 0 and d["col"] == 6
        )
        self.assertEqual(version["type"], "variable")
        self.assertIn("readonly", version["mods"])
        self.assertIn("declaration", version["mods"])

    def test_struct_declaration_is_type(self):
        src = (
            "type Point {\n"
            "    x: Int,\n"
            "    y: Int\n"
            "}\n"
        )
        types, mods, data = self.compute(src, "t.capa")
        decoded = self._decode(types, mods, data)
        point = next(
            d for d in decoded if d["line"] == 0 and d["col"] == 5
        )
        self.assertEqual(point["type"], "type")
        self.assertIn("declaration", point["mods"])

    def test_struct_field_is_property(self):
        src = (
            "type Point {\n"
            "    x: Int,\n"
            "    y: Int\n"
            "}\n"
        )
        types, mods, data = self.compute(src, "t.capa")
        decoded = self._decode(types, mods, data)
        x = next(d for d in decoded if d["line"] == 1 and d["col"] == 4)
        self.assertEqual(x["type"], "property")
        self.assertIn("declaration", x["mods"])

    def test_variant_is_enumMember(self):
        src = (
            "type Color =\n"
            "    Red\n"
            "    Green\n"
            "    Blue\n"
        )
        types, mods, data = self.compute(src, "t.capa")
        decoded = self._decode(types, mods, data)
        red = next(d for d in decoded if d["line"] == 1 and d["col"] == 4)
        self.assertEqual(red["type"], "enumMember")
        self.assertIn("declaration", red["mods"])

    def test_data_is_relative_encoded(self):
        # Same line: deltaLine should be 0, deltaStart should be
        # relative to the previous token's column.
        src = "fun add(x: Int, y: Int) -> Int\n    return x + y\n"
        types, mods, data = self.compute(src, "t.capa")
        # Two tokens on line 0 (add at col 4 and x at col 8).
        # First entry's deltaLine should be 0 (or whatever the
        # absolute first line is); subsequent ones on the same
        # line should have deltaLine=0 with the right deltaStart.
        for i in range(0, len(data), 5):
            dl, dc, *_ = data[i:i + 5]
            # delta values are always non-negative.
            self.assertGreaterEqual(dl, 0)
            self.assertGreaterEqual(dc, 0)

    def test_no_duplicate_position_tokens(self):
        # When a position would otherwise be tagged twice (e.g.
        # the reference-collector and the decl-collector both
        # pick up the same Ident), the encoder keeps one token,
        # not two.
        src = (
            "fun greet(name: String) -> String\n"
            "    return name\n"
            "fun main(stdio: Stdio)\n"
            "    let _ = greet(\"Ana\")\n"
        )
        types, mods, data = self.compute(src, "t.capa")
        decoded = self._decode(types, mods, data)
        seen = set()
        for d in decoded:
            key = (d["line"], d["col"])
            self.assertNotIn(key, seen)
            seen.add(key)


class TestLspModuleAwareness(unittest.TestCase):
    """When the buffer the editor is showing imports other files
    that exist on disk, ``LspContext`` now runs the loader so the
    linked module is what gets analysed. Without this the LSP
    surfaces false "undefined name" diagnostics for every call to
    an imported function. Completion also gains the imported
    public names automatically through the linked module's
    top-level items, while mangled private names from the loader
    are filtered out.
    """

    def setUp(self) -> None:
        import shutil
        import tempfile
        self._tmp = Path(tempfile.mkdtemp(prefix="capa_lsp_modaware_"))
        self.addCleanup(shutil.rmtree, self._tmp, ignore_errors=True)

    def _write(self, name: str, body: str) -> Path:
        p = self._tmp / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
        return p

    def test_imported_function_does_not_show_undefined(self):
        # Before module-awareness the LSP would report
        # "undefined name 'greet'" for an imported function.
        from capa.lsp.context import LspContext
        self._write(
            "util.capa",
            "pub fun greet(name: String) -> String\n"
            "    return \"Hi, \" + name\n"
        )
        main_src = (
            "import util\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(greet(\"x\"))\n"
        )
        main_path = self._write("main.capa", main_src)
        ctx = LspContext.parse(main_src, str(main_path))
        self.assertIsNotNone(ctx)
        # ctx.linked is the loader output; analysis used it.
        self.assertIsNotNone(ctx.linked)
        # No false-positive on the imported call.
        msgs = [str(e) for e in ctx.result.errors]
        self.assertFalse(
            any("undefined name 'greet'" in m for m in msgs),
            f"unexpected errors: {msgs}",
        )

    def test_completion_offers_imported_pub_names(self):
        from capa.lsp.completion import compute_completions
        self._write(
            "util.capa",
            "pub fun greet(name: String) -> String\n"
            "    return \"Hi, \" + name\n"
        )
        main_src = (
            "import util\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"hi\")\n"
        )
        main_path = self._write("main.capa", main_src)
        completions = compute_completions(main_src, str(main_path), 3, 4)
        labels = {c.label for c in completions}
        self.assertIn("greet", labels)

    def test_completion_hides_imported_private_names(self):
        # The loader mangles private names to _capa_m<N>__<name>;
        # completion filters those out so the user only sees what
        # they can actually call.
        from capa.lsp.completion import compute_completions
        self._write(
            "util.capa",
            "pub fun pub_fn() -> Int\n    return 1\n"
            "fun secret() -> Int\n    return 42\n"
        )
        main_src = (
            "import util\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"hi\")\n"
        )
        main_path = self._write("main.capa", main_src)
        labels = {
            c.label for c in
            compute_completions(main_src, str(main_path), 3, 4)
        }
        self.assertIn("pub_fn", labels)
        self.assertNotIn("secret", labels)
        # No mangled name should leak either.
        self.assertFalse(
            any(l.startswith("_capa_m") for l in labels),
            f"mangled name leaked into completions: {labels}",
        )

    def test_falls_back_to_single_file_when_loader_fails(self):
        # Missing import target: the loader raises LoaderError.
        # LspContext should fall back to single-file analysis so
        # the editor still works rather than crashing.
        from capa.lsp.context import LspContext
        main_src = (
            "import nonexistent\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"hi\")\n"
        )
        main_path = self._write("main.capa", main_src)
        ctx = LspContext.parse(main_src, str(main_path))
        self.assertIsNotNone(ctx)
        # Loader did not succeed; we fell back to single-file.
        self.assertIsNone(ctx.linked)

    def test_in_memory_filename_skips_loader(self):
        # When the LSP is called with an in-memory buffer (filename
        # starting with '<' or otherwise not on disk), the loader
        # is skipped: no I/O for a phantom path.
        from capa.lsp.context import LspContext
        src = (
            "import util\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"hi\")\n"
        )
        ctx = LspContext.parse(src, "<probe>")
        self.assertIsNotNone(ctx)
        self.assertIsNone(ctx.linked)

    def test_idents_filtered_to_current_file_when_linked(self):
        # When the linker merges the imported module's items in,
        # ctx.idents must only carry Idents originating in the
        # current buffer so cursor lookups don't collide with
        # line numbers from imported files.
        from capa.lsp.context import LspContext
        self._write(
            "util.capa",
            "pub fun greet(name: String) -> String\n"
            "    return \"Hi, \" + name\n"
        )
        main_src = (
            "import util\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(greet(\"x\"))\n"
        )
        main_path = self._write("main.capa", main_src)
        ctx = LspContext.parse(main_src, str(main_path))
        self.assertIsNotNone(ctx)
        this = str(main_path.resolve())
        for ident in ctx.idents:
            ident_file = ident.pos.filename
            if ident_file:
                self.assertEqual(
                    str(Path(ident_file).resolve()), this,
                    f"ident from a different file leaked: {ident.name}",
                )


@unittest.skipUnless(_HAVE_LSP, "requires `pygls` extra (pip install '.[lsp]')")
class TestFoldingRanges(unittest.TestCase):
    """``textDocument/foldingRange`` produces the gutter +/-
    regions the editor uses to collapse function bodies, type
    bodies, control-flow blocks, and match-arm lists. Computed
    from an AST walk; on lex / parse failure the result is an
    empty list so a mid-edit buffer never shows spurious folds."""

    def setUp(self):
        from capa.lsp.folding import compute_folding_ranges
        self.fold = compute_folding_ranges

    def test_folding_function_body(self):
        src = "fun foo()\n    let x = 1\n    return x\n"
        ranges = self.fold(src)
        self.assertTrue(
            any(r.start_line == 1 and r.end_line >= 3 for r in ranges),
            ranges,
        )

    def test_folding_type_struct(self):
        src = "type Point {\n    x: Int,\n    y: Int\n}\n"
        ranges = self.fold(src)
        # Struct body fold starts at the `type` line and reaches
        # the last field; the trailing `}` line is not tracked in
        # the AST so end_line may be the last-field line.
        self.assertTrue(
            any(r.start_line == 1 and r.end_line >= 3 for r in ranges),
            ranges,
        )

    def test_folding_type_sum_multi_line(self):
        src = "type Color =\n    Red\n    Green\n    Blue\n"
        ranges = self.fold(src)
        self.assertTrue(
            any(r.start_line == 1 and r.end_line >= 4 for r in ranges),
            ranges,
        )

    def test_folding_nested_if(self):
        src = (
            "fun foo()\n"
            "    if x > 0\n"
            "        return 1\n"
            "    return 0\n"
        )
        ranges = self.fold(src)
        # One fold for the function body, one for the if branch.
        self.assertGreaterEqual(len(ranges), 2)
        starts = {r.start_line for r in ranges}
        self.assertIn(1, starts)  # function body
        self.assertIn(2, starts)  # if body

    def test_folding_single_line_construct_not_folded(self):
        src = "fun foo() = 1\n"
        ranges = self.fold(src)
        self.assertEqual(ranges, [])

    def test_folding_match_expression(self):
        src = (
            "fun foo() -> Int\n"
            "    match x\n"
            "        1 -> 1\n"
            "        _ -> 0\n"
        )
        ranges = self.fold(src)
        # At least one fold whose span covers the match arms
        # (start at the `match` line, ending at the last arm).
        self.assertTrue(
            any(r.start_line == 2 and r.end_line >= 4 for r in ranges),
            ranges,
        )

    def test_folding_invalid_source_returns_empty(self):
        src = "fun foo(\n"
        self.assertEqual(self.fold(src), [])


@unittest.skipUnless(
    _HAVE_LSP and _HAVE_PYGLS,
    "requires pygls + lsprotocol (pip install '.[lsp]')",
)
class TestLspFoldingHandler(TestLspServerHandlersInProcess):
    """Integration check: when the registered ``textDocument/foldingRange``
    handler is wired in ``server.py``, it must translate the
    Capa-native ranges to 0-based LSP wire types. Skipped (per
    test) until that handler exists so this file can ship before
    the server wiring lands."""

    def test_folding_handler_emits_zero_based_lsp_ranges(self):
        from lsprotocol import types as lsp
        method = lsp.TEXT_DOCUMENT_FOLDING_RANGE
        if method not in self.server.protocol.fm.features:
            self.skipTest("foldingRange handler not yet registered")
        self._set_source(
            "fun foo()\n    let x = 1\n    return x\n"
        )
        params = lsp.FoldingRangeParams(text_document=self._text_doc_id())
        result = self._handler(method)(params)
        self.assertIsNotNone(result)
        self.assertTrue(
            any(r.start_line == 0 and r.end_line >= 2 for r in result),
            result,
        )

    def test_folding_handler_returns_none_on_invalid_source(self):
        from lsprotocol import types as lsp
        method = lsp.TEXT_DOCUMENT_FOLDING_RANGE
        if method not in self.server.protocol.fm.features:
            self.skipTest("foldingRange handler not yet registered")
        self._set_source("fun foo(\n")
        params = lsp.FoldingRangeParams(text_document=self._text_doc_id())
        result = self._handler(method)(params)
        self.assertIsNone(result)


class TestLspDeepNestingRobustness(unittest.TestCase):
    """P1: a deeply nested expression overflows Python's recursion
    limit inside the lexer / parser / analyzer. The LSP compute
    helpers must degrade (empty / floor result) rather than letting
    a ``RecursionError`` escape and crash the editor request.

    These hit the pure compute_* helpers, so they run without
    pygls / lsprotocol installed.
    """

    # 600 nested parens reliably overflows the recursive-descent
    # parser at the default recursion limit.
    DEEP_SRC = (
        "fun f(stdio: Stdio)\n"
        "    let x = " + ("(" * 600) + "1" + (")" * 600) + "\n"
    )

    def test_compute_diagnostics_degrades(self):
        from capa.lsp.diagnostics import compute_diagnostics
        # Must not raise; a degraded (possibly empty) list is fine.
        result = compute_diagnostics(self.DEEP_SRC, "t.capa")
        self.assertIsInstance(result, list)

    def test_compute_folding_ranges_degrades(self):
        from capa.lsp.folding import compute_folding_ranges
        result = compute_folding_ranges(self.DEEP_SRC)
        self.assertEqual(result, [])

    def test_compute_completions_degrades(self):
        from capa.lsp.completion import compute_completions
        # Cursor on the let line; should fall back to the floor list
        # (keywords + built-ins) instead of raising.
        result = compute_completions(self.DEEP_SRC, "t.capa", 2, 13)
        self.assertIsInstance(result, list)
        self.assertGreater(len(result), 0)


if __name__ == "__main__":
    unittest.main()
