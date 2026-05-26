"""Tests for the formatter v3 AST pretty-printer.

Covers three invariants:

1. **Structural coverage**: for every AST node category, a small
   targeted snippet parses, re-emits, and re-parses to a
   structurally equal AST. These tests double as documentation of
   the canonical surface form for each construct.
2. **Corpus round-trip**: every ``examples/*.capa`` file plus
   every ``evaluation/sbom_diff/*/capa.capa`` survives parse +
   emit + parse with structural AST equality. This is the key
   formatter invariant: the emitter never changes the semantics
   of well-formed source.
3. **Idempotence**: ``format(format(src)) == format(src)`` for
   the same corpus, byte-for-byte. Run without the CommentMap to
   isolate Phase-3 pretty-printer behaviour from Phase-2
   attachment quirks (the comment-map idempotence is a separate
   invariant for Phase 2 to own).
"""

from __future__ import annotations

import glob
import os
import re
import unittest

from capa import capa_ast as A
from capa.formatter._emit import _Emitter, format_source_emit
from capa.lexer import Lexer
from capa.parser import Parser


# AST positions differ between the original source and the
# re-emitted source because layout changes; we strip positions
# from the dump output before comparing so we test structure, not
# coordinates.
_POS_RE = re.compile(
    r"Pos\(line=\d+, col=\d+, offset=\d+, filename='[^']*'\)"
)


def _parse(source: str) -> A.Module:
    tokens = Lexer(source).lex()
    return Parser(tokens, source=source, filename="<test>").parse_module()


def _dump_structural(source: str) -> str:
    """Return the AST dump with all ``Pos(...)`` fields normalised
    so positional shift between the original and re-emitted forms
    does not register as a structural difference.
    """
    return _POS_RE.sub("Pos(...)", A.dump(_parse(source)))


def _fmt_no_cmap(source: str) -> str:
    """Format ``source`` skipping the CommentMap.

    Used by the idempotence tests so they isolate the pretty-
    printer from Phase-2 comment-attachment behaviour.
    """
    module = _parse(source)
    em = _Emitter(cmap=None)
    em.emit_module(module)
    return em.text()


# ----------------------------------------------------------------
# Structural tests: per-node-category targeted snippets
# ----------------------------------------------------------------
class TestPrettyPrinterStructure(unittest.TestCase):
    """One small snippet per AST node category. Each test asserts
    the snippet round-trips: parse, emit, re-parse, then compare
    structural dumps. The snippets are deliberately minimal so a
    failure points unambiguously at the responsible emitter.
    """

    def _assert_roundtrips(self, source: str) -> None:
        emitted = format_source_emit(source)
        # Re-parse must succeed; the dump must be structurally
        # equivalent to the original.
        self.assertEqual(
            _dump_structural(source),
            _dump_structural(emitted),
            f"AST mismatch after round-trip.\n"
            f"--- source ---\n{source}\n--- emitted ---\n{emitted}",
        )

    # -------- items --------
    def test_fun_decl(self):
        self._assert_roundtrips(
            "fun foo(x: Int) -> Int\n    return x + 1\n"
        )

    def test_fun_decl_pub_and_generics(self):
        self._assert_roundtrips(
            "pub fun first<T>(xs: List<T>) -> Option<T>\n"
            "    return Some(xs[0])\n"
        )

    def test_fun_decl_with_attributes(self):
        self._assert_roundtrips(
            '@security(cve: "CVE-2024-0001")\n'
            "fun verify(s: String) -> Bool\n"
            "    return true\n"
        )

    def test_type_struct(self):
        self._assert_roundtrips(
            "type Point {\n    x: Float,\n    y: Float\n}\n"
        )

    def test_type_struct_empty(self):
        self._assert_roundtrips("type Marker {}\n")

    def test_type_sum(self):
        self._assert_roundtrips(
            "type Color =\n    Red\n    Green\n    Blue\n"
        )

    def test_type_sum_with_payloads(self):
        self._assert_roundtrips(
            "type Shape =\n    Circle(Float)\n    Rect(Float, Float)\n"
        )

    def test_impl_inherent(self):
        self._assert_roundtrips(
            "type Foo {}\n\n"
            "impl Foo\n"
            "    fun hello(self) -> String\n"
            '        return "hi"\n'
        )

    def test_impl_trait_for(self):
        self._assert_roundtrips(
            "trait Greeter\n"
            "    fun greet(self) -> String\n\n"
            "type Foo {}\n\n"
            "impl Greeter for Foo\n"
            "    fun greet(self) -> String\n"
            '        return "hi"\n'
        )

    def test_trait_decl(self):
        self._assert_roundtrips(
            "trait Animal\n"
            "    fun name(self) -> String\n"
            "    fun sound(self) -> String\n"
        )

    def test_capability_decl(self):
        self._assert_roundtrips(
            "capability Logger\n"
            "    fun log(self, msg: String)\n"
        )

    def test_import_plain(self):
        self._assert_roundtrips("import util\n")

    def test_import_with_alias(self):
        self._assert_roundtrips("import util.helpers as H\n")

    def test_const_decl(self):
        self._assert_roundtrips('const VERSION: String = "1.0"\n')

    # -------- statements --------
    def test_let_stmt(self):
        self._assert_roundtrips(
            "fun foo()\n    let x: Int = 1 + 2\n"
        )

    def test_let_stmt_inferred_type(self):
        self._assert_roundtrips("fun foo()\n    let x = 42\n")

    def test_let_stmt_tuple_destructure(self):
        self._assert_roundtrips(
            "fun foo()\n    let (a, b) = (1, 2)\n"
        )

    def test_var_stmt(self):
        self._assert_roundtrips("fun foo()\n    var i = 0\n")

    def test_assign_stmt(self):
        self._assert_roundtrips(
            "fun foo()\n    var i = 0\n    i = i + 1\n"
        )

    def test_assign_stmt_op_equals(self):
        self._assert_roundtrips(
            "fun foo()\n    var i = 0\n    i += 1\n"
        )

    def test_return_stmt_void(self):
        self._assert_roundtrips("fun foo()\n    return\n")

    def test_return_stmt_value(self):
        self._assert_roundtrips(
            "fun foo() -> Int\n    return 42\n"
        )

    def test_if_stmt(self):
        self._assert_roundtrips(
            "fun foo(x: Int)\n"
            "    if x > 0\n"
            '        return\n'
        )

    def test_if_elif_else_stmt(self):
        self._assert_roundtrips(
            "fun foo(x: Int)\n"
            "    if x > 0\n"
            "        return\n"
            "    elif x < 0\n"
            "        return\n"
            "    else\n"
            "        return\n"
        )

    def test_for_stmt(self):
        self._assert_roundtrips(
            "fun foo()\n"
            "    for i in 0..10\n"
            "        let _ = i\n"
        )

    def test_while_stmt(self):
        self._assert_roundtrips(
            "fun foo()\n"
            "    var i = 0\n"
            "    while i < 10\n"
            "        i += 1\n"
        )

    def test_break_continue(self):
        self._assert_roundtrips(
            "fun foo()\n"
            "    for i in 0..10\n"
            "        if i > 5\n"
            "            break\n"
            "        continue\n"
        )

    # -------- expressions --------
    def test_match_expr_simple(self):
        self._assert_roundtrips(
            "fun foo(n: Int) -> Int\n"
            "    return match n\n"
            "        0 -> 1\n"
            "        _ -> 2\n"
        )

    def test_match_expr_with_guard(self):
        self._assert_roundtrips(
            "fun foo(n: Int) -> String\n"
            "    return match n\n"
            '        x if x > 0 -> "positive"\n'
            '        _ -> "non-positive"\n'
        )

    def test_match_with_or_pattern(self):
        self._assert_roundtrips(
            "type Color =\n    Red\n    Green\n    Blue\n\n"
            "fun foo(c: Color) -> Bool\n"
            "    return match c\n"
            "        Red | Green -> true\n"
            "        _ -> false\n"
        )

    def test_if_expr(self):
        self._assert_roundtrips(
            "fun foo(b: Bool) -> Int\n"
            "    let r = if b then 1 else 0\n"
            "    return r\n"
        )

    def test_lambda_single_expr(self):
        self._assert_roundtrips(
            "fun foo() -> Fun(Int) -> Int\n"
            "    return fun (x: Int) -> Int => x * 2\n"
        )

    def test_binop(self):
        self._assert_roundtrips(
            "fun foo() -> Int\n    return 1 + 2 * 3\n"
        )

    def test_binop_with_parens_via_precedence(self):
        self._assert_roundtrips(
            "fun foo() -> Int\n    return (1 + 2) * 3\n"
        )

    def test_unary_minus(self):
        self._assert_roundtrips(
            "fun foo() -> Int\n    return -42\n"
        )

    def test_unary_not(self):
        self._assert_roundtrips(
            "fun foo() -> Bool\n    return not true\n"
        )

    def test_call(self):
        self._assert_roundtrips(
            "fun add(a: Int, b: Int) -> Int\n    return a + b\n\n"
            "fun foo() -> Int\n    return add(1, 2)\n"
        )

    def test_call_named_args(self):
        self._assert_roundtrips(
            "fun add(a: Int, b: Int) -> Int\n    return a + b\n\n"
            "fun foo() -> Int\n    return add(a: 1, b: 2)\n"
        )

    def test_method_call(self):
        self._assert_roundtrips(
            'fun foo() -> Int\n    return "abc".length()\n'
        )

    def test_field_access(self):
        self._assert_roundtrips(
            "type P { x: Int }\n\n"
            "fun foo(p: P) -> Int\n    return p.x\n"
        )

    def test_index(self):
        self._assert_roundtrips(
            "fun foo() -> Int\n"
            "    let xs = [1, 2, 3]\n"
            "    return xs[0]\n"
        )

    def test_struct_lit(self):
        self._assert_roundtrips(
            "type P { x: Int, y: Int }\n\n"
            "fun foo() -> P\n"
            "    return P { x: 1, y: 2 }\n"
        )

    def test_list_lit(self):
        self._assert_roundtrips(
            "fun foo()\n    let xs = [1, 2, 3]\n"
        )

    def test_tuple_lit(self):
        self._assert_roundtrips(
            "fun foo()\n    let t = (1, 2, 3)\n"
        )

    def test_range_expr_exclusive(self):
        self._assert_roundtrips(
            "fun foo()\n    for i in 0..10\n        let _ = i\n"
        )

    def test_range_expr_inclusive(self):
        self._assert_roundtrips(
            "fun foo()\n    for i in 0..=10\n        let _ = i\n"
        )

    def test_try_operator(self):
        self._assert_roundtrips(
            "fun foo(fs: Fs) -> Result<String, IoError>\n"
            '    let t = fs.read("a")?\n'
            "    return Ok(t)\n"
        )

    # -------- literals --------
    def test_int_lit(self):
        self._assert_roundtrips(
            "fun foo() -> Int\n    return 42\n"
        )

    def test_float_lit(self):
        self._assert_roundtrips(
            "fun foo() -> Float\n    return 3.14\n"
        )

    def test_bool_lit(self):
        self._assert_roundtrips(
            "fun foo() -> Bool\n    return true\n"
        )

    def test_string_lit(self):
        self._assert_roundtrips(
            'fun foo() -> String\n    return "hello"\n'
        )

    def test_string_lit_with_escapes(self):
        self._assert_roundtrips(
            'fun foo() -> String\n    return "a\\nb\\tc"\n'
        )

    def test_interpolated_string(self):
        self._assert_roundtrips(
            'fun foo(stdio: Stdio)\n'
            '    let n = 7\n'
            '    stdio.println("value = ${n * 2}")\n'
        )

    # -------- patterns --------
    def test_wildcard_pattern(self):
        self._assert_roundtrips(
            "fun foo(n: Int) -> Int\n"
            "    return match n\n"
            "        _ -> 0\n"
        )

    def test_ident_pattern(self):
        self._assert_roundtrips(
            "fun foo(n: Int) -> Int\n"
            "    return match n\n"
            "        x -> x\n"
        )

    def test_literal_pattern(self):
        self._assert_roundtrips(
            "fun foo(n: Int) -> Int\n"
            "    return match n\n"
            "        0 -> 1\n"
            "        _ -> 2\n"
        )

    def test_variant_pattern(self):
        self._assert_roundtrips(
            "fun foo(o: Option<Int>) -> Int\n"
            "    return match o\n"
            "        Some(x) -> x\n"
            "        None -> 0\n"
        )

    def test_struct_pattern(self):
        self._assert_roundtrips(
            "type P { x: Int, y: Int }\n\n"
            "fun foo(p: P) -> Int\n"
            "    let P { x, y } = p\n"
            "    return x + y\n"
        )

    def test_tuple_pattern(self):
        self._assert_roundtrips(
            "fun foo()\n"
            '    let (a, b) = (1, 2)\n'
        )

    def test_or_pattern(self):
        self._assert_roundtrips(
            "type Color =\n    Red\n    Green\n    Blue\n\n"
            "fun foo(c: Color) -> Bool\n"
            "    return match c\n"
            "        Red | Blue -> true\n"
            "        _ -> false\n"
        )

    # -------- type expressions --------
    def test_type_name_with_args(self):
        self._assert_roundtrips(
            "fun foo(xs: List<Int>) -> List<Int>\n    return xs\n"
        )

    def test_type_fun(self):
        self._assert_roundtrips(
            "fun foo(f: Fun(Int) -> Int) -> Int\n    return f(1)\n"
        )

    def test_type_tuple(self):
        self._assert_roundtrips(
            "fun foo(p: (Int, Int)) -> Int\n"
            "    let (a, b) = p\n"
            "    return a + b\n"
        )

    def test_type_unit_in_result(self):
        self._assert_roundtrips(
            "fun foo() -> Result<(), String>\n"
            "    return Ok(())\n"
        )


# ----------------------------------------------------------------
# Corpus round-trip: every example survives parse + emit + parse
# ----------------------------------------------------------------
def _corpus_files() -> list[str]:
    """Return absolute paths to every Capa file in the corpus.

    The corpus is the union of ``examples/*.capa`` and every
    ``evaluation/sbom_diff/*/capa.capa``. Sorted for stable test
    output.
    """
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    paths = sorted(
        glob.glob(os.path.join(repo_root, "examples", "*.capa"))
        + glob.glob(
            os.path.join(
                repo_root, "evaluation", "sbom_diff", "*", "capa.capa",
            )
        )
    )
    assert paths, "expected at least one corpus file"
    return paths


class TestPrettyPrinterRoundtrip(unittest.TestCase):
    """For every corpus file: parse -> emit -> parse must yield a
    structurally equivalent AST.
    """

    def test_corpus_roundtrip(self):
        files = _corpus_files()
        failures: list[str] = []
        for path in files:
            with open(path, encoding="utf-8") as f:
                src = f.read()
            try:
                emitted = format_source_emit(src)
            except Exception as exc:
                failures.append(
                    f"{os.path.basename(path)}: emit raised "
                    f"{type(exc).__name__}: {exc}"
                )
                continue
            try:
                d1 = _dump_structural(src)
                d2 = _dump_structural(emitted)
            except Exception as exc:
                failures.append(
                    f"{os.path.basename(path)}: re-parse raised "
                    f"{type(exc).__name__}: {exc}"
                )
                continue
            if d1 != d2:
                failures.append(
                    f"{os.path.basename(path)}: AST mismatch"
                )
        self.assertFalse(
            failures,
            "Round-trip failures in corpus:\n  " + "\n  ".join(failures),
        )


# ----------------------------------------------------------------
# Idempotence: format(format(src)) == format(src)
# ----------------------------------------------------------------
class TestPrettyPrinterIdempotence(unittest.TestCase):
    """For every corpus file:
    ``format_source_emit(format_source_emit(src)) == format_source_emit(src)``
    byte-for-byte. Run without the CommentMap to isolate the
    pretty-printer from Phase-2 attachment behaviour.
    """

    def test_corpus_idempotent(self):
        files = _corpus_files()
        failures: list[str] = []
        for path in files:
            with open(path, encoding="utf-8") as f:
                src = f.read()
            try:
                out1 = _fmt_no_cmap(src)
                out2 = _fmt_no_cmap(out1)
            except Exception as exc:
                failures.append(
                    f"{os.path.basename(path)}: emit raised "
                    f"{type(exc).__name__}: {exc}"
                )
                continue
            if out1 != out2:
                failures.append(
                    f"{os.path.basename(path)}: not idempotent"
                )
        self.assertFalse(
            failures,
            "Idempotence failures in corpus:\n  " + "\n  ".join(failures),
        )


if __name__ == "__main__":
    unittest.main()
