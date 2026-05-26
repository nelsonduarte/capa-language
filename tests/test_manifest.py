"""Focused tests for the capability manifest builder.

The bulk of manifest behaviour (attribute parsing, per-function
record content, ineligibility proofs, downstream SBOM / VEX /
SLSA wrappers) lives in
[`tests/test_attributes.py`](tests/test_attributes.py), which
grew from attribute-system tests into the de facto manifest
test file. The 2026-05-25 audit (item #9) noted that
``capa/manifest/`` had no test file named after itself even
though the builder is the oracle the property test
``test_runtime_classes_subset_of_manifest_classes`` relies on.

This file complements (does not duplicate) ``test_attributes.py``
by exercising the manifest's *structural* surface:

- the ``SCHEMA_VERSION`` constant and its propagation;
- the empty-module corner;
- ``capa_version`` override;
- ``filename`` propagation;
- determinism + idempotence of ``build_manifest``;
- the multi-implementor sort guarantee;
- the top-level dict shape.

Attribute-driven cases stay in ``test_attributes.py``.
"""

import unittest

from capa import Lexer, Parser, analyze
from capa.manifest import SCHEMA_VERSION, build_manifest


def _analysed(source: str):
    tokens = Lexer(source).lex()
    module = Parser(tokens, source=source).parse_module()
    result = analyze(module, source=source)
    if not result.ok:
        raise AssertionError(f"analyzer errors: {result.errors}")
    return module


class TestSchemaVersion(unittest.TestCase):
    def test_schema_version_is_one(self):
        self.assertEqual(SCHEMA_VERSION, 1)

    def test_schema_version_in_manifest(self):
        m = build_manifest(_analysed("fun f()\n    return\n"))
        self.assertEqual(m["schema_version"], SCHEMA_VERSION)


class TestEmptyModule(unittest.TestCase):
    def test_empty_module_returns_well_formed_manifest(self):
        m = build_manifest(_analysed(""))
        self.assertEqual(m["functions"], [])
        self.assertEqual(m["user_defined_capabilities"], [])
        self.assertEqual(m["summary"], {
            "total_functions": 0,
            "functions_with_capabilities": 0,
            "functions_with_attributes": 0,
            "functions_crossing_unsafe": 0,
        })

    def test_empty_module_still_carries_schema_version(self):
        m = build_manifest(_analysed(""))
        self.assertEqual(m["schema_version"], SCHEMA_VERSION)
        self.assertIn("capa_version", m)
        self.assertIsInstance(m["capa_version"], str)


class TestCapaVersionOverride(unittest.TestCase):
    def test_default_capa_version_matches_package(self):
        from capa import __version__
        m = build_manifest(_analysed("fun f()\n    return\n"))
        self.assertEqual(m["capa_version"], __version__)

    def test_explicit_capa_version_overrides_default(self):
        m = build_manifest(
            _analysed("fun f()\n    return\n"),
            capa_version="9.9.9-test",
        )
        self.assertEqual(m["capa_version"], "9.9.9-test")


class TestFilenamePropagation(unittest.TestCase):
    def test_filename_appears_at_top_level(self):
        m = build_manifest(
            _analysed("fun f()\n    return\n"),
            filename="my-program.capa",
        )
        self.assertEqual(m["filename"], "my-program.capa")

    def test_filename_appears_in_function_pos(self):
        m = build_manifest(
            _analysed("fun f()\n    return\n"),
            filename="my-program.capa",
        )
        self.assertTrue(m["functions"][0]["pos"].startswith("my-program.capa:"))

    def test_default_filename_is_placeholder(self):
        m = build_manifest(_analysed("fun f()\n    return\n"))
        self.assertEqual(m["filename"], "<input>")


class TestTopLevelShape(unittest.TestCase):
    """Contract: every manifest carries the documented keys.
    Consumers that rely on the shape (capa-language.com/manifest.html,
    the docgen renderer, the property test oracle) break silently
    if the top-level keys drift."""

    _REQUIRED_KEYS = {
        "capa_version",
        "schema_version",
        "filename",
        "user_defined_capabilities",
        "functions",
        "summary",
    }

    _SUMMARY_KEYS = {
        "total_functions",
        "functions_with_capabilities",
        "functions_with_attributes",
        "functions_crossing_unsafe",
    }

    def test_required_top_level_keys_present(self):
        m = build_manifest(_analysed("fun f()\n    return\n"))
        self.assertEqual(set(m.keys()), self._REQUIRED_KEYS)

    def test_summary_keys_complete(self):
        m = build_manifest(_analysed("fun f()\n    return\n"))
        self.assertEqual(set(m["summary"].keys()), self._SUMMARY_KEYS)

    def test_function_record_required_keys(self):
        m = build_manifest(
            _analysed("fun f(stdio: Stdio)\n    stdio.println(\"hi\")\n"),
        )
        fn = m["functions"][0]
        required = {
            "name", "container", "pos", "is_pub", "doc",
            "params", "return_type",
            "declared_capabilities", "provably_excluded_capabilities",
            "has_unsafe", "attributes", "calls",
        }
        self.assertEqual(set(fn.keys()), required)


class TestDeterminism(unittest.TestCase):
    """Same source, two runs -> identical manifest dicts. The
    property test ``test_runtime_classes_subset_of_manifest_classes``
    in ``test_properties.py`` depends on this: it generates a
    program, lowers it, and compares the manifest against the
    runtime trace. Non-determinism would surface as flakes."""

    def test_repeated_build_is_byte_equal(self):
        src = (
            "capability SendEmail\n"
            "    fun send(self, to: String) -> Bool\n"
            "type SmtpMailer { net: Net }\n"
            "impl SendEmail for SmtpMailer\n"
            "    fun send(self, to: String) -> Bool\n"
            "        return true\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"ok\")\n"
        )
        m1 = build_manifest(_analysed(src))
        m2 = build_manifest(_analysed(src))
        self.assertEqual(m1, m2)


class TestMultiImplementor(unittest.TestCase):
    """When multiple structs implement one user-defined capability,
    the manifest must list all of them in sorted order so two runs
    on the same module agree byte-for-byte."""

    def test_implementors_sorted(self):
        # Declare three implementors out of alphabetical order in
        # source; manifest must sort them.
        src = (
            "capability Logger\n"
            "    fun log(self, msg: String) -> Bool\n"
            "type ZSink { stdio: Stdio }\n"
            "type ASink { stdio: Stdio }\n"
            "type MSink { stdio: Stdio }\n"
            "impl Logger for ZSink\n"
            "    fun log(self, msg: String) -> Bool\n"
            "        return true\n"
            "impl Logger for ASink\n"
            "    fun log(self, msg: String) -> Bool\n"
            "        return true\n"
            "impl Logger for MSink\n"
            "    fun log(self, msg: String) -> Bool\n"
            "        return true\n"
        )
        m = build_manifest(_analysed(src))
        ucs = m["user_defined_capabilities"]
        self.assertEqual(len(ucs), 1)
        self.assertEqual(ucs[0]["implementors"], ["ASink", "MSink", "ZSink"])

    def test_multiple_user_caps_each_with_implementors(self):
        src = (
            "capability Logger\n"
            "    fun log(self, m: String) -> Bool\n"
            "capability Mailer\n"
            "    fun send(self, to: String) -> Bool\n"
            "type SinkA { stdio: Stdio }\n"
            "type SinkB { stdio: Stdio }\n"
            "type MailerX { net: Net }\n"
            "impl Logger for SinkA\n"
            "    fun log(self, m: String) -> Bool\n"
            "        return true\n"
            "impl Logger for SinkB\n"
            "    fun log(self, m: String) -> Bool\n"
            "        return true\n"
            "impl Mailer for MailerX\n"
            "    fun send(self, to: String) -> Bool\n"
            "        return true\n"
        )
        m = build_manifest(_analysed(src))
        ucs = {uc["name"]: uc for uc in m["user_defined_capabilities"]}
        self.assertEqual(set(ucs.keys()), {"Logger", "Mailer"})
        self.assertEqual(ucs["Logger"]["implementors"], ["SinkA", "SinkB"])
        self.assertEqual(ucs["Mailer"]["implementors"], ["MailerX"])


class TestFunctionRecordFields(unittest.TestCase):
    """Fields not exercised by test_attributes.py: is_pub, doc."""

    def test_is_pub_default_false(self):
        m = build_manifest(_analysed("fun private_fn()\n    return\n"))
        self.assertFalse(m["functions"][0]["is_pub"])

    def test_pub_keyword_sets_is_pub_true(self):
        m = build_manifest(_analysed("pub fun exposed()\n    return\n"))
        self.assertTrue(m["functions"][0]["is_pub"])

    def test_doc_comment_captured(self):
        m = build_manifest(
            _analysed(
                "/// A function that does nothing.\n"
                "fun documented()\n"
                "    return\n"
            ),
        )
        doc = m["functions"][0]["doc"]
        self.assertIsNotNone(doc)
        self.assertIn("does nothing", doc)


class TestExports(unittest.TestCase):
    """The ``capa.manifest`` __init__ surface; consumers import
    these names directly."""

    def test_public_surface_resolves(self):
        from capa.manifest import (
            SCHEMA_VERSION, CYCLONEDX_SPEC_VERSION, SPDX_SPEC_VERSION,
            CAPA_BUILD_TYPE, CAPA_BUILDER_ID, SLSA_PREDICATE_TYPE,
            build_manifest, build_cyclonedx, build_spdx,
            build_vex_document, build_vex_entries, build_provenance,
        )
        for c in (
            SCHEMA_VERSION, CYCLONEDX_SPEC_VERSION, SPDX_SPEC_VERSION,
            CAPA_BUILD_TYPE, CAPA_BUILDER_ID, SLSA_PREDICATE_TYPE,
        ):
            self.assertIsNotNone(c)
        for fn in (
            build_manifest, build_cyclonedx, build_spdx,
            build_vex_document, build_vex_entries, build_provenance,
        ):
            self.assertTrue(callable(fn))


from capa import capa_ast as A
from capa.manifest._strings import (
    _quote_string,
    _root_type_name,
    _stringify_expr,
    _stringify_expr_full,
    _ty_text,
)
from capa.tokens import Pos


_P = Pos(line=1, col=1, offset=0)


def _ident(name: str) -> A.Ident:
    return A.Ident(pos=_P, name=name)


def _int(n: int) -> A.IntLit:
    return A.IntLit(pos=_P, value=n)


class TestManifestStringHelpers(unittest.TestCase):
    """Direct unit coverage of the small AST-to-string helpers in
    ``capa.manifest._strings``. One method per Expr/TypeExpr branch,
    so coverage tracks every isinstance check in the cascade."""

    # -- _stringify_expr (the truncating wrapper) ----------------

    def test_stringify_expr_short_passes_through(self):
        self.assertEqual(_stringify_expr(_ident("abc")), "abc")

    def test_stringify_expr_long_is_truncated_with_ellipsis(self):
        long_name = "x" * 200
        out = _stringify_expr(_ident(long_name))
        self.assertEqual(len(out), 80)
        self.assertTrue(out.endswith("..."))
        self.assertEqual(out, "x" * 77 + "...")

    # -- _stringify_expr_full per node shape ---------------------

    def test_full_none_returns_empty(self):
        self.assertEqual(_stringify_expr_full(None), "")

    def test_full_ident(self):
        self.assertEqual(_stringify_expr_full(_ident("foo")), "foo")

    def test_full_int_lit(self):
        self.assertEqual(_stringify_expr_full(_int(42)), "42")

    def test_full_float_lit(self):
        self.assertEqual(
            _stringify_expr_full(A.FloatLit(pos=_P, value=1.5)),
            repr(1.5),
        )

    def test_full_string_lit_quoted(self):
        self.assertEqual(
            _stringify_expr_full(A.StringLit(pos=_P, value="hi")),
            '"hi"',
        )

    def test_full_interpolated_string(self):
        # parts: literal "a", expr Ident("x"), literal "b"
        node = A.InterpolatedString(pos=_P, parts=["a", _ident("x"), "b"])
        self.assertEqual(_stringify_expr_full(node), '"a${...}b"')

    def test_full_char_lit(self):
        self.assertEqual(
            _stringify_expr_full(A.CharLit(pos=_P, value="z")),
            "'z'",
        )

    def test_full_bool_lit_true(self):
        self.assertEqual(
            _stringify_expr_full(A.BoolLit(pos=_P, value=True)),
            "true",
        )

    def test_full_bool_lit_false(self):
        self.assertEqual(
            _stringify_expr_full(A.BoolLit(pos=_P, value=False)),
            "false",
        )

    def test_full_unit_lit(self):
        self.assertEqual(_stringify_expr_full(A.UnitLit(pos=_P)), "()")

    def test_full_binop(self):
        node = A.BinOp(pos=_P, op="+", left=_int(1), right=_int(2))
        self.assertEqual(_stringify_expr_full(node), "1 + 2")

    def test_full_unary_op_symbolic_no_space(self):
        node = A.UnaryOp(pos=_P, op="-", operand=_int(3))
        self.assertEqual(_stringify_expr_full(node), "-3")

    def test_full_unary_op_alpha_inserts_space(self):
        node = A.UnaryOp(pos=_P, op="not", operand=A.BoolLit(pos=_P, value=True))
        self.assertEqual(_stringify_expr_full(node), "not true")

    def test_full_call(self):
        node = A.Call(pos=_P, callee=_ident("f"), args=[_int(1), _int(2)])
        self.assertEqual(_stringify_expr_full(node), "f(1, 2)")

    def test_full_method_call(self):
        node = A.MethodCall(
            pos=_P, receiver=_ident("x"), method="bar", args=[_int(7)]
        )
        self.assertEqual(_stringify_expr_full(node), "x.bar(7)")

    def test_full_field_access(self):
        node = A.FieldAccess(pos=_P, receiver=_ident("rec"), field_name="f")
        self.assertEqual(_stringify_expr_full(node), "rec.f")

    def test_full_index(self):
        node = A.Index(pos=_P, receiver=_ident("a"), index=_int(0))
        self.assertEqual(_stringify_expr_full(node), "a[0]")

    def test_full_try(self):
        node = A.Try(pos=_P, expr=_ident("res"))
        self.assertEqual(_stringify_expr_full(node), "res?")

    def test_full_list_lit(self):
        node = A.ListLit(pos=_P, elements=[_int(1), _int(2), _int(3)])
        self.assertEqual(_stringify_expr_full(node), "[1, 2, 3]")

    def test_full_tuple_lit(self):
        node = A.TupleLit(pos=_P, elements=[_int(1), _ident("x")])
        self.assertEqual(_stringify_expr_full(node), "(1, x)")

    def test_full_struct_lit(self):
        node = A.StructLit(
            pos=_P,
            type_name="Point",
            fields=[("x", _int(1)), ("y", _int(2))],
        )
        self.assertEqual(
            _stringify_expr_full(node),
            "Point { x: 1, y: 2 }",
        )

    def test_full_range_expr_exclusive(self):
        node = A.RangeExpr(pos=_P, start=_int(0), end=_int(10), inclusive=False)
        self.assertEqual(_stringify_expr_full(node), "0..10")

    def test_full_range_expr_inclusive(self):
        node = A.RangeExpr(pos=_P, start=_int(0), end=_int(10), inclusive=True)
        self.assertEqual(_stringify_expr_full(node), "0..=10")

    def test_full_lambda_expr(self):
        node = A.LambdaExpr(pos=_P, params=[], body=_int(1))
        self.assertEqual(_stringify_expr_full(node), "fun(...) => ...")

    def test_full_if_expr(self):
        node = A.IfExpr(
            pos=_P,
            cond=A.BoolLit(pos=_P, value=True),
            then_expr=_int(1),
            else_expr=_int(2),
        )
        self.assertEqual(
            _stringify_expr_full(node),
            "if true then ... else ...",
        )

    def test_full_match_expr(self):
        node = A.MatchExpr(pos=_P, scrutinee=_ident("v"), arms=[])
        self.assertEqual(_stringify_expr_full(node), "match v { ... }")

    def test_full_unknown_node_falls_back_to_class_name(self):
        # AssignStmt is a Stmt, not an Expr; the cascade should miss
        # every isinstance check and hit the final fallback.
        stmt = A.AssignStmt(
            pos=_P, target=_ident("x"), op="=", value=_int(1),
        )
        self.assertEqual(_stringify_expr_full(stmt), "<AssignStmt>")

    # -- _quote_string -------------------------------------------

    def test_quote_string_empty(self):
        self.assertEqual(_quote_string(""), '""')

    def test_quote_string_simple_ascii(self):
        self.assertEqual(_quote_string("hello"), '"hello"')

    def test_quote_string_escapes_double_quote(self):
        self.assertEqual(_quote_string('say "hi"'), '"say \\"hi\\""')

    def test_quote_string_escapes_backslash(self):
        self.assertEqual(_quote_string("a\\b"), '"a\\\\b"')

    def test_quote_string_escapes_newline(self):
        self.assertEqual(_quote_string("a\nb"), '"a\\nb"')

    def test_quote_string_escapes_tab(self):
        self.assertEqual(_quote_string("a\tb"), '"a\\tb"')

    def test_quote_string_other_control_char_passes_through(self):
        # The function only special-cases \\, ", \n, \t. Other control
        # characters are kept verbatim inside the literal.
        self.assertEqual(_quote_string("a\x01b"), '"a\x01b"')

    def test_quote_string_backslash_n_literal_not_double_escaped(self):
        # Input is the two-char sequence backslash + 'n'. The backslash
        # is escaped first, so the result is \\n (four chars). The 'n'
        # is not interpreted as the newline-escape replacement.
        self.assertEqual(_quote_string("\\n"), '"\\\\n"')

    # -- _ty_text -------------------------------------------------

    def test_ty_text_none_is_unit_string(self):
        self.assertEqual(_ty_text(None), "()")

    def test_ty_text_bare_type_name(self):
        self.assertEqual(_ty_text(A.TypeName(pos=_P, name="Int")), "Int")

    def test_ty_text_generic_type_name(self):
        node = A.TypeName(
            pos=_P, name="List", args=[A.TypeName(pos=_P, name="Int")],
        )
        self.assertEqual(_ty_text(node), "List<Int>")

    def test_ty_text_generic_type_name_two_args(self):
        node = A.TypeName(
            pos=_P,
            name="Result",
            args=[
                A.TypeName(pos=_P, name="Int"),
                A.TypeName(pos=_P, name="String"),
            ],
        )
        self.assertEqual(_ty_text(node), "Result<Int, String>")

    def test_ty_text_fun_type(self):
        node = A.FunType(
            pos=_P,
            param_types=[A.TypeName(pos=_P, name="Int")],
            return_type=A.TypeName(pos=_P, name="String"),
        )
        self.assertEqual(_ty_text(node), "Fun(Int) -> String")

    def test_ty_text_fun_type_no_params(self):
        node = A.FunType(
            pos=_P,
            param_types=[],
            return_type=A.UnitType(pos=_P),
        )
        self.assertEqual(_ty_text(node), "Fun() -> ()")

    def test_ty_text_tuple_type(self):
        node = A.TupleType(
            pos=_P,
            elements=[
                A.TypeName(pos=_P, name="Int"),
                A.TypeName(pos=_P, name="String"),
            ],
        )
        self.assertEqual(_ty_text(node), "(Int, String)")

    def test_ty_text_unit_type(self):
        self.assertEqual(_ty_text(A.UnitType(pos=_P)), "()")

    def test_ty_text_unknown_falls_back_to_class_name(self):
        # Pass a TypeExpr subclass the cascade does not handle. We do
        # not have one in the codebase today, so we synthesize a minimal
        # subclass to hit the final fallback line.
        from dataclasses import dataclass

        @dataclass(kw_only=True)
        class _Mystery(A.TypeExpr):
            pass

        self.assertEqual(_ty_text(_Mystery(pos=_P)), "<_Mystery>")

    # -- _root_type_name -----------------------------------------

    def test_root_type_name_none(self):
        self.assertIsNone(_root_type_name(None))

    def test_root_type_name_bare(self):
        self.assertEqual(
            _root_type_name(A.TypeName(pos=_P, name="Int")),
            "Int",
        )

    def test_root_type_name_generic_keeps_head(self):
        node = A.TypeName(
            pos=_P, name="List", args=[A.TypeName(pos=_P, name="Int")],
        )
        self.assertEqual(_root_type_name(node), "List")

    def test_root_type_name_non_type_name_returns_none(self):
        self.assertIsNone(_root_type_name(A.UnitType(pos=_P)))
        tup = A.TupleType(
            pos=_P,
            elements=[A.TypeName(pos=_P, name="Int")],
        )
        self.assertIsNone(_root_type_name(tup))


if __name__ == "__main__":
    unittest.main()
