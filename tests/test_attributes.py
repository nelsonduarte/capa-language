"""Tests for function attributes and the --manifest builder.

Three blocks:

  - parsing: ``@name(key: "value", ...)`` syntax accepted on top-level
    funs and on impl methods, rejected on other items.
  - semantic validation: the analyzer accepts the v1 catalogue of
    attribute names (security, deprecated, audited) and rejects
    unknown names, unknown keys, and duplicate attributes.
  - manifest emission: ``build_manifest`` produces the expected
    JSON-serialisable shape for a representative sample of programs.
"""

import unittest

from capa import Lexer, Parser, ParserError, analyze
from capa import ast as A
from capa.manifest import build_manifest


def parse(source: str) -> A.Module:
    tokens = Lexer(source).lex()
    return Parser(tokens, source=source).parse_module()


def check_errors(source: str) -> list[str]:
    tokens = Lexer(source).lex()
    module = Parser(tokens, source=source).parse_module()
    return [e.message for e in analyze(module, source=source).errors]


def manifest_of(source: str, filename: str = "<test>") -> dict:
    tokens = Lexer(source).lex()
    module = Parser(tokens, source=source).parse_module()
    # We do not require analysis to pass for the manifest tests — the
    # builder is robust to ASTs that have only been parsed, and we
    # want to inspect manifests for programs that the discipline
    # legitimately rejects (e.g., unused capability params).
    return build_manifest(module, filename=filename)


# =============================================================
# Parsing
# =============================================================

class TestAttributeParsing(unittest.TestCase):
    def test_single_attribute(self):
        m = parse(
            '@security(cve: "CVE-2024-1")\n'
            'fun f() -> Bool\n'
            '    return true\n'
        )
        fn = m.items[0]
        self.assertIsInstance(fn, A.FunDecl)
        self.assertEqual(len(fn.attributes), 1)
        self.assertEqual(fn.attributes[0].name, "security")
        self.assertEqual(fn.attributes[0].args, [("cve", "CVE-2024-1")])

    def test_stacked_attributes(self):
        m = parse(
            '@security(cve: "CVE-2024-1", severity: "high")\n'
            '@audited(date: "2026-05-11", by: "Ana")\n'
            'fun f() -> Bool\n'
            '    return true\n'
        )
        fn = m.items[0]
        self.assertEqual(len(fn.attributes), 2)
        self.assertEqual(fn.attributes[0].name, "security")
        self.assertEqual(fn.attributes[1].name, "audited")
        self.assertEqual(
            dict(fn.attributes[0].args),
            {"cve": "CVE-2024-1", "severity": "high"},
        )

    def test_trailing_comma_accepted(self):
        m = parse(
            '@security(cve: "X", severity: "low",)\n'
            'fun f()\n    return\n'
        )
        fn = m.items[0]
        self.assertEqual(len(fn.attributes[0].args), 2)

    def test_empty_args_accepted_by_parser(self):
        # Parser is permissive — analyzer may still complain about
        # certain attributes that conceptually need arguments.
        m = parse('@security()\nfun f()\n    return\n')
        fn = m.items[0]
        self.assertEqual(fn.attributes[0].args, [])

    def test_attribute_on_impl_method(self):
        m = parse(
            'type Foo {}\n'
            'impl Foo\n'
            '    @audited(date: "2026-05-11")\n'
            '    fun bar(self)\n'
            '        return\n'
        )
        impl = m.items[1]
        self.assertIsInstance(impl, A.ImplBlock)
        method = impl.methods[0]
        self.assertEqual(len(method.attributes), 1)
        self.assertEqual(method.attributes[0].name, "audited")

    def test_attribute_on_const_rejected(self):
        with self.assertRaises(ParserError) as cm:
            parse(
                '@security(cve: "X")\n'
                'const PI: Float = 3.14\n'
            )
        self.assertIn("const", cm.exception.message)

    def test_attribute_on_type_rejected(self):
        with self.assertRaises(ParserError) as cm:
            parse(
                '@security(cve: "X")\n'
                'type Foo {}\n'
            )
        self.assertIn("type", cm.exception.message)

    def test_at_without_name_rejected(self):
        with self.assertRaises(ParserError):
            parse('@\nfun f()\n    return\n')

    def test_non_string_value_rejected(self):
        with self.assertRaises(ParserError) as cm:
            parse(
                '@security(cve: 42)\n'
                'fun f()\n    return\n'
            )
        self.assertIn("string", cm.exception.message)


# =============================================================
# Analyzer validation
# =============================================================

class TestAttributeAnalysis(unittest.TestCase):
    def test_known_attributes_accepted(self):
        errs = check_errors(
            '@security(cve: "CVE-2024-1", severity: "high")\n'
            '@deprecated(reason: "x", since: "0.3.0")\n'
            '@audited(date: "2026-05-11", by: "Ana")\n'
            'fun f() -> Bool\n'
            '    return true\n'
        )
        self.assertEqual(errs, [], f"unexpected analyzer errors: {errs}")

    def test_unknown_attribute_rejected(self):
        errs = check_errors(
            '@bogus(x: "y")\n'
            'fun f()\n    return\n'
        )
        self.assertTrue(any("unknown attribute" in e for e in errs), errs)
        self.assertTrue(any("bogus" in e for e in errs), errs)

    def test_unknown_key_rejected(self):
        errs = check_errors(
            '@security(no_such_key: "x")\n'
            'fun f()\n    return\n'
        )
        self.assertTrue(any("unknown key" in e for e in errs), errs)
        self.assertTrue(any("no_such_key" in e for e in errs), errs)

    def test_duplicate_attribute_rejected(self):
        errs = check_errors(
            '@security(cve: "A")\n'
            '@security(cve: "B")\n'
            'fun f()\n    return\n'
        )
        self.assertTrue(
            any("appears more than once" in e for e in errs),
            errs,
        )

    def test_duplicate_key_within_attribute_rejected(self):
        errs = check_errors(
            '@security(cve: "A", cve: "B")\n'
            'fun f()\n    return\n'
        )
        self.assertTrue(
            any("appears more than once" in e for e in errs),
            errs,
        )

    def test_attribute_on_method_validated(self):
        errs = check_errors(
            'type Foo {}\n'
            'impl Foo\n'
            '    @nonsense(x: "y")\n'
            '    fun bar(self)\n'
            '        return\n'
        )
        self.assertTrue(
            any("unknown attribute" in e and "nonsense" in e for e in errs),
            errs,
        )


# =============================================================
# Manifest emission
# =============================================================

class TestManifest(unittest.TestCase):
    def test_hello_world(self):
        m = manifest_of(
            'fun main(stdio: Stdio)\n'
            '    stdio.println("hi")\n'
        )
        self.assertEqual(m["schema_version"], 1)
        self.assertEqual(m["summary"]["total_functions"], 1)
        self.assertEqual(m["summary"]["functions_with_capabilities"], 1)
        self.assertEqual(m["summary"]["functions_with_attributes"], 0)
        self.assertEqual(m["summary"]["functions_crossing_unsafe"], 0)

        fn = m["functions"][0]
        self.assertEqual(fn["name"], "main")
        self.assertEqual(fn["declared_capabilities"], ["Stdio"])
        self.assertFalse(fn["has_unsafe"])

        param = fn["params"][0]
        self.assertEqual(param["name"], "stdio")
        self.assertEqual(param["type"], "Stdio")
        self.assertTrue(param["is_capability"])

    def test_unsafe_boundary_detected(self):
        m = manifest_of(
            'fun crosses(u: Unsafe)\n'
            '    return\n'
        )
        fn = m["functions"][0]
        self.assertTrue(fn["has_unsafe"])
        self.assertIn("Unsafe", fn["declared_capabilities"])
        self.assertEqual(m["summary"]["functions_crossing_unsafe"], 1)

    def test_user_defined_capability_with_implementor(self):
        m = manifest_of(
            'capability SendEmail\n'
            '    fun send(self, to: String) -> Bool\n'
            'type SmtpMailer { net: Net }\n'
            'impl SendEmail for SmtpMailer\n'
            '    fun send(self, to: String) -> Bool\n'
            '        return true\n'
        )
        ucs = m["user_defined_capabilities"]
        self.assertEqual(len(ucs), 1)
        self.assertEqual(ucs[0]["name"], "SendEmail")
        self.assertEqual(ucs[0]["methods"], ["send"])
        self.assertEqual(ucs[0]["implementors"], ["SmtpMailer"])

    def test_impl_method_has_container(self):
        m = manifest_of(
            'type Foo {}\n'
            'impl Foo\n'
            '    fun bar(self)\n'
            '        return\n'
        )
        method = m["functions"][0]
        self.assertEqual(method["name"], "bar")
        self.assertEqual(method["container"], "Foo")

    def test_attributes_in_manifest(self):
        m = manifest_of(
            '@security(cve: "CVE-2024-1", severity: "high")\n'
            '@audited(date: "2026-05-11", by: "Ana")\n'
            'fun verify(stdio: Stdio) -> Bool\n'
            '    return true\n'
        )
        fn = m["functions"][0]
        attrs = fn["attributes"]
        names = [a["name"] for a in attrs]
        self.assertEqual(sorted(names), ["audited", "security"])
        sec = next(a for a in attrs if a["name"] == "security")
        self.assertEqual(sec["args"]["cve"], "CVE-2024-1")
        self.assertEqual(sec["args"]["severity"], "high")
        self.assertEqual(m["summary"]["functions_with_attributes"], 1)

    def test_pure_function_no_caps(self):
        m = manifest_of(
            'fun pure_fn(x: Int) -> Int\n'
            '    return x * 2\n'
        )
        fn = m["functions"][0]
        self.assertEqual(fn["declared_capabilities"], [])
        self.assertFalse(fn["has_unsafe"])
        self.assertEqual(m["summary"]["functions_with_capabilities"], 0)


if __name__ == "__main__":
    unittest.main()
