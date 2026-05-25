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


if __name__ == "__main__":
    unittest.main()
