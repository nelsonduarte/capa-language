"""Tests for the CycloneDX 1.6 dependency-component emitter (CRA SBOM).

The emitter is a pure CONSUMER of the resolve-layer
:func:`resolve_dependency_identities` records: it renders one added
``library`` component per real capa.toml dependency (name + version +
purl) and never parses capa.toml / capa.lock or assembles a purl itself.

The load-bearing guards here are the fail-closed single-source proofs:

- SOLE-PRODUCER: no ``pkg:`` / ``vcs_url`` / ``git+`` grammar and no
  ``_construct_purl`` live in the emitter modules; the purl is produced
  in exactly one place (the resolve layer).
- CONSUMER-AGREEMENT: every emitted component's purl is byte-identical to
  the purl on the upstream DependencyIdentity record.

Both are mutation-tested in the commit report (hand-build a purl in the
emitter -> SOLE-PRODUCER goes red; drop a component's purl -> AGREEMENT
goes red).
"""

import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from capa import Lexer, Parser, analyze
from capa.manifest import (
    CYCLONEDX_SPEC_VERSION,
    build_cyclonedx,
    resolve_dependency_identities,
)
import capa.manifest._cyclonedx as _cdx_mod
import capa.manifest._spdx as _spdx_mod
import capa.manifest._compose as _compose_mod


def _have(mod: str) -> bool:
    return importlib.util.find_spec(mod) is not None


def _write(base: Path, rel: str, text: str) -> None:
    p = base / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


_WORKED_URL = "https://github.com/acme/widget.git"
_WORKED_COMMIT = "ef1c0ffee1234567890abcdef1234567890abcd"


def _dep_components(doc: dict) -> list:
    return [
        c for c in doc["components"]
        if any(p["name"] == "capa:kind" and p["value"] == "dependency"
               for p in c.get("properties", []))
    ]


class _EmitterFixture(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="capa_cdx_dep_"))
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))

    def _project(self) -> Path:
        root = self.tmp / "proj"
        _write(root, "capa.toml", (
            '[package]\nname = "app"\nversion = "0.1.0"\n\n'
            '[dependencies.widget]\n'
            f'git = "{_WORKED_URL}"\ntag = "v1.2.3"\n\n'
            '[dependencies.localdep]\npath = "../localdep"\n\n'
            '[dependencies.missing]\n'
            'git = "https://github.com/acme/missing.git"\nrev = "abc123"\n'
        ))
        _write(root, "main.capa", "pub fun main()\n    return\n")
        _write(root, "vendor/widget/capa.toml",
               '[package]\nname = "widget"\nversion = "1.2.3"\n')
        _write(root, "vendor/widget/w.capa", "pub fun w()\n    return\n")
        _write(self.tmp / "localdep", "capa.toml",
               '[package]\nname = "localdep"\nversion = "9.9.9"\n')
        _write(self.tmp / "localdep", "l.capa", "pub fun l()\n    return\n")
        _write(root, "capa.lock", (
            "[[dependencies]]\n"
            'name = "widget"\n'
            f'git = "{_WORKED_URL}"\n'
            'pin = "v1.2.3"\npin_kind = "tag"\n'
            f'commit = "{_WORKED_COMMIT}"\n'
        ))
        return root

    def _emit(self, root: Path, *, with_deps: bool = True):
        filename = str(root / "main.capa")
        source = Path(filename).read_text(encoding="utf-8")
        module = Parser(Lexer(source).lex(), source=source).parse_module()
        self.assertTrue(analyze(module, source=source).ok)
        ids, graph = resolve_dependency_identities(root)
        doc = build_cyclonedx(
            module, filename=filename, source=source,
            timestamp="2020-01-01T00:00:00Z",
            dependency_components=ids if with_deps else None,
            dependency_graph=graph if with_deps else None,
        )
        return doc, ids, graph


class TestSpecVersionBump(unittest.TestCase):
    def test_spec_version_is_1_6(self):
        self.assertEqual(CYCLONEDX_SPEC_VERSION, "1.6")

    def test_document_declares_1_6(self):
        src = "pub fun f()\n    return\n"
        module = Parser(Lexer(src).lex(), source=src).parse_module()
        analyze(module, source=src)
        doc = build_cyclonedx(module, timestamp="2020-01-01T00:00:00Z")
        self.assertEqual(doc["specVersion"], "1.6")


class TestDependencyComponents(_EmitterFixture):
    def test_each_declared_dependency_is_a_component(self):
        doc, _, _ = self._emit(self._project())
        names = sorted(c["name"] for c in _dep_components(doc))
        self.assertEqual(names, ["localdep", "missing", "widget"])

    def test_git_dep_component_carries_version_and_worked_purl(self):
        doc, _, _ = self._emit(self._project())
        widget = next(c for c in _dep_components(doc) if c["name"] == "widget")
        self.assertEqual(widget["version"], "1.2.3")
        self.assertEqual(
            widget["purl"],
            "pkg:generic/widget@1.2.3?vcs_url=git%2Bhttps:%2F%2Fgithub.com%2F"
            "acme%2Fwidget.git%40ef1c0ffee1234567890abcdef1234567890abcd",
        )
        props = {p["name"]: p["value"] for p in widget["properties"]}
        self.assertEqual(props["capa:source_kind"], "git")
        self.assertEqual(props["capa:resolved"], "true")
        self.assertEqual(props["capa:commit"], _WORKED_COMMIT)

    def test_path_dep_component_has_no_purl(self):
        doc, _, _ = self._emit(self._project())
        local = next(c for c in _dep_components(doc) if c["name"] == "localdep")
        self.assertNotIn("purl", local)
        self.assertEqual(local["version"], "9.9.9")
        props = {p["name"]: p["value"] for p in local["properties"]}
        self.assertEqual(props["capa:source_kind"], "path")

    def test_unresolved_dep_component_has_purl_but_no_version(self):
        doc, _, _ = self._emit(self._project())
        missing = next(c for c in _dep_components(doc) if c["name"] == "missing")
        self.assertNotIn("version", missing)
        self.assertIn("purl", missing)

    def test_program_depends_on_the_top_level_deps(self):
        doc, ids, _ = self._emit(self._project())
        program_edge = next(
            d for d in doc["dependencies"]
            if d["ref"].startswith("capa:program:")
        )
        for record in ids:
            self.assertIn(record.bom_ref, program_edge["dependsOn"])

    def test_program_own_components_byte_identical_with_and_without_deps(self):
        root = self._project()
        with_deps, _, _ = self._emit(root, with_deps=True)
        without_deps, _, _ = self._emit(root, with_deps=False)

        def own(doc):
            return [c for c in doc["components"] if c not in _dep_components(doc)]

        self.assertEqual(
            json.dumps(own(with_deps)), json.dumps(own(without_deps)),
            "the program's own function/capability components must be "
            "unperturbed by the dependency feature",
        )


class TestLockResolvedDiamond(_EmitterFixture):
    """Under a lock, a diamond dependency (declared directly AND transitively
    at the same git URL + pin) must emit exactly ONE library component,
    carrying the resolved SHA. Guards the shipped artifact, not just the
    resolver."""

    def _diamond_project(self) -> Path:
        root = self.tmp / "proj"
        _write(root, "capa.toml", (
            '[package]\nname = "app"\nversion = "0.1.0"\n\n'
            '[dependencies.widget]\n'
            f'git = "{_WORKED_URL}"\ntag = "v1.2.3"\n\n'
            '[dependencies.mid]\n'
            'git = "https://github.com/acme/mid.git"\ntag = "v2.0.0"\n'
        ))
        _write(root, "main.capa", "pub fun main()\n    return\n")
        _write(root, "vendor/widget/capa.toml",
               '[package]\nname = "widget"\nversion = "1.2.3"\n')
        _write(root, "vendor/widget/w.capa", "pub fun w()\n    return\n")
        _write(root, "vendor/mid/capa.toml", (
            '[package]\nname = "mid"\nversion = "2.0.0"\n\n'
            '[dependencies.widget]\n'
            f'git = "{_WORKED_URL}"\ntag = "v1.2.3"\n'
        ))
        _write(root, "vendor/mid/m.capa", "pub fun m()\n    return\n")
        _write(root, "vendor/mid/vendor/widget/capa.toml",
               '[package]\nname = "widget"\nversion = "1.2.3"\n')
        _write(root, "vendor/mid/vendor/widget/w.capa",
               "pub fun w()\n    return\n")
        _write(root, "capa.lock", (
            "[[dependencies]]\n"
            'name = "widget"\n'
            f'git = "{_WORKED_URL}"\n'
            'pin = "v1.2.3"\npin_kind = "tag"\n'
            f'commit = "{_WORKED_COMMIT}"\n'
            "[[dependencies]]\n"
            'name = "mid"\n'
            'git = "https://github.com/acme/mid.git"\n'
            'pin = "v2.0.0"\npin_kind = "tag"\n'
            'commit = "aaaabbbbccccddddeeeeffff0000111122223333"\n'
        ))
        return root

    def test_lock_resolved_diamond_emits_one_widget_with_the_sha(self):
        doc, _, _ = self._emit(self._diamond_project())
        widgets = [c for c in _dep_components(doc) if c["name"] == "widget"]
        self.assertEqual(
            len(widgets), 1,
            "a lock-resolved diamond must emit exactly one widget component",
        )
        self.assertIn(_WORKED_COMMIT, widgets[0]["purl"])
        self.assertNotIn("%40v1.2.3", widgets[0]["purl"])


class TestNoDependencyCase(_EmitterFixture):
    def test_bare_file_emits_only_its_own_component(self):
        # No dependency_components passed -> exactly today's output.
        src = "pub fun bare()\n    return\n"
        module = Parser(Lexer(src).lex(), source=src).parse_module()
        analyze(module, source=src)
        doc = build_cyclonedx(module, timestamp="2020-01-01T00:00:00Z")
        self.assertEqual(_dep_components(doc), [])
        self.assertEqual(doc["specVersion"], "1.6")


class TestSoleProducerGuard(unittest.TestCase):
    """The purl is produced in exactly one place. If this test fails, an
    emitter has started assembling a purl of its own (the duplicated-
    knowledge anti-pattern this feature exists to avoid). Mutation-tested:
    hand-build any ``pkg:`` / ``vcs_url`` / ``git+`` string in
    _cyclonedx.py or _spdx.py and this goes red."""

    _FORBIDDEN = ("pkg:", "vcs_url", "git+")

    def test_emitters_contain_no_purl_grammar(self):
        for mod in (_cdx_mod, _spdx_mod):
            text = Path(mod.__file__).read_text(encoding="utf-8")
            for token in self._FORBIDDEN:
                self.assertNotIn(
                    token, text,
                    f"{Path(mod.__file__).name} must not assemble purl "
                    f"grammar ({token!r}); route it through the resolve "
                    f"layer's _construct_purl instead",
                )

    def test_construct_purl_defined_only_in_resolve_layer(self):
        self.assertTrue(hasattr(_compose_mod, "_construct_purl"))
        for mod in (_cdx_mod, _spdx_mod):
            text = Path(mod.__file__).read_text(encoding="utf-8")
            self.assertNotIn("_construct_purl", text)


class TestConsumerAgreementGuard(_EmitterFixture):
    """Every emitted component's purl is byte-identical to the purl on the
    upstream DependencyIdentity record. Mutation-tested: drop or alter a
    component's purl in the emitter and this goes red."""

    def test_component_purls_match_the_records(self):
        doc, ids, _ = self._emit(self._project())
        record_purl = {i.bom_ref: i.purl for i in ids}
        emitted = _dep_components(doc)
        # Same set of bom-refs on both sides (no dropped / spurious dep).
        self.assertEqual(
            sorted(c["bom-ref"] for c in emitted),
            sorted(record_purl),
        )
        for c in emitted:
            self.assertEqual(
                c.get("purl"), record_purl[c["bom-ref"]],
                f"component {c['name']!r} purl disagrees with its record",
            )


@unittest.skipUnless(
    _have("jsonschema") and _have("cyclonedx"),
    "CycloneDX 1.6 schema validation needs jsonschema + cyclonedx (dev-only)",
)
class TestSchemaValidation(_EmitterFixture):
    def _validate(self, doc):
        from cyclonedx.validation.json import JsonStrictValidator
        from cyclonedx.schema import SchemaVersion
        v = JsonStrictValidator(SchemaVersion.V1_6)
        return v.validate_str(json.dumps(doc))

    def test_project_document_validates_against_1_6(self):
        doc, _, _ = self._emit(self._project())
        self.assertIsNone(self._validate(doc))

    def test_bare_document_validates_against_1_6(self):
        src = "pub fun bare()\n    return\n"
        module = Parser(Lexer(src).lex(), source=src).parse_module()
        analyze(module, source=src)
        doc = build_cyclonedx(module, timestamp="2020-01-01T00:00:00Z")
        self.assertIsNone(self._validate(doc))


@unittest.skipUnless(
    _have("packageurl"),
    "purl round-trip needs the packageurl reference lib (dev-only)",
)
class TestPurlRoundTrip(_EmitterFixture):
    """The JSON schema does NOT validate purl grammar, so the round-trip
    through the reference lib is load-bearing."""

    def test_every_emitted_purl_round_trips(self):
        from packageurl import PackageURL
        doc, ids, _ = self._emit(self._project())
        by_ref = {i.bom_ref: i for i in ids}
        n_purls = 0
        for c in _dep_components(doc):
            if "purl" not in c:
                continue
            n_purls += 1
            parsed = PackageURL.from_string(c["purl"])
            record = by_ref[c["bom-ref"]]
            self.assertEqual(parsed.name, record.name)
            self.assertEqual(parsed.version, record.version)
            self.assertIn("vcs_url", parsed.qualifiers or {})
        self.assertGreater(n_purls, 0, "fixture must exercise real purls")


if __name__ == "__main__":
    unittest.main()
