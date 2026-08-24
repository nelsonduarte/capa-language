"""Tests for the SPDX 2.3 dependency-package emitter (CRA SBOM real deps).

The SPDX emitter is the SECOND pure CONSUMER of the resolve-layer
:func:`resolve_dependency_identities` records (the CycloneDX emitter is the
first). It renders one SPDX ``Package`` per real capa.toml dependency (name
+ version + a ``purl`` externalRef for git deps) and mirrors the declared
edges as ``DEPENDS_ON`` relationships. It never parses capa.toml / capa.lock
and never assembles a purl of its own: it reads ``record.purl`` verbatim.

The load-bearing guards here:

- OWN-SUBTREE BYTE-IDENTITY: the program's own package / file /
  relationship subtree is byte-identical with vs without the dependency
  records (deps are strictly appended); a bare .capa emits exactly today's
  document.
- SPDXID UNIQUENESS: a distinct-source diamond (two same-name/same-version
  deps at different git URLs) gets DISTINCT SPDXIDs, and the fail-closed
  uniqueness guard raises ``ComposeError`` if two SPDXIDs ever coincide.

The sole-producer grep guard (no ``pkg:`` / ``vcs_url`` / ``git+`` grammar
in _spdx.py) lives in :mod:`tests.test_cyclonedx_dependencies`; the
cross-emitter agreement guard lives in
:mod:`tests.test_sbom_dependency_parity`.
"""

import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from capa import Lexer, Parser, analyze
from capa.manifest import (
    ComposeError,
    DependencyIdentity,
    build_spdx,
    resolve_dependency_identities,
)


def _have(mod: str) -> bool:
    return importlib.util.find_spec(mod) is not None


def _write(base: Path, rel: str, text: str) -> None:
    p = base / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


_WORKED_URL = "https://github.com/acme/widget.git"
_WORKED_COMMIT = "ef1c0ffee1234567890abcdef1234567890abcd"
_WORKED_PURL = "pkg:github/acme/widget@ef1c0ffee1234567890abcdef1234567890abcd"


def _dep_packages(doc: dict) -> list:
    return [
        p for p in doc["packages"]
        if any(a["comment"] == "capa:kind=dependency"
               for a in p.get("annotations", []))
    ]


def _program_id(doc: dict) -> str:
    for r in doc["relationships"]:
        if r["relationshipType"] == "DESCRIBES":
            return r["relatedSpdxElement"]
    raise AssertionError("no DESCRIBES relationship")


class _EmitterFixture(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="capa_spdx_dep_"))
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
        doc = build_spdx(
            module, filename=filename, source=source,
            timestamp="2020-01-01T00:00:00Z",
            dependency_components=ids if with_deps else None,
            dependency_graph=graph if with_deps else None,
        )
        return doc, ids, graph


class TestDependencyPackages(_EmitterFixture):
    def test_each_declared_dependency_is_a_package(self):
        doc, _, _ = self._emit(self._project())
        names = sorted(p["name"] for p in _dep_packages(doc))
        self.assertEqual(names, ["localdep", "missing", "widget"])

    def test_git_dep_package_carries_version_and_worked_purl(self):
        doc, _, _ = self._emit(self._project())
        widget = next(p for p in _dep_packages(doc) if p["name"] == "widget")
        self.assertEqual(widget["versionInfo"], "1.2.3")
        self.assertEqual(len(widget["externalRefs"]), 1)
        ref = widget["externalRefs"][0]
        self.assertEqual(ref["referenceCategory"], "PACKAGE-MANAGER")
        self.assertEqual(ref["referenceType"], "purl")
        self.assertEqual(ref["referenceLocator"], _WORKED_PURL)
        annots = {a["comment"] for a in widget["annotations"]}
        self.assertIn("capa:source_kind=git", annots)
        self.assertIn("capa:resolved=true", annots)
        self.assertIn(f"capa:commit={_WORKED_COMMIT}", annots)

    def test_path_dep_package_has_version_but_no_externalref(self):
        doc, _, _ = self._emit(self._project())
        local = next(p for p in _dep_packages(doc) if p["name"] == "localdep")
        self.assertEqual(local["versionInfo"], "9.9.9")
        self.assertNotIn("externalRefs", local)
        annots = {a["comment"] for a in local["annotations"]}
        self.assertIn("capa:source_kind=path", annots)

    def test_unresolved_dep_package_has_purl_but_no_version(self):
        doc, _, _ = self._emit(self._project())
        missing = next(p for p in _dep_packages(doc) if p["name"] == "missing")
        self.assertNotIn("versionInfo", missing)
        self.assertEqual(len(missing["externalRefs"]), 1)
        self.assertEqual(
            missing["externalRefs"][0]["referenceLocator"],
            "pkg:github/acme/missing@abc123",
        )

    def test_required_package_fields_present(self):
        doc, _, _ = self._emit(self._project())
        for pkg in _dep_packages(doc):
            for field in ("SPDXID", "name", "downloadLocation"):
                self.assertIn(field, pkg)
            self.assertEqual(pkg["downloadLocation"], "NOASSERTION")
            self.assertTrue(pkg["SPDXID"].startswith("SPDXRef-Dep-"))

    def test_program_depends_on_the_top_level_deps(self):
        doc, ids, _ = self._emit(self._project())
        program_id = _program_id(doc)
        dep_ids = {p["SPDXID"] for p in _dep_packages(doc)}
        depends = {
            r["relatedSpdxElement"] for r in doc["relationships"]
            if r["spdxElementId"] == program_id
            and r["relationshipType"] == "DEPENDS_ON"
            and r["relatedSpdxElement"] in dep_ids
        }
        # Every top-level dependency is a DEPENDS_ON target of the program.
        self.assertEqual(depends, dep_ids)


class TestOwnSubtreeByteIdentity(_EmitterFixture):
    """The program's own package / file / relationship subtree must be
    byte-identical with vs without the dependency records: deps are strictly
    APPENDED, never interleaved into the existing document."""

    def _own(self, doc):
        dep_ids = {p["SPDXID"] for p in _dep_packages(doc)}
        own_pkgs = [p for p in doc["packages"] if p["SPDXID"] not in dep_ids]
        own_rels = [
            r for r in doc["relationships"]
            if r["spdxElementId"] not in dep_ids
            and r["relatedSpdxElement"] not in dep_ids
        ]
        return own_pkgs, own_rels

    def test_program_own_subtree_byte_identical_with_and_without_deps(self):
        root = self._project()
        with_deps, _, _ = self._emit(root, with_deps=True)
        without_deps, _, _ = self._emit(root, with_deps=False)
        self.assertEqual(
            json.dumps(self._own(with_deps)),
            json.dumps(self._own(without_deps)),
            "the program's own subtree must be unperturbed by the "
            "dependency feature",
        )

    def test_bare_file_emits_no_dependency_packages(self):
        src = "pub fun bare()\n    return\n"
        module = Parser(Lexer(src).lex(), source=src).parse_module()
        analyze(module, source=src)
        # No dependency records passed -> exactly today's document.
        with_default = build_spdx(module, timestamp="2020-01-01T00:00:00Z")
        with_empty = build_spdx(
            module, timestamp="2020-01-01T00:00:00Z",
            dependency_components=[], dependency_graph=None,
        )
        self.assertEqual(_dep_packages(with_default), [])
        self.assertEqual(
            json.dumps(with_default), json.dumps(with_empty),
            "an empty dependency set must produce byte-identical output",
        )


class TestSpdxIdUniqueness(_EmitterFixture):
    def test_distinct_source_diamond_gets_distinct_spdxids(self):
        # Two same-NAMED widgets at DIFFERENT git URLs are distinct packages
        # with distinct purls -> distinct bom_refs -> distinct SPDXIDs; both
        # must appear.
        other_url = "https://github.com/other/widget.git"
        root = self.tmp / "proj"
        _write(root, "capa.toml", (
            '[package]\nname = "app"\nversion = "0.1.0"\n\n'
            '[dependencies.widget]\n'
            f'git = "{_WORKED_URL}"\ntag = "v1.2.3"\n\n'
            '[dependencies.mid]\npath = "../mid"\n'
        ))
        _write(root, "main.capa", "pub fun main()\n    return\n")
        _write(root, "vendor/widget/capa.toml",
               '[package]\nname = "widget"\nversion = "1.2.3"\n')
        _write(root, "vendor/widget/w.capa", "pub fun w()\n    return\n")
        _write(self.tmp / "mid", "capa.toml", (
            '[package]\nname = "mid"\nversion = "2.0.0"\n\n'
            '[dependencies.widget]\n'
            f'git = "{other_url}"\ntag = "v1.2.3"\n'
        ))
        _write(self.tmp / "mid", "m.capa", "pub fun m()\n    return\n")
        _write(self.tmp / "mid", "vendor/widget/capa.toml",
               '[package]\nname = "widget"\nversion = "1.2.3"\n')
        _write(self.tmp / "mid", "vendor/widget/w.capa",
               "pub fun w()\n    return\n")
        doc, _, _ = self._emit(root)
        widgets = [p for p in _dep_packages(doc) if p["name"] == "widget"]
        self.assertEqual(len(widgets), 2, "both distinct widgets must appear")
        self.assertEqual(
            len({p["SPDXID"] for p in widgets}), 2,
            "distinct-source same-name/version deps need distinct SPDXIDs",
        )

    def test_uniqueness_guard_raises_on_forced_duplicate(self):
        # Two records with the same bom_ref (hence the same derived SPDXID)
        # must trip the fail-closed guard rather than emit a merged document.
        src = "pub fun bare()\n    return\n"
        module = Parser(Lexer(src).lex(), source=src).parse_module()
        analyze(module, source=src)
        dup = DependencyIdentity(
            name="dup", version="1.0", source_kind="path",
        )
        other = DependencyIdentity(
            name="dup", version="1.0", source_kind="path",
        )
        # Both have bom_ref ``capa:dep:dup@1.0`` -> identical SPDXID.
        self.assertEqual(dup.bom_ref, other.bom_ref)
        with self.assertRaises(ComposeError):
            build_spdx(
                module, timestamp="2020-01-01T00:00:00Z",
                dependency_components=[dup, other], dependency_graph=None,
            )


@unittest.skipUnless(
    _have("packageurl"),
    "purl round-trip needs the packageurl reference lib (dev-only)",
)
class TestPurlRoundTrip(_EmitterFixture):
    """The externalRef locator is a purl string; round-trip each through the
    reference lib to prove it is valid grammar (the JSON shape alone does not
    validate purl grammar)."""

    def test_every_externalref_purl_round_trips(self):
        from packageurl import PackageURL
        doc, ids, _ = self._emit(self._project())
        record_purls = {i.purl for i in ids if i.purl}
        n = 0
        for pkg in _dep_packages(doc):
            for ref in pkg.get("externalRefs", []):
                n += 1
                locator = ref["referenceLocator"]
                self.assertIn(locator, record_purls)
                parsed = PackageURL.from_string(locator)
                # Every fixture git dep is github-hosted.
                self.assertEqual(parsed.type, "github")
        self.assertGreater(n, 0, "fixture must exercise real purls")


if __name__ == "__main__":
    unittest.main()
