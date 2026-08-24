"""Tests for the dependency-identity resolve layer (CRA SBOM real deps).

The single source of truth for "what are this product's real declared
capa.toml dependencies, and how is each named as a package-URL" lives in
:mod:`capa.manifest._compose`:

- :class:`DependencyIdentity` - one frozen record per declared dependency.
- :func:`_construct_purl` - the ONE purl producer.
- :func:`resolve_dependency_identities` - runs the SAME
  :func:`build_package_dag` walk the composed SBOM uses (never a second
  walk), reads the root ``capa.lock`` exactly once, and marries edges +
  nodes + lock commits into the records.

These tests drive that layer directly (no emitter, no CLI), plus the
byte-identity guard proving the extension did not perturb the existing
composed product SBOM.
"""

import shutil
import tempfile
import unittest
from pathlib import Path

from capa import analyze
from capa.loader import ModuleLoader
from capa.manifest import (
    COMPOSED_SCHEMA_VERSION,
    DependencyGraph,
    DependencyIdentity,
    build_composed_sbom,
    build_manifest,
    canonical_bytes,
    canonical_manifest,
    resolve_dependency_identities,
)
from capa.manifest._compose import _construct_purl


def _write(base: Path, rel: str, text: str) -> None:
    p = base / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


# The worked example from the design, matched byte-for-byte: a github dep
# acme/widget v1.2.3 resolved to a full commit SHA.
_WORKED_URL = "https://github.com/acme/widget.git"
_WORKED_COMMIT = "ef1c0ffee1234567890abcdef1234567890abcd"
_WORKED_PURL = (
    "pkg:generic/widget@1.2.3?vcs_url=git%2Bhttps:%2F%2Fgithub.com%2F"
    "acme%2Fwidget.git%40ef1c0ffee1234567890abcdef1234567890abcd"
)


class TestConstructPurl(unittest.TestCase):
    """The ONE purl producer, unit-tested over every branch."""

    def test_git_dep_with_commit_matches_worked_example(self):
        purl = _construct_purl(
            name="widget", version="1.2.3", source_kind="git",
            git_url=_WORKED_URL, pin="v1.2.3", commit=_WORKED_COMMIT,
        )
        self.assertEqual(purl, _WORKED_PURL)

    def test_git_dep_falls_back_to_pin_when_no_commit(self):
        purl = _construct_purl(
            name="widget", version="1.2.3", source_kind="git",
            git_url=_WORKED_URL, pin="v1.2.3", commit=None,
        )
        self.assertEqual(
            purl,
            "pkg:generic/widget@1.2.3?vcs_url=git%2Bhttps:%2F%2Fgithub.com%2F"
            "acme%2Fwidget.git%40v1.2.3",
        )

    def test_git_dep_without_version_omits_version_segment(self):
        purl = _construct_purl(
            name="missing", version=None, source_kind="git",
            git_url="https://github.com/acme/missing.git", pin="abc123",
            commit=None,
        )
        self.assertEqual(
            purl,
            "pkg:generic/missing?vcs_url=git%2Bhttps:%2F%2Fgithub.com%2F"
            "acme%2Fmissing.git%40abc123",
        )
        # The version segment (``@<version>``) must be absent, but the
        # vcs_url qualifier must remain.
        self.assertNotIn("missing@", purl)
        self.assertIn("vcs_url=", purl)

    def test_path_dep_has_no_purl(self):
        self.assertIsNone(_construct_purl(
            name="localdep", version="9.9.9", source_kind="path",
            git_url=None, pin=None, commit=None,
        ))


class _Project(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="capa_depid_"))
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))

    def _fixture(self, *, with_lock: bool) -> Path:
        """A project with a resolved git dep, a resolved path dep, and an
        unresolved (never-vendored) git dep, optionally with a capa.lock."""
        root = self.tmp / "proj"
        _write(root, "capa.toml", (
            '[package]\n'
            'name = "app"\n'
            'version = "0.1.0"\n\n'
            '[dependencies.widget]\n'
            f'git = "{_WORKED_URL}"\n'
            'tag = "v1.2.3"\n\n'
            '[dependencies.localdep]\n'
            'path = "../localdep"\n\n'
            '[dependencies.missing]\n'
            'git = "https://github.com/acme/missing.git"\n'
            'rev = "abc123"\n'
        ))
        _write(root, "main.capa", "pub fun main()\n    return\n")
        _write(root, "vendor/widget/capa.toml",
               '[package]\nname = "widget"\nversion = "1.2.3"\n')
        _write(root, "vendor/widget/w.capa", "pub fun w()\n    return\n")
        _write(self.tmp / "localdep", "capa.toml",
               '[package]\nname = "localdep"\nversion = "9.9.9"\n')
        _write(self.tmp / "localdep", "l.capa", "pub fun l()\n    return\n")
        if with_lock:
            _write(root, "capa.lock", (
                "[[dependencies]]\n"
                'name = "widget"\n'
                f'git = "{_WORKED_URL}"\n'
                'pin = "v1.2.3"\n'
                'pin_kind = "tag"\n'
                f'commit = "{_WORKED_COMMIT}"\n'
            ))
        return root


class TestResolveDependencyIdentities(_Project):
    def test_lists_every_declared_dependency(self):
        ids, _ = resolve_dependency_identities(self._fixture(with_lock=True))
        self.assertEqual([i.name for i in ids], ["localdep", "missing", "widget"])

    def test_git_dep_carries_version_commit_and_worked_purl(self):
        ids, _ = resolve_dependency_identities(self._fixture(with_lock=True))
        widget = next(i for i in ids if i.name == "widget")
        self.assertTrue(widget.resolved)
        self.assertEqual(widget.version, "1.2.3")
        self.assertEqual(widget.commit, _WORKED_COMMIT)
        self.assertEqual(widget.pin, "v1.2.3")
        self.assertEqual(widget.pin_kind, "tag")
        self.assertEqual(widget.rel_path, "vendor/widget")
        self.assertEqual(widget.purl, _WORKED_PURL)
        self.assertEqual(widget.bom_ref, _WORKED_PURL)

    def test_unresolved_git_dep_is_listed_without_version(self):
        ids, _ = resolve_dependency_identities(self._fixture(with_lock=True))
        missing = next(i for i in ids if i.name == "missing")
        self.assertFalse(missing.resolved)
        self.assertIsNone(missing.version)
        self.assertIsNone(missing.commit)  # only top-level LOCKED deps get one
        self.assertIsNotNone(missing.purl)  # still identified by url + pin
        self.assertIn("missing", missing.purl)

    def test_path_dep_has_version_relpath_but_no_purl(self):
        ids, _ = resolve_dependency_identities(self._fixture(with_lock=True))
        local = next(i for i in ids if i.name == "localdep")
        self.assertTrue(local.resolved)
        self.assertEqual(local.version, "9.9.9")
        self.assertEqual(local.source_kind, "path")
        self.assertIsNone(local.purl)
        self.assertEqual(local.bom_ref, "capa:dep:localdep@9.9.9")
        self.assertEqual(local.rel_path, "../localdep")

    def test_commit_absent_when_no_lock(self):
        ids, _ = resolve_dependency_identities(self._fixture(with_lock=False))
        widget = next(i for i in ids if i.name == "widget")
        self.assertIsNone(widget.commit)
        # The purl still identifies the dep, falling back to the pin.
        self.assertIn("%40v1.2.3", widget.purl)

    def test_broken_lock_degrades_to_no_commit(self):
        root = self._fixture(with_lock=True)
        (root / "capa.lock").write_text("this is not valid toml = [", "utf-8")
        # Must not raise; the commit simply degrades to None.
        ids, _ = resolve_dependency_identities(root)
        widget = next(i for i in ids if i.name == "widget")
        self.assertIsNone(widget.commit)

    def test_result_is_deterministic(self):
        root = self._fixture(with_lock=True)
        a, ga = resolve_dependency_identities(root)
        b, gb = resolve_dependency_identities(root)
        self.assertEqual(a, b)
        self.assertEqual(ga, gb)

    def test_graph_lists_top_level_deps_as_root_children(self):
        _, graph = resolve_dependency_identities(self._fixture(with_lock=True))
        self.assertIsInstance(graph, DependencyGraph)
        ids, _ = resolve_dependency_identities(self._fixture(with_lock=True))
        self.assertEqual(
            set(graph.root_children), {i.bom_ref for i in ids},
        )

    def test_records_are_frozen(self):
        ids, _ = resolve_dependency_identities(self._fixture(with_lock=True))
        with self.assertRaises(Exception):
            ids[0].name = "mutated"  # type: ignore[misc]
        self.assertIsInstance(ids[0], DependencyIdentity)

    def test_diamond_dependency_is_listed_once(self):
        # widget is declared by both the root and localdep, resolving to the
        # same vendored package: it must appear once (deduplicated by purl).
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
            f'git = "{_WORKED_URL}"\ntag = "v1.2.3"\n'
        ))
        _write(self.tmp / "mid", "m.capa", "pub fun m()\n    return\n")
        # mid vendors its own identical copy of widget, so both edges
        # resolve to the same identity (same version + purl) and dedup.
        _write(self.tmp / "mid", "vendor/widget/capa.toml",
               '[package]\nname = "widget"\nversion = "1.2.3"\n')
        _write(self.tmp / "mid", "vendor/widget/w.capa",
               "pub fun w()\n    return\n")
        ids, _ = resolve_dependency_identities(root)
        self.assertEqual(
            [i.name for i in ids].count("widget"), 1,
            "a diamond dependency must be listed once",
        )

    def test_lock_resolved_diamond_is_listed_once_carrying_the_sha(self):
        # widget is declared BOTH directly by the root (its purl gets the
        # lock's resolved SHA) AND transitively via a direct dep mid (its
        # purl would otherwise get the declared tag). The two edges share the
        # same (git_url, pin), so both must inherit the lock commit, collapse
        # to ONE component, and that component must carry the SHA not the tag.
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
        ids, _ = resolve_dependency_identities(root)
        self.assertEqual(
            [i.name for i in ids].count("widget"), 1,
            "a lock-resolved diamond dependency must be listed once",
        )
        widget = next(i for i in ids if i.name == "widget")
        self.assertEqual(widget.commit, _WORKED_COMMIT)
        # The surviving component must carry the resolved SHA, not the tag.
        self.assertIn(f"%40{_WORKED_COMMIT}", widget.purl)
        self.assertNotIn("%40v1.2.3", widget.purl)

    def test_distinct_source_diamond_is_not_over_collapsed(self):
        # Two same-NAMED widgets at DIFFERENT git URLs are genuinely distinct
        # packages: the dedup must NOT fold them together. Neither shares the
        # root lock's (git_url, pin), so both keep their own pin + purl.
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
            f'git = "{other_url}"\ntag = "v9.9.9"\n'
        ))
        _write(self.tmp / "mid", "m.capa", "pub fun m()\n    return\n")
        _write(self.tmp / "mid", "vendor/widget/capa.toml",
               '[package]\nname = "widget"\nversion = "9.9.9"\n')
        _write(self.tmp / "mid", "vendor/widget/w.capa",
               "pub fun w()\n    return\n")
        _write(root, "capa.lock", (
            "[[dependencies]]\n"
            'name = "widget"\n'
            f'git = "{_WORKED_URL}"\n'
            'pin = "v1.2.3"\npin_kind = "tag"\n'
            f'commit = "{_WORKED_COMMIT}"\n'
        ))
        ids, _ = resolve_dependency_identities(root)
        widgets = [i for i in ids if i.name == "widget"]
        self.assertEqual(
            len(widgets), 2,
            "widgets at different git URLs are distinct packages",
        )
        purls = {w.purl for w in widgets}
        self.assertEqual(len(purls), 2, "distinct widgets must keep distinct purls")


class TestComposeByteIdentity(_Project):
    """The resolve-layer extension (retained DepEdge fields + the lock
    read now living inside build_package_dag) must NOT perturb the
    existing composed product SBOM by a single byte."""

    def _compose(self, root_dir: Path):
        root_dir = root_dir.resolve()
        search = [root_dir]
        for vendor in root_dir.rglob("vendor"):
            if vendor.is_dir():
                search.append(vendor)
        filename = str(root_dir / "main.capa")
        source = Path(filename).read_text(encoding="utf-8")
        loader = ModuleLoader(search_paths=search)
        linked = loader.load_root(source, filename)
        result = analyze(
            linked.module, source=source, filename=filename,
            sources=linked.sources, module_privates=linked.module_privates,
        )
        self.assertTrue(result.ok, result.errors)
        manifest = build_manifest(
            linked.module, filename=filename, expr_labels=result.expr_labels,
            unaudited_secret_sinks=result.unaudited_secret_sinks,
        )
        return build_composed_sbom(linked.module, manifest, root_dir)

    def test_schema_version_unchanged(self):
        self.assertEqual(COMPOSED_SCHEMA_VERSION, 6)

    def test_lock_read_does_not_leak_into_composed_output(self):
        # The composed SBOM must be byte-identical whether or not a
        # capa.lock is present: the lock read added to build_package_dag
        # feeds ONLY the dependency-identity records, never the compose
        # roll-up.
        with_lock = self._compose(self._fixture(with_lock=True))
        # Rebuild the same project without the lock.
        self.tmp = Path(tempfile.mkdtemp(prefix="capa_depid_"))
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))
        without_lock = self._compose(self._fixture(with_lock=False))
        self.assertEqual(
            canonical_bytes(canonical_manifest(with_lock)),
            canonical_bytes(canonical_manifest(without_lock)),
        )

    def test_composed_output_carries_no_dependency_identity_fields(self):
        composed = self._compose(self._fixture(with_lock=True))
        # None of the new dependency-identity keys leak into the composed
        # product SBOM shape.
        for pkg in composed["packages"]:
            self.assertNotIn("purl", pkg)
            self.assertNotIn("bom_ref", pkg)


if __name__ == "__main__":
    unittest.main()
