"""Tests for the composed capability SBOM (composition S2).

These build minimal, self-contained multi-package fixtures on disk
(a root ``capa.toml`` + ``.capa`` sources, plus vendored dependencies
under ``vendor/<name>``) and drive the whole pipeline the CLI drives:
loader link -> analyze -> ``build_manifest`` -> ``build_composed_sbom``.

The acceptance rows from the S2 design, in order:

- THE TOP TRAP FIRST: a pure product with a DECLARED-but-unresolvable
  dependency composes as authority-UNKNOWN, visibly labelled, and is NOT
  reported clean; TOP dominates (the composed set is not shrunk).
- A vendored zero-capability leaf dependency (the ``capa_paymentguard``
  / ``capa_hash`` shape): composed = caps(root) UNION empty; the leaf is
  a zero-capability node; the DAG carries the edge.
- A single package carrying a real surface (the ``capa_export_gate``
  shape): composed = attributed.
- ATTRIBUTION CORRECTNESS: a capability introduced by a dependency is
  attributed to the DEPENDENCY, not the root; a mangled/private
  dependency function is still attributed correctly.
- DETERMINISM: the composed artifact is byte-reproducible across runs
  and working directories (same content digest), reusing the S1
  canonical form.
- NON-REGRESSION: ``build_composed_sbom`` does not mutate the manifest
  it is handed.
"""

import copy
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from capa import analyze
from capa.loader import ModuleLoader
from capa.manifest import (
    COMPOSED_SCHEMA_VERSION,
    ComposeError,
    build_composed_sbom,
    build_manifest,
    build_package_dag,
    canonical_json,
    canonical_manifest,
    find_package_root,
    manifest_digest,
)
from capa.manifest._compose import (
    Authority, DepEdge, PackageNode, _compose_node,
)


def _write(base: Path, rel: str, text: str) -> None:
    p = base / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def _compose(root_dir: Path, root_file: str):
    """Link + analyze ``root_file`` under ``root_dir``, then build the
    composed SBOM. Search paths mirror the CLI: the project dir and every
    (possibly nested) ``vendor`` directory in the tree."""
    root_dir = root_dir.resolve()
    search = [root_dir]
    for vendor in root_dir.rglob("vendor"):
        if vendor.is_dir():
            search.append(vendor)
    filename = str(root_dir / root_file)
    source = Path(filename).read_text(encoding="utf-8")
    loader = ModuleLoader(search_paths=search)
    linked = loader.load_root(source, filename)
    result = analyze(
        linked.module, source=source, filename=filename,
        sources=linked.sources, module_privates=linked.module_privates,
    )
    if not result.ok:
        raise AssertionError(f"analyzer errors: {result.errors}")
    manifest = build_manifest(
        linked.module, filename=filename, expr_labels=result.expr_labels,
        unaudited_secret_sinks=result.unaudited_secret_sinks,
    )
    composed = build_composed_sbom(linked.module, manifest, root_dir)
    return composed, manifest


def _pkg(composed, name):
    for p in composed["packages"]:
        if p["name"] == name:
            return p
    raise AssertionError(f"no package {name!r} in {[p['name'] for p in composed['packages']]}")


class _TmpTree(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="capa_compose_"))
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))


class TestTopTrap(_TmpTree):
    """The soundness trap, tested FIRST: an unanalyzable subtree must
    make the product authority-unknown, never dishonestly clean."""

    def _pure_product_with_dep(self, dep_block: str) -> Path:
        root = self.tmp / "prod"
        _write(root, "capa.toml", (
            '[package]\n'
            'name = "pure_product"\n'
            'version = "0.1.0"\n\n'
            + dep_block
        ))
        _write(root, "main.capa", "pub fun add(a: Int, b: Int) -> Int\n    return a + b\n")
        return root

    def test_declared_dep_with_no_vendor_is_authority_unknown(self):
        root = self._pure_product_with_dep(
            '[dependencies.ghost]\n'
            'git = "https://github.com/example/ghost"\n'
            'tag = "v1.0"\n'
        )
        composed, _ = _compose(root, "main.capa")
        # TOP: visibly labelled, and the product is NOT clean/pure.
        self.assertTrue(composed["composed"]["authority_unknown"])
        self.assertTrue(composed["unresolved_dependencies"])
        self.assertEqual(
            composed["unresolved_dependencies"][0]["dependency"], "ghost",
        )
        # TOP dominates: the concrete set is a floor, still present, not
        # replaced by empty; the flag is what carries the honesty.
        self.assertEqual(composed["composed"]["capabilities"], [])
        reasons = composed["composed"]["authority_unknown_reasons"]
        self.assertTrue(any(r["dependency"] == "ghost" for r in reasons))

    def test_top_dominates_and_does_not_shrink_the_known_set(self):
        # A product that itself uses Fs AND has an unresolvable dep must
        # report BOTH the Fs floor and authority_unknown.
        root = self.tmp / "prod"
        _write(root, "capa.toml", (
            '[package]\nname = "p"\nversion = "0.1.0"\n\n'
            '[dependencies.ghost]\n'
            'git = "https://github.com/example/ghost"\ntag = "v1"\n'
        ))
        _write(root, "main.capa", "pub fun run(_fs: Fs)\n    return\n")
        composed, _ = _compose(root, "main.capa")
        self.assertIn("Fs", composed["composed"]["capabilities"])
        self.assertTrue(composed["composed"]["authority_unknown"])

    def test_native_dep_capa_toml_but_no_source_is_unknown(self):
        root = self._pure_product_with_dep(
            '[dependencies.native]\n'
            'git = "https://github.com/example/native"\ntag = "v1"\n'
        )
        # Vendored directory with a capa.toml but NO Capa source: a
        # native / non-Capa dependency whose authority cannot be derived.
        _write(root, "vendor/native/capa.toml",
               '[package]\nname = "native"\nversion = "1.0.0"\n')
        _write(root, "vendor/native/lib.rs", "// not capa\n")
        composed, _ = _compose(root, "main.capa")
        self.assertTrue(composed["composed"]["authority_unknown"])
        self.assertTrue(any(
            r["dependency"] == "native"
            for r in composed["composed"]["authority_unknown_reasons"]
        ))

    def test_unreadable_dep_capa_toml_is_unknown(self):
        root = self._pure_product_with_dep(
            '[dependencies.broken]\n'
            'git = "https://github.com/example/broken"\ntag = "v1"\n'
        )
        _write(root, "vendor/broken/capa.toml", "this is not valid toml = = =\n")
        _write(root, "vendor/broken/mod.capa", "pub fun f()\n    return\n")
        composed, _ = _compose(root, "main.capa")
        self.assertTrue(composed["composed"]["authority_unknown"])

    def test_recursive_dep_of_dep_with_no_vendor_is_unknown(self):
        # depB is analyzable, but its OWN capa.toml declares ghostsub with
        # no vendored source. Composition RECURSIVELY reads depB's capa.toml
        # (the read `capa install` does not do) and marks the product
        # authority-unknown through the transitive edge.
        root = self.tmp / "prod"
        _write(root, "capa.toml", (
            '[package]\nname = "p"\nversion = "0.1.0"\n\n'
            '[dependencies.depB]\n'
            'git = "https://github.com/example/depB"\ntag = "v1"\n'
        ))
        _write(root, "main.capa", "import depB.mod\n\npub fun run() -> String\n    return hello()\n")
        _write(root, "vendor/depB/capa.toml", (
            '[package]\nname = "depB"\nversion = "1.0.0"\n\n'
            '[dependencies.ghostsub]\n'
            'git = "https://github.com/example/ghostsub"\ntag = "v1"\n'
        ))
        _write(root, "vendor/depB/mod.capa", 'pub fun hello() -> String\n    return "hi"\n')
        composed, _ = _compose(root, "main.capa")
        self.assertTrue(composed["composed"]["authority_unknown"])
        self.assertTrue(any(
            u["declared_in"] == "depB" and u["dependency"] == "ghostsub"
            for u in composed["unresolved_dependencies"]
        ))

    def test_unsafe_crossing_package_is_authority_unknown(self):
        root = self.tmp / "prod"
        _write(root, "capa.toml", '[package]\nname = "p"\nversion = "0.1.0"\n')
        _write(root, "main.capa", (
            "pub fun risky(_u: Unsafe)\n"
            "    return\n"
        ))
        composed, _ = _compose(root, "main.capa")
        self.assertTrue(composed["composed"]["authority_unknown"])
        p = _pkg(composed, "p")
        self.assertTrue(p["authority_unknown"])


class TestZeroCapLeaf(_TmpTree):
    """The capa_paymentguard / capa_hash shape: a root package plus a
    vendored, zero-capability leaf dependency."""

    def _build(self):
        root = self.tmp / "product"
        _write(root, "capa.toml", (
            '[package]\nname = "product"\nversion = "0.1.0"\n\n'
            '[dependencies.leaf]\n'
            'git = "https://github.com/example/leaf"\ntag = "v1"\n'
        ))
        _write(root, "main.capa", (
            "import leaf.util\n\n"
            "pub fun audit(_fs: Fs) -> String\n"
            "    return tag()\n"
        ))
        _write(root, "vendor/leaf/capa.toml",
               '[package]\nname = "leaf"\nversion = "0.1.0"\n')
        _write(root, "vendor/leaf/util.capa",
               'pub fun tag() -> String\n    return "t"\n')
        return root

    def test_composed_is_root_union_empty_leaf(self):
        root = self._build()
        composed, _ = _compose(root, "main.capa")
        self.assertEqual(composed["composed"]["capabilities"], ["Fs"])
        self.assertFalse(composed["composed"]["authority_unknown"])

    def test_leaf_is_zero_capability_node(self):
        root = self._build()
        composed, _ = _compose(root, "main.capa")
        leaf = _pkg(composed, "leaf")
        self.assertEqual(leaf["attributed_capabilities"], [])
        self.assertEqual(leaf["composed_capabilities"], [])
        self.assertFalse(leaf["authority_unknown"])

    def test_dag_carries_the_edge(self):
        root = self._build()
        composed, _ = _compose(root, "main.capa")
        self.assertTrue(any(
            e["from"] == "product" and e["dependency"] == "leaf"
            and e["resolved"] and e["to_package"] == "leaf"
            for e in composed["edges"]
        ))


class TestSinglePackageSurface(_TmpTree):
    """The capa_export_gate shape: one package whose composed set equals
    its attributed set."""

    def test_composed_equals_attributed_for_single_package(self):
        root = self.tmp / "gate"
        _write(root, "capa.toml", '[package]\nname = "gate"\nversion = "0.1.0"\n')
        _write(root, "main.capa", (
            "pub fun log(_io: Stdio)\n    return\n"
            "pub fun save(_fs: Fs)\n    return\n"
        ))
        composed, _ = _compose(root, "main.capa")
        self.assertEqual(composed["composed"]["capabilities"], ["Fs", "Stdio"])
        self.assertFalse(composed["composed"]["authority_unknown"])
        p = _pkg(composed, "gate")
        self.assertEqual(p["attributed_capabilities"], ["Fs", "Stdio"])


class TestAttributionCorrectness(_TmpTree):
    """The hardest part: a capability introduced by a dependency is
    attributed to the DEPENDENCY, not the root; and a mangled/private
    dependency function is attributed correctly too."""

    def _build(self):
        root = self.tmp / "app"
        _write(root, "capa.toml", (
            '[package]\nname = "app"\nversion = "0.1.0"\n\n'
            '[dependencies.storage]\n'
            'git = "https://github.com/example/storage"\ntag = "v1"\n'
        ))
        # The ROOT is pure: it only calls a pure helper from storage.
        _write(root, "main.capa", (
            "import storage.api\n\n"
            "pub fun run() -> String\n"
            "    return name()\n"
        ))
        # storage carries the Fs surface: a pub Fs function AND a PRIVATE
        # (loader-mangled) Fs helper reached from it.
        _write(root, "vendor/storage/capa.toml",
               '[package]\nname = "storage"\nversion = "0.1.0"\n')
        _write(root, "vendor/storage/api.capa", (
            'pub fun name() -> String\n    return "s"\n\n'
            "fun secret_writer(_fs: Fs)\n    return\n\n"
            "pub fun persist(fs: Fs)\n    secret_writer(fs)\n    return\n"
        ))
        return root

    def test_capability_attributed_to_dependency_not_root(self):
        root = self._build()
        composed, _ = _compose(root, "main.capa")
        self.assertEqual(_pkg(composed, "app")["attributed_capabilities"], [])
        self.assertEqual(
            _pkg(composed, "storage")["attributed_capabilities"], ["Fs"],
        )
        # The product still SEES Fs (it composes up from the dependency).
        self.assertEqual(composed["composed"]["capabilities"], ["Fs"])

    def test_mangled_private_dep_function_attributed_to_dependency(self):
        # The private `secret_writer` is loader-mangled; its Fs surface
        # must still land on storage, not the root or nowhere. If it were
        # mis-attributed, storage would lose Fs or app would gain it.
        root = self._build()
        composed, m = _compose(root, "main.capa")
        # The mangled private function is present in the flat manifest.
        self.assertTrue(any(
            f["source_name"] == "secret_writer" and f["name"] != "secret_writer"
            for f in m["functions"]
        ))
        self.assertEqual(
            _pkg(composed, "storage")["attributed_capabilities"], ["Fs"],
        )
        self.assertEqual(_pkg(composed, "app")["attributed_capabilities"], [])


class TestDeterminism(_TmpTree):
    """The composed artifact is canonical and byte-reproducible, reusing
    the S1 canonical form."""

    def _tree(self, base: Path) -> Path:
        root = base / "prod"
        _write(root, "capa.toml", (
            '[package]\nname = "prod"\nversion = "0.1.0"\n\n'
            '[dependencies.leaf]\n'
            'git = "https://github.com/example/leaf"\ntag = "v1"\n'
        ))
        _write(root, "main.capa", (
            "import leaf.util\n\n"
            "pub fun run(_fs: Fs) -> String\n    return tag()\n"
        ))
        _write(root, "vendor/leaf/capa.toml",
               '[package]\nname = "leaf"\nversion = "0.1.0"\n')
        _write(root, "vendor/leaf/util.capa",
               'pub fun tag() -> String\n    return "t"\n')
        return root

    def test_digest_stable_across_runs(self):
        root = self._tree(self.tmp)
        c1, _ = _compose(root, "main.capa")
        c2, _ = _compose(root, "main.capa")
        self.assertEqual(canonical_json(c1), canonical_json(c2))
        self.assertEqual(manifest_digest(c1), manifest_digest(c2))

    def test_digest_stable_across_working_directories(self):
        os.environ["SOURCE_DATE_EPOCH"] = "1700000000"
        self.addCleanup(lambda: os.environ.pop("SOURCE_DATE_EPOCH", None))
        a = self._tree(self.tmp / "a")
        b = self._tree(self.tmp / "b")
        ca, _ = _compose(a, "main.capa")
        cb, _ = _compose(b, "main.capa")
        # Two different absolute locations, identical content: the paths
        # are root-relative, so the digests match.
        self.assertEqual(manifest_digest(ca), manifest_digest(cb))

    def test_content_integrity_envelope_roundtrips(self):
        root = self._tree(self.tmp)
        composed, _ = _compose(root, "main.capa")
        wrapped = canonical_manifest(composed)
        self.assertIn("content_integrity", wrapped)
        self.assertEqual(
            wrapped["content_integrity"]["digest"]["value"],
            manifest_digest(composed),
        )


class TestNonRegression(_TmpTree):
    def test_compose_does_not_mutate_the_manifest(self):
        root = self.tmp / "prod"
        _write(root, "capa.toml", '[package]\nname = "prod"\nversion = "0.1.0"\n')
        _write(root, "main.capa", "pub fun run(_fs: Fs)\n    return\n")
        _, manifest = _compose(root, "main.capa")
        before = canonical_json(manifest)
        build_composed_sbom(
            _link_module(root, "main.capa"), manifest, root,
        )
        self.assertEqual(canonical_json(manifest), before)

    def test_schema_version_constant(self):
        # Bumped to 2 in S3 (per-package declared_ceiling /
        # ceiling_violations + the product-level capability_ceilings block);
        # to 3 in feature #6 P2 (per-package + product declassification
        # rollup); to 4 in feature #6 B1 (per-package un-audited
        # secret->egress-sink rollup); to 5 when the per-package ceiling
        # check additionally fails closed on a declaring package whose OWN
        # authority is not provable from its types (self-scoped).
        self.assertEqual(COMPOSED_SCHEMA_VERSION, 5)

    def test_find_package_root(self):
        root = self.tmp / "prod"
        _write(root, "capa.toml", '[package]\nname = "prod"\nversion = "0.1.0"\n')
        _write(root, "sub/deep.capa", "pub fun f()\n    return\n")
        self.assertEqual(
            find_package_root(root / "sub" / "deep.capa"), root.resolve(),
        )
        self.assertIsNone(find_package_root(self.tmp / "nope"))


def _link_module(root_dir: Path, root_file: str):
    root_dir = root_dir.resolve()
    search = [root_dir]
    for vendor in root_dir.rglob("vendor"):
        if vendor.is_dir():
            search.append(vendor)
    filename = str(root_dir / root_file)
    source = Path(filename).read_text(encoding="utf-8")
    loader = ModuleLoader(search_paths=search)
    return loader.load_root(source, filename).module


class TestPackageDag(_TmpTree):
    def test_dag_recurses_into_vendored_dep_manifest(self):
        root = self.tmp / "prod"
        _write(root, "capa.toml", (
            '[package]\nname = "prod"\nversion = "0.1.0"\n\n'
            '[dependencies.mid]\n'
            'git = "https://github.com/example/mid"\ntag = "v1"\n'
        ))
        _write(root, "main.capa", "pub fun f()\n    return\n")
        _write(root, "vendor/mid/capa.toml",
               '[package]\nname = "mid"\nversion = "0.1.0"\n')
        _write(root, "vendor/mid/m.capa", "pub fun g()\n    return\n")
        nodes, node_root = build_package_dag(root)
        names = sorted(n.name for n in nodes.values())
        self.assertEqual(names, ["mid", "prod"])
        self.assertEqual(node_root.name, "prod")


class TestDeclassificationRollup(_TmpTree):
    """Feature #6 (P2): the composed SBOM rolls each audited
    @secret -> @public declassification site up to its owning package and
    to the product, mirroring the capability attribution. A package whose
    composed authority is TOP reports its count as a FLOOR (never a
    confident zero) so a policy can fail closed over it."""

    def _find(self, composed, name):
        for p in composed["packages"]:
            if p["name"] == name:
                return p
        raise AssertionError(f"no package {name!r}")

    def test_declassification_attributed_to_owning_dependency(self):
        # The declassify site lives in a VENDORED dependency, so it must be
        # attributed to that dependency, not the root; the root's composed
        # (transitive) count still sees it, and so does the product total.
        root = self.tmp / "app"
        _write(root, "capa.toml", (
            '[package]\nname = "app"\nversion = "0.1.0"\n\n'
            '[dependencies.lib]\n'
            'git = "https://github.com/example/lib"\ntag = "v1"\n'
        ))
        _write(root, "main.capa",
               "import lib.mod\n\npub fun run() -> Unit\n    go()\n    return\n")
        _write(root, "vendor/lib/capa.toml",
               '[package]\nname = "lib"\nversion = "0.1.0"\n')
        _write(root, "vendor/lib/mod.capa", (
            "pub fun go() -> Unit\n    return\n"
            "pub fun disclose(token: @secret String, stdio: Stdio) -> Unit\n"
            "    stdio.println(declassify(token, reason: \"audit\"))\n"
            "    return\n"
        ))
        composed, _ = _compose(root, "main.capa")
        self.assertEqual(composed["composed_schema_version"], 5)

        lib = self._find(composed, "lib")
        self.assertEqual(lib["attributed_declassification_sites"], 1)
        self.assertEqual(lib["composed_declassification_sites"], 1)
        self.assertTrue(lib["composed_has_declassification"])
        self.assertEqual(len(lib["attributed_declassifications"]), 1)
        site = lib["attributed_declassifications"][0]
        self.assertEqual(site["reason"], "audit")
        self.assertIn("vendor/lib/mod.capa", site["pos"])

        app = self._find(composed, "app")
        # The root did not declassify itself, but its transitive closure did.
        self.assertEqual(app["attributed_declassification_sites"], 0)
        self.assertEqual(app["composed_declassification_sites"], 1)
        self.assertTrue(app["composed_has_declassification"])

        self.assertEqual(composed["composed"]["declassification_sites"], 1)
        self.assertTrue(composed["composed"]["has_declassification"])

    def test_clean_product_has_zero_declassification(self):
        root = self.tmp / "app"
        _write(root, "capa.toml", '[package]\nname = "app"\nversion = "0.1.0"\n')
        _write(root, "main.capa",
               "pub fun add(a: Int, b: Int) -> Int\n    return a + b\n")
        composed, _ = _compose(root, "main.capa")
        app = self._find(composed, "app")
        self.assertEqual(app["composed_declassification_sites"], 0)
        self.assertFalse(app["composed_has_declassification"])
        self.assertFalse(app["attributed_declassifications"])
        self.assertEqual(composed["composed"]["declassification_sites"], 0)
        self.assertFalse(composed["composed"]["has_declassification"])

    def test_top_package_count_is_a_floor(self):
        # A package with an unresolvable dependency is TOP; its declassify
        # count is a FLOOR (the unanalyzable subtree may declassify unseen),
        # and composed_authority_unknown lets a policy fail closed.
        root = self.tmp / "prod"
        _write(root, "capa.toml", (
            '[package]\nname = "prod"\nversion = "0.1.0"\n\n'
            '[dependencies.ghost]\n'
            'git = "https://github.com/example/ghost"\ntag = "v1"\n'
        ))
        _write(root, "main.capa",
               "pub fun add(a: Int, b: Int) -> Int\n    return a + b\n")
        composed, _ = _compose(root, "main.capa")
        prod = self._find(composed, "prod")
        self.assertTrue(prod["composed_authority_unknown"])
        # The known count is zero, but it is a FLOOR, not a confident zero.
        self.assertEqual(prod["composed_declassification_sites"], 0)
        self.assertFalse(prod["composed_has_declassification"])


def _node(name, caps=(), unsafe=False):
    d = Path(f"/pkg/{name}").resolve()
    return PackageNode(
        name=name, version="0", manifest_dir=d, rel_path=name,
        attributed_caps=frozenset(caps), crosses_unsafe=unsafe,
    )


def _edge(target_node, resolved=True, name=None, reason=None):
    return DepEdge(
        name=name or (target_node.name if target_node else "x"),
        target_dir=target_node.manifest_dir if target_node else None,
        resolved=resolved,
        reason=reason,
    )


class TestCycleSoundness(unittest.TestCase):
    """A dependency CYCLE must never make a node under-count capabilities
    or drop a TOP flag: each node's composed_* is the join of its OWN
    authority over its ENTIRE transitively-reachable dependency set."""

    def _nodes(self, *ns):
        return {n.manifest_dir: n for n in ns}

    def test_cycle_closer_sees_caps_through_the_cut_edge(self):
        # Declared cycle: R->B, B->C, B->D, C->B; D carries Net.
        # C reaches Net only through the cut edge C->B->D.
        R = _node("R")
        B = _node("B")
        C = _node("C")
        D = _node("D", caps=["Net"])
        R.dep_edges = [_edge(B)]
        B.dep_edges = [_edge(C), _edge(D)]
        C.dep_edges = [_edge(B)]
        nodes = self._nodes(R, B, C, D)
        composed_C = _compose_node(C, nodes)
        self.assertIn("Net", composed_C.caps)
        # And the root sees it too.
        self.assertIn("Net", _compose_node(R, nodes).caps)

    def test_cycle_closer_inherits_top_through_the_cut_edge(self):
        # Same cycle, but D is unresolved (TOP). C must be authority-unknown.
        R = _node("R")
        B = _node("B")
        C = _node("C")
        R.dep_edges = [_edge(B)]
        B.dep_edges = [_edge(C), _edge(None, resolved=False, name="D",
                                       reason="no vendored package directory")]
        C.dep_edges = [_edge(B)]
        nodes = self._nodes(R, B, C)
        composed_C = _compose_node(C, nodes)
        self.assertTrue(composed_C.unknown)
        self.assertTrue(_compose_node(R, nodes).unknown)

    def test_two_cycle_both_nodes_see_the_full_union(self):
        # A<->B; A has Fs, B has Net; both composed = {Fs, Net}.
        A = _node("A", caps=["Fs"])
        B = _node("B", caps=["Net"])
        A.dep_edges = [_edge(B)]
        B.dep_edges = [_edge(A)]
        nodes = self._nodes(A, B)
        self.assertEqual(_compose_node(A, nodes).caps, frozenset({"Fs", "Net"}))
        self.assertEqual(_compose_node(B, nodes).caps, frozenset({"Fs", "Net"}))

    def test_join_is_order_independent(self):
        # Edge order must not change the composed result (join is
        # commutative + associative).
        A = _node("A", caps=["Fs"])
        B = _node("B", caps=["Net"])
        C = _node("C", caps=["Stdio"])
        A.dep_edges = [_edge(B), _edge(C)]
        r1 = _compose_node(A, self._nodes(A, B, C))
        A.dep_edges = [_edge(C), _edge(B)]
        r2 = _compose_node(A, self._nodes(A, B, C))
        self.assertEqual(r1.caps, r2.caps)
        self.assertEqual(r1.unknown, r2.unknown)
        self.assertEqual(r1.reasons, r2.reasons)


class TestHigherOrderTopTrigger(_TmpTree):
    """ASSESS-3: has_unsafe is the ONLY analyzed-package TOP trigger. A
    package that merely TAKES a Fun(...) is not authority-unknown, and
    the product stays sound because a closure's authority is accounted at
    its CREATION site."""

    def test_invoke_closure_product_is_sound_without_top(self):
        root = self.tmp / "app"
        _write(root, "capa.toml", (
            '[package]\nname = "app"\nversion = "0.1.0"\n\n'
            '[dependencies.hof]\n'
            'git = "https://github.com/example/hof"\ntag = "v1"\n'
        ))
        _write(root, "main.capa", (
            "import hof.api\n\n"
            "pub fun run(io: Stdio)\n"
            "    let l = fun () => io.println(\"x\")\n"
            "    invoke(l)\n"
            "    return\n"
        ))
        _write(root, "vendor/hof/capa.toml",
               '[package]\nname = "hof"\nversion = "0.1.0"\n')
        _write(root, "vendor/hof/api.capa",
               "pub fun invoke(f: Fun() -> Unit)\n    f()\n    return\n")
        composed, _ = _compose(root, "main.capa")
        # Stdio is accounted at the ROOT (the closure creator) and
        # composes into the product; hof stays authority-KNOWN.
        self.assertEqual(composed["composed"]["capabilities"], ["Stdio"])
        self.assertFalse(composed["composed"]["authority_unknown"])
        self.assertEqual(_pkg(composed, "app")["attributed_capabilities"], ["Stdio"])
        hof = _pkg(composed, "hof")
        self.assertEqual(hof["attributed_capabilities"], [])
        self.assertFalse(hof["authority_unknown"])


class TestOutOfTreePathDep(_TmpTree):
    """FIX 2: an out-of-tree (``../sib``) path dependency must serialise a
    ``..``-relative path, never an absolute one, so the artifact stays
    byte-reproducible across absolute locations and leaks no local
    layout."""

    def _product_with_sib(self, base: Path) -> Path:
        root = base / "product"
        _write(root, "capa.toml", (
            '[package]\nname = "product"\nversion = "0.1.0"\n\n'
            '[dependencies.sib]\n'
            'path = "../sib"\n'
        ))
        _write(root, "main.capa", "pub fun f()\n    return\n")
        sib = base / "sib"
        _write(sib, "capa.toml", '[package]\nname = "sib"\nversion = "0.1.0"\n')
        _write(sib, "mod.capa", "pub fun g()\n    return\n")
        return root

    def test_path_field_is_relative_not_absolute(self):
        root = self._product_with_sib(self.tmp)
        composed, _ = _compose(root, "main.capa")
        sib = _pkg(composed, "sib")
        self.assertEqual(sib["path"], "../sib")
        # No absolute path anywhere in the artifact.
        blob = canonical_json(composed)
        self.assertNotIn(str(self.tmp.resolve()), blob)
        self.assertNotIn(":\\", blob)  # no Windows drive-letter path

    def test_digest_stable_across_absolute_locations(self):
        a = self._product_with_sib(self.tmp / "locationA")
        b = self._product_with_sib(self.tmp / "an_entirely_different_locationB")
        ca, _ = _compose(a, "main.capa")
        cb, _ = _compose(b, "main.capa")
        self.assertEqual(manifest_digest(ca), manifest_digest(cb))


class TestCeilingSelfScopeUnprovable(_TmpTree):
    """A package that DECLARES a ceiling (``pure = true`` or ``max = [...]``)
    but whose OWN attributed functions expose authority its types cannot
    prove -- it invokes a caller-supplied ``Fun``, crosses ``Unsafe``, or
    takes a type that reaches a ``Fun`` through an impl -- cannot have a
    VERIFIABLE ceiling: a caller can inject authority the package's types
    never named.

    The product ROLL-UP stays byte-identical (a closure's authority is
    accounted at its CREATION site, so the higher-order-TAKING package
    gains no authority of its own). Only the per-package CEILING check
    newly fails, with the ``authority_unknown`` kind (the ceiling is
    UNVERIFIABLE, distinct from a KNOWN capability that exceeds a bound).
    """

    # A root that hands ``hof.invoke`` a Stdio-capturing closure: the
    # injected effect is an ordinary CAPABILITY effect.
    _STDIO_MAIN = (
        "import hof.api\n\n"
        "pub fun run(io: Stdio)\n"
        '    let l = fun () => io.println("x")\n'
        "    invoke(l)\n"
        "    return\n"
    )
    # A root that hands ``hof.invoke`` an Unsafe-capturing closure: the
    # injected effect drives an Unsafe FFI (a filesystem write, in a real
    # program). The Unsafe crossing is the ROOT's; hof stays higher-order.
    _UNSAFE_MAIN = (
        "import hof.api\n\n"
        "pub fun sink(_u: Unsafe)\n    return\n"
        "pub fun run(u: Unsafe)\n"
        "    let l = fun () => sink(u)\n"
        "    invoke(l)\n"
        "    return\n"
    )

    def _hof_app(self, main_src: str, cap_section: str) -> Path:
        """Root ``app`` depending on a vendored ``hof`` that declares
        ``cap_section`` and exports ``invoke(f: Fun() -> Unit)``. ``main_src``
        is the root module that calls ``invoke`` with some closure."""
        root = self.tmp / "app"
        _write(root, "capa.toml", (
            '[package]\nname = "app"\nversion = "0.1.0"\n\n'
            '[dependencies.hof]\n'
            'git = "https://github.com/example/hof"\ntag = "v1"\n'
        ))
        _write(root, "main.capa", main_src)
        _write(root, "vendor/hof/capa.toml",
               '[package]\nname = "hof"\nversion = "0.1.0"\n\n' + cap_section)
        _write(root, "vendor/hof/api.capa",
               "pub fun invoke(f: Fun() -> Unit)\n    f()\n    return\n")
        return root

    def test_pure_hof_invoking_caller_fun_fails_ceiling(self):
        # THE DEFECT: pure = true, only export invokes a caller-supplied
        # Fun. At 5611b79 the ceiling PASSED; it must now fail closed.
        root = self._hof_app(self._STDIO_MAIN, '[capabilities]\npure = true\n')
        composed, _ = _compose(root, "main.capa")
        hof = _pkg(composed, "hof")
        # The ROLL-UP is untouched: hof is authority-KNOWN and empty.
        self.assertFalse(hof["authority_unknown"])
        self.assertFalse(hof["composed_authority_unknown"])
        self.assertEqual(hof["composed_capabilities"], [])
        # But its CEILING is now UNVERIFIABLE (authority_unknown, not
        # exceeds -- we did not positively observe a cap outside a bound).
        kinds = [v["kind"] for v in hof["ceiling_violations"]]
        self.assertIn("authority_unknown", kinds)
        self.assertNotIn("exceeds", kinds)
        self.assertFalse(composed["capability_ceilings"]["pass"])

    def test_unsafe_ffi_variant_of_hof_shape_fails_ceiling(self):
        # Same hof (pure, invoke Fun); the injected closure drives an
        # Unsafe FFI effect instead of a capability effect. hof still
        # carries only has_fun_in_sig (the Unsafe crossing is the ROOT's),
        # so at 5611b79 its ceiling PASSED; it must now fail closed.
        root = self._hof_app(self._UNSAFE_MAIN, '[capabilities]\npure = true\n')
        composed, _ = _compose(root, "main.capa")
        hof = _pkg(composed, "hof")
        self.assertFalse(hof["authority_unknown"])
        self.assertFalse(hof["composed_authority_unknown"])
        kinds = [v["kind"] for v in hof["ceiling_violations"]]
        self.assertIn("authority_unknown", kinds)
        self.assertFalse(composed["capability_ceilings"]["pass"])

    def test_max_ceiling_hof_shape_fails_ceiling(self):
        # A max = [...] ceiling (not just pure) on the hof shape fails too.
        root = self._hof_app(self._STDIO_MAIN, '[capabilities]\nmax = ["Fs"]\n')
        composed, _ = _compose(root, "main.capa")
        hof = _pkg(composed, "hof")
        kinds = [v["kind"] for v in hof["ceiling_violations"]]
        self.assertIn("authority_unknown", kinds)
        self.assertFalse(composed["capability_ceilings"]["pass"])

    def test_provable_ceiling_still_passes(self):
        # The common case: a package whose authority IS provable from its
        # own types keeps passing -- no new false alarm.
        root = self.tmp / "lib"
        _write(root, "capa.toml", (
            '[package]\nname = "lib"\nversion = "0.1.0"\n\n'
            '[capabilities]\nmax = ["Stdio"]\n'
        ))
        _write(root, "main.capa",
               'pub fun log(io: Stdio)\n    io.println("x")\n    return\n')
        composed, _ = _compose(root, "main.capa")
        self.assertTrue(composed["capability_ceilings"]["pass"])
        self.assertEqual(_pkg(composed, "lib")["ceiling_violations"], [])

    def test_pure_ceiling_with_no_higher_order_still_passes(self):
        # A genuinely pure package (no Fun, no Unsafe, no reaching impl)
        # keeps passing under pure = true.
        root = self.tmp / "calc"
        _write(root, "capa.toml", (
            '[package]\nname = "calc"\nversion = "0.1.0"\n\n'
            '[capabilities]\npure = true\n'
        ))
        _write(root, "main.capa",
               "pub fun add(a: Int, b: Int) -> Int\n    return a + b\n")
        composed, _ = _compose(root, "main.capa")
        self.assertTrue(composed["capability_ceilings"]["pass"])
        self.assertEqual(_pkg(composed, "calc")["ceiling_violations"], [])

    def _rollup(self, composed):
        """The roll-up-only projection of a composed SBOM: the product
        ``composed`` block plus each package's attribution / composition
        fields, EXCLUDING the ceiling fields the new signal feeds."""
        return {
            "composed": composed["composed"],
            "packages": {
                p["name"]: {
                    "attributed_capabilities": p["attributed_capabilities"],
                    "authority_unknown": p["authority_unknown"],
                    "authority_unknown_reasons": p["authority_unknown_reasons"],
                    "composed_capabilities": p["composed_capabilities"],
                    "composed_authority_unknown": p["composed_authority_unknown"],
                }
                for p in composed["packages"]
            },
        }

    def test_rollup_byte_identical_with_and_without_ceiling(self):
        # The new signal feeds ONLY the ceiling check. The product roll-up
        # (composed block + every package's attribution/composition fields)
        # must be byte-identical whether or not hof declares a ceiling --
        # exactly the same hof-invoking program, with the ceiling toggled.
        with_ceiling = self._hof_app(
            self._STDIO_MAIN, '[capabilities]\npure = true\n',
        )
        c_with, _ = _compose(with_ceiling, "main.capa")
        # Rebuild the identical tree without the [capabilities] section.
        shutil.rmtree(self.tmp / "app", ignore_errors=True)
        without = self._hof_app(self._STDIO_MAIN, "")
        c_without, _ = _compose(without, "main.capa")
        self.assertEqual(self._rollup(c_with), self._rollup(c_without))

    def test_fun_bearing_user_capability_in_max_is_unprovable(self):
        # Once max can name a user-defined capability (1.20.0), a
        # Fun-BEARING user capability named in max makes the ceiling
        # UNVERIFIABLE: taking it drags in authority the types cannot
        # prove. No fleet cost today (no fleet user cap is Fun-bearing);
        # this pins the interaction so a later change to the self-scope
        # signal is caught.
        root = self.tmp / "ucap"
        _write(root, "capa.toml", (
            '[package]\nname = "ucap"\nversion = "0.1.0"\n\n'
            '[capabilities]\nmax = ["Runner"]\n'
        ))
        _write(root, "main.capa", (
            "capability Runner\n"
            "    fun go(self)\n"
            "type Job { task: Fun() -> Unit }\n"
            "impl Runner for Job\n"
            "    fun go(self)\n"
            "        let t = self.task\n"
            "        t()\n"
            "pub fun use_runner(r: Runner)\n"
            "    r.go()\n"
        ))
        composed, _ = _compose(root, "main.capa")
        ucap = _pkg(composed, "ucap")
        kinds = [v["kind"] for v in ucap["ceiling_violations"]]
        self.assertIn("authority_unknown", kinds)
        self.assertFalse(composed["capability_ceilings"]["pass"])

    def test_non_fun_bearing_user_capability_in_max_still_passes(self):
        # The counterpart the fleet actually has today: a user capability
        # named in max whose impls reach only PROVABLE authority keeps
        # passing -- the interaction bites ONLY the Fun-bearing shape.
        root = self.tmp / "ucap2"
        _write(root, "capa.toml", (
            '[package]\nname = "ucap2"\nversion = "0.1.0"\n\n'
            '[capabilities]\nmax = ["Logger", "Stdio"]\n'
        ))
        _write(root, "main.capa", (
            "capability Logger\n"
            "    fun log(self, msg: String)\n"
            "type FileLogger { out: Stdio }\n"
            "impl Logger for FileLogger\n"
            "    fun log(self, msg: String)\n"
            "        self.out.println(msg)\n"
            "pub fun use_logger(lg: Logger)\n"
            '    lg.log("x")\n'
        ))
        composed, _ = _compose(root, "main.capa")
        self.assertTrue(composed["capability_ceilings"]["pass"])
        self.assertEqual(_pkg(composed, "ucap2")["ceiling_violations"], [])

    def _link_and_manifest(self, root_dir: Path, root_file: str):
        """Link + analyze + build_manifest for ``root_file`` WITHOUT
        composing, so a test can mutate the manifest before it reaches
        build_composed_sbom (mirrors the CLI's fresh-manifest-then-compose
        pipeline)."""
        root_dir = root_dir.resolve()
        search = [root_dir]
        for vendor in root_dir.rglob("vendor"):
            if vendor.is_dir():
                search.append(vendor)
        filename = str(root_dir / root_file)
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
        return linked.module, manifest, root_dir

    def test_stale_pre_signal_manifest_is_refused_not_trusted(self):
        # FAIL CLOSED on missing evidence. A per-program manifest serialised
        # before schema 2 lacks authority_provable_from_types. Composing it
        # must NOT default the missing key to "provable" and silently PASS
        # the hof ceiling (fail-open, the very defect this subsystem closes);
        # the single choke point refuses the stale artifact outright.
        root = self._hof_app(self._STDIO_MAIN, '[capabilities]\npure = true\n')
        module, manifest, root_dir = self._link_and_manifest(root, "main.capa")
        # A CURRENT (schema 2) manifest composes and fails the hof ceiling.
        composed = build_composed_sbom(module, manifest, root_dir)
        self.assertFalse(composed["capability_ceilings"]["pass"])
        # Downgrade to a pre-signal (schema 1) shape: drop the key from every
        # record and roll schema_version back.
        stale = copy.deepcopy(manifest)
        stale["schema_version"] = 1
        for rec in stale["functions"]:
            rec.pop("authority_provable_from_types", None)
        # It must be REFUSED, never trusted into a silent pass.
        with self.assertRaises(ComposeError) as ctx:
            build_composed_sbom(module, stale, root_dir)
        self.assertIn("schema_version", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
