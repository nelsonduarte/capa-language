"""Tests for organization capability-compliance policies (feature #6, P1).

S2/S3 produced a composed product SBOM and a per-package ceiling check.
P1 adds a PRODUCT-LEVEL ``capa-policy.toml``: organization-owned rules
over a FIXED set of predicate kinds evaluated over the composed
capability graph, with a signed conformance report and a CI gate.

These tests are pure Python over the composed JSON: they build temp
multi-package fixtures, compose the SBOM, parse the policy file, and
evaluate. NO wasmtime / wasm tooling is involved, so they run on CI
unconditionally (no skip guard).

Acceptance rows, in order:

- EXCLUSION: a package holding both Net and Fs fails, naming the package;
  a product where no package holds both passes.
- PRODUCT-SUBSET: composed {Net,Fs,Stdio} under max=[Net,Stdio] fails
  naming Fs + the introducing package; under max=[Net,Fs,Stdio] passes.
- PURITY: a pure leaf passes; a cap-bearing package fails.
- FORBID-CAPABILITY / FORBID-DEPENDENCY / NO-UNRESOLVED-DEPENDENCIES each
  flagged correctly, clean on compliant products.
- FAIL-CLOSED: a policy over a TOP (unresolvable / native / Unsafe)
  subtree fails with 'authority_unknown', DISTINCT from a concrete
  violation, unless allow_unknown is set.
- SCHEMA STRICTNESS: unknown key / kind / capability / malformed -> clean
  parse errors.
- EVIDENCE: the conformance report is canonical / byte-reproducible; the
  --check-policies gate exits 0 on a clean product, 1 on a violation, and
  0 with 'nothing to verify' when there is no policy file.
"""

import io
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from capa import analyze
from capa.loader import ModuleLoader
from capa.manifest import (
    build_composed_sbom, build_manifest, canonical_json, canonical_manifest,
    evaluate_policies, find_policy_file, read_policy_file, PolicyError,
)


def _write(base: Path, rel: str, text: str) -> None:
    p = base / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def _compose(root_dir: Path, root_file: str):
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
    )
    return build_composed_sbom(linked.module, manifest, root_dir)


def _eval(root_dir: Path, root_file: str):
    composed = _compose(root_dir, root_file)
    policy_path = find_policy_file(root_dir.resolve())
    policies = read_policy_file(policy_path) if policy_path else []
    return evaluate_policies(composed, policies), composed


def _result(report, policy_id):
    for r in report["results"]:
        if r["policy"] == policy_id:
            return r
    raise AssertionError(f"no policy result {policy_id!r}")


class _TmpTree(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="capa_policy_"))
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))


# ---------------------------------------------------------------------------
# SCHEMA STRICTNESS
# ---------------------------------------------------------------------------


class TestPolicySchema(_TmpTree):
    def _read(self, text: str):
        root = self.tmp / "p"
        _write(root, "capa-policy.toml", text)
        return read_policy_file(root / "capa-policy.toml")

    def test_empty_file_is_no_policies(self):
        self.assertEqual(self._read(""), [])

    def test_exclusion_parses(self):
        pols = self._read(
            '[[policy]]\nkind = "exclusion"\ncapabilities = ["Net", "Fs"]\n'
        )
        self.assertEqual(len(pols), 1)
        self.assertEqual(pols[0].kind, "exclusion")
        self.assertEqual(pols[0].params["capabilities"], ["Fs", "Net"])
        self.assertEqual(pols[0].params["over"], "composed")
        # Default id is stable in file order.
        self.assertEqual(pols[0].id, "exclusion#0")

    def test_id_and_name_carried(self):
        pols = self._read(
            '[[policy]]\nid = "x"\nname = "no net+fs"\n'
            'kind = "exclusion"\ncapabilities = ["Net", "Fs"]\n'
        )
        self.assertEqual(pols[0].id, "x")
        self.assertEqual(pols[0].name, "no net+fs")

    def test_unknown_top_level_key_rejected(self):
        with self.assertRaises(PolicyError) as cm:
            self._read('bogus = 1\n[[policy]]\nkind = "purity"\n')
        self.assertIn("bogus", str(cm.exception))

    def test_unknown_kind_rejected(self):
        with self.assertRaises(PolicyError) as cm:
            self._read('[[policy]]\nkind = "teleport"\n')
        self.assertIn("teleport", str(cm.exception))

    def test_unknown_key_in_entry_rejected(self):
        with self.assertRaises(PolicyError) as cm:
            self._read(
                '[[policy]]\nkind = "purity"\npackage = "a"\nmxa = 1\n'
            )
        self.assertIn("mxa", str(cm.exception))

    def test_unknown_capability_name_rejected(self):
        with self.assertRaises(PolicyError) as cm:
            self._read(
                '[[policy]]\nkind = "exclusion"\n'
                'capabilities = ["Net", "Bogus"]\n'
            )
        self.assertIn("Bogus", str(cm.exception))

    def test_unsafe_is_not_a_valid_capability(self):
        with self.assertRaises(PolicyError):
            self._read(
                '[[policy]]\nkind = "forbid-capability"\ncapability = "Unsafe"\n'
            )

    def test_exclusion_needs_two_capabilities(self):
        with self.assertRaises(PolicyError) as cm:
            self._read(
                '[[policy]]\nkind = "exclusion"\ncapabilities = ["Net"]\n'
            )
        self.assertIn("at least two", str(cm.exception))

    def test_forbid_dependency_requires_both(self):
        with self.assertRaises(PolicyError):
            self._read(
                '[[policy]]\nkind = "forbid-dependency"\npackage = "a"\n'
            )

    def test_over_must_be_valid(self):
        with self.assertRaises(PolicyError):
            self._read(
                '[[policy]]\nkind = "exclusion"\n'
                'capabilities = ["Net", "Fs"]\nover = "sideways"\n'
            )

    def test_malformed_capabilities_type(self):
        with self.assertRaises(PolicyError):
            self._read(
                '[[policy]]\nkind = "product-subset"\nmax = "Net"\n'
            )

    def test_allow_unknown_must_be_bool(self):
        with self.assertRaises(PolicyError):
            self._read(
                '[[policy]]\nkind = "purity"\nallow_unknown = "yes"\n'
            )

    def test_policy_array_must_be_tables(self):
        with self.assertRaises(PolicyError):
            self._read('policy = [1, 2]\n')

    def test_duplicate_ids_rejected(self):
        # S1: policy ids identify results in the signed conformance report;
        # a duplicate would let tooling de-dupe and silently drop a result.
        with self.assertRaises(PolicyError) as cm:
            self._read(
                '[[policy]]\nid = "dup"\nkind = "purity"\n\n'
                '[[policy]]\nid = "dup"\nkind = "no-unresolved-dependencies"\n'
            )
        self.assertIn("dup", str(cm.exception))
        self.assertIn("duplicate", str(cm.exception).lower())

    def test_explicit_id_colliding_with_default_rejected(self):
        # An explicit id that collides with the "<kind>#<index>" default of
        # another entry is also caught.
        with self.assertRaises(PolicyError):
            self._read(
                '[[policy]]\nkind = "purity"\n\n'
                '[[policy]]\nid = "purity#0"\nkind = "purity"\npackage = "x"\n'
            )

    # Feature #6 (P2): declassification-aware kinds parse strictly too.

    def test_no_declassification_parses(self):
        pols = self._read(
            '[[policy]]\nkind = "no-declassification"\npackage = "a"\n'
        )
        self.assertEqual(pols[0].kind, "no-declassification")
        self.assertEqual(pols[0].params["package"], "a")

    def test_no_declassification_package_optional(self):
        pols = self._read('[[policy]]\nkind = "no-declassification"\n')
        self.assertIsNone(pols[0].params["package"])

    def test_no_declassification_unknown_key_rejected(self):
        with self.assertRaises(PolicyError) as cm:
            self._read(
                '[[policy]]\nkind = "no-declassification"\nbogus = 1\n'
            )
        self.assertIn("bogus", str(cm.exception))

    def test_no_secret_egress_parses(self):
        pols = self._read(
            '[[policy]]\nkind = "no-secret-egress"\ncapabilities = ["Net"]\n'
        )
        self.assertEqual(pols[0].kind, "no-secret-egress")
        self.assertEqual(pols[0].params["capabilities"], ["Net"])
        self.assertIsNone(pols[0].params["package"])

    def test_no_secret_egress_unknown_key_rejected(self):
        with self.assertRaises(PolicyError) as cm:
            self._read(
                '[[policy]]\nkind = "no-secret-egress"\n'
                'capabilities = ["Net"]\nsink = "x"\n'
            )
        self.assertIn("sink", str(cm.exception))

    def test_no_secret_egress_bad_capability_rejected(self):
        with self.assertRaises(PolicyError) as cm:
            self._read(
                '[[policy]]\nkind = "no-secret-egress"\n'
                'capabilities = ["Nett"]\n'
            )
        self.assertIn("Nett", str(cm.exception))

    def test_no_secret_egress_requires_capabilities(self):
        with self.assertRaises(PolicyError):
            self._read(
                '[[policy]]\nkind = "no-secret-egress"\npackage = "a"\n'
            )


# ---------------------------------------------------------------------------
# EXCLUSION
# ---------------------------------------------------------------------------


class TestExclusion(_TmpTree):
    def _tree(self, main_src: str, policy: str) -> Path:
        root = self.tmp / "app"
        _write(root, "capa.toml",
               '[package]\nname = "app"\nversion = "0.1.0"\n')
        _write(root, "main.capa", main_src)
        _write(root, "capa-policy.toml", policy)
        return root

    def test_package_holding_net_and_fs_fails(self):
        root = self._tree(
            "pub fun both(_n: Net, _fs: Fs) -> Unit\n    return\n",
            '[[policy]]\nid = "no-net-fs"\nkind = "exclusion"\n'
            'capabilities = ["Net", "Fs"]\n',
        )
        report, _ = _eval(root, "main.capa")
        r = _result(report, "no-net-fs")
        self.assertFalse(r["pass"])
        v = r["violations"][0]
        self.assertEqual(v["verdict"], "violation")
        self.assertEqual(v["package"], "app")
        self.assertIn("Fs", v["detail"])
        self.assertIn("Net", v["detail"])
        self.assertFalse(report["pass"])

    def test_no_package_holds_both_passes(self):
        # Two separate functions, but same package holds both -> still fails;
        # so put Fs behind a resolved dependency that only reaches Fs and Net
        # only in root. They are DIFFERENT packages, so neither holds both.
        root = self.tmp / "app"
        _write(root, "capa.toml", (
            '[package]\nname = "app"\nversion = "0.1.0"\n\n'
            '[dependencies.fslib]\n'
            'git = "https://github.com/example/fslib"\ntag = "v1"\n'
        ))
        _write(root, "main.capa",
               "import fslib.api\n\n"
               "pub fun run(_n: Net) -> Unit\n    go()\n    return\n")
        _write(root, "vendor/fslib/capa.toml",
               '[package]\nname = "fslib"\nversion = "0.1.0"\n')
        # ``store`` is linked (imported module) and attributes Fs to fslib
        # even though it is never called; ``go`` is the reachable no-arg entry.
        _write(root, "vendor/fslib/api.capa",
               "pub fun go() -> Unit\n    return\n"
               "pub fun store(_fs: Fs) -> Unit\n    return\n")
        _write(root, "capa-policy.toml",
               '[[policy]]\nid = "no-net-fs"\nkind = "exclusion"\n'
               'capabilities = ["Net", "Fs"]\nover = "attributed"\n')
        report, _ = _eval(root, "main.capa")
        # attributed: app has Net only, fslib has Fs only -> neither holds both.
        self.assertTrue(_result(report, "no-net-fs")["pass"])

    def test_scoped_exclusion_only_checks_named_package(self):
        root = self._tree(
            "pub fun both(_n: Net, _fs: Fs) -> Unit\n    return\n",
            '[[policy]]\nid = "scoped"\nkind = "exclusion"\n'
            'capabilities = ["Net", "Fs"]\nscope = "nonexistent"\n',
        )
        report, _ = _eval(root, "main.capa")
        r = _result(report, "scoped")
        # names a package not in the graph -> unsatisfiable (fail loud).
        self.assertFalse(r["pass"])
        self.assertEqual(r["violations"][0]["verdict"], "unsatisfiable")


# ---------------------------------------------------------------------------
# PRODUCT-SUBSET
# ---------------------------------------------------------------------------


class TestProductSubset(_TmpTree):
    def _gate(self, policy: str) -> Path:
        root = self.tmp / "gate"
        _write(root, "capa.toml",
               '[package]\nname = "gate"\nversion = "0.1.0"\n')
        _write(root, "main.capa", (
            "pub fun fetch(_n: Net) -> Unit\n    return\n"
            "pub fun store(_fs: Fs) -> Unit\n    return\n"
            "pub fun log(_io: Stdio) -> Unit\n    return\n"
        ))
        _write(root, "capa-policy.toml", policy)
        return root

    def test_tight_subset_fails_naming_fs(self):
        root = self._gate(
            '[[policy]]\nid = "sub"\nkind = "product-subset"\n'
            'max = ["Net", "Stdio"]\n'
        )
        report, _ = _eval(root, "main.capa")
        r = _result(report, "sub")
        self.assertFalse(r["pass"])
        fs = [v for v in r["violations"] if v["capability"] == "Fs"]
        self.assertEqual(len(fs), 1)
        self.assertEqual(fs[0]["verdict"], "violation")
        self.assertEqual(fs[0]["package"], "gate")
        self.assertIn("Fs", fs[0]["detail"])

    def test_covering_subset_passes(self):
        root = self._gate(
            '[[policy]]\nid = "sub"\nkind = "product-subset"\n'
            'max = ["Net", "Fs", "Stdio"]\n'
        )
        report, _ = _eval(root, "main.capa")
        self.assertTrue(_result(report, "sub")["pass"])


# ---------------------------------------------------------------------------
# PURITY
# ---------------------------------------------------------------------------


class TestPurity(_TmpTree):
    def test_pure_leaf_passes(self):
        root = self.tmp / "pure"
        _write(root, "capa.toml",
               '[package]\nname = "pure"\nversion = "0.1.0"\n')
        _write(root, "main.capa",
               "pub fun add(a: Int, b: Int) -> Int\n    return a + b\n")
        _write(root, "capa-policy.toml",
               '[[policy]]\nid = "pure"\nkind = "purity"\n')
        report, _ = _eval(root, "main.capa")
        self.assertTrue(_result(report, "pure")["pass"])

    def test_cap_bearing_package_fails(self):
        root = self.tmp / "impure"
        _write(root, "capa.toml",
               '[package]\nname = "impure"\nversion = "0.1.0"\n')
        _write(root, "main.capa",
               "pub fun run(_n: Net) -> Unit\n    return\n")
        _write(root, "capa-policy.toml",
               '[[policy]]\nid = "pure"\nkind = "purity"\npackage = "impure"\n')
        report, _ = _eval(root, "main.capa")
        r = _result(report, "pure")
        self.assertFalse(r["pass"])
        self.assertEqual(r["violations"][0]["capability"], "Net")
        self.assertEqual(r["violations"][0]["verdict"], "violation")

    def test_named_missing_package_unsatisfiable(self):
        root = self.tmp / "p"
        _write(root, "capa.toml", '[package]\nname = "p"\nversion = "0.1.0"\n')
        _write(root, "main.capa", "pub fun f() -> Unit\n    return\n")
        _write(root, "capa-policy.toml",
               '[[policy]]\nid = "pure"\nkind = "purity"\npackage = "ghost"\n')
        report, _ = _eval(root, "main.capa")
        r = _result(report, "pure")
        self.assertFalse(r["pass"])
        self.assertEqual(r["violations"][0]["verdict"], "unsatisfiable")


# ---------------------------------------------------------------------------
# FORBID-CAPABILITY
# ---------------------------------------------------------------------------


class TestForbidCapability(_TmpTree):
    def test_forbidden_capability_flagged(self):
        root = self.tmp / "app"
        _write(root, "capa.toml", '[package]\nname = "app"\nversion = "0.1.0"\n')
        _write(root, "main.capa", "pub fun run(_n: Net) -> Unit\n    return\n")
        _write(root, "capa-policy.toml",
               '[[policy]]\nid = "no-net"\nkind = "forbid-capability"\n'
               'capability = "Net"\n')
        report, _ = _eval(root, "main.capa")
        r = _result(report, "no-net")
        self.assertFalse(r["pass"])
        self.assertEqual(r["violations"][0]["capability"], "Net")
        self.assertEqual(r["violations"][0]["package"], "app")

    def test_compliant_product_passes(self):
        root = self.tmp / "app"
        _write(root, "capa.toml", '[package]\nname = "app"\nversion = "0.1.0"\n')
        _write(root, "main.capa", "pub fun run(_fs: Fs) -> Unit\n    return\n")
        _write(root, "capa-policy.toml",
               '[[policy]]\nid = "no-net"\nkind = "forbid-capability"\n'
               'capability = "Net"\n')
        report, _ = _eval(root, "main.capa")
        self.assertTrue(_result(report, "no-net")["pass"])


# ---------------------------------------------------------------------------
# FORBID-DEPENDENCY
# ---------------------------------------------------------------------------


class TestForbidDependency(_TmpTree):
    def _tree(self, policy: str) -> Path:
        root = self.tmp / "app"
        _write(root, "capa.toml", (
            '[package]\nname = "app"\nversion = "0.1.0"\n\n'
            '[dependencies.mid]\n'
            'git = "https://github.com/example/mid"\ntag = "v1"\n'
        ))
        _write(root, "main.capa",
               "import mid.api\n\npub fun run() -> Unit\n    go()\n    return\n")
        _write(root, "vendor/mid/capa.toml",
               '[package]\nname = "mid"\nversion = "0.1.0"\n')
        _write(root, "vendor/mid/api.capa",
               "pub fun go() -> Unit\n    return\n")
        _write(root, "capa-policy.toml", policy)
        return root

    def test_direct_dependency_flagged(self):
        root = self._tree(
            '[[policy]]\nid = "no-mid"\nkind = "forbid-dependency"\n'
            'package = "app"\nforbidden = "mid"\n'
        )
        report, _ = _eval(root, "main.capa")
        r = _result(report, "no-mid")
        self.assertFalse(r["pass"])
        v = r["violations"][0]
        self.assertEqual(v["verdict"], "violation")
        self.assertEqual(v["package"], "app")
        self.assertEqual(v["path"], ["app", "mid"])

    def test_non_dependency_passes(self):
        # mid is a real package in the graph but genuinely does NOT depend
        # on app (the edge runs the other way): a true negative that still
        # names a present target, so it is not a typo (W2).
        root = self._tree(
            '[[policy]]\nid = "mid-not-app"\nkind = "forbid-dependency"\n'
            'package = "mid"\nforbidden = "app"\n'
        )
        report, _ = _eval(root, "main.capa")
        self.assertTrue(_result(report, "mid-not-app")["pass"])

    def test_typo_forbidden_target_is_unsatisfiable(self):
        # A misspelled `forbidden` matches no package / edge name -> loud
        # unsatisfiable, never a silent pass (W2).
        root = self._tree(
            '[[policy]]\nid = "typo"\nkind = "forbid-dependency"\n'
            'package = "app"\nforbidden = "nosuchpkg"\n'
        )
        report, _ = _eval(root, "main.capa")
        r = _result(report, "typo")
        self.assertFalse(r["pass"])
        self.assertEqual(r["violations"][0]["verdict"], "unsatisfiable")

    def test_forbidden_unresolved_edge_name_is_allowed_target(self):
        # `forbidden` naming an unresolved / native dependency edge (a real
        # declared edge name, not a typo) is a valid target: app2 declares
        # `netdep` which is unresolved, and app2 does depend on it -> fires.
        root = self.tmp / "app2"
        _write(root, "capa.toml", (
            '[package]\nname = "app2"\nversion = "0.1.0"\n\n'
            '[dependencies.netdep]\n'
            'git = "https://github.com/example/netdep"\ntag = "v1"\n'
        ))
        _write(root, "main.capa", "pub fun f() -> Unit\n    return\n")
        _write(root, "capa-policy.toml",
               '[[policy]]\nid = "no-netdep"\nkind = "forbid-dependency"\n'
               'package = "app2"\nforbidden = "netdep"\n')
        report, _ = _eval(root, "main.capa")
        r = _result(report, "no-netdep")
        self.assertFalse(r["pass"])
        self.assertEqual(r["violations"][0]["verdict"], "violation")

    def test_missing_source_package_unsatisfiable(self):
        root = self._tree(
            '[[policy]]\nid = "x"\nkind = "forbid-dependency"\n'
            'package = "ghost"\nforbidden = "mid"\n'
        )
        report, _ = _eval(root, "main.capa")
        r = _result(report, "x")
        self.assertFalse(r["pass"])
        self.assertEqual(r["violations"][0]["verdict"], "unsatisfiable")


# ---------------------------------------------------------------------------
# NO-UNRESOLVED-DEPENDENCIES
# ---------------------------------------------------------------------------


class TestNoUnresolved(_TmpTree):
    def test_unresolved_dependency_flagged(self):
        root = self.tmp / "app"
        _write(root, "capa.toml", (
            '[package]\nname = "app"\nversion = "0.1.0"\n\n'
            '[dependencies.ghost]\n'
            'git = "https://github.com/example/ghost"\ntag = "v1"\n'
        ))
        _write(root, "main.capa", "pub fun f() -> Unit\n    return\n")
        _write(root, "capa-policy.toml",
               '[[policy]]\nid = "resolved"\n'
               'kind = "no-unresolved-dependencies"\n')
        report, _ = _eval(root, "main.capa")
        r = _result(report, "resolved")
        self.assertFalse(r["pass"])
        v = r["violations"][0]
        self.assertEqual(v["verdict"], "violation")
        self.assertEqual(v["package"], "app")
        self.assertIn("ghost", v["detail"])

    def test_fully_resolved_product_passes(self):
        root = self.tmp / "app"
        _write(root, "capa.toml", '[package]\nname = "app"\nversion = "0.1.0"\n')
        _write(root, "main.capa", "pub fun f() -> Unit\n    return\n")
        _write(root, "capa-policy.toml",
               '[[policy]]\nid = "resolved"\n'
               'kind = "no-unresolved-dependencies"\n')
        report, _ = _eval(root, "main.capa")
        self.assertTrue(_result(report, "resolved")["pass"])


# ---------------------------------------------------------------------------
# FAIL-CLOSED ON AUTHORITY-UNKNOWN
# ---------------------------------------------------------------------------


class TestFailClosed(_TmpTree):
    def _ghost_tree(self, policy: str) -> Path:
        root = self.tmp / "prod"
        _write(root, "capa.toml", (
            '[package]\nname = "prod"\nversion = "0.1.0"\n\n'
            '[dependencies.ghost]\n'
            'git = "https://github.com/example/ghost"\ntag = "v1"\n'
        ))
        _write(root, "main.capa",
               "pub fun add(a: Int, b: Int) -> Int\n    return a + b\n")
        _write(root, "capa-policy.toml", policy)
        return root

    def test_purity_over_top_subtree_fails_closed(self):
        root = self._ghost_tree(
            '[[policy]]\nid = "pure"\nkind = "purity"\npackage = "prod"\n'
        )
        report, _ = _eval(root, "main.capa")
        r = _result(report, "pure")
        self.assertFalse(r["pass"])
        verdicts = {v["verdict"] for v in r["violations"]}
        self.assertIn("authority_unknown", verdicts)
        self.assertNotIn("violation", verdicts)
        v = next(v for v in r["violations"]
                 if v["verdict"] == "authority_unknown")
        self.assertIn("UNKNOWN", v["detail"])

    def test_allow_unknown_waives_the_top_failure(self):
        root = self._ghost_tree(
            '[[policy]]\nid = "pure"\nkind = "purity"\npackage = "prod"\n'
            'allow_unknown = true\n'
        )
        report, _ = _eval(root, "main.capa")
        self.assertTrue(_result(report, "pure")["pass"])

    def test_product_subset_over_top_fails_closed(self):
        root = self._ghost_tree(
            '[[policy]]\nid = "sub"\nkind = "product-subset"\nmax = ["Fs"]\n'
        )
        report, _ = _eval(root, "main.capa")
        r = _result(report, "sub")
        self.assertFalse(r["pass"])
        self.assertTrue(any(v["verdict"] == "authority_unknown"
                            for v in r["violations"]))

    def test_forbid_capability_over_top_fails_closed(self):
        root = self._ghost_tree(
            '[[policy]]\nid = "no-net"\nkind = "forbid-capability"\n'
            'capability = "Net"\n'
        )
        report, _ = _eval(root, "main.capa")
        r = _result(report, "no-net")
        self.assertFalse(r["pass"])
        self.assertTrue(any(v["verdict"] == "authority_unknown"
                            for v in r["violations"]))

    def test_native_dep_fails_closed(self):
        root = self.tmp / "prod"
        _write(root, "capa.toml", (
            '[package]\nname = "prod"\nversion = "0.1.0"\n\n'
            '[dependencies.native]\n'
            'git = "https://github.com/example/native"\ntag = "v1"\n'
        ))
        _write(root, "main.capa", "pub fun f() -> Unit\n    return\n")
        _write(root, "vendor/native/capa.toml",
               '[package]\nname = "native"\nversion = "1.0.0"\n')
        _write(root, "vendor/native/lib.rs", "// not capa\n")
        _write(root, "capa-policy.toml",
               '[[policy]]\nid = "pure"\nkind = "purity"\n')
        report, _ = _eval(root, "main.capa")
        r = _result(report, "pure")
        self.assertFalse(r["pass"])
        self.assertTrue(any(v["verdict"] == "authority_unknown"
                            for v in r["violations"]))

    def test_unsafe_crossing_fails_closed(self):
        root = self.tmp / "prod"
        _write(root, "capa.toml", '[package]\nname = "prod"\nversion = "0.1.0"\n')
        _write(root, "main.capa",
               "pub fun risky(_u: Unsafe) -> Unit\n    return\n")
        _write(root, "capa-policy.toml",
               '[[policy]]\nid = "pure"\nkind = "purity"\n')
        report, _ = _eval(root, "main.capa")
        r = _result(report, "pure")
        self.assertFalse(r["pass"])
        self.assertTrue(any(v["verdict"] == "authority_unknown"
                            for v in r["violations"]))

    def test_forbid_dependency_over_unresolved_closure_fails_closed(self):
        # app -> mid (resolved) -> ghost (UNRESOLVED); app -> other
        # (resolved) -> secret (UNRESOLVED). "secret" is a real declared
        # edge name in the graph (so it is a valid target, not a typo, W2)
        # but is NOT reachable from mid over resolved edges. Because mid's
        # closure contains an unresolved edge (ghost), a hidden path from
        # mid to secret cannot be ruled out -> fail closed.
        root = self.tmp / "app"
        _write(root, "capa.toml", (
            '[package]\nname = "app"\nversion = "0.1.0"\n\n'
            '[dependencies.mid]\n'
            'git = "https://github.com/example/mid"\ntag = "v1"\n\n'
            '[dependencies.other]\n'
            'git = "https://github.com/example/other"\ntag = "v1"\n'
        ))
        _write(root, "main.capa",
               "import mid.api\nimport other.lib\n\n"
               "pub fun run() -> Unit\n    go()\n    doit()\n    return\n")
        _write(root, "vendor/mid/capa.toml", (
            '[package]\nname = "mid"\nversion = "0.1.0"\n\n'
            '[dependencies.ghost]\n'
            'git = "https://github.com/example/ghost"\ntag = "v1"\n'
        ))
        _write(root, "vendor/mid/api.capa", "pub fun go() -> Unit\n    return\n")
        _write(root, "vendor/other/capa.toml", (
            '[package]\nname = "other"\nversion = "0.1.0"\n\n'
            '[dependencies.secret]\n'
            'git = "https://github.com/example/secret"\ntag = "v1"\n'
        ))
        _write(root, "vendor/other/lib.capa",
               "pub fun doit() -> Unit\n    return\n")
        _write(root, "capa-policy.toml",
               '[[policy]]\nid = "x"\nkind = "forbid-dependency"\n'
               'package = "mid"\nforbidden = "secret"\nallow_unknown = false\n')
        report, _ = _eval(root, "main.capa")
        r = _result(report, "x")
        self.assertFalse(r["pass"])
        self.assertEqual(r["violations"][0]["verdict"], "authority_unknown")

    def test_allow_unknown_still_flags_a_concrete_violation(self):
        # allow_unknown waives ONLY the TOP failure; a positively observed
        # capability still fails a forbid-capability policy.
        root = self.tmp / "prod"
        _write(root, "capa.toml", (
            '[package]\nname = "prod"\nversion = "0.1.0"\n\n'
            '[dependencies.ghost]\n'
            'git = "https://github.com/example/ghost"\ntag = "v1"\n'
        ))
        _write(root, "main.capa", "pub fun run(_n: Net) -> Unit\n    return\n")
        _write(root, "capa-policy.toml",
               '[[policy]]\nid = "no-net"\nkind = "forbid-capability"\n'
               'capability = "Net"\nallow_unknown = true\n')
        report, _ = _eval(root, "main.capa")
        r = _result(report, "no-net")
        self.assertFalse(r["pass"])
        verdicts = {v["verdict"] for v in r["violations"]}
        self.assertIn("violation", verdicts)
        self.assertNotIn("authority_unknown", verdicts)


# ---------------------------------------------------------------------------
# HARDENING: fail-closed must not depend on a downstream field (W1)
# ---------------------------------------------------------------------------


class TestFailClosedRobustness(unittest.TestCase):
    """evaluate_policies is a public API accepting ANY composed dict (incl.
    from an older / foreign producer). A product marked authority_unknown
    must FAIL CLOSED even when the reasons list is empty - never PASS."""

    def _policy(self, text: str):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "capa-policy.toml"
            p.write_text(text, encoding="utf-8")
            return read_policy_file(p)

    def test_product_subset_fails_closed_with_empty_reasons(self):
        composed = {
            "product": {"name": "prod", "version": "0.1.0"},
            "packages": [],
            "edges": [],
            "unresolved_dependencies": [],
            "composed": {
                "capabilities": [],
                # TOP is set, but the reasons list is EMPTY (a malformed /
                # foreign producer): the fail-closed must still fire.
                "authority_unknown": True,
                "authority_unknown_reasons": [],
            },
        }
        pols = self._policy(
            '[[policy]]\nid = "sub"\nkind = "product-subset"\nmax = ["Net"]\n'
        )
        report = evaluate_policies(composed, pols)
        r = report["results"][0]
        self.assertFalse(r["pass"])
        self.assertFalse(report["pass"])
        self.assertEqual(r["violations"][0]["verdict"], "authority_unknown")

    def test_product_subset_empty_reasons_waived_by_allow_unknown(self):
        composed = {
            "product": {"name": "prod", "version": "0.1.0"},
            "packages": [],
            "edges": [],
            "unresolved_dependencies": [],
            "composed": {
                "capabilities": [],
                "authority_unknown": True,
                "authority_unknown_reasons": [],
            },
        }
        pols = self._policy(
            '[[policy]]\nid = "sub"\nkind = "product-subset"\nmax = ["Net"]\n'
            'allow_unknown = true\n'
        )
        report = evaluate_policies(composed, pols)
        self.assertTrue(report["pass"])


# ---------------------------------------------------------------------------
# EVIDENCE: canonical / byte-reproducible report
# ---------------------------------------------------------------------------


class TestConformanceEvidence(_TmpTree):
    def _tree(self) -> Path:
        root = self.tmp / "app"
        _write(root, "capa.toml", '[package]\nname = "app"\nversion = "0.1.0"\n')
        _write(root, "main.capa", (
            "pub fun fetch(_n: Net) -> Unit\n    return\n"
            "pub fun store(_fs: Fs) -> Unit\n    return\n"
        ))
        _write(root, "capa-policy.toml", (
            '[[policy]]\nid = "sub"\nkind = "product-subset"\nmax = ["Net"]\n\n'
            '[[policy]]\nid = "no-net-fs"\nkind = "exclusion"\n'
            'capabilities = ["Net", "Fs"]\n'
        ))
        return root

    def test_report_is_byte_reproducible(self):
        root = self._tree()
        r1, _ = _eval(root, "main.capa")
        r2, _ = _eval(root, "main.capa")
        b1 = canonical_json(canonical_manifest(r1))
        b2 = canonical_json(canonical_manifest(r2))
        self.assertEqual(b1, b2)

    def test_report_has_schema_and_pass(self):
        root = self._tree()
        report, _ = _eval(root, "main.capa")
        self.assertEqual(report["policy_schema_version"], 1)
        self.assertEqual(report["product"]["name"], "app")
        self.assertFalse(report["pass"])
        self.assertEqual(len(report["results"]), 2)

    def test_canonical_envelope_digest_stable(self):
        root = self._tree()
        report, _ = _eval(root, "main.capa")
        wrapped = canonical_manifest(report)
        self.assertIn("content_integrity", wrapped)
        self.assertIsNotNone(
            wrapped["content_integrity"]["digest"]["value"]
        )
        # Signature slot is empty (compiler holds no keys).
        self.assertIsNone(wrapped["content_integrity"]["signature"]["value"])


# ---------------------------------------------------------------------------
# CLI GATE: --check-policies and --conformance-report
# ---------------------------------------------------------------------------


class TestCheckPoliciesCli(_TmpTree):
    def _run(self, root: Path, root_file: str, *flags: str):
        from capa.cli import main
        out, err = io.StringIO(), io.StringIO()
        argv = ["capa", *flags, str(root / root_file)]
        with mock.patch.object(sys, "argv", argv), \
                mock.patch.object(sys, "stdout", out), \
                mock.patch.object(sys, "stderr", err), \
                mock.patch.dict(os.environ, {"NO_COLOR": "1"}, clear=False):
            try:
                rc = main()
            except SystemExit as e:
                rc = e.code if isinstance(e.code, int) else (
                    0 if e.code is None else 1
                )
        return rc, out.getvalue(), err.getvalue()

    def test_clean_product_exits_zero(self):
        root = self.tmp / "gate"
        _write(root, "capa.toml", '[package]\nname = "gate"\nversion = "0.1.0"\n')
        _write(root, "main.capa", "pub fun fetch(_n: Net) -> Unit\n    return\n")
        _write(root, "capa-policy.toml",
               '[[policy]]\nid = "sub"\nkind = "product-subset"\nmax = ["Net"]\n')
        rc, _out, err = self._run(root, "main.capa", "--check-policies")
        self.assertEqual(rc, 0)
        self.assertIn("OK", err)

    def test_violation_exits_nonzero_with_detail(self):
        root = self.tmp / "gate"
        _write(root, "capa.toml", '[package]\nname = "gate"\nversion = "0.1.0"\n')
        _write(root, "main.capa", "pub fun fetch(_n: Net) -> Unit\n    return\n")
        _write(root, "capa-policy.toml",
               '[[policy]]\nid = "no-net"\nkind = "forbid-capability"\n'
               'capability = "Net"\n')
        rc, _out, err = self._run(root, "main.capa", "--check-policies")
        self.assertNotEqual(rc, 0)
        self.assertIn("FAILED", err)
        self.assertIn("Net", err)

    def test_top_subtree_gate_exits_nonzero(self):
        root = self.tmp / "prod"
        _write(root, "capa.toml", (
            '[package]\nname = "prod"\nversion = "0.1.0"\n\n'
            '[dependencies.ghost]\n'
            'git = "https://github.com/example/ghost"\ntag = "v1"\n'
        ))
        _write(root, "main.capa", "pub fun f() -> Unit\n    return\n")
        _write(root, "capa-policy.toml",
               '[[policy]]\nid = "pure"\nkind = "purity"\n')
        rc, _out, err = self._run(root, "main.capa", "--check-policies")
        self.assertNotEqual(rc, 0)
        self.assertIn("authority_unknown", err)

    def test_no_policy_file_exits_zero(self):
        root = self.tmp / "prod"
        _write(root, "capa.toml", '[package]\nname = "prod"\nversion = "0.1.0"\n')
        _write(root, "main.capa", "pub fun run(_n: Net) -> Unit\n    return\n")
        rc, _out, err = self._run(root, "main.capa", "--check-policies")
        self.assertEqual(rc, 0)
        self.assertIn("nothing to verify", err)

    def test_bad_policy_file_exits_one(self):
        root = self.tmp / "prod"
        _write(root, "capa.toml", '[package]\nname = "prod"\nversion = "0.1.0"\n')
        _write(root, "main.capa", "pub fun f() -> Unit\n    return\n")
        _write(root, "capa-policy.toml", '[[policy]]\nkind = "teleport"\n')
        rc, _out, err = self._run(root, "main.capa", "--check-policies")
        self.assertEqual(rc, 1)
        self.assertIn("teleport", err)

    def test_conformance_report_emits_canonical_artifact(self):
        root = self.tmp / "gate"
        _write(root, "capa.toml", '[package]\nname = "gate"\nversion = "0.1.0"\n')
        _write(root, "main.capa", "pub fun fetch(_n: Net) -> Unit\n    return\n")
        _write(root, "capa-policy.toml",
               '[[policy]]\nid = "no-net"\nkind = "forbid-capability"\n'
               'capability = "Net"\n')
        rc, out, _err = self._run(root, "main.capa", "--conformance-report")
        self.assertEqual(rc, 0)
        import json
        doc = json.loads(out)
        self.assertIn("content_integrity", doc)
        self.assertFalse(doc["pass"])
        self.assertEqual(doc["results"][0]["policy"], "no-net")

    def test_conformance_report_reproducible_across_runs(self):
        root = self.tmp / "gate"
        _write(root, "capa.toml", '[package]\nname = "gate"\nversion = "0.1.0"\n')
        _write(root, "main.capa", "pub fun fetch(_n: Net) -> Unit\n    return\n")
        _write(root, "capa-policy.toml",
               '[[policy]]\nid = "sub"\nkind = "product-subset"\nmax = ["Fs"]\n')
        _rc1, out1, _ = self._run(root, "main.capa", "--conformance-report")
        _rc2, out2, _ = self._run(root, "main.capa", "--conformance-report")
        self.assertEqual(out1, out2)


# ---------------------------------------------------------------------------
# NO-DECLASSIFICATION (feature #6, P2)
# ---------------------------------------------------------------------------


# A function that audibly declassifies a @secret value to a public sink.
_DISCLOSE = (
    "pub fun handler(token: @secret String, stdio: Stdio) -> Unit\n"
    "    stdio.println(declassify(token, reason: \"audit\"))\n"
    "    return\n"
)
_CLEAN = "pub fun add(a: Int, b: Int) -> Int\n    return a + b\n"


class TestNoDeclassification(_TmpTree):
    def _tree(self, main_src: str, policy: str) -> Path:
        root = self.tmp / "app"
        _write(root, "capa.toml", '[package]\nname = "app"\nversion = "0.1.0"\n')
        _write(root, "main.capa", main_src)
        _write(root, "capa-policy.toml", policy)
        return root

    def _ghost_tree(self, policy: str) -> Path:
        # prod is analyzable but declares an unresolvable dependency, so its
        # composed authority is TOP (composed_authority_unknown).
        root = self.tmp / "prod"
        _write(root, "capa.toml", (
            '[package]\nname = "prod"\nversion = "0.1.0"\n\n'
            '[dependencies.ghost]\n'
            'git = "https://github.com/example/ghost"\ntag = "v1"\n'
        ))
        _write(root, "main.capa", _CLEAN)
        _write(root, "capa-policy.toml", policy)
        return root

    def test_clean_package_passes(self):
        root = self._tree(
            _CLEAN,
            '[[policy]]\nid = "nd"\nkind = "no-declassification"\n'
            'package = "app"\n',
        )
        report, _ = _eval(root, "main.capa")
        self.assertTrue(_result(report, "nd")["pass"])

    def test_declassifying_package_violation(self):
        root = self._tree(
            _DISCLOSE,
            '[[policy]]\nid = "nd"\nkind = "no-declassification"\n'
            'package = "app"\n',
        )
        report, _ = _eval(root, "main.capa")
        r = _result(report, "nd")
        self.assertFalse(r["pass"])
        v = r["violations"][0]
        self.assertEqual(v["verdict"], "violation")
        self.assertEqual(v["package"], "app")
        self.assertIn("declassification", v["detail"])

    def test_product_wide_violation_when_product_declassifies(self):
        root = self._tree(
            _DISCLOSE,
            '[[policy]]\nid = "nd"\nkind = "no-declassification"\n',
        )
        report, _ = _eval(root, "main.capa")
        r = _result(report, "nd")
        self.assertFalse(r["pass"])
        v = r["violations"][0]
        self.assertEqual(v["verdict"], "violation")
        self.assertIsNone(v["package"])

    def test_product_wide_clean_passes(self):
        root = self._tree(
            _CLEAN,
            '[[policy]]\nid = "nd"\nkind = "no-declassification"\n',
        )
        report, _ = _eval(root, "main.capa")
        self.assertTrue(_result(report, "nd")["pass"])

    def test_missing_named_package_unsatisfiable(self):
        root = self._tree(
            _CLEAN,
            '[[policy]]\nid = "nd"\nkind = "no-declassification"\n'
            'package = "ghost"\n',
        )
        report, _ = _eval(root, "main.capa")
        r = _result(report, "nd")
        self.assertFalse(r["pass"])
        self.assertEqual(r["violations"][0]["verdict"], "unsatisfiable")

    def test_top_package_fails_closed(self):
        root = self._ghost_tree(
            '[[policy]]\nid = "nd"\nkind = "no-declassification"\n'
            'package = "prod"\n',
        )
        report, _ = _eval(root, "main.capa")
        r = _result(report, "nd")
        self.assertFalse(r["pass"])
        self.assertEqual(r["violations"][0]["verdict"], "authority_unknown")

    def test_top_package_waived_by_allow_unknown(self):
        root = self._ghost_tree(
            '[[policy]]\nid = "nd"\nkind = "no-declassification"\n'
            'package = "prod"\nallow_unknown = true\n',
        )
        report, _ = _eval(root, "main.capa")
        self.assertTrue(_result(report, "nd")["pass"])

    def test_top_product_wide_fails_closed(self):
        root = self._ghost_tree(
            '[[policy]]\nid = "nd"\nkind = "no-declassification"\n',
        )
        report, _ = _eval(root, "main.capa")
        r = _result(report, "nd")
        self.assertFalse(r["pass"])
        self.assertEqual(r["violations"][0]["verdict"], "authority_unknown")


# ---------------------------------------------------------------------------
# NO-SECRET-EGRESS (feature #6, P2)
# ---------------------------------------------------------------------------


class TestNoSecretEgress(_TmpTree):
    # BOTH declassifies AND holds an egress capability (Net) in one package.
    _BOTH = (
        "pub fun leak(token: @secret String, _net: Net, stdio: Stdio) -> Unit\n"
        "    stdio.println(declassify(token, reason: \"send\"))\n"
        "    return\n"
    )
    # Declassifies but holds no egress capability (Stdio only).
    _DISC_ONLY = _DISCLOSE
    # Holds Net but declassifies nothing.
    _NET_ONLY = "pub fun send(_net: Net) -> Unit\n    return\n"

    def _tree(self, main_src: str, policy: str) -> Path:
        root = self.tmp / "app"
        _write(root, "capa.toml", '[package]\nname = "app"\nversion = "0.1.0"\n')
        _write(root, "main.capa", main_src)
        _write(root, "capa-policy.toml", policy)
        return root

    def _ghost_tree(self, policy: str) -> Path:
        root = self.tmp / "prod"
        _write(root, "capa.toml", (
            '[package]\nname = "prod"\nversion = "0.1.0"\n\n'
            '[dependencies.ghost]\n'
            'git = "https://github.com/example/ghost"\ntag = "v1"\n'
        ))
        _write(root, "main.capa", _CLEAN)
        _write(root, "capa-policy.toml", policy)
        return root

    def test_declassify_and_egress_violation(self):
        root = self._tree(
            self._BOTH,
            '[[policy]]\nid = "nse"\nkind = "no-secret-egress"\n'
            'capabilities = ["Net"]\n',
        )
        report, _ = _eval(root, "main.capa")
        r = _result(report, "nse")
        self.assertFalse(r["pass"])
        v = r["violations"][0]
        self.assertEqual(v["verdict"], "violation")
        self.assertEqual(v["package"], "app")
        self.assertIn("Net", v["detail"])
        self.assertIn("exfiltration", v["detail"])

    def test_declassify_without_egress_passes(self):
        root = self._tree(
            self._DISC_ONLY,
            '[[policy]]\nid = "nse"\nkind = "no-secret-egress"\n'
            'capabilities = ["Net"]\n',
        )
        report, _ = _eval(root, "main.capa")
        self.assertTrue(_result(report, "nse")["pass"])

    def test_egress_without_declassify_passes(self):
        root = self._tree(
            self._NET_ONLY,
            '[[policy]]\nid = "nse"\nkind = "no-secret-egress"\n'
            'capabilities = ["Net"]\n',
        )
        report, _ = _eval(root, "main.capa")
        self.assertTrue(_result(report, "nse")["pass"])

    def _orchestrator_tree(self, policy: str) -> Path:
        # Separation-of-duties product (feature #6, P2 dogfood F-1): an
        # orchestrator WIRES a declassifier dependency (unmasks, holds no
        # egress cap) and a networker dependency (holds Net, declassifies
        # nothing). The orchestrator's OWN code neither unmasks nor sends; it
        # only composes a transitive declassification (from redactor) AND an
        # egress cap (from sender) out of two DIFFERENT children. This is the
        # exact shape the policy is meant to REWARD, so it must PASS.
        root = self.tmp / "prod"
        _write(root, "capa.toml", (
            '[package]\nname = "prod"\nversion = "0.1.0"\n\n'
            '[dependencies.redactor]\n'
            'git = "https://github.com/example/redactor"\ntag = "v1"\n\n'
            '[dependencies.sender]\n'
            'git = "https://github.com/example/sender"\ntag = "v1"\n'
        ))
        _write(root, "main.capa",
               "import redactor.redact\nimport sender.send\n\n"
               "pub fun run() -> Unit\n    return\n")
        # redactor: declassifies in its OWN code, egress-free (Stdio only).
        _write(root, "vendor/redactor/capa.toml",
               '[package]\nname = "redactor"\nversion = "0.1.0"\n')
        _write(root, "vendor/redactor/redact.capa", _DISCLOSE)
        # sender: holds Net, declassifies nothing.
        _write(root, "vendor/sender/capa.toml",
               '[package]\nname = "sender"\nversion = "0.1.0"\n')
        _write(root, "vendor/sender/send.capa", self._NET_ONLY)
        _write(root, "capa-policy.toml", policy)
        return root

    def test_product_wide_orchestrator_wiring_passes(self):
        # F-1 regression: the product-wide form (no `package`) must NOT flag
        # the orchestrator that merely wires a separate declassifier and a
        # separate networker. The orchestrator composes both a transitive
        # declassification and Net, but its OWN declassification count is 0.
        root = self._orchestrator_tree(
            '[[policy]]\nid = "nse"\nkind = "no-secret-egress"\n'
            'capabilities = ["Net"]\n',
        )
        report, _ = _eval(root, "main.capa")
        r = _result(report, "nse")
        self.assertTrue(r["pass"], r["violations"])
        # And specifically: the orchestrator is not among any flagged package.
        self.assertEqual(r["violations"], [])

    def test_own_declassify_plus_wired_egress_still_violation(self):
        # The egress side stays COMPOSED: a package that unmasks in its OWN
        # code AND wires a networker child (so Net enters its composed reach)
        # is a real single-package unmask-and-send and must still fire.
        root = self.tmp / "leaker"
        _write(root, "capa.toml", (
            '[package]\nname = "leaker"\nversion = "0.1.0"\n\n'
            '[dependencies.sender]\n'
            'git = "https://github.com/example/sender"\ntag = "v1"\n'
        ))
        _write(root, "main.capa", "import sender.api\n\n" + _DISCLOSE)
        _write(root, "vendor/sender/capa.toml",
               '[package]\nname = "sender"\nversion = "0.1.0"\n')
        _write(root, "vendor/sender/api.capa", self._NET_ONLY)
        _write(root, "capa-policy.toml",
               '[[policy]]\nid = "nse"\nkind = "no-secret-egress"\n'
               'capabilities = ["Net"]\n')
        report, _ = _eval(root, "main.capa")
        r = _result(report, "nse")
        self.assertFalse(r["pass"])
        v = next(x for x in r["violations"] if x["package"] == "leaker")
        self.assertEqual(v["verdict"], "violation")
        self.assertIn("Net", v["detail"])

    def test_egress_set_is_explicit_no_hardcoded_default(self):
        # The package declassifies AND holds Net, but the DECLARED egress set
        # is [Fs]: no co-residence with the declared set -> passes. Confirms
        # the egress vocabulary is author-declared, not a hardcoded default.
        root = self._tree(
            self._BOTH,
            '[[policy]]\nid = "nse"\nkind = "no-secret-egress"\n'
            'capabilities = ["Fs"]\n',
        )
        report, _ = _eval(root, "main.capa")
        self.assertTrue(_result(report, "nse")["pass"])

    def test_scoped_to_named_package(self):
        root = self._tree(
            self._BOTH,
            '[[policy]]\nid = "nse"\nkind = "no-secret-egress"\n'
            'capabilities = ["Net"]\npackage = "app"\n',
        )
        report, _ = _eval(root, "main.capa")
        r = _result(report, "nse")
        self.assertFalse(r["pass"])
        self.assertEqual(r["violations"][0]["verdict"], "violation")

    def test_missing_named_package_unsatisfiable(self):
        root = self._tree(
            self._BOTH,
            '[[policy]]\nid = "nse"\nkind = "no-secret-egress"\n'
            'capabilities = ["Net"]\npackage = "ghost"\n',
        )
        report, _ = _eval(root, "main.capa")
        r = _result(report, "nse")
        self.assertFalse(r["pass"])
        self.assertEqual(r["violations"][0]["verdict"], "unsatisfiable")

    def test_top_package_fails_closed(self):
        root = self._ghost_tree(
            '[[policy]]\nid = "nse"\nkind = "no-secret-egress"\n'
            'capabilities = ["Net"]\npackage = "prod"\n',
        )
        report, _ = _eval(root, "main.capa")
        r = _result(report, "nse")
        self.assertFalse(r["pass"])
        self.assertEqual(r["violations"][0]["verdict"], "authority_unknown")

    def test_top_package_waived_by_allow_unknown(self):
        root = self._ghost_tree(
            '[[policy]]\nid = "nse"\nkind = "no-secret-egress"\n'
            'capabilities = ["Net"]\npackage = "prod"\nallow_unknown = true\n',
        )
        report, _ = _eval(root, "main.capa")
        self.assertTrue(_result(report, "nse")["pass"])


if __name__ == "__main__":
    unittest.main()
