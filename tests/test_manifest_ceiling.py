"""Tests for capability-ceiling conflict detection (composition S3).

S2 produced a composed product SBOM where each package carries a sound
``composed_capabilities`` set and an ``authority_unknown`` (TOP) flag. S3
lets a package DECLARE its intended ceiling (a ``capa.toml``
``[capabilities]`` section) and flags any violation introduced by its own
code or a transitive dependency - the "a transitive dep introduces Net
into a subgraph declared pure" check no scanner can do.

The acceptance rows from the S3 brief, in order:

- SCHEMA: a strict/closed ``[capabilities]`` block (``max`` / ``pure`` /
  ``allow_unknown``); an unknown key, an unknown capability name, or the
  ``pure = true`` + non-empty ``max`` conflict is a hard parse error.
- PASS: the ``capa_export_gate`` shape with ``max = [Net, Fs, Stdio]``
  passes (composed == ceiling).
- EXCEEDS: the same product tightened to drop ``Net`` fails, naming the
  offending capability and where it enters.
- PURE LEAF: a ``pure = true`` leaf with a Net-bearing transitive
  dependency fails, naming the offending dep edge.
- FAIL CLOSED: a declared-ceiling package with an unresolvable / native /
  Unsafe-crossing transitive dep (composed TOP) fails with the
  authority-unknown message, DISTINCT from an exceeds-by-capability
  failure; ``allow_unknown = true`` waives only that TOP failure.
- UNCONSTRAINED: a package with no ``[capabilities]`` section is not
  checked (no false violation).
- DETERMINISM: the violations list is deterministically ordered and the
  artifact stays byte-reproducible.
"""

import shutil
import tempfile
import unittest
from pathlib import Path

from capa import analyze
from capa.loader import ModuleLoader
from capa.manifest import build_composed_sbom, build_manifest, canonical_json
from capa.pkg import CapabilityCeiling, ManifestError, read_manifest


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


def _pkg(composed, name):
    for p in composed["packages"]:
        if p["name"] == name:
            return p
    raise AssertionError(f"no package {name!r}")


class _TmpTree(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="capa_ceiling_"))
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))

    def _read(self, toml_text: str):
        root = self.tmp / "p"
        _write(root, "capa.toml", toml_text)
        return read_manifest(root / "capa.toml")


class TestCeilingSchema(_TmpTree):
    """The ``[capabilities]`` block is strict/closed exactly like every
    other Capa manifest table."""

    def test_no_section_means_no_ceiling(self):
        m = self._read('[package]\nname = "p"\nversion = "0.1.0"\n')
        self.assertIsNone(m.capability_ceiling)

    def test_max_parses(self):
        m = self._read(
            '[package]\nname = "p"\nversion = "0.1.0"\n\n'
            '[capabilities]\nmax = ["Net", "Fs"]\n'
        )
        self.assertEqual(
            m.capability_ceiling, CapabilityCeiling(max=frozenset({"Net", "Fs"})),
        )

    def test_pure_is_sugar_for_empty_max(self):
        m = self._read(
            '[package]\nname = "p"\nversion = "0.1.0"\n\n'
            '[capabilities]\npure = true\n'
        )
        self.assertEqual(m.capability_ceiling.max, frozenset())

    def test_allow_unknown_parses(self):
        m = self._read(
            '[package]\nname = "p"\nversion = "0.1.0"\n\n'
            '[capabilities]\nmax = ["Fs"]\nallow_unknown = true\n'
        )
        self.assertTrue(m.capability_ceiling.allow_unknown)

    def test_unknown_key_rejected(self):
        with self.assertRaises(ManifestError) as cm:
            self._read(
                '[package]\nname = "p"\nversion = "0.1.0"\n\n'
                '[capabilities]\nmax = ["Fs"]\nmxa = ["Net"]\n'
            )
        self.assertIn("capabilities", str(cm.exception))

    def test_unknown_capability_name_rejected(self):
        with self.assertRaises(ManifestError) as cm:
            self._read(
                '[package]\nname = "p"\nversion = "0.1.0"\n\n'
                '[capabilities]\nmax = ["Net", "Bogus"]\n'
            )
        self.assertIn("Bogus", str(cm.exception))

    def test_unsafe_is_not_a_valid_ceiling_capability(self):
        # Unsafe composes as authority-unknown; it can never be a bounded
        # capability a ceiling permits.
        with self.assertRaises(ManifestError):
            self._read(
                '[package]\nname = "p"\nversion = "0.1.0"\n\n'
                '[capabilities]\nmax = ["Unsafe"]\n'
            )

    def test_pure_true_with_nonempty_max_conflicts(self):
        with self.assertRaises(ManifestError) as cm:
            self._read(
                '[package]\nname = "p"\nversion = "0.1.0"\n\n'
                '[capabilities]\npure = true\nmax = ["Net"]\n'
            )
        self.assertIn("conflict", str(cm.exception).lower())

    def test_empty_section_is_rejected(self):
        with self.assertRaises(ManifestError):
            self._read(
                '[package]\nname = "p"\nversion = "0.1.0"\n\n'
                '[capabilities]\nallow_unknown = true\n'
            )

    def test_max_must_be_list_of_strings(self):
        with self.assertRaises(ManifestError):
            self._read(
                '[package]\nname = "p"\nversion = "0.1.0"\n\n'
                '[capabilities]\nmax = "Net"\n'
            )

    def test_pure_must_be_bool(self):
        with self.assertRaises(ManifestError):
            self._read(
                '[package]\nname = "p"\nversion = "0.1.0"\n\n'
                '[capabilities]\npure = "yes"\n'
            )

    def test_pure_false_with_max_is_fine(self):
        m = self._read(
            '[package]\nname = "p"\nversion = "0.1.0"\n\n'
            '[capabilities]\npure = false\nmax = ["Fs"]\n'
        )
        self.assertEqual(m.capability_ceiling.max, frozenset({"Fs"}))


class TestExportGatePasses(_TmpTree):
    """The capa_export_gate surface {Net, Fs, Stdio}: a ceiling that
    equals the composed set PASSES."""

    def _gate(self, ceiling_block: str) -> Path:
        root = self.tmp / "export_gate"
        _write(root, "capa.toml", (
            '[package]\nname = "export_gate"\nversion = "0.1.0"\n\n'
            + ceiling_block
        ))
        _write(root, "main.capa", (
            "pub fun fetch(_n: Net) -> Unit\n    return\n"
            "pub fun store(_fs: Fs) -> Unit\n    return\n"
            "pub fun log(_io: Stdio) -> Unit\n    return\n"
        ))
        return root

    def test_ceiling_equal_to_composed_passes(self):
        root = self._gate('[capabilities]\nmax = ["Net", "Fs", "Stdio"]\n')
        composed = _compose(root, "main.capa")
        self.assertTrue(composed["capability_ceilings"]["pass"])
        self.assertTrue(composed["capability_ceilings"]["checked"])
        self.assertEqual(composed["capability_ceilings"]["violations"], [])
        p = _pkg(composed, "export_gate")
        self.assertEqual(p["declared_ceiling"], ["Fs", "Net", "Stdio"])
        self.assertEqual(p["ceiling_violations"], [])

    def test_ceiling_superset_of_composed_passes(self):
        # Declaring MORE than you use is fine (subset-or-equal).
        root = self._gate('[capabilities]\nmax = ["Net", "Fs", "Stdio", "Env"]\n')
        composed = _compose(root, "main.capa")
        self.assertTrue(composed["capability_ceilings"]["pass"])

    def test_dropping_net_fails_and_names_net(self):
        root = self._gate('[capabilities]\nmax = ["Fs", "Stdio"]\n')
        composed = _compose(root, "main.capa")
        ceilings = composed["capability_ceilings"]
        self.assertFalse(ceilings["pass"])
        net = [v for v in ceilings["violations"] if v["capability"] == "Net"]
        self.assertEqual(len(net), 1)
        self.assertEqual(net[0]["kind"], "exceeds")
        self.assertEqual(net[0]["package"], "export_gate")
        self.assertIn("Net", net[0]["detail"])
        self.assertIn("export_gate", net[0]["path"])


class TestTransitiveExceeds(_TmpTree):
    """A capability introduced by a TRANSITIVE dependency is attributed to
    the offending dependency edge, not left as 'somewhere in the tree'."""

    def _tree(self, root_ceiling: str) -> Path:
        root = self.tmp / "app"
        _write(root, "capa.toml", (
            '[package]\nname = "app"\nversion = "0.1.0"\n\n'
            + root_ceiling +
            '\n[dependencies.netdep]\n'
            'git = "https://github.com/example/netdep"\ntag = "v1"\n'
        ))
        _write(root, "main.capa", (
            "import netdep.api\n\n"
            "pub fun run() -> Unit\n    ping()\n    return\n"
        ))
        _write(root, "vendor/netdep/capa.toml",
               '[package]\nname = "netdep"\nversion = "0.1.0"\n')
        _write(root, "vendor/netdep/api.capa",
               "pub fun ping() -> Unit\n    return\n"
               "pub fun call(_n: Net) -> Unit\n    return\n")
        return root

    def test_pure_leaf_with_net_transitive_dep_fails(self):
        root = self._tree("[capabilities]\npure = true\n")
        composed = _compose(root, "main.capa")
        ceilings = composed["capability_ceilings"]
        self.assertFalse(ceilings["pass"])
        net = [v for v in ceilings["violations"] if v["capability"] == "Net"]
        self.assertEqual(len(net), 1)
        self.assertEqual(net[0]["kind"], "exceeds")
        self.assertEqual(net[0]["introduced_by"], "netdep")
        self.assertEqual(net[0]["path"], ["app", "netdep"])
        self.assertIn("netdep", net[0]["detail"])
        self.assertIn("Net", net[0]["detail"])

    def test_ceiling_covering_net_passes_despite_transitive_source(self):
        root = self._tree('[capabilities]\nmax = ["Net"]\n')
        composed = _compose(root, "main.capa")
        self.assertTrue(composed["capability_ceilings"]["pass"])


class TestFailClosedOnUnknown(_TmpTree):
    """The honesty rule: a declared-ceiling package whose composed
    authority is TOP fails CLOSED, distinctly from an exceeds failure,
    unless allow_unknown opts out explicitly."""

    def _ghost(self, ceiling_block: str) -> Path:
        root = self.tmp / "prod"
        _write(root, "capa.toml", (
            '[package]\nname = "prod"\nversion = "0.1.0"\n\n'
            + ceiling_block +
            '\n[dependencies.ghost]\n'
            'git = "https://github.com/example/ghost"\ntag = "v1"\n'
        ))
        _write(root, "main.capa", "pub fun add(a: Int, b: Int) -> Int\n    return a + b\n")
        return root

    def test_unresolvable_dep_fails_closed_with_unknown_kind(self):
        root = self._ghost("[capabilities]\npure = true\n")
        composed = _compose(root, "main.capa")
        ceilings = composed["capability_ceilings"]
        self.assertFalse(ceilings["pass"])
        kinds = {v["kind"] for v in ceilings["violations"]}
        self.assertIn("authority_unknown", kinds)
        # DISTINCT from an exceeds-by-capability failure.
        self.assertNotIn("exceeds", kinds)
        v = next(v for v in ceilings["violations"]
                 if v["kind"] == "authority_unknown")
        self.assertIsNone(v["capability"])
        self.assertIn("UNKNOWN", v["detail"])
        self.assertIn("ghost", v["detail"])

    def test_allow_unknown_waives_the_top_failure(self):
        root = self._ghost("[capabilities]\npure = true\nallow_unknown = true\n")
        composed = _compose(root, "main.capa")
        self.assertTrue(composed["capability_ceilings"]["pass"])

    def test_native_dep_fails_closed(self):
        root = self.tmp / "prod"
        _write(root, "capa.toml", (
            '[package]\nname = "prod"\nversion = "0.1.0"\n\n'
            '[capabilities]\npure = true\n\n'
            '[dependencies.native]\n'
            'git = "https://github.com/example/native"\ntag = "v1"\n'
        ))
        _write(root, "main.capa", "pub fun f() -> Unit\n    return\n")
        _write(root, "vendor/native/capa.toml",
               '[package]\nname = "native"\nversion = "1.0.0"\n')
        _write(root, "vendor/native/lib.rs", "// not capa\n")
        composed = _compose(root, "main.capa")
        ceilings = composed["capability_ceilings"]
        self.assertFalse(ceilings["pass"])
        self.assertTrue(any(v["kind"] == "authority_unknown"
                            for v in ceilings["violations"]))

    def test_unsafe_crossing_package_fails_closed(self):
        root = self.tmp / "prod"
        _write(root, "capa.toml", (
            '[package]\nname = "prod"\nversion = "0.1.0"\n\n'
            '[capabilities]\npure = true\n'
        ))
        _write(root, "main.capa", "pub fun risky(_u: Unsafe) -> Unit\n    return\n")
        composed = _compose(root, "main.capa")
        ceilings = composed["capability_ceilings"]
        self.assertFalse(ceilings["pass"])
        self.assertTrue(any(v["kind"] == "authority_unknown"
                            for v in ceilings["violations"]))

    def test_allow_unknown_still_flags_a_known_exceeds(self):
        # allow_unknown waives ONLY the TOP failure; a positively observed
        # capability outside the bound still fails.
        root = self.tmp / "prod"
        _write(root, "capa.toml", (
            '[package]\nname = "prod"\nversion = "0.1.0"\n\n'
            '[capabilities]\nmax = ["Fs"]\nallow_unknown = true\n\n'
            '[dependencies.ghost]\n'
            'git = "https://github.com/example/ghost"\ntag = "v1"\n'
        ))
        _write(root, "main.capa", "pub fun run(_n: Net) -> Unit\n    return\n")
        composed = _compose(root, "main.capa")
        ceilings = composed["capability_ceilings"]
        self.assertFalse(ceilings["pass"])
        kinds = {v["kind"] for v in ceilings["violations"]}
        self.assertIn("exceeds", kinds)
        # The TOP part is waived.
        self.assertNotIn("authority_unknown", kinds)


class TestUnconstrained(_TmpTree):
    def test_no_ceiling_is_not_checked(self):
        root = self.tmp / "prod"
        _write(root, "capa.toml", '[package]\nname = "prod"\nversion = "0.1.0"\n')
        _write(root, "main.capa", "pub fun run(_n: Net) -> Unit\n    return\n")
        composed = _compose(root, "main.capa")
        ceilings = composed["capability_ceilings"]
        self.assertFalse(ceilings["checked"])
        self.assertTrue(ceilings["pass"])
        self.assertEqual(ceilings["violations"], [])
        p = _pkg(composed, "prod")
        self.assertIsNone(p["declared_ceiling"])
        self.assertEqual(p["ceiling_violations"], [])

    def test_only_a_dependency_declares_a_ceiling(self):
        # A dependency with a tighter ceiling than what composes THROUGH it
        # (its transitive subtree) is checked on its own composed set.
        root = self.tmp / "app"
        _write(root, "capa.toml", (
            '[package]\nname = "app"\nversion = "0.1.0"\n\n'
            '[dependencies.mid]\n'
            'git = "https://github.com/example/mid"\ntag = "v1"\n'
        ))
        _write(root, "main.capa",
               "import mid.api\n\npub fun run() -> Unit\n    go()\n    return\n")
        # mid declares pure, but reaches Net through its own function.
        _write(root, "vendor/mid/capa.toml",
               '[package]\nname = "mid"\nversion = "0.1.0"\n\n'
               '[capabilities]\npure = true\n')
        _write(root, "vendor/mid/api.capa",
               "pub fun go() -> Unit\n    return\n"
               "pub fun net(_n: Net) -> Unit\n    return\n")
        composed = _compose(root, "main.capa")
        ceilings = composed["capability_ceilings"]
        self.assertTrue(ceilings["checked"])
        self.assertFalse(ceilings["pass"])
        self.assertTrue(any(v["package"] == "mid" and v["capability"] == "Net"
                            for v in ceilings["violations"]))


class TestDeterminism(_TmpTree):
    def _tree(self) -> Path:
        root = self.tmp / "app"
        _write(root, "capa.toml", (
            '[package]\nname = "app"\nversion = "0.1.0"\n\n'
            '[capabilities]\nmax = ["Fs"]\n'
        ))
        _write(root, "main.capa", (
            "pub fun a(_n: Net) -> Unit\n    return\n"
            "pub fun b(_io: Stdio) -> Unit\n    return\n"
            "pub fun c(_e: Env) -> Unit\n    return\n"
        ))
        return root

    def test_violations_ordering_is_stable(self):
        root = self._tree()
        c1 = _compose(root, "main.capa")
        c2 = _compose(root, "main.capa")
        self.assertEqual(canonical_json(c1), canonical_json(c2))
        # Three over-ceiling caps, deterministically ordered.
        caps = [v["capability"]
                for v in c1["capability_ceilings"]["violations"]]
        self.assertEqual(caps, sorted(caps))
        self.assertEqual(caps, ["Env", "Net", "Stdio"])


class TestCheckCapabilitiesCli(_TmpTree):
    """The CI gate: ``capa --check-capabilities`` exits non-zero on any
    violation, zero on a clean product."""

    def _run(self, root: Path, root_file: str):
        import io
        import os
        import sys
        from unittest import mock

        from capa.cli import main

        out, err = io.StringIO(), io.StringIO()
        argv = ["capa", "--check-capabilities", str(root / root_file)]
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
        _write(root, "capa.toml", (
            '[package]\nname = "gate"\nversion = "0.1.0"\n\n'
            '[capabilities]\nmax = ["Net", "Fs", "Stdio"]\n'
        ))
        _write(root, "main.capa", (
            "pub fun fetch(_n: Net) -> Unit\n    return\n"
            "pub fun store(_fs: Fs) -> Unit\n    return\n"
            "pub fun log(_io: Stdio) -> Unit\n    return\n"
        ))
        rc, _out, err = self._run(root, "main.capa")
        self.assertEqual(rc, 0)
        self.assertIn("OK", err)

    def test_violation_exits_nonzero_with_actionable_message(self):
        root = self.tmp / "gate"
        _write(root, "capa.toml", (
            '[package]\nname = "gate"\nversion = "0.1.0"\n\n'
            '[capabilities]\nmax = ["Fs", "Stdio"]\n'
        ))
        _write(root, "main.capa", (
            "pub fun fetch(_n: Net) -> Unit\n    return\n"
            "pub fun store(_fs: Fs) -> Unit\n    return\n"
        ))
        rc, _out, err = self._run(root, "main.capa")
        self.assertNotEqual(rc, 0)
        self.assertIn("FAILED", err)
        self.assertIn("Net", err)

    def test_top_subtree_exits_nonzero(self):
        root = self.tmp / "prod"
        _write(root, "capa.toml", (
            '[package]\nname = "prod"\nversion = "0.1.0"\n\n'
            '[capabilities]\npure = true\n\n'
            '[dependencies.ghost]\n'
            'git = "https://github.com/example/ghost"\ntag = "v1"\n'
        ))
        _write(root, "main.capa", "pub fun f() -> Unit\n    return\n")
        rc, _out, err = self._run(root, "main.capa")
        self.assertNotEqual(rc, 0)
        self.assertIn("UNKNOWN", err)

    def test_no_ceiling_exits_zero(self):
        root = self.tmp / "prod"
        _write(root, "capa.toml", '[package]\nname = "prod"\nversion = "0.1.0"\n')
        _write(root, "main.capa", "pub fun run(_n: Net) -> Unit\n    return\n")
        rc, _out, err = self._run(root, "main.capa")
        self.assertEqual(rc, 0)
        self.assertIn("nothing to verify", err)


if __name__ == "__main__":
    unittest.main()
