"""Tests for the signed authority changelog between releases (feature #2).

The diff operates on the JSON artifacts ``--manifest`` /
``--manifest-digest`` / ``--compose-sbom`` already emit. Most rows build
minimal manifest dicts directly (so the exact capability views are under
test control); the node-ipc demo additionally builds two real manifests
through ``build_manifest`` so the end-to-end shape is exercised.

Acceptance rows (from the feature #2 brief), in order:

- NODE-IPC DEMO: a benign vN and a vN+1 whose exported ``send`` gains
  Fs -> ``send`` added=[Fs], classified widening; summary counts 1
  widening; both input digests recorded; canonical.
- POSITION INDEPENDENCE: two manifests identical except line numbers ->
  EMPTY diff.
- GUARANTEE LOST: a function provably-excluded of Net in vN, not excluded
  in vN+1 -> guarantee_lost=[Net], widening.
- NARROWING: a function that DROPS a capability -> removed, narrowing;
  --fail-on-widening still exits 0.
- ADDED / REMOVED functions and a grant change classified.
- PRODUCT-LEVEL: a transitive dep gaining Net with no exported-signature
  change -> composed_added=[Net]; an authority-unknown transition
  flagged high-severity.
- DETERMINISM / CANONICAL: the changelog is byte-reproducible and its
  digest stable across runs / cwd; reuses S1.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from capa import analyze
from capa.loader import ModuleLoader
from capa.manifest import (
    DIFF_SCHEMA_VERSION,
    DiffError,
    build_capability_diff,
    build_manifest,
    canonical_json,
    canonical_manifest,
    manifest_digest,
)


ALL_CAPS = ["Clock", "Db", "Env", "Fs", "Net", "Proc", "Random", "Stdio",
            "Unsafe"]


def _fn(
    name,
    *,
    container=None,
    is_pub=True,
    declared=(),
    reachable=None,
    excluded=None,
    has_unsafe=False,
    pos="main.capa:1:1",
):
    """Build one manifest function record. ``reachable`` defaults to
    ``declared``; ``excluded`` defaults to the provable complement (every
    capability not reachable), matching how a real manifest fills the
    exclusion set for a proof-holding function."""
    reachable = list(declared) if reachable is None else list(reachable)
    if excluded is None:
        excluded = [c for c in ALL_CAPS if c not in reachable]
    return {
        "name": name,
        "source_name": name,
        "container": container,
        "source_container": container,
        "pos": pos,
        "is_pub": is_pub,
        "declared_capabilities": list(declared),
        "transitively_reachable_capabilities": sorted(reachable),
        "provably_excluded_capabilities": sorted(excluded),
        "has_unsafe": has_unsafe,
    }


def _manifest(functions, *, preopens=None, allow_hosts=None):
    return {
        "capa_version": "test",
        "schema_version": 1,
        "filename": "main.capa",
        "functions": list(functions),
        "operator_declared_grants": {
            "trust_level": "operator-declared",
            "preopens": list(preopens or []),
            "allow_hosts": list(allow_hosts or []),
        },
    }


def _composed(caps, *, authority_unknown=False):
    """A minimal composed-SBOM-shaped doc: only the ``composed`` block the
    diff reads."""
    return {
        "capa_version": "test",
        "composed_schema_version": 2,
        "product": {"name": "p", "version": "0.1.0"},
        "composed": {
            "capabilities": sorted(caps),
            "authority_unknown": authority_unknown,
        },
    }


def _diff(old, new):
    return build_capability_diff(old, new, capa_version="test")


class TestNodeIpcDemo(unittest.TestCase):
    """The flagship: an update whose exported send gains Fs."""

    def _build_manifest_from_source(self, src):
        loader = ModuleLoader(search_paths=[])
        linked = loader.load_root(src, "main.capa")
        result = analyze(linked.module, source=src, filename="main.capa",
                         sources=linked.sources)
        self.assertTrue(result.ok, [e.format() for e in result.errors])
        return build_manifest(linked.module, filename="main.capa",
                              expr_labels=result.expr_labels)

    def test_send_gains_fs_is_widening(self):
        v_n = self._build_manifest_from_source(
            "pub fun send(stdio: Stdio, msg: String)\n"
            "    stdio.println(msg)\n"
        )
        v_n1 = self._build_manifest_from_source(
            "pub fun send(stdio: Stdio, fs: Fs, msg: String)\n"
            "    stdio.println(msg)\n"
            "    let _ = fs.read(msg)\n"
        )
        diff = _diff(v_n, v_n1)

        # send appears once, classified widening, added=[Fs].
        sends = [f for f in diff["functions"] if f["name"] == "send"]
        self.assertEqual(len(sends), 1)
        self.assertEqual(sends[0]["classification"], "widening")
        self.assertIn("Fs", sends[0]["added"])
        self.assertNotIn("Fs", sends[0]["removed"])

        # Exactly one widening (the Fs gain, deduped across views + product).
        self.assertEqual(diff["summary"]["widenings"], 1)
        self.assertEqual(diff["summary"]["narrowings"], 0)

        # Both input digests recorded, and correct.
        self.assertEqual(diff["from_digest"]["value"], manifest_digest(v_n))
        self.assertEqual(diff["to_digest"]["value"], manifest_digest(v_n1))
        self.assertEqual(diff["diff_schema_version"], DIFF_SCHEMA_VERSION)

    def test_fail_on_widening_exits_nonzero(self):
        old = _manifest([_fn("send", declared=["Stdio"])])
        new = _manifest([_fn("send", declared=["Stdio", "Fs"])])
        with tempfile.TemporaryDirectory() as d:
            op = Path(d) / "old.json"
            npth = Path(d) / "new.json"
            op.write_text(canonical_json(canonical_manifest(old)))
            npth.write_text(canonical_json(canonical_manifest(new)))
            rc = _run_cli(["--capability-diff", str(op), str(npth),
                           "--fail-on-widening"])
            self.assertEqual(rc.returncode, 1)
            # The changelog is still emitted on stdout (gate is a report+exit).
            doc = json.loads(rc.stdout)
            self.assertEqual(doc["summary"]["widenings"], 1)


class TestPositionIndependence(unittest.TestCase):
    def test_line_only_move_is_empty_diff(self):
        old = _manifest([
            _fn("a", declared=["Stdio"], pos="main.capa:1:1"),
            _fn("b", container="T", declared=["Fs"], pos="main.capa:5:1"),
        ])
        # Same functions, same caps, only positions differ.
        new = _manifest([
            _fn("a", declared=["Stdio"], pos="main.capa:99:7"),
            _fn("b", container="T", declared=["Fs"], pos="main.capa:250:3"),
        ])
        diff = _diff(old, new)
        self.assertEqual(diff["functions"], [])
        self.assertEqual(diff["added_functions"], [])
        self.assertEqual(diff["removed_functions"], [])
        self.assertEqual(diff["grant_changes"], [])
        self.assertEqual(diff["product"]["composed_added"], [])
        self.assertEqual(diff["product"]["composed_removed"], [])
        self.assertEqual(diff["summary"]["widenings"], 0)
        self.assertEqual(diff["summary"]["narrowings"], 0)


class TestGuaranteeLost(unittest.TestCase):
    def test_leaving_provably_excluded_is_widening(self):
        # vN: f provably excludes Net (and does not declare it).
        old = _manifest([_fn("f", declared=["Stdio"])])
        self.assertIn(
            "Net", old["functions"][0]["provably_excluded_capabilities"])
        # vN+1: f's exclusion proof collapsed (e.g. gained Unsafe): Net is
        # no longer provably excluded, but f still does not DECLARE Net.
        new = _manifest([
            _fn("f", declared=["Stdio"], reachable=["Stdio"],
                excluded=[], has_unsafe=True),
        ])
        diff = _diff(old, new)
        entry = next(f for f in diff["functions"] if f["name"] == "f")
        self.assertIn("Net", entry["guarantee_lost"])
        self.assertNotIn("Net", entry["added"])  # not declared/reachable
        self.assertIn(entry["classification"], ("widening", "mixed"))
        self.assertGreater(diff["summary"]["widenings"], 0)

    def test_entering_provably_excluded_is_narrowing(self):
        old = _manifest([
            _fn("f", declared=["Stdio"], reachable=["Stdio"],
                excluded=[], has_unsafe=True),
        ])
        new = _manifest([_fn("f", declared=["Stdio"])])
        diff = _diff(old, new)
        entry = next(f for f in diff["functions"] if f["name"] == "f")
        self.assertIn("Net", entry["guarantee_gained"])
        self.assertEqual(entry["classification"], "narrowing")


class TestNarrowing(unittest.TestCase):
    def test_dropping_a_capability_is_narrowing_and_gate_passes(self):
        old = _manifest([_fn("f", declared=["Stdio", "Fs"])])
        new = _manifest([_fn("f", declared=["Stdio"])])
        diff = _diff(old, new)
        entry = next(f for f in diff["functions"] if f["name"] == "f")
        self.assertEqual(entry["removed"], ["Fs"])
        self.assertEqual(entry["classification"], "narrowing")
        self.assertEqual(diff["summary"]["widenings"], 0)
        self.assertGreater(diff["summary"]["narrowings"], 0)

        with tempfile.TemporaryDirectory() as d:
            op = Path(d) / "old.json"
            npth = Path(d) / "new.json"
            op.write_text(canonical_json(canonical_manifest(old)))
            npth.write_text(canonical_json(canonical_manifest(new)))
            rc = _run_cli(["--capability-diff", str(op), str(npth),
                           "--fail-on-widening"])
            self.assertEqual(rc.returncode, 0)


class TestAddedRemovedFunctions(unittest.TestCase):
    def test_added_and_removed_pub_functions(self):
        old = _manifest([_fn("keep", declared=["Stdio"]),
                         _fn("gone", declared=["Net"])])
        new = _manifest([_fn("keep", declared=["Stdio"]),
                         _fn("fresh", declared=["Fs"])])
        diff = _diff(old, new)
        self.assertEqual([f["name"] for f in diff["added_functions"]],
                         ["fresh"])
        self.assertEqual(diff["added_functions"][0]["classification"],
                         "widening")
        self.assertEqual([f["name"] for f in diff["removed_functions"]],
                         ["gone"])
        self.assertEqual(diff["removed_functions"][0]["classification"],
                         "narrowing")
        self.assertGreater(diff["summary"]["widenings"], 0)
        self.assertGreater(diff["summary"]["narrowings"], 0)

    def test_added_capability_free_function_is_neutral(self):
        old = _manifest([_fn("keep", declared=["Stdio"])])
        new = _manifest([_fn("keep", declared=["Stdio"]),
                         _fn("pure", declared=[])])
        diff = _diff(old, new)
        self.assertEqual(diff["added_functions"][0]["classification"],
                         "neutral")
        self.assertEqual(diff["summary"]["widenings"], 0)


class TestGrantChanges(unittest.TestCase):
    def test_new_allow_host_is_widening(self):
        old = _manifest([_fn("f", declared=["Net"])])
        new = _manifest([_fn("f", declared=["Net"])],
                        allow_hosts=[{"kind": "net", "host": "api.example.com",
                                      "access": "get"}])
        diff = _diff(old, new)
        gc = diff["grant_changes"]
        self.assertEqual(len(gc), 1)
        self.assertEqual(gc[0]["grant_type"], "net")
        self.assertEqual(gc[0]["target"], "api.example.com")
        self.assertEqual(gc[0]["change"], "added")
        self.assertEqual(gc[0]["classification"], "widening")
        self.assertGreater(diff["summary"]["widenings"], 0)

    def test_widened_access_get_to_connect(self):
        old = _manifest([_fn("f", declared=["Net"])],
                        allow_hosts=[{"kind": "net", "host": "h",
                                      "access": "get"}])
        new = _manifest([_fn("f", declared=["Net"])],
                        allow_hosts=[{"kind": "net", "host": "h",
                                      "access": "connect"}])
        diff = _diff(old, new)
        gc = diff["grant_changes"][0]
        self.assertEqual(gc["change"], "widened")
        self.assertEqual(gc["classification"], "widening")
        self.assertEqual(gc["from"], ["get"])
        self.assertEqual(gc["to"], ["get", "post"])

    def test_preopen_ro_to_rw_is_widening(self):
        old = _manifest([_fn("f", declared=["Fs"])],
                        preopens=[{"host_dir": "/data", "permission": "ro",
                                   "kind": "fs"}])
        new = _manifest([_fn("f", declared=["Fs"])],
                        preopens=[{"host_dir": "/data", "permission": "rw",
                                   "kind": "fs"}])
        diff = _diff(old, new)
        gc = diff["grant_changes"][0]
        self.assertEqual(gc["grant_type"], "fs")
        self.assertEqual(gc["classification"], "widening")

    def test_removed_grant_is_narrowing(self):
        old = _manifest([_fn("f", declared=["Net"])],
                        allow_hosts=[{"kind": "net", "host": "h",
                                      "access": "connect"}])
        new = _manifest([_fn("f", declared=["Net"])])
        diff = _diff(old, new)
        gc = diff["grant_changes"][0]
        self.assertEqual(gc["change"], "removed")
        self.assertEqual(gc["classification"], "narrowing")
        self.assertEqual(diff["summary"]["widenings"], 0)
        self.assertGreater(diff["summary"]["narrowings"], 0)


class TestProductLevel(unittest.TestCase):
    def test_transitive_dep_gains_net_no_signature_change(self):
        # No exported-signature change (an internal dep gained Net); the
        # composed product set grows. Composed-SBOM inputs carry no
        # per-function records, so this surfaces purely at product level.
        old = _composed(["Stdio"])
        new = _composed(["Stdio", "Net"])
        diff = _diff(old, new)
        self.assertEqual(diff["functions"], [])
        self.assertEqual(diff["product"]["composed_added"], ["Net"])
        self.assertEqual(diff["product"]["composed_removed"], [])
        self.assertEqual(diff["summary"]["widenings"], 1)

    def test_authority_unknown_transition_is_high_severity(self):
        old = _composed(["Stdio"], authority_unknown=False)
        new = _composed(["Stdio"], authority_unknown=True)
        diff = _diff(old, new)
        self.assertEqual(diff["product"]["authority_unknown_transition"],
                         "gained")
        self.assertTrue(diff["summary"]["authority_unknown_regression"])
        self.assertGreater(diff["summary"]["widenings"], 0)

    def test_authority_unknown_resolved_is_narrowing(self):
        old = _composed(["Stdio"], authority_unknown=True)
        new = _composed(["Stdio"], authority_unknown=False)
        diff = _diff(old, new)
        self.assertEqual(diff["product"]["authority_unknown_transition"],
                         "resolved")
        self.assertFalse(diff["summary"]["authority_unknown_regression"])
        self.assertGreater(diff["summary"]["narrowings"], 0)

    def test_manifest_product_union_dedupes_function_widening(self):
        # A bare-manifest input: send gains Fs. The product union also
        # gains Fs, but it must NOT be counted a second time.
        old = _manifest([_fn("send", declared=["Stdio"])])
        new = _manifest([_fn("send", declared=["Stdio", "Fs"])])
        diff = _diff(old, new)
        self.assertEqual(diff["product"]["composed_added"], ["Fs"])
        self.assertEqual(diff["summary"]["widenings"], 1)


class TestDeterminism(unittest.TestCase):
    def test_byte_reproducible_and_stable_digest(self):
        old = _manifest([_fn("send", declared=["Stdio"]),
                         _fn("q", container="T", declared=["Net"])])
        new = _manifest([_fn("send", declared=["Stdio", "Fs"]),
                         _fn("q", container="T", declared=["Net"])])
        a = canonical_json(canonical_manifest(_diff(old, new)))
        b = canonical_json(canonical_manifest(_diff(old, new)))
        self.assertEqual(a, b)
        # Digest is self-consistent (S1 envelope over the bare changelog).
        doc = json.loads(a)
        recomputed = manifest_digest(doc)
        self.assertEqual(doc["content_integrity"]["digest"]["value"],
                         recomputed)

    def test_cli_digest_stable_across_cwd(self):
        old = _manifest([_fn("send", declared=["Stdio"])])
        new = _manifest([_fn("send", declared=["Stdio", "Fs"])])
        with tempfile.TemporaryDirectory() as d:
            op = Path(d) / "old.json"
            npth = Path(d) / "new.json"
            op.write_text(canonical_json(canonical_manifest(old)))
            npth.write_text(canonical_json(canonical_manifest(new)))
            r1 = _run_cli(["--capability-diff", str(op), str(npth)], cwd=d)
            sub = Path(d) / "sub"
            sub.mkdir()
            r2 = _run_cli(["--capability-diff", str(op), str(npth)],
                          cwd=str(sub))
            self.assertEqual(r1.returncode, 0)
            self.assertEqual(r1.stdout, r2.stdout)  # byte-identical


class TestErrors(unittest.TestCase):
    def test_unrecognized_shape_raises(self):
        with self.assertRaises(DiffError):
            _diff({"hello": "world"}, {"hello": "world"})

    def test_cli_invalid_json_exits_2(self):
        with tempfile.TemporaryDirectory() as d:
            op = Path(d) / "old.json"
            npth = Path(d) / "new.json"
            op.write_text("{not json")
            npth.write_text("{}")
            rc = _run_cli(["--capability-diff", str(op), str(npth)])
            self.assertEqual(rc.returncode, 2)


def _run_cli(args, cwd=None):
    """Invoke ``python -m capa`` with ``args``, capturing stdout/stderr."""
    env = dict(os.environ)
    env["PYTHONPATH"] = str(
        Path(__file__).resolve().parent.parent
    ) + os.pathsep + env.get("PYTHONPATH", "")
    return subprocess.run(
        [sys.executable, "-m", "capa", *args],
        capture_output=True, text=True, cwd=cwd, env=env,
    )


if __name__ == "__main__":
    unittest.main()
