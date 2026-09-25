"""What the ``unaudited_secret_sinks`` family is entitled to claim.

Five artefacts carry the per-function ``unaudited_secret_sinks`` fact or
a value derived from it: ``--manifest``, ``--manifest-digest``,
``--compose-sbom`` (``attributed_unaudited_secret_sinks`` /
``unaudited_secret_sink_capabilities``), ``--conformance-report`` and the
``--check-policies`` gate (``no-secret-egress``). The fact is the set of
explicit secret-to-sink flows the warn-tier check REPORTED; an empty list
is not a proof of absence. Each of the four documents therefore carries,
under one top-level key, the ONE sentence stating that scope, sourced from
:mod:`capa.manifest._scope`, and ``docs/trust-model.md`` carries a block
generated from the same constant by ``tools/gen_trust_register.py``.

Five groups of pins, over the corpus in ``tests/fixtures/attestation_scope``
(each program is wrapped as a one-package project declaring a
``no-secret-egress`` policy over ``Stdio``):

- characterization (RED before the key and the constant existed): the key
  is present, byte-equal to the constant in all four documents, the
  content-integrity envelopes still verify, the register block is
  generated and the generator's check passes, and the wording keeps its
  load-bearing clauses while naming no tier as covering anything;
- single source: the sentence's text lives in exactly one module, every
  producer references the constant by name, and no other document in the
  repository restates it;
- members: the CURRENT value of the field, the composed sink-capability
  set and the conformance verdict for every corpus program, including the
  explicit misses pinned as ``[]`` and the reported-but-not-recorded
  member pinned as warning AND empty, so a silent widening or narrowing of
  the VALUE turns red and must be reconciled with the sentence;
- derivation: every claim-bearing key the manifest, the composed SBOM and
  the conformance report emit, enumerated from the documents themselves,
  is classified, and every ANALYSIS-class key carries its scope in band.
  Two bounds, both measured: a key whose leaf name carries none of the
  claim vocabulary is not classified here (the exact top-level key set in
  ``test_manifest`` catches a new top-level one, a nested one escapes), and
  the class label of a non-family key is a fixture judgement, so editing it
  in the fixture is a visible diff, not a failure;
- producers: exactly three call sites record the fact, each on the
  non-strict branch of its innermost tier test.

Everything runs in-process; no wasm tooling is needed.
"""

import ast
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from capa import analyze
from capa.docgen import build_html
from capa.loader import ModuleLoader
from capa.manifest import (
    CONTENT_INTEGRITY_KEY,
    build_composed_sbom,
    build_cyclonedx,
    build_manifest,
    build_provenance,
    build_spdx,
    build_vex_document,
    canonical_manifest,
    evaluate_policies,
    find_policy_file,
    manifest_digest,
    read_policy_file,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
PACKAGE = REPO_ROOT / "capa"
CORPUS = Path(__file__).resolve().parent / "fixtures" / "attestation_scope"
GENERATOR = REPO_ROOT / "tools" / "gen_trust_register.py"
REGISTER = REPO_ROOT / "docs" / "trust-model.md"

_DOCUMENT_FLAGS = (
    "--manifest", "--manifest-digest", "--compose-sbom", "--conformance-report",
)

# Every corpus project declares the same egress policy: Stdio is the one
# sink each program can reach.
_POLICY = (
    '[[policy]]\n'
    'id = "nse"\n'
    'name = "no secret egress via Stdio"\n'
    'kind = "no-secret-egress"\n'
    'capabilities = ["Stdio"]\n'
)


def _scope():
    """The one constant and its key. A missing module is the RED-first
    reason of every characterization pin below."""
    try:
        from capa.manifest._scope import (
            UNAUDITED_SECRET_SINKS_SCOPE, UNAUDITED_SECRET_SINKS_SCOPE_KEY,
        )
    except ImportError as e:  # pragma: no cover - the RED-first state
        raise AssertionError(f"no scope constant module: {e}") from e
    return UNAUDITED_SECRET_SINKS_SCOPE_KEY, UNAUDITED_SECRET_SINKS_SCOPE


def _collapse(text: str) -> str:
    return " ".join(text.split())


def _corpus_names() -> list[str]:
    return sorted(p.stem for p in CORPUS.glob("*.capa"))


def _make_project(base: Path, name: str) -> Path:
    root = base / name
    root.mkdir(parents=True)
    shutil.copyfile(CORPUS / f"{name}.capa", root / "main.capa")
    (root / "capa.toml").write_text(
        f'[package]\nname = "leakdemo_{name}"\nversion = "1.0.0"\n',
        encoding="utf-8",
    )
    (root / "capa-policy.toml").write_text(_POLICY, encoding="utf-8")
    return root


def _analyse(root: Path):
    root = root.resolve()
    filename = str(root / "main.capa")
    source = Path(filename).read_text(encoding="utf-8")
    linked = ModuleLoader(search_paths=[root]).load_root(source, filename)
    result = analyze(
        linked.module, source=source, filename=filename,
        sources=linked.sources, module_privates=linked.module_privates,
    )
    return linked, result, filename


def _documents(root: Path):
    """The four documents as the emitters build them, in-process: the
    manifest, its canonical (digest) form, the composed SBOM and the
    conformance report. None when the analyzer refuses the program (no
    artefact exists)."""
    linked, result, filename = _analyse(root)
    if not result.ok:
        return None
    manifest = build_manifest(
        linked.module, filename=filename, bindings=result.bindings,
        expr_labels=result.expr_labels,
        unaudited_secret_sinks=result.unaudited_secret_sinks,
    )
    composed = build_composed_sbom(linked.module, manifest, root.resolve())
    policy_path = find_policy_file(root.resolve())
    policies = read_policy_file(policy_path) if policy_path else []
    report = evaluate_policies(composed, policies)
    return {
        "--manifest": manifest,
        "--manifest-digest": canonical_manifest(manifest),
        "--compose-sbom": canonical_manifest(composed),
        "--conformance-report": canonical_manifest(report),
    }


def _cli(root: Path, *flags: str):
    """Drive the real CLI in-process on ``<root>/main.capa``. Returns
    ``(rc, stdout, stderr)``."""
    from capa.cli import main
    out, err = io.StringIO(), io.StringIO()
    argv = ["capa", *flags, str(root / "main.capa")]
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


def _key_paths(obj, prefix: str, acc: set) -> None:
    """Every key path a JSON document carries, ``[]`` marking a list."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            acc.add(f"{prefix}/{k}")
            _key_paths(v, f"{prefix}/{k}", acc)
    elif isinstance(obj, list):
        for v in obj:
            _key_paths(v, f"{prefix}[]", acc)


class _CorpusProjects(unittest.TestCase):
    """One temporary project per corpus program, built once per class."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory(prefix="capa_scope_")
        base = Path(cls._tmp.name)
        cls.roots = {name: _make_project(base, name) for name in _corpus_names()}

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()


# ---------------------------------------------------------------------------
# Characterization pins (RED before the key existed)
# ---------------------------------------------------------------------------


class TestScopeStatement(_CorpusProjects):
    """The four documents state the scope, identically, from one constant."""

    _LEAKER = "c1_loop_break_default"

    def _emitted(self, flag: str) -> dict:
        rc, out, err = _cli(self.roots[self._LEAKER], flag)
        self.assertEqual(rc, 0, err)
        return json.loads(out)

    def test_manifest_carries_the_scope_key(self):
        key, _ = _scope()
        doc = self._emitted("--manifest")
        self.assertIn(key, doc, "--manifest does not carry the scope key")
        self.assertIsInstance(doc[key], str)
        self.assertTrue(doc[key].strip())

    def test_four_documents_carry_the_one_sentence_byte_equal(self):
        key, sentence = _scope()
        for flag in _DOCUMENT_FLAGS:
            with self.subTest(flag=flag):
                self.assertEqual(
                    self._emitted(flag).get(key), sentence,
                    f"{flag} does not carry the ONE constant byte-equal",
                )

    def test_envelopes_verify_with_the_key_present(self):
        for flag in _DOCUMENT_FLAGS[1:]:
            with self.subTest(flag=flag):
                doc = self._emitted(flag)
                self.assertIn(CONTENT_INTEGRITY_KEY, doc)
                self.assertEqual(
                    doc[CONTENT_INTEGRITY_KEY]["digest"]["value"],
                    manifest_digest(doc),
                )

    def test_wording_keeps_every_load_bearing_clause(self):
        _, sentence = _scope()
        low = sentence.lower()
        for phrase in (
            "reported",
            "recorded with a sink capability",
            "did not attribute is not recorded",
            "recorded nothing",
            "not a proof of absence in either direction",
            "implicit",
            "never recorded at any tier",
            "including under @strict_ifc",
            "documented misses",
            "refused under @strict_ifc produces no artifact",
            "can still leak",
            "without the analysis result",
            "never as 'cannot leak'",
        ):
            self.assertIn(phrase, low, f"missing clause: {phrase!r}")
        # Never a tier as covering anything, never a proof of absence,
        # never verdict vocabulary.
        for pattern in (
            r"covered (only )?(under|by|at)", r"implicit flows are covered",
            r"\bcovers\b", r"\bno explicit\b", r"\bguarantee", r"noninterference",
            r"\bcomplete", r"flow_unproven", r"authority_unknown", r"\bverdict\b",
            r"\bviolation", r"\bpass\b", r"\bfails?\b", r"\bexactly\b",
        ):
            self.assertIsNone(re.search(pattern, low), f"forbidden: {pattern}")
        self.assertEqual(low.count("cannot leak"), 1)


class TestRegister(unittest.TestCase):
    """``docs/trust-model.md`` carries a block generated from the constant,
    and the generator's check mode holds it to the constant."""

    def _generator(self):
        self.assertTrue(GENERATOR.is_file(), f"no generator at {GENERATOR}")
        spec = importlib.util.spec_from_file_location(
            "gen_trust_register", GENERATOR,
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_register_block_is_generated_from_the_constant(self):
        _, sentence = _scope()
        gen = self._generator()
        text = REGISTER.read_text(encoding="utf-8")
        self.assertIn(
            gen.BEGIN, text, "docs/trust-model.md has no generated register block",
        )
        self.assertIn(gen.END, text)
        block = text.split(gen.BEGIN, 1)[1].split(gen.END, 1)[0]
        self.assertIn(
            _collapse(sentence), _collapse(block),
            "register block does not match the constant (stale copy)",
        )

    def test_generator_check_passes(self):
        self.assertTrue(GENERATOR.is_file(), f"no generator at {GENERATOR}")
        proc = subprocess.run(
            [sys.executable, str(GENERATOR), "--check"],
            cwd=str(REPO_ROOT), stdin=subprocess.DEVNULL,
            capture_output=True, text=True, timeout=120,
        )
        self.assertEqual(
            proc.returncode, 0,
            f"generator --check reports drift\nstdout:\n{proc.stdout}\n"
            f"stderr:\n{proc.stderr}",
        )


# ---------------------------------------------------------------------------
# Single source
# ---------------------------------------------------------------------------


def _probe() -> str:
    """A distinctive clause of the sentence, collapsed and lowercased, so a
    copy survives re-wrapping, re-casing or a different split across
    string literals. Asserted to be part of the sentence first."""
    _, sentence = _scope()
    probe = "not a proof of absence in either direction"
    assert probe in _collapse(sentence).lower()
    return probe


def _string_literals(path: Path):
    """Every string constant in a Python source file, adjacent literals
    already joined by the parser, collapsed and lowercased."""
    tree = ast.parse(path.read_text(encoding="utf-8"), str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            yield _collapse(node.value).lower()


class TestSingleSource(unittest.TestCase):
    _PRODUCERS = (
        "capa/manifest/_funrec.py",
        "capa/manifest/_compose.py",
        "capa/manifest/_policy.py",
    )

    def test_sentence_text_lives_in_exactly_one_module(self):
        probe = _probe()
        hits = sorted(
            p.relative_to(REPO_ROOT).as_posix()
            for p in PACKAGE.rglob("*.py")
            if any(probe in literal for literal in _string_literals(p))
        )
        self.assertEqual(hits, ["capa/manifest/_scope.py"], hits)

    def test_every_producer_references_the_constant_by_name(self):
        for rel in self._PRODUCERS:
            with self.subTest(module=rel):
                text = (REPO_ROOT / rel).read_text(encoding="utf-8")
                self.assertTrue(
                    "UNAUDITED_SECRET_SINKS_SCOPE_KEY" in text,
                    f"{rel} does not reference the scope constant by name",
                )

    def test_sentence_is_restated_in_no_other_document(self):
        probe = _probe()
        candidates = [
            *REPO_ROOT.glob("*.md"),
            *(REPO_ROOT / "docs").rglob("*.md"),
            *(REPO_ROOT / "specs").rglob("*.md"),
        ]
        hits = sorted(
            p.relative_to(REPO_ROOT).as_posix()
            for p in candidates
            if probe in _collapse(
                p.read_text(encoding="utf-8", errors="replace"),
            ).lower()
        )
        self.assertEqual(hits, [REGISTER.relative_to(REPO_ROOT).as_posix()], hits)


# ---------------------------------------------------------------------------
# Members: the CURRENT value of the field on every corpus program
# ---------------------------------------------------------------------------

# name -> (accepted by the analyzer,
#          {function name: [(sink capability, pos), ...]} in the manifest,
#          unaudited_secret_sink_capabilities of the one package,
#          no-secret-egress pass)
# A refused program has no artefact at all, so only the first entry holds.
#
# Control-direction leakers (c1, c3, c4, g2_k1, trap) and the explicit
# data-direction misses (c2 at both tiers) are pinned ``[]`` and passing:
# that IS the current value, and the sentence states why it is not a
# proof of absence. The day one of them flips, this table and the
# sentence are re-derived together.
_MEMBERS = {
    "c1_loop_break_default": (True, {"main": []}, [], True),
    "c2_fr01_strict": (True, {"main": []}, [], True),
    "c2_fr02_warn": (True, {"main": []}, [], True),
    "c3_lb23_strict": (True, {"pick": [], "main": []}, [], True),
    "c3_lb23_warn": (True, {"pick": [], "main": []}, [], True),
    "c4_gn04_strict": (True, {"pick_eq": [], "main": []}, [], True),
    "d1_direct_default": (True, {"main": [("Stdio", "3:19")]}, ["Stdio"], False),
    "g2_k1_method_strict": (True, {"pick": [], "main": []}, [], True),
    "g2_k1b_fun_strict": (False, None, None, None),
    # Reported but NOT recorded: the warn-tier check emits a warning for
    # the capture-carried callee sink, the secret prints on three backends,
    # and the recorder receives no sink capability for it, so the field is
    # empty and the conformance report passes. See _REPORTED_NOT_RECORDED.
    "k1_capture_callee_warn_default": (
        True, {"reveal": [], "leak": [], "main": []}, [], True,
    ),
    "n1_clean": (True, {"main": []}, [], True),
    # Authorized disclosure: the field is (correctly) empty; the policy
    # refuses on declassify + egress co-residence, a separate rule.
    "n3_declassified": (True, {"main": []}, [], False),
    "trap_strict": (True, {"main": []}, [], True),
}


# Members whose --check EMITS an information-flow warning while the field
# stays empty: the check reported the flow, the recorder did not record it.
# The sentence states this case; the pin below holds both halves, so the
# day the recorder attributes such a flow the row above flips, this pin
# flips, and the sentence is re-derived rather than silently outgrown.
_REPORTED_NOT_RECORDED = ("k1_capture_callee_warn_default",)


class TestMembers(_CorpusProjects):
    def test_corpus_and_table_agree(self):
        self.assertEqual(_corpus_names(), sorted(_MEMBERS))

    def test_reported_but_not_recorded_members_warn_and_stay_empty(self):
        for name in _REPORTED_NOT_RECORDED:
            with self.subTest(program=name):
                rc, _out, err = _cli(self.roots[name], "--check")
                self.assertEqual(rc, 0, err)
                self.assertIn(
                    "information-flow", err,
                    "the warn-tier check no longer reports this flow",
                )
                docs = _documents(self.roots[name])
                recorded = [
                    s for f in docs["--manifest"]["functions"]
                    for s in f["unaudited_secret_sinks"]
                ]
                self.assertEqual(
                    recorded, [],
                    "the recorder now attributes this reported flow: "
                    "re-derive the scope sentence and move this member",
                )

    def test_current_values_pinned(self):
        for name, (accepted, sinks, caps, passes) in _MEMBERS.items():
            with self.subTest(program=name):
                docs = _documents(self.roots[name])
                self.assertEqual(docs is not None, accepted, name)
                if docs is None:
                    continue
                observed = {
                    f["name"]: [
                        (s["capability"], s["pos"])
                        for s in f["unaudited_secret_sinks"]
                    ]
                    for f in docs["--manifest"]["functions"]
                }
                self.assertEqual(observed, sinks)
                packages = docs["--compose-sbom"]["packages"]
                self.assertEqual(len(packages), 1)
                self.assertEqual(
                    packages[0]["unaudited_secret_sink_capabilities"], caps,
                )
                self.assertEqual(docs["--conformance-report"]["pass"], passes)

    def test_gate_and_refusal_track_the_table(self):
        for name, (accepted, _sinks, _caps, passes) in _MEMBERS.items():
            with self.subTest(program=name):
                rc, out, _err = _cli(self.roots[name], "--manifest")
                if not accepted:
                    self.assertNotEqual(rc, 0)
                    self.assertEqual(out, "", "a refused program emitted an artefact")
                    continue
                self.assertEqual(rc, 0)
                rc, _out, _err = _cli(self.roots[name], "--check-policies")
                self.assertEqual(rc, 0 if passes else 1)

    def test_positive_and_negative_members_differ(self):
        # The discriminating control: a listed program and a clean one
        # must not produce the same value, or an empty result proves
        # nothing about the instrument.
        listed = _documents(self.roots["d1_direct_default"])
        clean = _documents(self.roots["n1_clean"])
        self.assertNotEqual(
            listed["--manifest"]["functions"][-1]["unaudited_secret_sinks"],
            clean["--manifest"]["functions"][-1]["unaudited_secret_sinks"],
        )
        self.assertNotEqual(
            listed["--conformance-report"]["pass"],
            clean["--conformance-report"]["pass"],
        )

    def test_other_artefacts_carry_no_member_of_the_family(self):
        linked, result, filename = _analyse(self.roots["d1_direct_default"])
        self.assertTrue(result.ok)
        ts = "2026-01-01T00:00:00Z"
        source = Path(filename).read_text(encoding="utf-8")
        others = {
            "--cyclonedx": build_cyclonedx(
                linked.module, filename=filename, timestamp=ts,
            ),
            "--spdx": build_spdx(linked.module, filename=filename, timestamp=ts),
            "--vex": build_vex_document(
                linked.module, filename=filename, timestamp=ts,
            ),
            "--provenance": build_provenance(
                source, filename=filename, started_on=ts, finished_on=ts,
            ),
            "--doc": build_html(linked.module, filename=filename),
        }
        for flag, doc in others.items():
            with self.subTest(flag=flag):
                text = doc if isinstance(doc, str) else json.dumps(doc)
                self.assertNotIn("unaudited", text)


# ---------------------------------------------------------------------------
# Derivation: every claim-bearing key is classified; ANALYSIS keys carry
# their scope in band
# ---------------------------------------------------------------------------

EXACT = "EXACT"          # true by construction (declared, or computed exactly)
BOUNDED = "BOUNDED"      # a sound over-approximation that declares its direction
ANALYSIS = "ANALYSIS"    # what an analysis REPORTED; needs an in-band scope
ANNOTATION = "ANNOTATION"  # records a marking, not an analysis outcome

# A key is claim-bearing when its leaf name carries the vocabulary an
# auditor reads as a security claim. Descendants of a classified key are
# its facts and are not classified separately.
_CLAIM_VOCABULARY = re.compile(
    r"secret|declass|audit|flow|capabilit|unsafe|constant_time|authority"
    r"|path_arg|^pass$",
)


def _derivation_table(scope_key: str) -> dict:
    """document flag -> {key path: (class, in-band scope path, facts path)};
    the last two are None unless the class is ANALYSIS."""
    scope = f"/{scope_key}"
    surface = "/compiler_derived_path_arg_surface"
    return {
        "--manifest": {
            surface: (ANALYSIS, f"{surface}/note", f"{surface}/arguments"),
            "/functions[]/authority_provable_from_types": (EXACT, None, None),
            "/functions[]/calls[]/args_flow": (EXACT, None, None),
            "/functions[]/ceiling_authority_provable": (EXACT, None, None),
            "/functions[]/constant_time": (ANNOTATION, None, None),
            "/functions[]/declared_capabilities": (EXACT, None, None),
            "/functions[]/declassifications": (EXACT, None, None),
            "/functions[]/has_unsafe": (EXACT, None, None),
            "/functions[]/params[]/is_capability": (EXACT, None, None),
            "/functions[]/provably_excluded_capabilities": (BOUNDED, None, None),
            "/functions[]/transitively_reachable_capabilities": (BOUNDED, None, None),
            "/functions[]/unaudited_secret_sinks": (
                ANALYSIS, scope, "/functions[]/unaudited_secret_sinks[]/capability",
            ),
            "/module_declassifications": (EXACT, None, None),
            "/summary/declassification_sites": (EXACT, None, None),
            "/summary/functions_crossing_unsafe": (EXACT, None, None),
            "/summary/functions_with_capabilities": (EXACT, None, None),
            "/user_defined_capabilities": (EXACT, None, None),
        },
        "--compose-sbom": {
            "/capability_ceilings": (BOUNDED, None, None),
            "/composed/authority_unknown": (EXACT, None, None),
            "/composed/authority_unknown_reasons": (EXACT, None, None),
            "/composed/capabilities": (BOUNDED, None, None),
            "/composed/declassification_sites": (EXACT, None, None),
            "/composed/has_declassification": (EXACT, None, None),
            "/packages[]/attributed_capabilities": (BOUNDED, None, None),
            "/packages[]/attributed_declassification_sites": (EXACT, None, None),
            "/packages[]/attributed_declassifications": (EXACT, None, None),
            "/packages[]/attributed_unaudited_secret_sinks": (
                ANALYSIS, scope,
                "/packages[]/attributed_unaudited_secret_sinks[]/capability",
            ),
            "/packages[]/authority_unknown": (EXACT, None, None),
            "/packages[]/authority_unknown_reasons": (EXACT, None, None),
            "/packages[]/composed_authority_unknown": (EXACT, None, None),
            "/packages[]/composed_capabilities": (BOUNDED, None, None),
            "/packages[]/composed_declassification_sites": (EXACT, None, None),
            "/packages[]/composed_has_declassification": (EXACT, None, None),
            "/packages[]/unaudited_secret_sink_capabilities": (
                ANALYSIS, scope,
                "/packages[]/attributed_unaudited_secret_sinks[]/capability",
            ),
        },
        "--conformance-report": {
            # The declared egress set and a positively observed violation's
            # capability are exact; a pass is only as strong as the weakest
            # fact it quantifies over, and no-secret-egress quantifies over
            # the ANALYSIS-class family, so it carries the scope in band.
            "/policies[]/capabilities": (EXACT, None, None),
            "/results[]/violations[]/capability": (EXACT, None, None),
            "/pass": (ANALYSIS, scope, "/results[]/pass"),
            "/results[]/pass": (ANALYSIS, scope, "/results[]/violations"),
        },
    }


def _claim_paths(observed: set, scope_key: str) -> set:
    """The outermost observed paths whose leaf carries the claim
    vocabulary. Descendants of a claim-bearing key are its facts, and the
    in-band scope statement itself is not a claim."""
    def leaf(path: str) -> str:
        return path.rsplit("/", 1)[1].replace("[]", "")

    def parents(path: str):
        parts = path.replace("[]", "").split("/")[1:]
        for n in range(1, len(parts)):
            yield "/" + "/".join(parts[:n])

    bearing = {
        p for p in observed
        if _CLAIM_VOCABULARY.search(leaf(p)) and leaf(p) != scope_key
    }
    flat = {p.replace("[]", "") for p in bearing}
    return {
        p for p in bearing
        if not any(parent in flat for parent in parents(p))
    }


class TestDerivation(_CorpusProjects):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.observed = {flag: set() for flag in _DOCUMENT_FLAGS}
        for root in cls.roots.values():
            docs = _documents(root)
            if docs is None:
                continue
            for flag, doc in docs.items():
                _key_paths(doc, "", cls.observed[flag])

    def test_every_claim_bearing_key_is_classified(self):
        key, _ = _scope()
        table = _derivation_table(key)
        for flag in table:
            with self.subTest(document=flag):
                self.assertEqual(
                    _claim_paths(self.observed[flag], key), set(table[flag]),
                    "a claim-bearing key is emitted without a derivation "
                    "class, or a classified key is no longer emitted",
                )

    def test_analysis_class_keys_carry_their_scope_in_band(self):
        key, _ = _scope()
        table = _derivation_table(key)
        for flag, entries in table.items():
            for path, (cls, scope, facts) in entries.items():
                if cls != ANALYSIS:
                    continue
                with self.subTest(document=flag, key=path):
                    self.assertIn(scope, self.observed[flag])
                    self.assertIn(facts, self.observed[flag])

    def test_the_family_is_analysis_class_and_shares_the_one_scope(self):
        key, _ = _scope()
        table = _derivation_table(key)
        family = [
            (flag, path)
            for flag, entries in table.items()
            for path in entries
            if "unaudited_secret_sink" in path
        ]
        self.assertEqual(len(family), 3, family)
        for flag, path in family:
            cls, scope, _facts = table[flag][path]
            self.assertEqual((cls, scope), (ANALYSIS, f"/{key}"), (flag, path))

    def test_digest_form_derives_from_the_manifest(self):
        # --manifest-digest adds only the envelope: every other key path
        # is the manifest's, so it needs no producer of its own.
        digest = {
            p for p in self.observed["--manifest-digest"]
            if not p.startswith(f"/{CONTENT_INTEGRITY_KEY}")
        }
        self.assertEqual(digest, self.observed["--manifest"])


# ---------------------------------------------------------------------------
# Producers: three call sites, all on the non-strict branch
# ---------------------------------------------------------------------------


def _record_calls():
    """Every call to ``_record_unaudited_secret_sink`` in the package, with
    the branch of its INNERMOST enclosing ``if`` and that test's source."""
    calls = []
    for path in sorted(PACKAGE.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), str(path))
        parents = {
            child: node
            for node in ast.walk(tree)
            for child in ast.iter_child_nodes(node)
        }
        for node in ast.walk(tree):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "_record_unaudited_secret_sink"
            ):
                continue
            branch, test = None, ""
            cur = node
            while cur in parents:
                par = parents[cur]
                if isinstance(par, ast.If):
                    branch = "body" if cur in par.body else "orelse"
                    test = ast.unparse(par.test)
                    break
                cur = par
            calls.append((
                path.relative_to(REPO_ROOT).as_posix(), node.lineno, branch, test,
            ))
    return calls


class TestProducers(unittest.TestCase):
    def test_three_producers_each_on_the_non_strict_branch(self):
        calls = _record_calls()
        self.assertEqual(len(calls), 3, calls)
        for rel, lineno, branch, test in calls:
            with self.subTest(site=f"{rel}:{lineno}"):
                self.assertEqual(rel, "capa/analyzer/_ifc.py")
                self.assertEqual(branch, "orelse")
                self.assertIn("_strict_ifc", test)


if __name__ == "__main__":
    unittest.main()
