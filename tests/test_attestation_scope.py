"""What the ``unaudited_secret_sinks`` family is entitled to claim.

Five artefacts carry the per-function ``unaudited_secret_sinks`` fact or
a value derived from it: ``--manifest``, ``--manifest-digest``,
``--compose-sbom`` (``attributed_unaudited_secret_sinks`` /
``unaudited_secret_sink_capabilities``), ``--conformance-report`` and the
``--check-policies`` gate (``no-secret-egress``). What the fact is entitled
to claim is the ONE sentence of :mod:`capa.manifest._scope`; each of the
four documents carries it under one top-level key, and
``docs/trust-model.md`` carries a block generated from the same constant
by ``tools/gen_trust_register.py``.

The corpus in ``tests/fixtures/attestation_scope`` holds two shapes: each
``*.capa`` program is wrapped as a one-package project declaring a
``no-secret-egress`` policy over ``Stdio``, and each directory under
``projects/`` is a whole project with its own policies and, where named,
``vendor/`` packages, for the clauses a one-package wrapper cannot reach
(where a record sits across packages, what a recorded name means). Seven
groups of pins:

- characterization (RED before the key and the constant existed): the key
  is present, byte-equal to the constant in all four documents, the
  content-integrity envelopes still verify, the register block is
  generated and the generator's check passes, the register carries
  exactly one block and states the field nowhere outside it, the
  generator refuses to run against a capa that is not the checkout it
  sits in, and the wording keeps its load-bearing clauses while naming no
  tier as covering anything;
- universe: the capability sets the sentence names are DERIVED from the
  declared tables (the recordable set from the sink table and the one
  panic capability, the never-recordable set from the policy ceiling
  minus it) and hold their current values, the sentence renders every
  derived name in its clause and types none by hand, the renderer refuses
  an empty set, both panic producers read the one panic capability, the
  policy reader quantifies over the two axes the sentence covers, and
  every hand copy of the sink table in ``docs/`` and ``specs/`` equals it;
- single source: the sentence's text lives in exactly one module, every
  producer references the constant by name, and no other document in the
  repository restates it;
- members: the CURRENT value of the field, the composed sink-capability
  set and the conformance verdict for every corpus program, including the
  explicit misses pinned as ``[]`` and the reported-but-not-recorded
  members pinned as warning AND empty, so a silent widening or narrowing
  of the VALUE turns red and must be reconciled with the sentence;
- reconciliation: every warn-tier secret-to-sink diagnostic of the corpus
  is recorded at its position or listed with the reason the sentence
  gives, and every record has a diagnostic;
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
from types import SimpleNamespace
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
PROJECTS = CORPUS / "projects"
GENERATOR = REPO_ROOT / "tools" / "gen_trust_register.py"
REGISTER = REPO_ROOT / "docs" / "trust-model.md"

_DOCUMENT_FLAGS = (
    "--manifest", "--manifest-digest", "--compose-sbom", "--conformance-report",
)

# Every wrapped single-file program declares the same egress policy: Stdio
# is the one sink each of them can reach. A whole project brings its own.
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


def _universe() -> SimpleNamespace:
    """The derived sets the sentence renders, the renderer, and the one
    panic sink capability. A missing name is the RED-first reason of every
    universe pin below."""
    try:
        from capa.analyzer._ifc_tables import _PANIC_SINK_CAP
        from capa.manifest._scope import (
            UNAUDITED_SECRET_SINKS_NEVER_RECORDABLE_POLICY_CAPABILITIES,
            UNAUDITED_SECRET_SINKS_RECORDABLE_CAPABILITIES,
            UNAUDITED_SECRET_SINKS_SINK_METHODS,
            _name_list,
        )
    except ImportError as e:  # pragma: no cover - the RED-first state
        raise AssertionError(
            f"the scope module does not derive the field's universe: {e}",
        ) from e
    return SimpleNamespace(
        panic=_PANIC_SINK_CAP,
        recordable=UNAUDITED_SECRET_SINKS_RECORDABLE_CAPABILITIES,
        never=UNAUDITED_SECRET_SINKS_NEVER_RECORDABLE_POLICY_CAPABILITIES,
        methods=UNAUDITED_SECRET_SINKS_SINK_METHODS,
        name_list=_name_list,
    )


def _collapse(text: str) -> str:
    return " ".join(text.split())


def _corpus_names() -> list[str]:
    return sorted(p.stem for p in CORPUS.glob("*.capa"))


def _project_names() -> list[str]:
    return sorted(p.name for p in PROJECTS.iterdir() if (p / "main.capa").is_file())


def _copy_project(base: Path, name: str) -> Path:
    root = base / name
    shutil.copytree(PROJECTS / name, root)
    return root


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
    # A project's vendored packages resolve the way the package manager
    # lays them out, beside the root's own modules.
    search = [root, *sorted(v for v in root.rglob("vendor") if v.is_dir())]
    filename = str(root / "main.capa")
    source = Path(filename).read_text(encoding="utf-8")
    linked = ModuleLoader(search_paths=search).load_root(source, filename)
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
    """Drive the real CLI in-process on ``<root>/main.capa`` from the
    project root, as a user runs it (the CLI reads ``capa.toml`` and the
    vendored dependencies from the working directory). Returns
    ``(rc, stdout, stderr)``."""
    from capa.cli import main
    out, err = io.StringIO(), io.StringIO()
    argv = ["capa", *flags, str(root / "main.capa")]
    original_cwd = os.getcwd()
    try:
        os.chdir(str(root))
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
    finally:
        os.chdir(original_cwd)
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
    """One temporary project per corpus program, built once per class: the
    wrapped single-file programs and a copy of every whole project."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory(prefix="capa_scope_")
        base = Path(cls._tmp.name)
        clash = set(_corpus_names()) & set(_project_names())
        assert not clash, f"a program and a project share a name: {clash}"
        cls.roots = {name: _make_project(base, name) for name in _corpus_names()}
        cls.roots.update(
            (name, _copy_project(base, name)) for name in _project_names()
        )

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

    def test_sentence_renders_the_field_universe_in_its_clauses(self):
        # Each derived set is rendered, by the module's own renderer, inside
        # the clause that states it: a set dropped from its clause or moved
        # to another one is RED, not only a name gone missing.
        _, sentence = _scope()
        u = _universe()
        text = _collapse(sentence)
        for clause in (
            "The check recognizes as sinks only the built-in methods "
            f"{u.name_list(u.methods, ', ')} and the panic builtin",
            f"recorded as {u.panic} whether or not the function holds {u.panic}",
            "a recorded capability is always one of "
            f"{u.name_list(u.recordable, ', ')},",
            "a no-secret-egress policy that names only "
            f"{u.name_list(u.never, ' or ')} has nothing in this field to match",
        ):
            self.assertIn(clause, text, "a derived set is not rendered in its clause")
        low = text.lower()
        for phrase in (
            "any other operation is outside this field",
            "its declassify co-residence check still applies to those names",
            "and that list is not closed",
        ):
            self.assertIn(phrase, low, f"missing clause: {phrase!r}")

    def test_sentence_states_where_a_record_sits_and_what_its_name_means(self):
        _, sentence = _scope()
        low = _collapse(sentence).lower()
        for phrase in (
            "neither is one reported outside every function body",
            "through a callee it matches a sink by method name, not receiver type",
            "a recorded name is not evidence that the package holds that capability",
            "recorded against the function in whose body the check saw the "
            "@secret value, and that function's package",
            "at the caller for a @secret argument whose callee sink the "
            "analysis attributed",
            "inside the callee for a parameter or field the callee declares "
            "@secret",
            "one flow may be recorded against the caller, the callee or both",
            "a policy scoped to a package sees only the records charged to "
            "that package",
        ):
            self.assertIn(phrase, low, f"missing clause: {phrase!r}")
        # Two wordings measured false or ambiguous on programs that compile:
        # a callee that declares its parameter @secret holds the record
        # itself, and the co-residence half of the same policy does flag the
        # capability names the field never records.
        for phrase in ("never against the callee", "can never flag"):
            self.assertNotIn(phrase, low, f"measured-false wording: {phrase!r}")


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
        # Exactly one marker pair: a second block, however worded, would
        # carry a copy the generator never checks.
        self.assertEqual(
            (text.count(gen.BEGIN), text.count(gen.END)), (1, 1),
            "docs/trust-model.md carries more than one register block",
        )
        block = text.split(gen.BEGIN, 1)[1].split(gen.END, 1)[0]
        self.assertIn(
            _collapse(sentence), _collapse(block),
            "register block does not match the constant (stale copy)",
        )

    def test_register_states_the_field_only_inside_the_generated_block(self):
        # The register document is the one file the restatement pin below
        # expects to hit, so it must be held on its own: outside the
        # generated block it may not mention the field at all, nor carry a
        # tier claim, or a hand-written restatement beside the block would
        # pass every other pin.
        gen = self._generator()
        text = REGISTER.read_text(encoding="utf-8")
        head, rest = text.split(gen.BEGIN, 1)
        _block, tail = rest.split(gen.END, 1)
        outside = _collapse(head + tail).lower()
        self.assertNotIn(
            "unaudited_secret_sinks", outside,
            "docs/trust-model.md restates the field outside the generated block",
        )
        # A claim that implicit flows are covered, in either word order,
        # within one sentence.
        for pattern in (
            r"implicit[^.]{0,80}\bcover(ed|s)\b", r"\bcover(ed|s)\b[^.]{0,80}implicit",
        ):
            self.assertIsNone(re.search(pattern, outside), f"tier claim: {pattern}")

    def test_generator_refuses_a_foreign_capa(self):
        # A copy of tools/ and docs/ with no capa/ beside them, and another
        # tree's capa importable through PYTHONPATH: the generator must
        # refuse to verify or regenerate against that tree's constant, and
        # the document must be left untouched.
        gen = self._generator()
        with tempfile.TemporaryDirectory(prefix="capa_gen_") as tmp:
            root = Path(tmp)
            (root / "tools").mkdir()
            (root / "docs").mkdir()
            shutil.copyfile(GENERATOR, root / "tools" / GENERATOR.name)
            shutil.copyfile(REGISTER, root / "docs" / REGISTER.name)
            before = (root / "docs" / REGISTER.name).read_bytes()
            env = dict(os.environ, PYTHONPATH=str(REPO_ROOT), PYTHONIOENCODING="utf-8")
            for args in (["--check"], []):
                with self.subTest(args=args):
                    proc = subprocess.run(
                        [sys.executable, str(root / "tools" / GENERATOR.name), *args],
                        cwd=str(root), env=env, stdin=subprocess.DEVNULL,
                        capture_output=True, text=True, timeout=120,
                    )
                    self.assertEqual(
                        proc.returncode, gen.EXIT_FOREIGN_CAPA,
                        f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}",
                    )
                    self.assertIn("refus", proc.stderr.lower())
                    self.assertEqual(
                        (root / "docs" / REGISTER.name).read_bytes(), before,
                        "the generator wrote the document from a foreign capa",
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
# Universe: every name the sentence carries is derived from a declared table
# ---------------------------------------------------------------------------


def _template_literals() -> list[str]:
    """Every string literal of the sentence's template in ``_scope.py``: the
    prose the renderer joins to the rendered names."""
    path = PACKAGE / "manifest" / "_scope.py"
    tree = ast.parse(path.read_text(encoding="utf-8"), str(path))
    for node in tree.body:
        if isinstance(node, ast.Assign):
            targets = node.targets
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
        else:
            continue
        if any(
            isinstance(t, ast.Name) and t.id == "UNAUDITED_SECRET_SINKS_SCOPE"
            for t in targets
        ):
            return [
                c.value for c in ast.walk(node.value)
                if isinstance(c, ast.Constant) and isinstance(c.value, str)
            ]
    raise AssertionError("no UNAUDITED_SECRET_SINKS_SCOPE assignment in _scope.py")


# The capability argument of the recorder and of the summary's sink
# capability attribution, by position.
_CAPABILITY_ARGUMENT = {"_record_unaudited_secret_sink": 0, "_attribute_sink_caps": 1}


def _capability_arguments():
    """``(module, line, enclosing function, enclosing if-test, argument)``
    for every capability argument the package passes to the recorder or to
    the summary's attribution, found over the AST."""
    out = []
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
                and node.func.attr in _CAPABILITY_ARGUMENT
                and len(node.args) > _CAPABILITY_ARGUMENT[node.func.attr]
            ):
                continue
            function, tests, cur = "", [], node
            while cur in parents:
                cur = parents[cur]
                if isinstance(cur, ast.If):
                    tests.append(ast.unparse(cur.test))
                if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    function = cur.name
                    break
            out.append((
                path.relative_to(REPO_ROOT).as_posix(), node.lineno, function,
                " ".join(tests), node.args[_CAPABILITY_ARGUMENT[node.func.attr]],
            ))
    return out


# The hand copies of the sink table that ``docs/`` and ``specs/`` keep. The
# pin below finds every passage naming more than half of the table's methods
# and holds each to the table; registering the files here is what turns a
# rewording the parser can no longer read into a failure instead of a copy
# nothing checks.
_SINK_TABLE_COPIES = frozenset({
    "docs/reference.md",
    "docs/semantics.md",
    "specs/15-ifc-model-and-labels.md",
})


def _sink_mentions(text: str) -> set:
    """Every ``(Capability, method)`` a passage names in backticks:
    ``Cap.method`` in any case of the capability, and the
    ``Cap.method`` / ``method`` shorthand continuing the same capability."""
    from capa.typesys import CAPABILITY_NAMES
    by_lower = {c.lower(): c for c in CAPABILITY_NAMES}
    run = re.compile(
        rf"`({'|'.join(sorted(by_lower))})\.(\w+)`((?:\s*/\s*`\w+`)*)",
        re.IGNORECASE,
    )
    found = set()
    for cap, meth, rest in run.findall(text):
        owner = by_lower[cap.lower()]
        found.add((owner, meth))
        found.update((owner, m) for m in re.findall(r"`(\w+)`", rest))
    return found


def _sink_table_passages():
    """``(document, passage, mentions)`` for every paragraph of every Markdown
    document under ``docs/`` and ``specs/`` that names more than half of the
    sink table's methods."""
    from capa.analyzer._ifc_tables import _PUBLIC_SINKS
    table = set(_PUBLIC_SINKS)
    documents = sorted([
        *(REPO_ROOT / "docs").rglob("*.md"), *(REPO_ROOT / "specs").rglob("*.md"),
    ])
    for path in documents:
        text = path.read_text(encoding="utf-8", errors="replace")
        for passage in re.split(r"\n[ \t]*\n", text):
            mentions = _sink_mentions(passage)
            if 2 * len(mentions & table) > len(table):
                yield path.relative_to(REPO_ROOT).as_posix(), passage, mentions


class TestUniverse(unittest.TestCase):
    """The sets the sentence names are derived, never typed: the recordable
    capabilities from the sink table and the one panic capability, the
    never-recordable ones from the policy ceiling minus those, the methods
    from the sink table."""

    def test_recordable_set_is_the_sink_table_capabilities_and_the_panic_one(self):
        from capa.analyzer._ifc_tables import _PUBLIC_SINKS
        u = _universe()
        self.assertEqual(
            u.recordable, frozenset(cap for cap, _m in _PUBLIC_SINKS) | {u.panic},
        )

    def test_never_recordable_set_is_the_policy_ceiling_minus_the_recordable(self):
        from capa.pkg._manifest import _CEILING_CAP_NAMES
        u = _universe()
        self.assertEqual(u.never, frozenset(_CEILING_CAP_NAMES) - u.recordable)

    def test_sink_methods_are_the_sink_table(self):
        from capa.analyzer._ifc_tables import _PUBLIC_SINKS
        u = _universe()
        self.assertEqual(
            u.methods, tuple(sorted(f"{cap}.{meth}" for cap, meth in _PUBLIC_SINKS)),
        )

    def test_derived_sets_hold_their_current_values(self):
        # A capability added to or moved between the declared sets re-renders
        # the sentence; this turns RED so the sentence is re-read with the
        # new value, not silently outgrown.
        u = _universe()
        self.assertEqual(u.recordable, frozenset({"Db", "Fs", "Net", "Serve", "Stdio"}))
        self.assertEqual(u.never, frozenset({"Clock", "Env", "Proc", "Random"}))

    def test_renderer_refuses_an_empty_set(self):
        u = _universe()
        for joiner in (", ", " or "):
            with self.subTest(joiner=joiner):
                with self.assertRaises(ValueError):
                    u.name_list(frozenset(), joiner)
        # The legitimate forms stay accepted.
        self.assertEqual(u.name_list({"Proc"}, " or "), "Proc")
        self.assertEqual(u.name_list({"Random", "Clock"}, " or "), "Clock or Random")
        self.assertEqual(u.name_list(["Net", "Db", "Fs"], ", "), "Db, Fs, Net")

    def test_template_types_no_capability_or_method_name(self):
        from capa.analyzer._ifc_tables import _PUBLIC_SINKS
        from capa.typesys import CAPABILITY_NAMES
        literals = _template_literals()
        self.assertTrue(literals)
        text = " ".join(literals)
        for cap in sorted(CAPABILITY_NAMES):
            self.assertIsNone(
                re.search(rf"\b{cap}\b", text),
                f"capability {cap} typed by hand in the sentence template",
            )
        for cap, meth in sorted(_PUBLIC_SINKS):
            self.assertNotIn(f"{cap}.{meth}", text)

    def test_no_producer_types_a_capability_name(self):
        arguments = _capability_arguments()
        self.assertTrue(arguments, "no recorder or attribution call found")
        for rel, lineno, _function, _tests, argument in arguments:
            with self.subTest(site=f"{rel}:{lineno}"):
                literals = [
                    c.value for c in ast.walk(argument)
                    if isinstance(c, ast.Constant) and isinstance(c.value, str)
                ]
                self.assertEqual(literals, [], "a producer types a capability name")

    def test_both_panic_producers_read_the_one_panic_capability(self):
        # The direct site records inside ``_check_ifc_panic_sink``; the callee
        # summary attributes inside the branch that recognizes the builtin.
        sites = [
            (rel, lineno, argument)
            for rel, lineno, function, tests, argument in _capability_arguments()
            if function == "_check_ifc_panic_sink" or "'panic'" in tests
        ]
        self.assertEqual(
            sorted(rel for rel, _lineno, _argument in sites),
            ["capa/analyzer/_ifc.py", "capa/analyzer/_ifc_summary.py"],
            "the two panic producer sites are not where this pin looks",
        )
        for rel, lineno, argument in sites:
            with self.subTest(site=f"{rel}:{lineno}"):
                self.assertIn(
                    "_PANIC_SINK_CAP",
                    {n.id for n in ast.walk(argument) if isinstance(n, ast.Name)},
                )

    def test_policy_reader_quantifies_over_the_two_axes_the_sentence_covers(self):
        # A third key on no-secret-egress is a third axis a reader can
        # quantify over, which the sentence does not state.
        from capa.manifest._policy import _KIND_KEYS
        self.assertEqual(
            _KIND_KEYS["no-secret-egress"], frozenset({"capabilities", "package"}),
        )

    def test_every_sink_table_copy_in_docs_and_specs_matches_the_table(self):
        from capa.analyzer._ifc_tables import _PUBLIC_SINKS
        table = set(_PUBLIC_SINKS)
        found = list(_sink_table_passages())
        self.assertEqual(
            {document for document, _passage, _mentions in found},
            set(_SINK_TABLE_COPIES),
            "a copy of the sink table appeared or is no longer recognized",
        )
        for document, passage, mentions in found:
            with self.subTest(copy=document):
                self.assertEqual(
                    sorted(f"{c}.{m}" for c, m in mentions - table), [],
                    "the copy names a method the sink table does not hold",
                )
                self.assertEqual(
                    sorted(f"{c}.{m}" for c, m in table - mentions), [],
                    "the copy lacks a method of the sink table",
                )
                # A copy that states argument positions, as a table row
                # ``| `Cap.m` | `{0, 1}` |``, states the table's.
                for line in passage.splitlines():
                    cells = line.strip().strip("|").split("|")
                    if not line.lstrip().startswith("|") or len(cells) < 2:
                        continue
                    stated = re.search(r"\{([\d,\s]*)\}", cells[1])
                    if not stated:
                        continue
                    positions = {
                        int(x) for x in stated.group(1).split(",") if x.strip()
                    }
                    for key in sorted(_sink_mentions(cells[0]) & table):
                        self.assertEqual(
                            positions, set(_PUBLIC_SINKS[key]),
                            f"sink positions of {key[0]}.{key[1]}",
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
        # And exactly once in the register: a second copy in the same file
        # would otherwise hide behind the expected hit.
        self.assertEqual(
            _collapse(REGISTER.read_text(encoding="utf-8")).lower().count(probe), 1,
            "docs/trust-model.md carries the sentence more than once",
        )


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


# Whole-project members: name -> (
#     {function name: [(sink capability, pos), ...]} in the manifest,
#     {package: (unaudited_secret_sink_capabilities, composed_capabilities)},
#     {policy id: pass},
# )
# The CURRENT values of the clauses a one-package wrapper cannot reach. The
# day one moves (a record charged elsewhere, a name gated by receiver type,
# a policy reader that flags a name the field never records), this table
# and the sentence are re-derived together.
_PROJECT_MEMBERS = {
    # Where a record sits. A @secret argument to an unlabelled callee
    # parameter is recorded at the caller only, so a policy scoped to a
    # package further down the chain sees nothing, at any depth.
    "locus_caller_unlabelled": (
        {"emit": [], "main": [("Stdio", "5:22")]},
        {"rootpkg": (["Stdio"], ["Env", "Stdio"]), "sinkpkg": ([], ["Stdio"])},
        {"nse_root": False, "nse_sink": True, "nse_all": False},
    ),
    "locus_two_level": (
        {"emit": [], "forward": [], "main": [("Stdio", "5:24")]},
        {
            "midpkg": ([], ["Stdio"]),
            "rootpkg": (["Stdio"], ["Env", "Stdio"]),
            "sinkpkg": ([], ["Stdio"]),
        },
        {"nse_root": False, "nse_mid": True, "nse_sink": True, "nse_all": False},
    ),
    # A callee that declares its parameter @secret holds a record of its own:
    # beside the caller's when it sinks the parameter directly, alone when it
    # sinks it through a local closure, and then a policy scoped to the
    # caller's package sees nothing.
    "locus_secret_param_both": (
        {"emit": [("Stdio", "2:19")], "main": [("Stdio", "5:22")]},
        {"rootpkg": (["Stdio"], ["Env", "Stdio"]), "sinkpkg": (["Stdio"], ["Stdio"])},
        {"nse_root": False, "nse_sink": False, "nse_all": False},
    ),
    "locus_secret_param_callee_only": (
        {"emit": [("Stdio", "3:7")], "main": []},
        {"rootpkg": ([], ["Env", "Stdio"]), "sinkpkg": (["Stdio"], ["Stdio"])},
        {"nse_root": True, "nse_sink": False, "nse_all": False},
    ),
    # What a recorded name means. Through a callee a sink is matched by
    # method name, so Map.get and a user type's post are recorded as Net in
    # a package that holds no Net.
    "name_map_get": (
        {"look": [], "main": [("Net", "7:21")]},
        {"rootpkg": (["Net"], ["Env", "Stdio"])},
        {"nse_net": False},
    ),
    "name_user_method": (
        {"main": [("Net", "12:37")], "post": [], "send": []},
        {"rootpkg": (["Net"], ["Env", "Stdio"])},
        {"nse_net": False},
    ),
    # panic is recorded under the panic sink capability whether or not the
    # function holds it, at the direct site and through a callee.
    "panic_without_stdio": (
        {"main": [("Stdio", "3:11")]},
        {"rootpkg": (["Stdio"], ["Env"])},
        {"nse_all": False},
    ),
    "panic_in_callee": (
        {"boom": [], "main": [("Stdio", "6:10")]},
        {"rootpkg": (["Stdio"], ["Env"])},
        {"nse_all": False},
    ),
    # Reported but recorded nowhere: the flow sits in a module-level const
    # initializer, outside every function body (see _REPORTED_NOT_RECORDED).
    "const_initializer": (
        {"main": []},
        {"rootpkg": ([], ["Stdio"])},
        {"nse_all": True},
    ),
    # A policy over capability names the field never records has nothing in
    # it to match, beside a record it does carry ...
    "policy_names_outside_field": (
        {"main": [("Stdio", "3:19")]},
        {"rootpkg": (["Stdio"], ["Env", "Stdio"])},
        {"nse_proc": True, "nse_clock_env_random": True, "nse_stdio": False},
    ),
    # ... while the co-residence half of the same policy kind still flags
    # such a name: a package that declassifies and holds Proc.
    "co_residence_proc": (
        {"main": []},
        {"rootpkg": ([], ["Env", "Proc", "Stdio"])},
        {"nse_proc": False},
    ),
}


# Every warn-tier secret-to-sink diagnostic of the corpus with no record at
# its position: program -> {(file, line, col): reason}. Each reason is a
# phrase of the scope sentence, so a row cannot cite a reason the artefact
# does not state, and a row whose diagnostic is gone or whose flow is now
# recorded is stale and fails: the sentence is then re-derived rather than
# silently outgrown. The members listed here also --check with a warning
# while the field stays empty (the pin right below).
_REPORTED_NOT_RECORDED = {
    # The capture-carried callee sink: no sink capability is attributed.
    "k1_capture_callee_warn_default": {
        ("main.capa", 10, 5): "whose sink capability the analysis did not attribute",
    },
    # Reported with its capability, outside every function body.
    "const_initializer": {
        ("main.capa", 2, 71): "outside every function body",
    },
}


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


class TestProjectMembers(_CorpusProjects):
    def test_projects_and_table_agree(self):
        self.assertEqual(_project_names(), sorted(_PROJECT_MEMBERS))

    def test_current_values_pinned(self):
        for name, (functions, packages, results) in _PROJECT_MEMBERS.items():
            with self.subTest(project=name):
                docs = _documents(self.roots[name])
                self.assertIsNotNone(docs, "the project no longer compiles")
                records = docs["--manifest"]["functions"]
                observed = {
                    f["name"]: [
                        (s["capability"], s["pos"])
                        for s in f["unaudited_secret_sinks"]
                    ]
                    for f in records
                }
                self.assertEqual(
                    len(observed), len(records),
                    "two functions share a name: key this pin by file",
                )
                self.assertEqual(observed, functions)
                self.assertEqual(
                    {
                        p["name"]: (
                            p["unaudited_secret_sink_capabilities"],
                            p["composed_capabilities"],
                        )
                        for p in docs["--compose-sbom"]["packages"]
                    },
                    packages,
                )
                self.assertEqual(
                    {
                        r["policy"]: r["pass"]
                        for r in docs["--conformance-report"]["results"]
                    },
                    results,
                )

    def test_gate_tracks_the_table(self):
        for name, (_functions, _packages, results) in _PROJECT_MEMBERS.items():
            with self.subTest(project=name):
                rc, _out, err = _cli(self.roots[name], "--check-policies")
                self.assertEqual(rc, 0 if all(results.values()) else 1, err)


# ---------------------------------------------------------------------------
# Reconciliation: every reported flow is recorded, or tabled with a reason
# the sentence states
# ---------------------------------------------------------------------------

# The one warn-tier information-flow diagnostic that is not a secret-to-sink
# flow: a closure whose @secret return label reaches a public-returning
# slot. No sink is reached at that site, so there is nothing to record.
_NOT_A_SINK_FLOW = ("information-flow: a closure that returns a @secret value",)

# The message forms of the three recorder sites (``TestProducers``). The
# corpus must exercise each, or the selection below has drifted from them.
_SINK_FLOW_FORMS = {
    "sink method": re.compile(r"^information-flow: a @secret value reaches \w+\.\w+ "),
    "panic": re.compile(r"^information-flow: a @secret value reaches panic "),
    "callee": re.compile(r"^information-flow: a @secret value is passed to "),
}


def _reconcile(root: Path):
    """``(reported, recorded, forms)`` for one program: the positions of its
    warn-tier secret-to-sink diagnostics and the positions its ``--manifest``
    document records (each function's file taken from that function's own
    ``pos``), both as ``(file relative to the project, line, col)``, and the
    message forms the diagnostics took. None when the program is refused.
    Every other ``information-flow:`` warning counts as a sink flow, so a new
    diagnostic form is reconciled until it is shown not to be one."""
    linked, result, filename = _analyse(root)
    if not result.ok:
        return None
    root = root.resolve()

    def relative(path) -> str:
        return Path(path).resolve().relative_to(root).as_posix()

    reported, forms = set(), set()
    for w in result.warnings:
        if not w.message.startswith("information-flow:"):
            continue
        if w.message.startswith(_NOT_A_SINK_FLOW):
            continue
        reported.add((relative(w.pos.filename or filename), w.pos.line, w.pos.col))
        forms.update(
            form for form, pattern in _SINK_FLOW_FORMS.items()
            if pattern.match(w.message)
        )
    manifest = build_manifest(
        linked.module, filename=filename, bindings=result.bindings,
        expr_labels=result.expr_labels,
        unaudited_secret_sinks=result.unaudited_secret_sinks,
    )
    recorded = set()
    for fn in manifest["functions"]:
        fn_file = fn["pos"].rsplit(":", 2)[0]
        for sink in fn["unaudited_secret_sinks"]:
            line, col = sink["pos"].split(":")
            recorded.add((relative(root / fn_file), int(line), int(col)))
    return reported, recorded, forms


class TestReconciliation(_CorpusProjects):
    def test_every_reported_flow_is_recorded_or_tabled_with_a_stated_reason(self):
        _, sentence = _scope()
        low = _collapse(sentence).lower()
        self.assertLessEqual(set(_REPORTED_NOT_RECORDED), set(self.roots))
        seen_forms = set()
        for name, root in sorted(self.roots.items()):
            with self.subTest(program=name):
                observed = _reconcile(root)
                if observed is None:
                    self.assertNotIn(name, _REPORTED_NOT_RECORDED)
                    continue
                reported, recorded, forms = observed
                seen_forms |= forms
                tabled = _REPORTED_NOT_RECORDED.get(name, {})
                self.assertEqual(
                    reported - recorded, set(tabled),
                    "a reported flow is recorded nowhere and not tabled, or a "
                    "tabled one is recorded or no longer reported",
                )
                self.assertEqual(
                    recorded - reported, set(),
                    "a record with no diagnostic at its position",
                )
                for row, reason in sorted(tabled.items()):
                    self.assertIn(
                        reason, low,
                        f"{row}: the sentence does not state the reason {reason!r}",
                    )
        self.assertEqual(
            seen_forms, set(_SINK_FLOW_FORMS),
            "the corpus no longer exercises every recorder's diagnostic form",
        )


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
