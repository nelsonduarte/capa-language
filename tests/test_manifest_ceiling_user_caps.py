"""A ``[capabilities].max`` ceiling may name a user-defined capability.

A ``capability Notifier`` declaration composes as introduced authority
exactly like a built-in does, so it turns up in a package's composed
capability set. Until this change the ceiling's vocabulary was the
built-in set and nothing else, which left a package that declares one
with no satisfiable ceiling at all: omitting the name failed with

    package 'p' declares max=[...] but its own code introduces 'Notifier'

and naming it failed one layer earlier, at parse time, with

    [capabilities].max names unknown capability(ies): ['Notifier']

Measured on ``capa_claimdesk``, which was red on ``notify.capa`` and
``main.capa`` for exactly this reason (``Notifier``, declared in its own
``notify.capa``, and ``Logger``, coming from ``capa_log``).

What the widened vocabulary must NOT cost, and what each test here pins:

- a name that is neither a built-in nor a declared capability is still
  REFUSED, naming itself, so a typo cannot silently widen the ceiling;
- ``Unsafe`` stays unnameable;
- a capability that arrives from a dependency still BREAKS THE BUILD
  until somebody names it, which is the whole reviewability point;
- a built-in-only ceiling behaves exactly as it did before.

The last class pins the interaction with the self-scoped ceiling rule: a
user capability whose method signature carries a ``Fun`` is marked
authority-not-provable by the reachability pass, so a package that takes
it and DECLARES a ceiling fails closed with ``authority_unknown`` (its own
types cannot prove its authority), whether or not the capability is named
in ``max``.
"""

import shutil
import tempfile
import unittest
from pathlib import Path

from capa import Lexer, Parser, analyze
from capa.loader import ModuleLoader
from capa.manifest import build_composed_sbom, build_manifest
from capa.pkg import ManifestError, read_manifest

# A package declaring its own capability over Stdio: the capa_claimdesk
# ``notify.capa`` shape, reduced to the part the ceiling reacts to.
NOTIFIER_SRC = (
    "pub capability Notifier\n"
    "    fun announce(self, msg: String) -> Unit\n"
    "\n"
    "type StdioNotifier {\n"
    "    out: Stdio\n"
    "}\n"
    "\n"
    "impl Notifier for StdioNotifier\n"
    "    fun announce(self, msg: String) -> Unit\n"
    "        self.out.println(msg)\n"
    "        return\n"
    "\n"
    "pub fun make(io: Stdio) -> StdioNotifier\n"
    "    return StdioNotifier { out: io }\n"
    "\n"
    "pub fun announce_all(n: Notifier) -> Unit\n"
    "    n.announce(\"decided\")\n"
    "    return\n"
)

# The same shape, with a ``Fun`` in the capability's method signature.
# The reachability pass treats that as authority-not-provable.
RUNNER_SRC = (
    "pub capability Runner\n"
    "    fun go(self, task: Fun() -> Unit) -> Unit\n"
    "\n"
    "type StdioRunner {\n"
    "    out: Stdio\n"
    "}\n"
    "\n"
    "impl Runner for StdioRunner\n"
    "    fun go(self, task: Fun() -> Unit) -> Unit\n"
    "        task()\n"
    "        return\n"
    "\n"
    "pub fun make(io: Stdio) -> StdioRunner\n"
    "    return StdioRunner { out: io }\n"
    "\n"
    "pub fun drive(r: Runner, io: Stdio) -> Unit\n"
    "    let task = fun () -> Unit => io.println(\"tick\")\n"
    "    r.go(task)\n"
    "    return\n"
)


def _write(base: Path, rel: str, text: str) -> None:
    p = base / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def _compose(root_dir: Path, root_file: str):
    """Compile ``root_file`` and compose the product SBOM, exactly as
    ``--check-capabilities`` does."""
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
    return manifest, build_composed_sbom(linked.module, manifest, root_dir)


class _TmpTree(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="capa_usercap_"))
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))

    def _notifier_pkg(self, ceiling_block: str, extra_toml: str = "") -> Path:
        root = self.tmp / "claimdesk"
        _write(root, "capa.toml", (
            '[package]\nname = "claimdesk"\nversion = "0.1.0"\n\n'
            + ceiling_block + extra_toml
        ))
        _write(root, "notify.capa", NOTIFIER_SRC)
        return root


class TestDeclaredUserCapabilityIsNameable(_TmpTree):
    """The capa_claimdesk shape: a package that declares a capability can
    put it in its own ceiling, and the product then passes."""

    def test_manifest_accepts_a_declared_user_capability(self):
        root = self._notifier_pkg('[capabilities]\nmax = ["Stdio", "Notifier"]\n')
        m = read_manifest(root / "capa.toml")
        self.assertEqual(
            m.capability_ceiling.max, frozenset({"Stdio", "Notifier"}),
        )

    def test_named_user_capability_passes_the_ceiling(self):
        root = self._notifier_pkg('[capabilities]\nmax = ["Stdio", "Notifier"]\n')
        _manifest, composed = _compose(root, "notify.capa")
        ceilings = composed["capability_ceilings"]
        self.assertTrue(ceilings["checked"])
        self.assertTrue(ceilings["pass"], ceilings["violations"])
        pkg = composed["packages"][0]
        self.assertIn("Notifier", pkg["attributed_capabilities"])
        self.assertEqual(pkg["declared_ceiling"], ["Notifier", "Stdio"])

    def test_omitting_it_still_fails_naming_the_capability(self):
        # The reviewability half: the capability is introduced authority,
        # so a ceiling that does not name it is still breached.
        root = self._notifier_pkg('[capabilities]\nmax = ["Stdio"]\n')
        _manifest, composed = _compose(root, "notify.capa")
        ceilings = composed["capability_ceilings"]
        self.assertFalse(ceilings["pass"])
        v = [v for v in ceilings["violations"]
             if v["capability"] == "Notifier"]
        self.assertEqual(len(v), 1)
        self.assertEqual(v[0]["kind"], "exceeds")
        self.assertIn("Notifier", v[0]["detail"])

    def test_a_pure_leaf_cannot_hide_a_user_capability(self):
        root = self._notifier_pkg("[capabilities]\npure = true\n")
        _manifest, composed = _compose(root, "notify.capa")
        self.assertFalse(composed["capability_ceilings"]["pass"])
        caps = {v["capability"]
                for v in composed["capability_ceilings"]["violations"]}
        self.assertIn("Notifier", caps)


class TestUnknownNamesAreStillRefused(_TmpTree):
    """Widening the vocabulary must not turn a typo into a silent
    widening of the ceiling."""

    def test_misspelled_user_capability_is_refused_naming_it(self):
        root = self._notifier_pkg('[capabilities]\nmax = ["Stdio", "Notifer"]\n')
        with self.assertRaises(ManifestError) as cm:
            read_manifest(root / "capa.toml")
        msg = str(cm.exception)
        self.assertIn("Notifer", msg)
        self.assertIn("unknown capability(ies)", msg)

    def test_the_diagnostic_says_what_could_be_written_instead(self):
        # Actionable: it lists the built-ins AND the capabilities this
        # package actually declares, so the fix is readable off the error.
        root = self._notifier_pkg('[capabilities]\nmax = ["Stdio", "Notifer"]\n')
        with self.assertRaises(ManifestError) as cm:
            read_manifest(root / "capa.toml")
        msg = str(cm.exception)
        self.assertIn("'Notifier'", msg)
        self.assertIn("'Stdio'", msg)

    def test_misspelled_builtin_is_refused_naming_it(self):
        root = self._notifier_pkg('[capabilities]\nmax = ["Stdio", "Nett"]\n')
        with self.assertRaises(ManifestError) as cm:
            read_manifest(root / "capa.toml")
        self.assertIn("Nett", str(cm.exception))

    def test_lowercase_builtin_is_refused(self):
        root = self._notifier_pkg('[capabilities]\nmax = ["stdio"]\n')
        with self.assertRaises(ManifestError) as cm:
            read_manifest(root / "capa.toml")
        self.assertIn("stdio", str(cm.exception))

    def test_a_package_with_no_sources_accepts_no_user_names(self):
        root = self.tmp / "empty"
        _write(root, "capa.toml", (
            '[package]\nname = "empty"\nversion = "0.1.0"\n\n'
            '[capabilities]\nmax = ["Notifier"]\n'
        ))
        with self.assertRaises(ManifestError) as cm:
            read_manifest(root / "capa.toml")
        self.assertIn("Notifier", str(cm.exception))
        self.assertIn("none declared", str(cm.exception))

    def test_a_line_commented_declaration_does_not_widen_the_vocabulary(self):
        root = self.tmp / "commented"
        _write(root, "capa.toml", (
            '[package]\nname = "commented"\nversion = "0.1.0"\n\n'
            '[capabilities]\nmax = ["Notifier"]\n'
        ))
        _write(root, "main.capa",
               "// pub capability Notifier\n"
               "pub fun f() -> Unit\n    return\n")
        with self.assertRaises(ManifestError):
            read_manifest(root / "capa.toml")

    def test_a_block_commented_declaration_does_not_widen_the_vocabulary(self):
        # The vocabulary comes from the lexer's token stream, which strips
        # comments, so a ``capability`` inside a ``/* */`` block comment is
        # not a declaration and cannot be named. A raw-text regex missed
        # this and accepted the phantom name.
        root = self.tmp / "block"
        _write(root, "capa.toml", (
            '[package]\nname = "block"\nversion = "0.1.0"\n\n'
            '[capabilities]\nmax = ["Ghost"]\n'
        ))
        _write(root, "main.capa",
               "/*\ncapability Ghost\n*/\n"
               "pub fun f() -> Unit\n    return\n")
        with self.assertRaises(ManifestError) as cm:
            read_manifest(root / "capa.toml")
        self.assertIn("Ghost", str(cm.exception))

    def test_a_unicode_named_capability_is_nameable(self):
        # The lexer accepts non-ASCII identifiers, so a Unicode-named
        # capability is a real declaration and must be nameable in max.
        # An ASCII-only name check rejected it before the scan, which
        # reintroduced the unsatisfiable-ceiling trap this fix removes.
        root = self.tmp / "unicode"
        _write(root, "capa.toml", (
            '[package]\nname = "unicode"\nversion = "0.1.0"\n\n'
            '[capabilities]\nmax = ["Stdio", "Café"]\n'
        ))
        _write(root, "notify.capa",
               "pub capability Café\n"
               "    fun announce(self, msg: String) -> Unit\n"
               "\n"
               "type StdioCafe {\n    out: Stdio\n}\n"
               "\n"
               "impl Café for StdioCafe\n"
               "    fun announce(self, msg: String) -> Unit\n"
               "        self.out.println(msg)\n"
               "        return\n"
               "\n"
               "pub fun make(io: Stdio) -> StdioCafe\n"
               "    return StdioCafe { out: io }\n"
               "\n"
               "pub fun run(c: Café) -> Unit\n"
               "    c.announce(\"x\")\n"
               "    return\n")
        m = read_manifest(root / "capa.toml")
        self.assertEqual(
            m.capability_ceiling.max, frozenset({"Stdio", "Café"}),
        )
        _manifest, composed = _compose(root, "notify.capa")
        self.assertTrue(
            composed["capability_ceilings"]["pass"],
            composed["capability_ceilings"]["violations"],
        )

    def test_malformed_names_are_refused_before_any_source_is_read(self):
        root = self.tmp / "bad"
        _write(root, "capa.toml", (
            '[package]\nname = "bad"\nversion = "0.1.0"\n\n'
            '[capabilities]\nmax = ["Net Fs"]\n'
        ))
        with self.assertRaises(ManifestError) as cm:
            read_manifest(root / "capa.toml")
        self.assertIn("Net Fs", str(cm.exception))

    def test_unsafe_is_still_unnameable(self):
        # Unsafe composes as authority-unknown TOP; no vocabulary widening
        # may make it a bounded capability a ceiling permits.
        root = self._notifier_pkg('[capabilities]\nmax = ["Stdio", "Unsafe"]\n')
        with self.assertRaises(ManifestError) as cm:
            read_manifest(root / "capa.toml")
        self.assertIn("Unsafe", str(cm.exception))

    def test_unsafe_is_unnameable_even_when_a_capability_declares_it(self):
        # Belt and braces: the Unsafe refusal runs ahead of the source
        # scan, so no source text can smuggle the name back in.
        root = self.tmp / "sneaky"
        _write(root, "capa.toml", (
            '[package]\nname = "sneaky"\nversion = "0.1.0"\n\n'
            '[capabilities]\nmax = ["Unsafe"]\n'
        ))
        _write(root, "main.capa",
               "pub capability Unsafe\n"
               "    fun go(self) -> Unit\n")
        with self.assertRaises(ManifestError) as cm:
            read_manifest(root / "capa.toml")
        self.assertIn("Unsafe", str(cm.exception))


class TestDependencyCapabilities(_TmpTree):
    """A capability arriving from a dependency still breaks the build
    until somebody names it, for user-defined names as for built-in ones."""

    def _tree(self, root_ceiling: str) -> Path:
        root = self.tmp / "app"
        _write(root, "capa.toml", (
            '[package]\nname = "app"\nversion = "0.1.0"\n\n'
            + root_ceiling +
            '\n[dependencies.logdep]\n'
            'git = "https://github.com/example/logdep"\ntag = "v1"\n'
        ))
        _write(root, "main.capa", (
            "import logdep.api\n\n"
            "pub fun run() -> Unit\n    ping()\n    return\n"
        ))
        _write(root, "vendor/logdep/capa.toml",
               '[package]\nname = "logdep"\nversion = "0.1.0"\n')
        _write(root, "vendor/logdep/api.capa", (
            "pub capability Logger\n"
            "    fun info(self, msg: String) -> Unit\n"
            "\n"
            "pub fun ping() -> Unit\n    return\n"
            "\n"
            "pub fun emit(l: Logger) -> Unit\n"
            "    l.info(\"x\")\n"
            "    return\n"
            "\n"
            "pub fun call(_n: Net) -> Unit\n    return\n"
        ))
        return root

    def test_unnamed_dependency_user_capability_breaks_the_build(self):
        root = self._tree('[capabilities]\nmax = ["Net"]\n')
        _manifest, composed = _compose(root, "main.capa")
        ceilings = composed["capability_ceilings"]
        self.assertFalse(ceilings["pass"])
        v = [v for v in ceilings["violations"] if v["capability"] == "Logger"]
        self.assertEqual(len(v), 1)
        self.assertEqual(v[0]["kind"], "exceeds")
        self.assertEqual(v[0]["introduced_by"], "logdep")
        self.assertIn("logdep", v[0]["detail"])

    def test_unnamed_dependency_builtin_capability_breaks_the_build(self):
        root = self._tree('[capabilities]\nmax = ["Logger"]\n')
        _manifest, composed = _compose(root, "main.capa")
        ceilings = composed["capability_ceilings"]
        self.assertFalse(ceilings["pass"])
        self.assertTrue(any(v["capability"] == "Net"
                            for v in ceilings["violations"]))

    def test_naming_the_dependency_capability_passes(self):
        root = self._tree('[capabilities]\nmax = ["Net", "Logger"]\n')
        _manifest, composed = _compose(root, "main.capa")
        ceilings = composed["capability_ceilings"]
        self.assertTrue(ceilings["pass"], ceilings["violations"])

    def test_a_dependency_cannot_name_its_consumers_capability(self):
        # The vocabulary is the package's OWN tree, so a capability
        # declared only in the consumer is not nameable from below.
        root = self.tmp / "app"
        _write(root, "capa.toml", (
            '[package]\nname = "app"\nversion = "0.1.0"\n\n'
            '[dependencies.leaf]\n'
            'git = "https://github.com/example/leaf"\ntag = "v1"\n'
        ))
        _write(root, "notify.capa", NOTIFIER_SRC)
        _write(root, "vendor/leaf/capa.toml", (
            '[package]\nname = "leaf"\nversion = "0.1.0"\n\n'
            '[capabilities]\nmax = ["Notifier"]\n'
        ))
        _write(root, "vendor/leaf/api.capa", "pub fun ping() -> Unit\n    return\n")
        with self.assertRaises(ManifestError) as cm:
            read_manifest(root / "vendor" / "leaf" / "capa.toml")
        self.assertIn("Notifier", str(cm.exception))

    def test_a_path_dependency_contributes_its_capabilities(self):
        # A path dep sits OUTSIDE the consumer's tree, so it needs its own
        # walk; without one, naming its capability would be a false refusal.
        root = self.tmp / "app"
        sibling = self.tmp / "sibling"
        _write(root, "capa.toml", (
            '[package]\nname = "app"\nversion = "0.1.0"\n\n'
            '[capabilities]\nmax = ["Stdio", "Notifier"]\n\n'
            '[dependencies.sibling]\npath = "../sibling"\n'
        ))
        _write(root, "main.capa", "pub fun run() -> Unit\n    return\n")
        _write(sibling, "capa.toml",
               '[package]\nname = "sibling"\nversion = "0.1.0"\n')
        _write(sibling, "notify.capa", NOTIFIER_SRC)
        m = read_manifest(root / "capa.toml")
        self.assertEqual(
            m.capability_ceiling.max, frozenset({"Stdio", "Notifier"}),
        )

    def test_a_path_dependency_does_not_excuse_a_typo(self):
        root = self.tmp / "app"
        sibling = self.tmp / "sibling"
        _write(root, "capa.toml", (
            '[package]\nname = "app"\nversion = "0.1.0"\n\n'
            '[capabilities]\nmax = ["Stdio", "Notifer"]\n\n'
            '[dependencies.sibling]\npath = "../sibling"\n'
        ))
        _write(root, "main.capa", "pub fun run() -> Unit\n    return\n")
        _write(sibling, "capa.toml",
               '[package]\nname = "sibling"\nversion = "0.1.0"\n')
        _write(sibling, "notify.capa", NOTIFIER_SRC)
        with self.assertRaises(ManifestError) as cm:
            read_manifest(root / "capa.toml")
        self.assertIn("Notifer", str(cm.exception))

    def test_an_uninstalled_dependency_defers_the_refusal(self):
        # ``capa install`` reads the very manifest it is about to satisfy.
        # Refusing a not-yet-vendored dependency's capability there would
        # make the package impossible to install; the ceiling check still
        # fails closed on the unanalyzable subtree.
        root = self.tmp / "app"
        _write(root, "capa.toml", (
            '[package]\nname = "app"\nversion = "0.1.0"\n\n'
            '[capabilities]\nmax = ["Logger"]\n\n'
            '[dependencies.logdep]\n'
            'git = "https://github.com/example/logdep"\ntag = "v1"\n'
        ))
        _write(root, "main.capa", "pub fun run() -> Unit\n    return\n")
        m = read_manifest(root / "capa.toml")
        self.assertEqual(m.capability_ceiling.max, frozenset({"Logger"}))
        _manifest, composed = _compose(root, "main.capa")
        ceilings = composed["capability_ceilings"]
        self.assertFalse(ceilings["pass"])
        self.assertTrue(any(v["kind"] == "authority_unknown"
                            for v in ceilings["violations"]))


class TestBuiltinOnlyCeilingUnchanged(_TmpTree):
    """A ceiling naming only built-ins behaves exactly as before: no
    source is consulted, and no dependency needs to be on disk."""

    def test_builtin_only_ceiling_parses_with_no_sources_present(self):
        root = self.tmp / "gate"
        _write(root, "capa.toml", (
            '[package]\nname = "gate"\nversion = "0.1.0"\n\n'
            '[capabilities]\nmax = ["Net", "Fs", "Stdio"]\n\n'
            '[dependencies.absent]\n'
            'git = "https://github.com/example/absent"\ntag = "v1"\n'
        ))
        m = read_manifest(root / "capa.toml")
        self.assertEqual(
            m.capability_ceiling.max, frozenset({"Net", "Fs", "Stdio"}),
        )

    def test_builtin_only_ceiling_still_passes_and_still_exceeds(self):
        root = self.tmp / "gate"
        _write(root, "capa.toml", (
            '[package]\nname = "gate"\nversion = "0.1.0"\n\n'
            '[capabilities]\nmax = ["Net", "Fs"]\n'
        ))
        _write(root, "main.capa", (
            "pub fun fetch(_n: Net) -> Unit\n    return\n"
            "pub fun store(_fs: Fs) -> Unit\n    return\n"
        ))
        _manifest, composed = _compose(root, "main.capa")
        self.assertTrue(composed["capability_ceilings"]["pass"])
        (root / "capa.toml").write_text(
            '[package]\nname = "gate"\nversion = "0.1.0"\n\n'
            '[capabilities]\nmax = ["Fs"]\n', encoding="utf-8",
        )
        _manifest, composed = _compose(root, "main.capa")
        self.assertFalse(composed["capability_ceilings"]["pass"])
        self.assertTrue(any(v["capability"] == "Net"
                            for v in composed["capability_ceilings"]["violations"]))

    def test_pure_ceiling_is_unaffected(self):
        root = self.tmp / "leaf"
        _write(root, "capa.toml", (
            '[package]\nname = "leaf"\nversion = "0.1.0"\n\n'
            '[capabilities]\npure = true\n'
        ))
        _write(root, "main.capa", "pub fun add(a: Int, b: Int) -> Int\n    return a + b\n")
        m = read_manifest(root / "capa.toml")
        self.assertEqual(m.capability_ceiling.max, frozenset())
        _manifest, composed = _compose(root, "main.capa")
        self.assertTrue(composed["capability_ceilings"]["pass"])


class TestFunBearingUserCapability(_TmpTree):
    """A user capability whose method signature carries a ``Fun`` is
    authority-NOT-PROVABLE: a closure can launder any capability the caller
    captured into it, so the reachability pass refuses to make an exclusion
    claim for anything that touches it (``provably_excluded_capabilities``
    is voided and the function's ``authority_provable_from_types`` is False).

    Naming such a capability in ``max`` was unreachable before user names
    could be written there at all. It is reachable now, and a package that
    DECLARES a ceiling while its own code takes such a capability cannot
    have a VERIFIABLE ceiling: the ceiling is a claim about the package's
    own subtree, into which a caller can inject authority the package's
    types never named. So the ceiling check fails closed with
    ``authority_unknown`` (the self-scoped rule), whether or not the
    capability is itself named in ``max``. The exclusion proof being voided
    (below) is the per-function half of the same signal.

    Neither fleet user capability is Fun-bearing today, so this has no
    fleet cost; the tests here pin the interaction so a later change to the
    self-scoped signal is caught."""

    def _runner_pkg(self, ceiling_block: str) -> Path:
        root = self.tmp / "runner"
        _write(root, "capa.toml", (
            '[package]\nname = "runner"\nversion = "0.1.0"\n\n' + ceiling_block
        ))
        _write(root, "main.capa", RUNNER_SRC)
        return root

    def test_fun_bearing_capability_voids_the_exclusion_proof(self):
        root = self._runner_pkg('[capabilities]\nmax = ["Stdio", "Runner"]\n')
        manifest, _composed = _compose(root, "main.capa")
        by_name = {(r["name"], r["container"]): r for r in manifest["functions"]}
        go = by_name[("go", "StdioRunner")]
        self.assertEqual(go["provably_excluded_capabilities"], [])
        self.assertEqual(
            go["transitively_reachable_capabilities"], ["Runner", "Stdio"],
        )
        # The per-function half of the same signal, now exported for the
        # composed ceiling check.
        self.assertFalse(go["authority_provable_from_types"])

    def test_fun_bearing_capability_named_in_the_ceiling_is_unverifiable(self):
        # Even naming Runner in max cannot make the ceiling verifiable: the
        # package's OWN types cannot prove its authority (it takes a
        # Fun-bearing capability), so a caller can inject authority the
        # types never named. Fails closed with authority_unknown, NOT
        # exceeds (the attributed set is unchanged -- exactly the named
        # ones).
        root = self._runner_pkg('[capabilities]\nmax = ["Stdio", "Runner"]\n')
        _manifest, composed = _compose(root, "main.capa")
        ceilings = composed["capability_ceilings"]
        self.assertFalse(ceilings["pass"], ceilings["violations"])
        kinds = {v["kind"] for v in ceilings["violations"]}
        self.assertEqual(kinds, {"authority_unknown"})
        # The ATTRIBUTED set is still exactly the named caps: the roll-up is
        # untouched, only the ceiling claim is voided.
        self.assertEqual(
            composed["packages"][0]["attributed_capabilities"],
            ["Runner", "Stdio"],
        )

    def test_fun_bearing_capability_omitted_from_the_ceiling_fails(self):
        # Omitting Runner adds an EXCEEDS violation on top of the
        # authority_unknown one; either way the package fails.
        root = self._runner_pkg('[capabilities]\nmax = ["Stdio"]\n')
        _manifest, composed = _compose(root, "main.capa")
        ceilings = composed["capability_ceilings"]
        self.assertFalse(ceilings["pass"])
        self.assertTrue(any(v["capability"] == "Runner"
                            for v in ceilings["violations"]))
        self.assertTrue(any(v["kind"] == "authority_unknown"
                            for v in ceilings["violations"]))


class TestCheckCapabilitiesCli(_TmpTree):
    """End to end through the gate CI actually runs."""

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

    def test_named_user_capability_exits_zero(self):
        root = self._notifier_pkg('[capabilities]\nmax = ["Stdio", "Notifier"]\n')
        rc, _out, err = self._run(root, "notify.capa")
        self.assertEqual(rc, 0, err)
        self.assertIn("OK", err)

    def test_typo_exits_nonzero_with_a_manifest_diagnostic(self):
        root = self._notifier_pkg('[capabilities]\nmax = ["Stdio", "Notifer"]\n')
        rc, _out, err = self._run(root, "notify.capa")
        self.assertNotEqual(rc, 0)
        self.assertIn("broken capa.toml", err)
        self.assertIn("Notifer", err)


# A user capability exercised through a value MINTED in a function body:
# constructed inline (``let b = Bomb {}``) or returned by a factory whose
# static return type names the cap-bearing type (``let b = make_bomb()``).
# The signature never names ``Danger`` or ``Bomb``, so a signature-only
# exclusion walk falsely provably-excluded ``Danger`` while the body ran
# ``b.boom()`` (H-F1). ``make_bomb`` and both triggers carry an EMPTY
# signature so the only route to the authority is through the body.
DANGER_SRC = (
    "pub capability Danger\n"
    "    fun boom(self) -> Unit\n"
    "\n"
    "pub type Bomb {}\n"
    "\n"
    "impl Danger for Bomb\n"
    "    fun boom(self) -> Unit\n"
    "        return\n"
    "\n"
    "pub fun make_bomb() -> Bomb\n"
    "    return Bomb {}\n"
    "\n"
    "pub fun trigger_inline() -> Unit\n"
    "    let b = Bomb {}\n"
    "    b.boom()\n"
    "    return\n"
    "\n"
    "pub fun trigger_factory() -> Unit\n"
    "    let b = make_bomb()\n"
    "    b.boom()\n"
    "    return\n"
    "\n"
    "pub fun trigger_and_exclude() -> Unit\n"
    "    let b = Bomb {}\n"
    "    b.boom()\n"
    "    return\n"
)

# The library half of ``DANGER_SRC`` alone: the capability, the cap-bearing
# type, its impl and the factory, with none of the trigger functions. Used
# as a separate dependency so the consumer's own triggers do not clash.
DANGER_LIB_SRC = (
    "pub capability Danger\n"
    "    fun boom(self) -> Unit\n"
    "\n"
    "pub type Bomb {}\n"
    "\n"
    "impl Danger for Bomb\n"
    "    fun boom(self) -> Unit\n"
    "        return\n"
    "\n"
    "pub fun make_bomb() -> Bomb\n"
    "    return Bomb {}\n"
)


def _records_of(source: str, filename: str = "danger.capa") -> dict:
    """Build a manifest and return its function records keyed by
    ``(name, container)``. Parsed, not analysed, exactly like the
    other manifest-builder tests: the point is to inspect the exclusion
    surface for programs whose whole shape is the thing under test."""
    tokens = Lexer(source).lex()
    module = Parser(tokens, source=source).parse_module()
    manifest = build_manifest(module, filename=filename)
    return {(r["name"], r["container"]): r for r in manifest["functions"]}


class TestBodyMintedUserCapability(_TmpTree):
    """H-F1: a user capability obtained as a body LOCAL (constructed inline
    or returned by a factory) is REAL, live authority the function runs.

    The fix SURFACES it into ``transitively_reachable_capabilities`` through
    the same reachability map the signature walk uses, so it drops out of
    ``provably_excluded_capabilities`` -- it does NOT void the list the way a
    ``Fun`` or ``Unsafe`` in the signature does (approach a, not b). The
    discriminator below pins that choice: an unrelated cap the body never
    obtains STAYS provably-excluded."""

    def test_inline_construction_surfaces_the_capability(self):
        recs = _records_of(DANGER_SRC)
        r = recs[("trigger_inline", None)]
        self.assertNotIn("Danger", r["provably_excluded_capabilities"])
        self.assertIn("Danger", r["transitively_reachable_capabilities"])

    def test_factory_return_type_surfaces_the_capability(self):
        recs = _records_of(DANGER_SRC)
        r = recs[("trigger_factory", None)]
        self.assertNotIn("Danger", r["provably_excluded_capabilities"])
        self.assertIn("Danger", r["transitively_reachable_capabilities"])

    def test_unrelated_cap_stays_excluded_the_discriminator(self):
        # Approach (a): surfacing the minted cap must not blank the list.
        # A Net/Fs/Db-free function that mints a Bomb still provably-excludes
        # Net. Under approach (b) (void the list) this assertion fails.
        recs = _records_of(DANGER_SRC)
        r = recs[("trigger_and_exclude", None)]
        self.assertNotIn("Danger", r["provably_excluded_capabilities"])
        self.assertIn("Net", r["provably_excluded_capabilities"])

    def test_used_caps_are_disjoint_from_provably_excluded(self):
        # General invariant: for EVERY function record, a user cap reachable
        # through a method it actually CALLS may never be provably-excluded.
        # This closes the blind spot the signature-only walk left open.
        tokens = Lexer(DANGER_SRC).lex()
        module = Parser(tokens, source=DANGER_SRC).parse_module()
        manifest = build_manifest(module, filename="danger.capa")
        # method name -> user caps declaring a method of that name.
        method_caps: dict[str, set[str]] = {}
        for uc in manifest["user_defined_capabilities"]:
            for m in uc["methods"]:
                method_caps.setdefault(m, set()).add(uc["name"])
        for r in manifest["functions"]:
            excluded = set(r["provably_excluded_capabilities"])
            used: set[str] = set()
            for call in r["calls"]:
                if call["kind"] != "method":
                    continue
                method = call["callee"].rsplit(".", 1)[-1]
                used |= method_caps.get(method, set())
            self.assertEqual(
                used & excluded, set(),
                f"{r['name']}: {used & excluded} both used and "
                f"provably-excluded",
            )

    def _cross_module_records(self) -> dict:
        # Danger/Bomb/impl/make_bomb live in a dependency; the consumer's
        # function obtains the value as a local without naming the type.
        root = self.tmp / "app"
        _write(root, "capa.toml", (
            '[package]\nname = "app"\nversion = "0.1.0"\n\n'
            '[dependencies.dangerdep]\n'
            'git = "https://github.com/example/dangerdep"\ntag = "v1"\n'
        ))
        _write(root, "main.capa", (
            "import dangerdep.api\n\n"
            "pub fun trigger_inline() -> Unit\n"
            "    let b = Bomb {}\n"
            "    b.boom()\n"
            "    return\n"
            "\n"
            "pub fun trigger_factory() -> Unit\n"
            "    let b = make_bomb()\n"
            "    b.boom()\n"
            "    return\n"
        ))
        _write(root, "vendor/dangerdep/capa.toml",
               '[package]\nname = "dangerdep"\nversion = "0.1.0"\n')
        _write(root, "vendor/dangerdep/api.capa", DANGER_LIB_SRC)
        root = root.resolve()
        search = [root]
        for vendor in root.rglob("vendor"):
            if vendor.is_dir():
                search.append(vendor)
        filename = str(root / "main.capa")
        source = (root / "main.capa").read_text(encoding="utf-8")
        loader = ModuleLoader(search_paths=search)
        linked = loader.load_root(source, filename)
        manifest = build_manifest(linked.module, filename=filename)
        return {(r["name"], r["container"]): r for r in manifest["functions"]}

    def test_cross_module_inline_construction_surfaces_the_capability(self):
        recs = self._cross_module_records()
        r = recs[("trigger_inline", None)]
        self.assertNotIn("Danger", r["provably_excluded_capabilities"])
        self.assertIn("Danger", r["transitively_reachable_capabilities"])

    def test_cross_module_factory_surfaces_the_capability(self):
        recs = self._cross_module_records()
        r = recs[("trigger_factory", None)]
        self.assertNotIn("Danger", r["provably_excluded_capabilities"])
        self.assertIn("Danger", r["transitively_reachable_capabilities"])


# The residual of the SAME class: authority obtained through an INHERENT
# (non-trait) impl method whose declared return type names a cap-bearing
# type. ``impl Factory { fun produce(self) -> Bomb }`` lets a holder of a
# ``Factory`` mint a ``Bomb`` and run ``Danger`` through it. Pre-fix
# ``compute_reachability`` folded impl-method signatures into ``reachable[]``
# only for TRAIT impls, so ``reachable[Factory]`` was empty and both the
# ``f: Factory`` param and a body-local factory falsely provably-excluded
# ``Danger``. SEAM A folds inherent impls at the same struct fixpoint, which
# repairs the sig side (the param) and the body side (the free-fn factory
# walk already resolves ``make_factory() -> Factory`` through
# ``reachable[Factory]``) from one source.
FACTORY_SRC = (
    "pub capability Danger\n"
    "    fun boom(self) -> Unit\n"
    "\n"
    "pub type Bomb {}\n"
    "\n"
    "impl Danger for Bomb\n"
    "    fun boom(self) -> Unit\n"
    "        return\n"
    "\n"
    "pub type Factory {}\n"
    "\n"
    "impl Factory\n"
    "    fun produce(self) -> Bomb\n"
    "        return Bomb {}\n"
    "\n"
    "pub fun make_factory() -> Factory\n"
    "    return Factory {}\n"
    "\n"
    "pub fun trigger_method(f: Factory) -> Unit\n"
    "    let b = f.produce()\n"
    "    b.boom()\n"
    "    return\n"
    "\n"
    "pub fun trigger_local_method() -> Unit\n"
    "    let fac = make_factory()\n"
    "    fac.produce().boom()\n"
    "    return\n"
    "\n"
    "pub fun holds(f: Factory) -> Unit\n"
    "    return\n"
)


class TestInherentImplMethodFactory(_TmpTree):
    """H-F1 method-factory residual: a cap minted through an inherent-impl
    method that returns a cap-bearing type is REAL, live authority.

    SEAM A folds inherent-impl method signatures into ``reachable[]`` at the
    struct fixpoint, exactly mirroring the trait-impl fold, so a value of the
    struct type charges the caps its inherent methods can hand out. This
    restores the inherent-vs-trait symmetry and, because ``reachable[]`` is
    the one source both the signature walk and the body walk consume, closes
    the ``f: Factory`` param case and the body-local factory case together."""

    def test_inherent_method_param_surfaces_the_capability(self):
        # The exact residual: a Factory PARAM whose inherent method returns
        # the cap-bearing Bomb. The signature walk reads reachable[Factory].
        recs = _records_of(FACTORY_SRC)
        r = recs[("trigger_method", None)]
        self.assertNotIn("Danger", r["provably_excluded_capabilities"])
        self.assertIn("Danger", r["transitively_reachable_capabilities"])

    def test_local_receiver_method_factory_surfaces_the_capability(self):
        # The body-side path: a local Factory obtained from make_factory(),
        # whose inherent produce() mints the Bomb. Resolved through the same
        # reachable[Factory] the SEAM A fold now populates.
        recs = _records_of(FACTORY_SRC)
        r = recs[("trigger_local_method", None)]
        self.assertNotIn("Danger", r["provably_excluded_capabilities"])
        self.assertIn("Danger", r["transitively_reachable_capabilities"])

    def test_pure_holder_is_over_approximated_the_discriminator(self):
        # SEAM A is a SOURCE-level over-approximation: holding a Factory
        # charges the authority its inherent methods can mint, even for a
        # function that never calls produce(). This mirrors the existing
        # struct-field and trait-impl folds. It is intentional and sound
        # (widening transitively_reachable only shrinks provably_excluded);
        # do NOT "tighten" it back into a per-call dataflow check, which
        # would reopen the false-exclude hole this fix closes.
        recs = _records_of(FACTORY_SRC)
        r = recs[("holds", None)]
        self.assertIn("Danger", r["transitively_reachable_capabilities"])
        self.assertNotIn("Danger", r["provably_excluded_capabilities"])

    def test_used_caps_are_disjoint_from_provably_excluded(self):
        # The disjointness invariant, now exercising the method-call shape:
        # trigger_method / trigger_local_method both CALL boom (a Danger
        # method) and must not provably-exclude Danger.
        tokens = Lexer(FACTORY_SRC).lex()
        module = Parser(tokens, source=FACTORY_SRC).parse_module()
        manifest = build_manifest(module, filename="factory.capa")
        method_caps: dict[str, set[str]] = {}
        for uc in manifest["user_defined_capabilities"]:
            for m in uc["methods"]:
                method_caps.setdefault(m, set()).add(uc["name"])
        for r in manifest["functions"]:
            excluded = set(r["provably_excluded_capabilities"])
            used: set[str] = set()
            for call in r["calls"]:
                if call["kind"] != "method":
                    continue
                method = call["callee"].rsplit(".", 1)[-1]
                used |= method_caps.get(method, set())
            self.assertEqual(
                used & excluded, set(),
                f"{r['name']}: {used & excluded} both used and "
                f"provably-excluded",
            )


if __name__ == "__main__":
    unittest.main()
