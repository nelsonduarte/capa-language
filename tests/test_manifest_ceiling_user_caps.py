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

The last class pins an interaction rather than fixing one: a user
capability whose method signature carries a ``Fun`` is marked
authority-not-provable by the reachability pass, and naming such a
capability in ``max`` is only now reachable at all.
"""

import shutil
import tempfile
import unittest
from pathlib import Path

from capa import analyze
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

    def test_a_commented_out_declaration_does_not_widen_the_vocabulary(self):
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
    """PINNED, NOT FIXED. A user capability whose method signature carries
    a ``Fun`` is authority-NOT-PROVABLE: a closure can launder any
    capability the caller captured into it, so the reachability pass
    refuses to make an exclusion claim for anything that touches it.

    Naming such a capability in ``max`` was unreachable before this
    change, because no user-defined name could be written there at all.
    It is reachable now, and today the two facts sit side by side: the
    exclusion proof is voided (``provably_excluded_capabilities`` is
    empty) while the ATTRIBUTED set stays exactly the named ones, so the
    ceiling passes. If the unprovability is ever widened into the
    attributed set (crediting a Fun-bearing capability with every
    capability it might launder, the sound-but-wider reading), the
    ceiling here starts failing with ``exceeds``. This test is what
    catches that, so the change is a decision rather than a surprise."""

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

    def test_fun_bearing_capability_named_in_the_ceiling_passes_today(self):
        root = self._runner_pkg('[capabilities]\nmax = ["Stdio", "Runner"]\n')
        _manifest, composed = _compose(root, "main.capa")
        ceilings = composed["capability_ceilings"]
        self.assertTrue(ceilings["pass"], ceilings["violations"])
        self.assertEqual(
            composed["packages"][0]["attributed_capabilities"],
            ["Runner", "Stdio"],
        )

    def test_fun_bearing_capability_omitted_from_the_ceiling_fails(self):
        root = self._runner_pkg('[capabilities]\nmax = ["Stdio"]\n')
        _manifest, composed = _compose(root, "main.capa")
        ceilings = composed["capability_ceilings"]
        self.assertFalse(ceilings["pass"])
        self.assertTrue(any(v["capability"] == "Runner"
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


if __name__ == "__main__":
    unittest.main()
