"""The ``capa = ">=X.Y.Z"`` manifest floor, enforced since 1.19.0.

Five things are under test here, and each one is a precondition rather
than a nicety:

1. the comparator, against a golden table built oracle-first (see the
   table's own comment for how it was validated);
2. the grammar, differentially against ``tools/capa_floor.sh``, so a
   manifest that passes the release guard can never be one the compiler
   refuses;
3. the root-errors / dependency-warns / absence-is-unconstrained policy
   split;
4. the exemptions, each exercised as a real CLI invocation with a
   violating root ``capa.toml`` on disk;
5. the structural invariants that are otherwise invisible: that
   ``CapaFloorError`` does not subclass ``ManifestError``, and that
   ``capa/cli.py``'s ``except Exception`` arm does not swallow it.
"""

from __future__ import annotations

import io
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from capa.pkg import ManifestError, read_manifest
from capa.pkg._floor import (
    IGNORE_ENV,
    UNKNOWN_VERSION,
    CapaFloorError,
    check_root_floor,
    enforce_root_floor,
    parse_requirement,
    parse_version,
    satisfies,
    warn_dependency_floor,
)
from tests.test_cli import _run_main

REPO_ROOT = Path(__file__).resolve().parent.parent
CAPA_FLOOR_SH = REPO_ROOT / "tools" / "capa_floor.sh"
BASH = shutil.which("bash")


# ---------------------------------------------------------------------------
# 1. The comparator.
# ---------------------------------------------------------------------------

# (running, floor, satisfied?). Built ORACLE-FIRST, before the comparator
# existed: every row was cross-checked against ``packaging.version``
# (a dev-only dependency; the shipped comparator is stdlib-only, since
# the compiler has no runtime dependencies by policy), together with an
# exhaustive 14400-pair grid over components drawn from
# {0,1,2,9,10,11}. Zero mismatches.
#
# TEN of the twenty rows below are rows a naive LEXICAL string
# comparison gets BACKWARDS, which is the single most likely way to get
# this wrong. ``"1.2.0" >= "1.11.0"`` is True as strings and False as
# versions; so are 1.9.0/1.10.0, 9.0.0/10.0.0, 1.18.9/1.18.10 and
# 1.3.0/1.20.0, each present in both directions.
GOLDEN_COMPARISONS = [
    ("1.19.0", "1.19.0", True),
    ("1.19.1", "1.19.0", True),
    ("1.18.1", "1.19.0", False),
    ("1.2.0", "1.11.0", False),     # the lexical trap, and its mirror
    ("1.11.0", "1.2.0", True),
    ("1.9.0", "1.10.0", False),
    ("1.10.0", "1.9.0", True),
    ("2.0.0", "1.99.99", True),
    ("1.99.99", "2.0.0", False),
    ("0.1.0", "0.1.0", True),
    ("0.0.1", "0.1.0", False),
    ("1.0.0", "0.9.9", True),
    ("10.0.0", "9.0.0", True),
    ("9.0.0", "10.0.0", False),
    ("1.18.10", "1.18.9", True),
    ("1.18.9", "1.18.10", False),
    ("1.2.3", "1.2.3", True),
    ("0.0.0", "0.0.0", True),
    ("1.20.0", "1.3.0", True),
    ("1.3.0", "1.20.0", False),
]


class ComparatorTests(unittest.TestCase):
    def test_golden_table(self):
        for running, floor, want in GOLDEN_COMPARISONS:
            with self.subTest(running=running, floor=floor):
                got = satisfies(parse_version(running), parse_version(floor))
                self.assertEqual(
                    got, want,
                    f"{running} >= {floor} should be {want}",
                )

    def test_lexical_comparison_would_fail_this_table(self):
        """The table actually BITES on the bug it exists to catch.

        A guard asserted correct but never shown capable of failing is
        worthless. Here is the neutering edit written out: a comparator
        that compares the version STRINGS rather than their numeric
        components. It disagrees with the golden table on ten of the
        twenty rows, so ``test_golden_table`` reddens under it.
        """
        wrong = [
            (r, f, w) for r, f, w in GOLDEN_COMPARISONS if (r >= f) != w
        ]
        self.assertEqual(
            len(wrong), 10,
            "the golden table must keep enough lexical-trap rows to redden "
            "a string-comparison implementation",
        )

    def test_parse_version_accepts_exactly_three_components(self):
        self.assertEqual(parse_version("1.19.0"), (1, 19, 0))
        self.assertEqual(parse_version("10.20.30"), (10, 20, 30))
        for bad in (
            "1.19", "1.19.0.1", "1..0", "v1.19.0", "1.19.0-rc1",
            "1.19.0.dev1", "", " 1.19.0", "1.19.0 ", UNKNOWN_VERSION,
        ):
            with self.subTest(bad=bad):
                self.assertIsNone(parse_version(bad))

    def test_parse_version_rejects_non_strings(self):
        for bad in (None, 1, 1.19, ["1", "19", "0"]):
            with self.subTest(bad=bad):
                self.assertIsNone(parse_version(bad))


# ---------------------------------------------------------------------------
# 2. The grammar, differentially against tools/capa_floor.sh.
# ---------------------------------------------------------------------------

# One corpus, fed to BOTH the shell release guard and the Python parser.
# The two must agree case for case: if the compiler were STRICTER than
# the guard, a manifest that PASSES release guard 2 would FAIL the
# compiler, which inverts the relationship the two are supposed to have.
#
# Each entry is the raw string that appears between the quotes in
# ``capa = "..."``. ``None`` means "both sides must refuse it"; a string
# means "both sides must read that floor out of it".
GRAMMAR_CORPUS = [
    # Accepted. The bare form is a FLOOR, not a pin, because that is
    # what the shell guard has always treated it as.
    (">=1.17.0", "1.17.0"),
    ("1.17.0", "1.17.0"),
    (">= 1.17.0", "1.17.0"),          # a space after the operator
    (">=  1.17.0", "1.17.0"),         # two spaces
    (">=1.17.0 ", "1.17.0"),          # a trailing space
    (" >=1.17.0", "1.17.0"),          # a leading space
    (" 1.17.0 ", "1.17.0"),
    (">=\t1.17.0", "1.17.0"),         # a tab after the operator
    ("0.0.0", "0.0.0"),
    ("10.20.30", "10.20.30"),
    (">=99.0.0", "99.0.0"),
    # Refused: names no single release.
    ("^1.17", None),
    ("^1.17.0", None),
    (">=1.17.0,<2", None),
    ("1.*", None),
    (">1.17.0", None),
    ("<=1.17.0", None),
    ("==1.17.0", None),
    ("~1.17.0", None),
    # Refused: not a three-component release. These three are the cases
    # the guard's old ``[0-9][0-9.]*[0-9]`` pattern WRONGLY accepted;
    # both sides were tightened together.
    ("1.17", None),
    ("1.2.3.4", None),
    ("1..2", None),
    ("1", None),
    ("1.", None),
    (".1.2", None),
    # Refused: not a version at all.
    ("", None),
    ("v1.17.0", None),
    ("1.17.0-rc1", None),
    ("1.17.0.dev1", None),
    ("latest", None),
    (">=", None),
]


class GrammarTests(unittest.TestCase):
    def test_python_parser_matches_the_corpus(self):
        for raw, want in GRAMMAR_CORPUS:
            with self.subTest(raw=raw):
                got = parse_requirement(raw)
                if want is None:
                    self.assertIsNone(got, f"{raw!r} must be refused")
                else:
                    self.assertEqual(got, parse_version(want), repr(raw))

    def test_parse_requirement_rejects_non_strings(self):
        for bad in (None, 1, ["1.17.0"]):
            with self.subTest(bad=bad):
                self.assertIsNone(parse_requirement(bad))


class ShellDifferentialTests(unittest.TestCase):
    """``tools/capa_floor.sh`` and ``capa/pkg/_floor.py`` must agree.

    Skipped without ``bash``, matching ``tests/test_release_guards.py``;
    CI runs on ubuntu-latest, where it always executes.
    """

    @classmethod
    def setUpClass(cls):
        if BASH is None:
            raise unittest.SkipTest("bash is not available on this host")
        cls._tmp = tempfile.TemporaryDirectory()
        cls.tmp = Path(cls._tmp.name)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    @staticmethod
    def _bash_path(path) -> str:
        text = str(path)
        if os.name == "nt" and len(text) > 1 and text[1] == ":":
            return "/" + text[0].lower() + text[2:].replace("\\", "/")
        return text

    def _shell_floor(self, raw: str):
        """Run the guard on a manifest declaring ``raw``.

        Returns the floor string it printed, or ``None`` when it
        refused.
        """
        manifest = self.tmp / "capa.toml"
        manifest.write_text(
            f'[package]\nname = "x"\nversion = "0.1.0"\ncapa = "{raw}"\n',
            encoding="utf-8",
        )
        proc = subprocess.run(
            [BASH, self._bash_path(CAPA_FLOOR_SH), self._bash_path(manifest)],
            capture_output=True, text=True,
        )
        if proc.returncode != 0:
            return None
        return proc.stdout.strip()

    def test_shell_and_python_agree_case_for_case(self):
        for raw, want in GRAMMAR_CORPUS:
            with self.subTest(raw=raw):
                shell = self._shell_floor(raw)
                python = parse_requirement(raw)
                if want is None:
                    self.assertIsNone(
                        shell, f"the shell guard must refuse {raw!r}",
                    )
                    self.assertIsNone(
                        python, f"the Python parser must refuse {raw!r}",
                    )
                else:
                    self.assertIsNotNone(
                        shell, f"the shell guard must accept {raw!r}",
                    )
                    self.assertIsNotNone(
                        python, f"the Python parser must accept {raw!r}",
                    )
                    # Compare through ``parse_version`` rather than by
                    # string, so a leading-zero spelling agrees on the
                    # RELEASE both sides name.
                    self.assertEqual(parse_version(shell), python, repr(raw))

    def test_the_shell_guard_no_longer_claims_nothing_enforces_the_field(self):
        """The guard's header used to say the field was unenforced.

        That paragraph became a lie the moment enforcement shipped, and
        a stale comment in a security guard is how the next reader
        concludes there is no gate.
        """
        text = CAPA_FLOOR_SH.read_text(encoding="utf-8")
        self.assertNotIn("nothing in the", text.lower().replace("\n# ", " "))
        self.assertIn("_floor.py", text)


# ---------------------------------------------------------------------------
# 3. The policy split: root errors, dependencies warn, absence is free.
# ---------------------------------------------------------------------------


def _manifest(tmp: Path, body: str) -> Path:
    path = tmp / "capa.toml"
    path.write_text(body, encoding="utf-8")
    return path


class RootPolicyTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        self.err = io.StringIO()

    def test_violated_root_floor_is_a_hard_error(self):
        with self.assertRaises(CapaFloorError) as ctx:
            check_root_floor(
                ">=99.0.0", self.tmp / "capa.toml",
                running="1.19.0", stream=self.err,
            )
        message = str(ctx.exception)
        self.assertIn("99.0.0", message)
        self.assertIn("1.19.0", message)

    def test_satisfied_root_floor_is_silent(self):
        check_root_floor(
            ">=1.2.0", self.tmp / "capa.toml",
            running="1.19.0", stream=self.err,
        )
        self.assertEqual(self.err.getvalue(), "")

    def test_equal_version_satisfies_the_floor(self):
        check_root_floor(
            ">=1.19.0", self.tmp / "capa.toml",
            running="1.19.0", stream=self.err,
        )
        self.assertEqual(self.err.getvalue(), "")

    def test_the_lexical_trap_at_the_policy_level(self):
        """1.2.0 must not satisfy a >=1.11.0 floor.

        The comparator test covers the ordering; this one covers it
        having been wired through to the decision that matters.
        """
        with self.assertRaises(CapaFloorError):
            check_root_floor(
                ">=1.11.0", self.tmp / "capa.toml",
                running="1.2.0", stream=self.err,
            )
        check_root_floor(
            ">=1.2.0", self.tmp / "capa.toml",
            running="1.11.0", stream=self.err,
        )

    def test_missing_capa_key_is_unconstrained(self):
        """Absence must FAIL OPEN, and silently.

        This is the OPPOSITE policy from ``tools/capa_floor.sh``, which
        fails closed on a missing key. The divergence is intentional:
        the guard has to choose a released compiler and cannot guess
        one, while the compiler only ever asks whether a STATED
        requirement is violated.
        """
        check_root_floor(
            None, self.tmp / "capa.toml", running="0.0.1", stream=self.err,
        )
        self.assertEqual(self.err.getvalue(), "")

    def test_manifest_with_no_capa_key_parses_to_none(self):
        path = _manifest(self.tmp, '[package]\nname = "x"\nversion = "0.1.0"\n')
        self.assertIsNone(read_manifest(path).capa_requirement)
        enforce_root_floor(self.tmp, running="0.0.1", stream=self.err)
        self.assertEqual(self.err.getvalue(), "")

    def test_unreadable_requirement_is_refused_at_the_root(self):
        with self.assertRaises(CapaFloorError) as ctx:
            check_root_floor(
                "^1.17", self.tmp / "capa.toml",
                running="99.0.0", stream=self.err,
            )
        self.assertIn(
            "is not a requirement this compiler can read",
            str(ctx.exception),
        )

    def test_unknown_running_version_warns_and_continues(self):
        """The ``0+unknown`` sentinel does not refuse the build.

        A hard stop there would punish a packaging defect in the
        compiler itself, and the remediation menu would be empty: the
        user can neither upgrade to satisfy a comparison that was never
        made, nor fix it by editing their own floor. It is fail-open,
        and it says so every time.
        """
        check_root_floor(
            ">=99.0.0", self.tmp / "capa.toml",
            running=UNKNOWN_VERSION, stream=self.err,
        )
        text = self.err.getvalue()
        self.assertIn("cannot check the compiler floor", text)
        self.assertIn(UNKNOWN_VERSION, text)
        self.assertIn("NOT being enforced", text)

    def test_error_message_carries_the_full_remediation_menu(self):
        with self.assertRaises(CapaFloorError) as ctx:
            check_root_floor(
                ">=99.0.0", self.tmp / "capa.toml",
                running="1.19.0", stream=self.err,
            )
        message = str(ctx.exception)
        # A manifest-level, reviewable decision AND a for-this-run
        # override, distinguished, the way _install.py does it.
        self.assertIn("Upgrade the compiler", message)
        self.assertIn("reviewable decision", message)
        self.assertIn(IGNORE_ENV, message)
        self.assertIn("for this run", message)

    def test_enforce_root_floor_reads_the_manifest_on_disk(self):
        _manifest(
            self.tmp,
            '[package]\nname = "x"\nversion = "0.1.0"\ncapa = ">=99.0.0"\n',
        )
        with self.assertRaises(CapaFloorError):
            enforce_root_floor(self.tmp, running="1.19.0", stream=self.err)

    def test_enforce_root_floor_ignores_a_missing_manifest(self):
        enforce_root_floor(self.tmp, running="1.19.0", stream=self.err)
        self.assertEqual(self.err.getvalue(), "")

    def test_enforce_root_floor_ignores_a_broken_manifest(self):
        """A broken capa.toml is not the floor gate's business.

        The CLI already reports it once, from ``_capa_search_paths``; a
        second diagnostic from a policy gate would only obscure it.
        """
        _manifest(self.tmp, "this is not [ valid toml")
        enforce_root_floor(self.tmp, running="1.19.0", stream=self.err)
        self.assertEqual(self.err.getvalue(), "")


class EscapeHatchTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        self.err = io.StringIO()

    def test_ignore_env_downgrades_to_a_loud_warning(self):
        with mock.patch.dict(os.environ, {IGNORE_ENV: "1"}, clear=False):
            check_root_floor(
                ">=99.0.0", self.tmp / "capa.toml",
                running="1.19.0", stream=self.err,
            )
        text = self.err.getvalue()
        self.assertIn(f"{IGNORE_ENV}=1", text)
        self.assertIn("NOT enforced", text)
        # It prints the refusal it overrode IN FULL, so the escape is
        # never indistinguishable from no gate at all.
        self.assertIn("99.0.0", text)
        self.assertIn("Upgrade the compiler", text)

    def test_ignore_env_is_read_as_exactly_one(self):
        """Anything other than ``"1"`` leaves the gate armed.

        A half-remembered spelling must fail SAFE. If this ever
        loosened to a truthiness test, ``CAPA_IGNORE_CAPA_FLOOR=0``
        would disable the gate.
        """
        for value in ("0", "", "true", "yes", "TRUE", "2", " 1"):
            with self.subTest(value=value):
                with mock.patch.dict(
                    os.environ, {IGNORE_ENV: value}, clear=False,
                ):
                    with self.assertRaises(CapaFloorError):
                        check_root_floor(
                            ">=99.0.0", self.tmp / "capa.toml",
                            running="1.19.0", stream=self.err,
                        )

    def test_ignore_env_also_covers_an_unreadable_requirement(self):
        with mock.patch.dict(os.environ, {IGNORE_ENV: "1"}, clear=False):
            check_root_floor(
                "^1.17", self.tmp / "capa.toml",
                running="1.19.0", stream=self.err,
            )
        self.assertIn(IGNORE_ENV, self.err.getvalue())


class DependencyPolicyTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        self.err = io.StringIO()

    def test_violated_dependency_floor_warns_and_names_the_package(self):
        warned = warn_dependency_floor(
            ">=99.0.0", "capa_hex", self.tmp / "capa.toml",
            running="1.19.0", stream=self.err,
        )
        self.assertTrue(warned)
        text = self.err.getvalue()
        self.assertIn("capa_hex", text)
        self.assertIn("99.0.0", text)
        self.assertIn("warning", text)

    def test_violated_dependency_floor_never_raises(self):
        """The whole point of the root/transitive split.

        A dependency's floor is someone else's declaration, which the
        consumer cannot satisfy by editing their own manifest.
        """
        try:
            warn_dependency_floor(
                ">=99.0.0", "capa_hex", self.tmp / "capa.toml",
                running="1.19.0", stream=self.err,
            )
        except CapaFloorError:  # pragma: no cover - the failure we assert against
            self.fail("a dependency floor must never raise")

    def test_satisfied_dependency_floor_is_silent(self):
        warned = warn_dependency_floor(
            ">=1.2.0", "capa_hex", self.tmp / "capa.toml",
            running="1.19.0", stream=self.err,
        )
        self.assertFalse(warned)
        self.assertEqual(self.err.getvalue(), "")

    def test_absent_dependency_floor_is_silent(self):
        warned = warn_dependency_floor(
            None, "capa_hex", self.tmp / "capa.toml",
            running="0.0.1", stream=self.err,
        )
        self.assertFalse(warned)
        self.assertEqual(self.err.getvalue(), "")

    def test_unreadable_dependency_requirement_warns(self):
        warned = warn_dependency_floor(
            "^1.17", "capa_hex", self.tmp / "capa.toml",
            running="1.19.0", stream=self.err,
        )
        self.assertTrue(warned)
        self.assertIn("not a requirement this compiler can read",
                      self.err.getvalue())

    def test_unknown_running_version_does_not_repeat_per_dependency(self):
        warned = warn_dependency_floor(
            ">=99.0.0", "capa_hex", self.tmp / "capa.toml",
            running=UNKNOWN_VERSION, stream=self.err,
        )
        self.assertFalse(warned)
        self.assertEqual(self.err.getvalue(), "")


class ComposeDagTests(unittest.TestCase):
    """``build_package_dag`` warns for dependencies, not for the root."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def _package(self, rel: str, name: str, body_extra: str = "") -> Path:
        d = self.tmp / rel
        d.mkdir(parents=True, exist_ok=True)
        (d / "capa.toml").write_text(
            f'[package]\nname = "{name}"\nversion = "0.1.0"\n{body_extra}',
            encoding="utf-8",
        )
        (d / "lib.capa").write_text("fun noop()\n    pass\n", encoding="utf-8")
        return d

    def test_dependency_floor_warns_once_and_the_dag_still_builds(self):
        from capa.manifest._compose import build_package_dag

        self._package("dep", "dep", 'capa = ">=99.0.0"\n')
        root = self._package(
            ".", "root",
            '\n[dependencies.dep]\npath = "dep"\n',
        )
        err = io.StringIO()
        with mock.patch.object(sys, "stderr", err):
            nodes, node = build_package_dag(root)
        self.assertEqual(node.name, "root")
        text = err.getvalue()
        self.assertIn("'dep'", text)
        self.assertIn("99.0.0", text)
        self.assertEqual(
            text.count("capa: warning: dependency"), 1,
            "each offending package must be named exactly once per build",
        )

    def test_the_root_floor_does_not_warn_from_the_dag(self):
        """The root is the HARD-error path; warning there too would
        double-report it."""
        from capa.manifest._compose import build_package_dag

        root = self._package(".", "root", 'capa = ">=99.0.0"\n')
        err = io.StringIO()
        with mock.patch.object(sys, "stderr", err):
            build_package_dag(root)
        self.assertEqual(err.getvalue(), "")


# ---------------------------------------------------------------------------
# 4. Structural invariants.
# ---------------------------------------------------------------------------


class StructuralTests(unittest.TestCase):
    def test_capa_floor_error_is_not_a_manifest_error(self):
        """``manifest/_compose.py`` catches ``(ManifestError, OSError,
        ValueError)`` around each dependency's ``read_manifest``. A
        ``CapaFloorError`` subclassing ``ManifestError`` would be caught
        there and reported as "capa.toml is unreadable or invalid",
        turning a POLICY decision into a claim about file integrity: the
        composed SBOM would mark the dependency authority-UNKNOWN for a
        reason that has nothing to do with its authority.

        The invariant is invisible in the code (it is an absence), so it
        is asserted here.
        """
        self.assertFalse(issubclass(CapaFloorError, ManifestError))
        self.assertTrue(issubclass(CapaFloorError, Exception))

    def test_the_floor_reads_the_single_version_source(self):
        """``_floor`` must resolve the running version through
        ``capa.__version__`` and never through
        ``importlib.metadata.version``.

        ``capa/__init__.py``'s ``_resolve_version`` reads the ADJACENT
        ``pyproject.toml`` FIRST and only then falls back to metadata,
        which is why the floor is correct in a source tree, an editable
        install with stale dist-info, a wheel and the frozen binary
        alike. A second version source would be a second version.
        """
        import re

        source = (
            REPO_ROOT / "capa" / "pkg" / "_floor.py"
        ).read_text(encoding="utf-8")
        # No IMPORT of a metadata module (the docstring may name it; an
        # import is what would make it a second version source).
        self.assertIsNone(
            re.search(
                r"^\s*(?:from\s+importlib(?:_metadata|\.metadata)|"
                r"import\s+importlib)",
                source, re.MULTILINE,
            ),
            "_floor.py must not import a distribution-metadata module",
        )
        self.assertIn("from .. import __version__", source)

    def test_running_version_is_capa_dunder_version(self):
        import capa
        from capa.pkg._floor import _running_version

        self.assertEqual(_running_version(), capa.__version__)

    def test_the_cli_re_raise_arm_is_present(self):
        source = (REPO_ROOT / "capa" / "cli.py").read_text(encoding="utf-8")
        self.assertIn("except CapaFloorError:", source)


class SearchPathReRaiseTests(unittest.TestCase):
    """``cli._capa_search_paths`` must not swallow the floor error.

    Its ``except Exception`` arm degrades a broken ``capa.toml`` to a
    warning and then continues with ``./vendor`` dropped from the search
    path. Applied to a floor violation that is strictly worse than not
    checking at all: the user is told their manifest was "ignored" and
    the build proceeds anyway. The explicit ``except CapaFloorError:
    raise`` arm placed before it is what prevents that, and deleting it
    as redundant is exactly what this test exists to catch.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def test_floor_error_propagates_out_of_capa_search_paths(self):
        from capa import cli

        (self.tmp / "capa.toml").write_text(
            '[package]\nname = "x"\nversion = "0.1.0"\ncapa = ">=99.0.0"\n'
            '\n[dependencies.dep]\ngit = "https://example.com/dep"\n'
            'tag = "v0.1.0"\n',
            encoding="utf-8",
        )
        err = io.StringIO()
        original = os.getcwd()
        os.chdir(self.tmp)
        try:
            with mock.patch.object(sys, "stderr", err):
                with self.assertRaises(CapaFloorError):
                    cli._capa_search_paths()
        finally:
            os.chdir(original)
        # And it did NOT come out as the generic "ignoring capa.toml"
        # warning that the ``except Exception`` arm would have produced.
        self.assertNotIn("ignoring capa.toml", err.getvalue())


# ---------------------------------------------------------------------------
# 5. The exemptions, as real CLI invocations.
# ---------------------------------------------------------------------------

_VIOLATING_MANIFEST = (
    '[package]\nname = "proj"\nversion = "0.1.0"\ncapa = ">=99.0.0"\n'
)

# The marker every exemption test looks for. If the gate fired, this
# substring is on stderr and the invocation returned 1.
_FLOOR_MARKER = "99.0.0"


class ExemptionTests(unittest.TestCase):
    """Each exempt invocation must RUN with a violating root capa.toml.

    Not "is listed as exempt": actually run, in the directory whose
    manifest declares a floor no compiler will ever satisfy. Every entry
    is a case where hard-erroring would take away the user's route out
    of the error, so a regression here is silent and expensive.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        (self.tmp / "capa.toml").write_text(
            _VIOLATING_MANIFEST, encoding="utf-8",
        )
        (self.tmp / "main.capa").write_text(
            'fun main(stdio: Stdio)\n    stdio.println("hi")\n',
            encoding="utf-8",
        )

    def assertNotGated(self, err: str, argv):
        self.assertNotIn(
            _FLOOR_MARKER, err,
            f"`capa {' '.join(argv)}` must bypass the compiler-floor gate; "
            f"stderr was:\n{err}",
        )

    # -- The negative control. Without this the whole class could pass
    # -- against a gate that never fires at all.

    def test_control_a_non_exempt_command_IS_gated(self):
        rc, _, err = _run_main(["--check", "main.capa"], cwd=self.tmp)
        self.assertEqual(rc, 1)
        self.assertIn(_FLOOR_MARKER, err)
        self.assertIn("99.0.0", err)

    # -- The exemptions.

    def test_no_arguments(self):
        rc, out, err = _run_main([], cwd=self.tmp)
        self.assertNotGated(err, [])

    def test_top_level_help(self):
        rc, out, err = _run_main(["--help"], cwd=self.tmp)
        self.assertEqual(rc, 0)
        self.assertNotGated(err, ["--help"])

    def test_top_level_short_help(self):
        rc, out, err = _run_main(["-h"], cwd=self.tmp)
        self.assertEqual(rc, 0)
        self.assertNotGated(err, ["-h"])

    def test_version(self):
        """``--version`` is an argparse action handled INSIDE
        ``_main_dispatch``. Without the exemption, a floor violation
        bricks the one command the error message tells the user to run
        to find out which compiler they actually have.
        """
        import capa

        rc, out, err = _run_main(["--version"], cwd=self.tmp)
        self.assertEqual(rc, 0)
        self.assertIn(capa.__version__, out)
        self.assertNotGated(err, ["--version"])

    def test_subcommand_help_for_every_subcommand(self):
        """``capa build --help`` puts ``build`` in argv[0], so a naive
        ``argv[0] in EXEMPT`` test would gate the help of every
        subcommand."""
        for command in (
            "init", "install", "add", "search", "migrate", "build",
            "run-aot", "test",
        ):
            with self.subTest(command=command):
                rc, out, err = _run_main([command, "--help"], cwd=self.tmp)
                self.assertEqual(rc, 0, err)
                self.assertNotGated(err, [command, "--help"])

    def _assert_dispatch_reached(self, name, argv):
        """Patch a subcommand's dispatcher and assert the gate let the
        invocation through to it. The dispatchers themselves reach the
        network / a language server, which is not what is under test
        here: the gate runs strictly before dispatch, so reaching the
        dispatcher IS the property."""
        from capa import cli

        with mock.patch.object(cli, name, return_value=0) as dispatch:
            rc, out, err = _run_main(argv, cwd=self.tmp)
        self.assertTrue(
            dispatch.called,
            f"`capa {' '.join(argv)}` never reached {name}; stderr:\n{err}",
        )
        self.assertEqual(rc, 0)
        self.assertNotGated(err, argv)

    def test_search_is_exempt(self):
        """``search`` queries the registry and needs no local manifest."""
        self._assert_dispatch_reached("_dispatch_search", ["search", "http"])

    def test_add_is_exempt(self):
        """``add`` WRITES capa.toml. Blocking it would stop the user
        repairing the very file that is blocking them."""
        self._assert_dispatch_reached("_dispatch_add", ["add", "capa_hex"])

    def test_init_is_exempt(self):
        """``init`` scaffolds a NEW project, in a directory that is not
        the one whose manifest is at fault."""
        self._assert_dispatch_reached("_dispatch_init", ["init", "newproj"])

    def test_lsp_is_exempt(self):
        """A hard error in ``lsp`` makes an editor silently lose
        language support, with the reason in a stderr it discards."""
        from capa import cli

        with mock.patch("capa.lsp_server.serve", return_value=0) as serve:
            rc, out, err = _run_main(["lsp"], cwd=self.tmp)
        self.assertTrue(serve.called, err)
        self.assertNotGated(err, ["lsp"])

    def test_there_is_no_dash_capital_v_to_exempt(self):
        """``-V`` does not exist on this parser, and the exemption list
        must not pretend it does: exempting a flag that is not there
        only misleads the next reader. argparse rejects it (exit 2)."""
        rc, out, err = _run_main(["-V"], cwd=self.tmp)
        self.assertNotEqual(rc, 0)
        from capa.cli import _floor_check_exempt
        self.assertFalse(_floor_check_exempt(["-V"]))

    def test_ignore_env_lets_a_gated_command_through(self):
        rc, out, err = _run_main(
            ["--check", "main.capa"], cwd=self.tmp, env={IGNORE_ENV: "1"},
        )
        self.assertEqual(rc, 0, err)
        self.assertIn(IGNORE_ENV, err)


class ExemptPredicateTests(unittest.TestCase):
    """Unit coverage of ``_floor_check_exempt`` itself."""

    def test_exempt_shapes(self):
        from capa.cli import _floor_check_exempt

        for argv in (
            [], ["--help"], ["-h"], ["--version"],
            ["build", "--help"], ["run-aot", "-h"], ["install", "--help"],
            ["search", "json"], ["add", "capa_hex"], ["init", "p"],
            ["lsp"], ["--check", "x.capa", "--help"],
        ):
            with self.subTest(argv=argv):
                self.assertTrue(_floor_check_exempt(argv))

    def test_non_exempt_shapes(self):
        from capa.cli import _floor_check_exempt

        for argv in (
            ["--check", "x.capa"], ["--run", "x.capa"], ["build", "x.capa"],
            ["install"], ["test"], ["migrate", "x.capa"], ["repl"],
            ["run-aot", "a.capaot"], ["x.capa"], ["-V"],
            ["--manifest", "x.capa"],
        ):
            with self.subTest(argv=argv):
                self.assertFalse(_floor_check_exempt(argv))


# ---------------------------------------------------------------------------
# `capa init` on a sentinel version.
# ---------------------------------------------------------------------------


class InitSentinelTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def test_init_refuses_a_sentinel_version_and_writes_nothing(self):
        """``capa init`` used to stamp ``capa = ">=0+unknown"``, a
        manifest the compiler that wrote it could not then parse. Now
        that the floor is enforced, every later command in that project
        would refuse it as an unreadable requirement."""
        from capa.init_project import init_project

        target = self.tmp / "proj"
        err = io.StringIO()
        with mock.patch.object(sys, "stderr", err):
            rc = init_project(target, capa_version=UNKNOWN_VERSION)
        self.assertEqual(rc, 2)
        self.assertFalse(
            target.exists(),
            "a refused init must leave nothing on disk",
        )
        self.assertIn(UNKNOWN_VERSION, err.getvalue())

    def test_init_refuses_any_non_release_version(self):
        from capa.init_project import init_project

        for bogus in ("1.19", "1.19.0.dev1", "", "v1.19.0"):
            with self.subTest(bogus=bogus):
                target = self.tmp / f"p-{bogus or 'empty'}"
                with mock.patch.object(sys, "stderr", io.StringIO()):
                    rc = init_project(target, capa_version=bogus)
                self.assertEqual(rc, 2)
                self.assertFalse(target.exists())

    def test_init_stamps_a_readable_enforced_floor(self):
        from capa.init_project import init_project

        target = self.tmp / "proj"
        err = io.StringIO()
        with mock.patch.object(sys, "stderr", err):
            rc = init_project(target, capa_version="1.19.0")
        self.assertEqual(rc, 0)
        manifest = read_manifest(target / "capa.toml")
        self.assertEqual(manifest.capa_requirement, ">=1.19.0")
        # The floor it stamped is parseable by this very compiler.
        self.assertEqual(parse_requirement(manifest.capa_requirement),
                         (1, 19, 0))
        # And the user is told it is enforced.
        text = err.getvalue()
        self.assertIn(">=1.19.0", text)
        self.assertIn("enforced", text)

    def test_a_scaffolded_project_builds_on_the_compiler_that_made_it(self):
        """End to end: `capa init` then a gated command in the new
        project. The stamped floor must never gate the compiler that
        stamped it."""
        import capa
        from capa import cli

        target = self.tmp / "proj"
        with mock.patch.object(sys, "stderr", io.StringIO()):
            rc = init_project_or_skip(self, target, capa.__version__)
        if rc is None:
            return
        rc, out, err = _run_main(["--check", "main.capa"], cwd=target)
        self.assertEqual(rc, 0, err)
        del cli


def init_project_or_skip(case, target, version):
    """Scaffold at ``target``, or skip when this build has no version.

    A source checkout always resolves a real version from the adjacent
    pyproject.toml, so this only skips on a build that is already
    known-broken.
    """
    from capa.init_project import init_project

    if parse_version(version) is None:  # pragma: no cover - broken build only
        case.skipTest(f"this build reports {version!r}, not an X.Y.Z release")
        return None
    return init_project(target, capa_version=version)


if __name__ == "__main__":
    unittest.main()
