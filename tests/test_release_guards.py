"""Regression tests for the release guards in ``tools/``.

These guard the guards. ``.github/workflows/release-guards.yml`` is a
reusable workflow that every Capa package repository is meant to call,
and the three shell scripts it invokes are the only copy of that logic
anywhere. If one of them regresses, every repository that adopted it
starts reporting success while checking nothing, which is worse than
having no guard at all.

THE NEGATIVE CASES ARE THE POINT. A guard is worth exactly what its
FAILURES are worth. Asserting that ``check_tag_version.sh`` prints OK on
the happy path proves almost nothing, because ``true`` would pass that
assertion too. So nearly every case below asserts a NON-ZERO exit, and
``MutationTests`` at the bottom makes that concrete: it replaces each
guard with an unconditional ``exit 0`` and asserts this file notices.
A suite that survives its own guard being neutered was never testing it.

Run them the way CI does::

    python -m unittest discover tests
"""

import os
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

# Imported unconditionally, and deliberately so. These checks used to
# wrap it in `try: import yaml / except ImportError: self.skipTest(...)`,
# which meant that on any environment without PyYAML they reported OK
# having verified nothing, and PyYAML was declared in no extra, so that
# was the DEFAULT. It is now in the `[test]` extra, and a missing PyYAML
# is an ERROR at import time under `python -m unittest discover tests`
# rather than a silent pass. Failing loudly when a guard cannot run is
# the same rule the guards themselves are built on.
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
TOOLS = REPO_ROOT / "tools"
CHECK_TAG_VERSION = TOOLS / "check_tag_version.sh"
CAPA_FLOOR = TOOLS / "capa_floor.sh"
CLEAN_ROOM_BUILD = TOOLS / "clean_room_build.sh"
VERIFY_GUARD_DIGESTS = TOOLS / "verify_guard_digests.sh"

BASH = shutil.which("bash")


def bash_path(path) -> str:
    """Render a filesystem path the way the ``bash`` on this host wants it.

    The guards are shell and run on ``ubuntu-latest`` in CI, but they are
    also meant to be runnable by hand on a developer's machine, which
    here is Windows with Git Bash. Git Bash takes ``/c/Users/...`` rather
    than ``C:\\Users\\...``, and ``clean_room_build.sh`` insists on an
    absolute room path (a relative one would resolve against the source
    checkout, which is the tree the clean room exists to be away from).
    Translating here keeps a single suite covering all three platforms
    instead of skipping the guards on the one they are authored on.
    """
    text = str(path)
    if os.name == "nt" and len(text) > 1 and text[1] == ":":
        return "/" + text[0].lower() + text[2:].replace("\\", "/")
    return text


def run_guard(script, *args):
    """Run a guard script and return ``(exit_code, combined_output)``."""
    proc = subprocess.run(
        [BASH, bash_path(script), *args],
        capture_output=True,
        text=True,
    )
    return proc.returncode, proc.stdout + proc.stderr


# --------------------------------------------------------------------------
# Guard 1: the tag matches the manifest version.
# --------------------------------------------------------------------------

# The manifests every guard-1 case is written against. `stale` is the
# real capa_authgate v0.2.0 defect, preserved as a fixture: the tag said
# v0.2.0 and the manifest still said 0.1.0.
TAG_MANIFESTS = {
    "good": '[package]\nname = "capa_authgate"\nversion = "0.2.1"\ncapa = ">=1.17.0"\n',
    "stale": '[package]\nname = "capa_authgate"\nversion = "0.1.0"\n',
    "noversion": '[package]\nname = "capa_authgate"\ncapa = ">=1.17.0"\n',
    "empty": '[package]\nname = "capa_authgate"\nversion = ""\n',
    "dup": '[package]\nname = "x"\nversion = "0.2.1"\nversion = "9.9.9"\n',
    "deponly": '[package]\nname = "x"\n\n[dependencies.capa_jwt]\nversion = "0.2.1"\n',
    "comment": '[package]\nname = "x"\nversion = "0.2.1"  # trailing comment\n',
    # The pyproject dialect: the version lives in [project], and
    # [project.optional-dependencies] must not be read as part of it.
    "pyproject": (
        '[build-system]\nrequires = ["setuptools>=68"]\n\n'
        '[project]\nname = "capa"\nversion = "1.17.0"\nrequires-python = ">=3.10"\n\n'
        '[project.optional-dependencies]\nlsp = ["pygls>=2.0"]\n'
    ),
}

# (description, expected_exit, args-as-manifest-keys). A manifest key is
# resolved to its temp path; anything else is passed through verbatim.
TAG_CASES = [
    ("matching tag and version", 0, ["v0.2.1", "good"]),
    ("version with a trailing comment", 0, ["v0.2.1", "comment"]),
    ("pyproject dialect via the table argument", 0, ["v1.17.0", "pyproject", "project"]),
    ("the real v0.2.0 defect: tag ahead of manifest", 1, ["v0.2.0", "stale"]),
    ("tag behind the manifest", 1, ["v0.1.0", "good"]),
    ("tag without the v prefix", 1, ["0.2.1", "good"]),
    ("missing manifest", 1, ["v0.2.1", "absent"]),
    ("empty tag (unset GITHUB_REF_NAME)", 1, ["", "good"]),
    ("manifest with no [package] version", 1, ["v0.2.1", "noversion"]),
    ("version present but empty", 1, ["v0.2.1", "empty"]),
    ("two [package] version lines", 1, ["v0.2.1", "dup"]),
    ("only a DEPENDENCY declares the version", 1, ["v0.2.1", "deponly"]),
    # Without the table argument, pyproject's version is in a table the
    # guard was not pointed at, so it must refuse rather than fall back
    # to any version-looking line it can find.
    ("pyproject read with the default [package] table", 1, ["v1.17.0", "pyproject"]),
    ("[project.optional-dependencies] is not part of [project]", 1,
     ["v2.0.0", "pyproject", "project"]),
    ("table name carrying regex metacharacters", 1, ["v1.17.0", "pyproject", "pro.ect"]),
    ("empty table name", 1, ["v1.17.0", "pyproject", ""]),
]


class CheckTagVersionTests(unittest.TestCase):
    """``tools/check_tag_version.sh``: guard 1."""

    @classmethod
    def setUpClass(cls):
        if BASH is None:
            raise unittest.SkipTest("bash is not available on this host")
        cls._tmp = tempfile.TemporaryDirectory()
        cls.manifests = {}
        for name, body in TAG_MANIFESTS.items():
            path = Path(cls._tmp.name) / f"{name}.toml"
            path.write_text(body, encoding="utf-8")
            cls.manifests[name] = path
        cls.manifests["absent"] = Path(cls._tmp.name) / "absent.toml"

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "_tmp"):
            cls._tmp.cleanup()

    @classmethod
    def resolve(cls, args):
        return [
            bash_path(cls.manifests[a]) if a in cls.manifests else a
            for a in args
        ]

    def test_cases(self):
        for description, want, args in TAG_CASES:
            with self.subTest(case=description):
                got, output = run_guard(CHECK_TAG_VERSION, *self.resolve(args))
                self.assertEqual(
                    got, want,
                    f"{description}: wanted exit {want}, got {got}\n{output}",
                )

    def test_live_pyproject_against_its_own_tag(self):
        """The guard as this repository's own release would invoke it."""
        version = None
        in_project = False
        for line in (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8").splitlines():
            if line.strip().startswith("["):
                in_project = line.strip() == "[project]"
                continue
            if in_project and line.strip().startswith("version"):
                version = line.split("=", 1)[1].strip().strip('"').strip("'")
        self.assertIsNotNone(version, "pyproject.toml has no [project] version")

        got, output = run_guard(
            CHECK_TAG_VERSION, f"v{version}",
            bash_path(REPO_ROOT / "pyproject.toml"), "project",
        )
        self.assertEqual(got, 0, output)

        got, output = run_guard(
            CHECK_TAG_VERSION, "v9.9.9",
            bash_path(REPO_ROOT / "pyproject.toml"), "project",
        )
        self.assertEqual(got, 1, f"a wrong tag must be refused\n{output}")


# --------------------------------------------------------------------------
# The compiler floor, which decides WHICH released compiler guard 2 uses.
# --------------------------------------------------------------------------

FLOOR_MANIFESTS = {
    "floor": '[package]\nname = "x"\nversion = "1.0.0"\ncapa = ">=1.17.0"\n',
    "spaced": '[package]\nname = "x"\ncapa = ">= 1.17.0"\n',
    "exact": '[package]\nname = "x"\ncapa = "1.17.0"\n',
    "commented": '[package]\nname = "x"\ncapa = ">=1.17.0"  # the Serve floor\n',
    "none": '[package]\nname = "x"\nversion = "1.0.0"\n',
    "caret": '[package]\nname = "x"\ncapa = "^1.17"\n',
    "range": '[package]\nname = "x"\ncapa = ">=1.17.0,<2"\n',
    "wildcard": '[package]\nname = "x"\ncapa = "1.*"\n',
    "dup": '[package]\nname = "x"\ncapa = ">=1.17.0"\ncapa = ">=1.2.0"\n',
    # A dependency's own capa pin must not be mistaken for the package's.
    "deponly": '[package]\nname = "x"\n\n[dependencies.capa_jwt]\ncapa = ">=1.17.0"\n',
}

# (description, expected_exit, manifest key, expected stdout or None)
FLOOR_CASES = [
    ("a >= floor", 0, "floor", "1.17.0"),
    ("a spaced >= floor", 0, "spaced", "1.17.0"),
    ("an exact pin", 0, "exact", "1.17.0"),
    ("a floor with a trailing comment", 0, "commented", "1.17.0"),
    ("no capa requirement at all", 1, "none", None),
    ("a caret constraint names no single release", 1, "caret", None),
    ("a range names no single release", 1, "range", None),
    ("a wildcard names no single release", 1, "wildcard", None),
    ("two capa requirements", 1, "dup", None),
    ("only a DEPENDENCY declares capa", 1, "deponly", None),
    ("missing manifest", 1, "absent", None),
]


class CapaFloorTests(unittest.TestCase):
    """``tools/capa_floor.sh``: which released compiler guard 2 builds with.

    Getting this wrong is not a loud failure, it is a quiet one: guard 2
    would build the artefact with a compiler no consumer is obliged to
    have, and report success about the wrong thing. Hence the refusals
    for every constraint form that does not name exactly one release.
    """

    @classmethod
    def setUpClass(cls):
        if BASH is None:
            raise unittest.SkipTest("bash is not available on this host")
        cls._tmp = tempfile.TemporaryDirectory()
        cls.manifests = {}
        for name, body in FLOOR_MANIFESTS.items():
            path = Path(cls._tmp.name) / f"{name}.toml"
            path.write_text(body, encoding="utf-8")
            cls.manifests[name] = path
        cls.manifests["absent"] = Path(cls._tmp.name) / "absent.toml"

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "_tmp"):
            cls._tmp.cleanup()

    def test_cases(self):
        for description, want, key, want_out in FLOOR_CASES:
            with self.subTest(case=description):
                got, output = run_guard(CAPA_FLOOR, bash_path(self.manifests[key]))
                self.assertEqual(
                    got, want,
                    f"{description}: wanted exit {want}, got {got}\n{output}",
                )
                if want_out is not None:
                    self.assertEqual(output.strip(), want_out, description)

    def test_authgate_style_manifest(self):
        """The floor of a real package manifest, header comments and all."""
        manifest = Path(self._tmp.name) / "real.toml"
        manifest.write_text(
            "# capa_authgate - package manifest.\n"
            "#\n"
            "# `Serve` shipped in capa 1.17.0, which is why the floor moved.\n"
            "\n"
            '[package]\nname = "capa_authgate"\nversion = "0.2.1"\ncapa = ">=1.17.0"\n'
            "\n"
            '[capabilities]\nmax = ["Serve", "Env"]\n'
            "\n"
            "[dependencies.capa_jwt]\n"
            'git = "https://github.com/nelsonduarte/capa_jwt"\ntag = "v0.1.0"\n',
            encoding="utf-8",
        )
        got, output = run_guard(CAPA_FLOOR, bash_path(manifest))
        self.assertEqual(got, 0, output)
        self.assertEqual(output.strip(), "1.17.0")


# --------------------------------------------------------------------------
# Guard 2: the artefact builds from a clean location.
# --------------------------------------------------------------------------


def make_tarball(path: Path, prefix: str, files: dict) -> Path:
    """Write a gzipped tarball with ``files`` under a single ``prefix`` dir."""
    with tarfile.open(path, "w:gz") as tar:
        for name, body in files.items():
            data = body.encode("utf-8")
            info = tarfile.TarInfo(f"{prefix}/{name}")
            info.size = len(data)
            info.mode = 0o755
            import io
            tar.addfile(info, io.BytesIO(data))
    return path


class CleanRoomBuildTests(unittest.TestCase):
    """``tools/clean_room_build.sh``: guard 2.

    Two of the three failures this whole exercise came from are
    reproduced here as fixtures:

    * ``test_sibling_satisfied_import_is_caught`` is capa_authgate
      v0.1.0. A build step that only succeeds because a same-named
      directory sits next to the project. The guard's room has no
      neighbours, so it fails, which is what should have happened before
      that tarball was signed and published.

    * ``test_missing_file_the_readme_documents_is_caught`` is the
      export-ignored ``tools/``. The README's own command is run against
      the artefact's contents, so a file the tarball does not carry is a
      failure rather than a thing nobody noticed.
    """

    @classmethod
    def setUpClass(cls):
        if BASH is None:
            raise unittest.SkipTest("bash is not available on this host")

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        self.room = self.tmp / "room"
        self.tarball = make_tarball(
            self.tmp / "pkg-v1.0.0.tar.gz",
            "pkg-v1.0.0",
            {
                "capa.toml": '[package]\nname = "pkg"\nversion = "1.0.0"\n',
                "main.capa": "fun main() {}\n",
                "tools/build.sh": "echo built\n",
            },
        )

    def guard(self, *args):
        return run_guard(CLEAN_ROOM_BUILD, *args)

    def base_args(self, room=None, tarball=None):
        return [
            "--tarball", bash_path(tarball or self.tarball),
            "--room", bash_path(room or self.room),
        ]

    # -- the happy path, which on its own proves almost nothing ---------

    def test_a_buildable_artefact_passes(self):
        code, out = self.guard(
            *self.base_args(),
            "--run", "test -f capa.toml",
            "--run", "bash tools/build.sh",
        )
        self.assertEqual(code, 0, out)
        self.assertIn("siblings: none", out)
        self.assertIn("builds from a clean location", out)

    def test_the_digest_of_what_it_verified_is_recorded(self):
        out_file = self.tmp / "digest.txt"
        code, out = self.guard(
            *self.base_args(),
            "--sha256-out", bash_path(out_file),
            "--run", "true",
        )
        self.assertEqual(code, 0, out)
        import hashlib
        want = hashlib.sha256(self.tarball.read_bytes()).hexdigest()
        self.assertEqual(out_file.read_text(encoding="utf-8").strip(), want)
        self.assertIn(want, out)

    # -- the two failures that actually shipped ------------------------

    def test_sibling_satisfied_import_is_caught(self):
        """capa_authgate v0.1.0, in miniature.

        The package's build only works when a ``capa_hash`` directory is
        its neighbour. In the development tree it was; in the clean room
        nothing is, so the guard fails, loudly, before publication.
        """
        code, out = self.guard(
            *self.base_args(),
            "--run", "test -d ../capa_hash",
        )
        self.assertEqual(code, 1, out)
        self.assertIn("does not build outside the development tree", out)

    def test_missing_file_the_readme_documents_is_caught(self):
        """The export-ignored ``tools/``, in miniature."""
        stripped = make_tarball(
            self.tmp / "stripped-v1.0.0.tar.gz",
            "stripped-v1.0.0",
            {"capa.toml": '[package]\nname = "pkg"\nversion = "1.0.0"\n'},
        )
        code, out = self.guard(
            *self.base_args(tarball=stripped),
            "--run", "bash tools/build.sh",
        )
        self.assertEqual(code, 1, out)
        self.assertIn("clean-room step 1 failed", out)

    def test_a_later_step_failing_fails_the_guard(self):
        code, out = self.guard(
            *self.base_args(),
            "--run", "true",
            "--run", "true",
            "--run", "exit 3",
        )
        self.assertEqual(code, 1, out)
        self.assertIn("clean-room step 3 failed", out)
        # The REPORTED status must be the step's real one. It was not:
        # the first draft read `$?` inside an `if ! cmd`, which is the
        # status of the negation, so every failing step was announced as
        # "exit 0" while the guard nonetheless failed. A guard whose
        # diagnostics cannot be trusted is how the next defect gets
        # waved through.
        self.assertIn("(exit 3)", out)

    # -- every way of not knowing ---------------------------------------

    def test_no_run_commands_is_refused(self):
        """The most important refusal in the whole guard.

        A clean room that runs nothing would extract a tarball, find no
        problem, and report success. That is the exact shape of the
        false confidence this work exists to remove, so it is an error.
        """
        code, out = self.guard(*self.base_args())
        self.assertEqual(code, 1, out)
        self.assertIn("proves nothing", out)

    def test_empty_run_command_is_refused(self):
        code, out = self.guard(*self.base_args(), "--run", "   ")
        self.assertEqual(code, 1, out)
        self.assertIn("refusing to pretend it ran", out)

    def test_missing_tarball_is_refused(self):
        code, out = self.guard(
            "--tarball", bash_path(self.tmp / "absent.tar.gz"),
            "--room", bash_path(self.room),
            "--run", "true",
        )
        self.assertEqual(code, 1, out)
        self.assertIn("not found", out)

    def test_no_tarball_argument_is_refused(self):
        code, out = self.guard("--room", bash_path(self.room), "--run", "true")
        self.assertEqual(code, 1, out)
        self.assertIn("no artefact to verify", out)

    def test_no_room_argument_is_refused(self):
        code, out = self.guard("--tarball", bash_path(self.tarball), "--run", "true")
        self.assertEqual(code, 1, out)
        self.assertIn("needs an explicit location", out)

    def test_relative_room_is_refused(self):
        """A relative room resolves against the source checkout."""
        code, out = self.guard(
            "--tarball", bash_path(self.tarball),
            "--room", "room",
            "--run", "true",
        )
        self.assertEqual(code, 1, out)
        self.assertIn("must be an absolute path", out)

    def test_non_empty_room_is_refused(self):
        """Anything already in the room becomes the artefact's sibling."""
        self.room.mkdir()
        (self.room / "capa_hash").mkdir()
        code, out = self.guard(*self.base_args(), "--run", "true")
        self.assertEqual(code, 1, out)
        self.assertIn("would give the artefact siblings", out)

    def test_room_that_is_a_file_is_refused(self):
        room = self.tmp / "notadir"
        room.write_text("", encoding="utf-8")
        code, out = self.guard(
            *self.base_args(room=room), "--run", "true",
        )
        self.assertEqual(code, 1, out)
        self.assertIn("not a directory", out)

    def test_tarball_without_a_single_root_is_refused(self):
        """Loose files at the top level have no project root to build in."""
        loose = self.tmp / "loose.tar.gz"
        with tarfile.open(loose, "w:gz") as tar:
            import io
            for name in ("a.capa", "b.capa"):
                data = b"x"
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        code, out = self.guard(
            *self.base_args(tarball=loose), "--run", "true",
        )
        self.assertEqual(code, 1, out)
        self.assertIn("expected exactly 1", out)

    def test_unknown_argument_is_refused(self):
        code, out = self.guard(*self.base_args(), "--run", "true", "--yolo")
        self.assertEqual(code, 1, out)
        self.assertIn("unknown argument", out)

    def test_inherited_capa_path_does_not_reach_the_clean_room(self):
        """CAPA_PATH is an explicit list of module search roots.

        Inheriting it would let the clean room reach straight back into
        the tree it is supposed to be isolated from, which would rebuild
        the capa_authgate v0.1.0 blind spot inside the guard meant to
        catch it.
        """
        env = dict(os.environ, CAPA_PATH="/somewhere/with/siblings")
        proc = subprocess.run(
            [
                BASH, bash_path(CLEAN_ROOM_BUILD),
                *self.base_args(),
                "--run", 'test -z "${CAPA_PATH-}"',
            ],
            capture_output=True, text=True, env=env,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)


# --------------------------------------------------------------------------
# The mutation test: does this file actually notice a dead guard?
# --------------------------------------------------------------------------

# For each guard: the mutant that replaces it, and the negative cases
# that must stop failing once it is in place. If a guard can be swapped
# for `exit 0` and these tests stay green, the tests were decorative.
MUTANT = "#!/usr/bin/env bash\n# MUTANT: an unconditional pass.\nexit 0\n"


class VerifyGuardDigestsTests(unittest.TestCase):
    """``tools/verify_guard_digests.sh``: the independent anchor.

    It exists because the step it accompanies used to be called "Confirm
    the guards are the revision the caller pinned" and did no such
    thing: it compared the checked-out SHA against the value it had just
    used as the checkout ref, so both sides came from one variable and
    it agreed with itself. Handed the wrong revision it reported OK.

    This is deliberately NOT a claim to have fixed that in general. A
    workflow cannot establish its own identity from the inside; a
    substituted workflow substitutes this check too. What the digests
    add is an anchor written in the ADOPTER's repository rather than
    ours, which is the only thing that would notice the guard scripts
    changing under an adopter who pinned a moving ref.
    """

    @classmethod
    def setUpClass(cls):
        if BASH is None:
            raise unittest.SkipTest("bash is not available on this host")

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        self.root = self.tmp / "guards"
        (self.root / "tools").mkdir(parents=True)
        self.script = self.root / "tools" / "check_tag_version.sh"
        self.script.write_text("#!/usr/bin/env bash\necho hi\n", encoding="utf-8")
        import hashlib
        self.digest = hashlib.sha256(self.script.read_bytes()).hexdigest()

    def write_digests(self, body: str) -> Path:
        path = self.tmp / "digests.txt"
        path.write_text(body, encoding="utf-8")
        return path

    def guard(self, digests_body):
        return run_guard(
            VERIFY_GUARD_DIGESTS,
            bash_path(self.root),
            bash_path(self.write_digests(digests_body)),
        )

    def test_a_matching_digest_passes(self):
        code, out = self.guard(f"{self.digest}  tools/check_tag_version.sh\n")
        self.assertEqual(code, 0, out)
        self.assertIn("1 guard file(s) match", out)

    def test_sha256sum_binary_mode_marker_is_accepted(self):
        code, out = self.guard(f"{self.digest} *tools/check_tag_version.sh\n")
        self.assertEqual(code, 0, out)

    def test_uppercase_digest_is_accepted(self):
        code, out = self.guard(f"{self.digest.upper()}  tools/check_tag_version.sh\n")
        self.assertEqual(code, 0, out)

    def test_comments_and_blank_lines_are_ignored(self):
        code, out = self.guard(
            f"# the guards I audited on 2026-07-19\n\n"
            f"{self.digest}  tools/check_tag_version.sh\n\n"
        )
        self.assertEqual(code, 0, out)

    # -- the failures, which are the point ------------------------------

    def test_a_changed_script_is_caught(self):
        """The scenario the anchor exists for: the guards moved."""
        self.script.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
        code, out = self.guard(f"{self.digest}  tools/check_tag_version.sh\n")
        self.assertEqual(code, 1, out)
        self.assertIn("does not match the digest you pinned", out)
        self.assertIn("re-audit and re-pin", out)

    def test_a_pinned_file_that_is_absent_is_caught(self):
        code, out = self.guard(f"{self.digest}  tools/gone.sh\n")
        self.assertEqual(code, 1, out)
        self.assertIn("is not present in the fetched guards", out)

    def test_an_empty_digests_file_is_refused(self):
        """'Verified nothing' must never render as 'verified'."""
        code, out = self.guard("\n# only a comment\n\n")
        self.assertEqual(code, 1, out)
        self.assertIn("lists no files", out)

    def test_a_malformed_line_is_refused(self):
        code, out = self.guard("not-a-digest  tools/check_tag_version.sh\n")
        self.assertEqual(code, 1, out)
        self.assertIn("malformed digest line", out)

    def test_a_truncated_digest_is_refused(self):
        code, out = self.guard(f"{self.digest[:32]}  tools/check_tag_version.sh\n")
        self.assertEqual(code, 1, out)
        self.assertIn("malformed digest line", out)

    def test_a_line_with_no_path_is_refused(self):
        code, out = self.guard(f"{self.digest}\n")
        self.assertEqual(code, 1, out)
        self.assertIn("names no path", out)

    def test_a_path_escaping_the_guard_tree_is_refused(self):
        """`..` would let the digests file aim the check at other bytes."""
        code, out = self.guard(f"{self.digest}  ../outside.sh\n")
        self.assertEqual(code, 1, out)
        self.assertIn("inside the guard tree", out)

    def test_an_absolute_path_is_refused(self):
        code, out = self.guard(f"{self.digest}  /etc/passwd\n")
        self.assertEqual(code, 1, out)
        self.assertIn("inside the guard tree", out)

    def test_a_missing_digests_file_is_refused(self):
        code, out = run_guard(
            VERIFY_GUARD_DIGESTS,
            bash_path(self.root),
            bash_path(self.tmp / "absent.txt"),
        )
        self.assertEqual(code, 1, out)
        self.assertIn("not found", out)

    def test_a_missing_guard_root_is_refused(self):
        code, out = run_guard(
            VERIFY_GUARD_DIGESTS,
            bash_path(self.tmp / "absent-root"),
            bash_path(self.write_digests(f"{self.digest}  tools/x.sh\n")),
        )
        self.assertEqual(code, 1, out)
        self.assertIn("is not a directory", out)

    def test_no_arguments_is_refused(self):
        code, out = run_guard(VERIFY_GUARD_DIGESTS)
        self.assertEqual(code, 1, out)
        self.assertIn("usage", out)

    def test_it_can_pin_itself(self):
        """The self-reference, included so its limit is on the record.

        Listing this script in its own digests file works, and proves
        nothing against an adversary who controls the repository: such
        an adversary edits the comparison as readily as the file. It is
        useful against accident, not against attack, and the workflow
        comment says so where an adopter will read it.
        """
        import hashlib, shutil as _shutil
        _shutil.copy(VERIFY_GUARD_DIGESTS, self.root / "tools" / "verify_guard_digests.sh")
        own = hashlib.sha256(VERIFY_GUARD_DIGESTS.read_bytes()).hexdigest()
        code, out = self.guard(f"{own}  tools/verify_guard_digests.sh\n")
        self.assertEqual(code, 0, out)


class MutationTests(unittest.TestCase):
    """Neuter each guard and prove the cases above catch it.

    This is the check that makes the rest of the file mean something.
    Every negative case is re-run against a guard replaced by
    ``exit 0``; each one must flip from failing to passing. A case that
    does not flip was not testing the guard, it was testing something
    incidental, and it is reported by name.
    """

    @classmethod
    def setUpClass(cls):
        if BASH is None:
            raise unittest.SkipTest("bash is not available on this host")

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        self.mutant = self.tmp / "mutant.sh"
        self.mutant.write_text(MUTANT, encoding="utf-8")

    def assert_all_negatives_flip(self, cases_run, negatives):
        """Every negative case must pass against the mutant."""
        survivors = []
        for description in negatives:
            code = cases_run(description)
            if code != 0:
                survivors.append(f"{description} (still exited {code})")
        self.assertEqual(
            survivors, [],
            "these cases do not detect a guard replaced by `exit 0`, so they "
            "are not testing the guard:\n  " + "\n  ".join(survivors),
        )
        return len(negatives)

    def test_check_tag_version_mutant_is_caught(self):
        manifests = {}
        for name, body in TAG_MANIFESTS.items():
            path = self.tmp / f"{name}.toml"
            path.write_text(body, encoding="utf-8")
            manifests[name] = path
        manifests["absent"] = self.tmp / "absent.toml"

        negatives = [d for d, want, _ in TAG_CASES if want != 0]
        args_by_desc = {
            d: [bash_path(manifests[a]) if a in manifests else a for a in args]
            for d, _, args in TAG_CASES
        }

        def run(description):
            code, _ = run_guard(self.mutant, *args_by_desc[description])
            return code

        checked = self.assert_all_negatives_flip(run, negatives)
        self.assertGreaterEqual(checked, 12, "guard 1 has too few negative cases")

    def test_capa_floor_mutant_is_caught(self):
        manifests = {}
        for name, body in FLOOR_MANIFESTS.items():
            path = self.tmp / f"{name}.toml"
            path.write_text(body, encoding="utf-8")
            manifests[name] = path
        manifests["absent"] = self.tmp / "absent.toml"

        negatives = [(d, key) for d, want, key, _ in FLOOR_CASES if want != 0]

        def run(description):
            key = dict((d, k) for d, k in negatives)[description]
            code, _ = run_guard(self.mutant, bash_path(manifests[key]))
            return code

        checked = self.assert_all_negatives_flip(run, [d for d, _ in negatives])
        self.assertGreaterEqual(checked, 6, "the floor reader has too few negative cases")

    def test_clean_room_build_mutant_is_caught(self):
        tarball = make_tarball(
            self.tmp / "pkg-v1.0.0.tar.gz", "pkg-v1.0.0",
            {"capa.toml": '[package]\nname = "pkg"\nversion = "1.0.0"\n'},
        )
        room = self.tmp / "room"
        base = ["--tarball", bash_path(tarball), "--room", bash_path(room)]

        # The same refusals CleanRoomBuildTests asserts, by name.
        negatives = {
            "no --run commands": base,
            "empty --run command": base + ["--run", "   "],
            "missing tarball": [
                "--tarball", bash_path(self.tmp / "absent.tar.gz"),
                "--room", bash_path(room), "--run", "true",
            ],
            "no --tarball": ["--room", bash_path(room), "--run", "true"],
            "no --room": ["--tarball", bash_path(tarball), "--run", "true"],
            "relative room": [
                "--tarball", bash_path(tarball), "--room", "room", "--run", "true",
            ],
            "sibling-satisfied build step": base + ["--run", "test -d ../capa_hash"],
            "a step that fails": base + ["--run", "exit 3"],
            "unknown argument": base + ["--run", "true", "--yolo"],
        }

        def run(description):
            code, _ = run_guard(self.mutant, *negatives[description])
            return code

        checked = self.assert_all_negatives_flip(run, list(negatives))
        self.assertGreaterEqual(checked, 8, "guard 2 has too few negative cases")


class WorkflowWiringTests(unittest.TestCase):
    """The reusable workflow must keep the properties it promises.

    These are cheap textual checks, and they exist because the workflow
    is the one piece of this that CI cannot exercise here: it only runs
    on a tag push in a repository that calls it. Every third-party
    action stays SHA-pinned, the workflow denies permissions by default,
    and the guards never hold a write token.
    """

    WORKFLOW = REPO_ROOT / ".github" / "workflows" / "release-guards.yml"

    def setUp(self):
        self.text = self.WORKFLOW.read_text(encoding="utf-8")

    def test_every_third_party_action_is_sha_pinned(self):
        import re
        unpinned = [
            line.strip()
            for line in self.text.splitlines()
            # Comment lines are prose, not wiring. The header's worked
            # example is deliberately not a real pin: it carries a
            # placeholder the adopter must replace.
            if not line.strip().startswith("#")
            and re.search(r"uses:\s*\S+@(?!\w{40}\b)", line)
        ]
        self.assertEqual(unpinned, [], f"unpinned actions: {unpinned}")

    def test_permissions_are_denied_by_default(self):
        self.assertIn("permissions: {}", self.text)

    def test_guards_never_hold_a_write_token_of_any_kind(self):
        """A guard generates nothing, so it needs no credential to sign with.

        `id-token: write` in particular is for GENERATING an attestation,
        not for `gh attestation verify`, which only needs an API read.
        It was granted here on that mistaken reading and removed.
        """
        for name, job in yaml.safe_load(self.text)["jobs"].items():
            self.assertNotIn(
                "write", set(job["permissions"].values()),
                f"guard job '{name}' holds a write token: {job['permissions']}",
            )

    def test_it_is_callable_as_a_reusable_workflow(self):
        self.assertIn("workflow_call:", self.text)

    def test_the_guard_scripts_it_names_all_exist(self):
        for script in (CHECK_TAG_VERSION, CAPA_FLOOR, CLEAN_ROOM_BUILD):
            self.assertTrue(script.is_file(), f"{script} is missing")
            self.assertIn(f"tools/{script.name}", self.text,
                          f"{script.name} is not invoked by the workflow")

    def test_the_guard_revision_comes_from_the_job_context(self):
        """The defect that broke the first real adopter's release.

        It was written ``github.job_workflow_sha``. There is no such
        property on the ``github`` context; it is an OIDC token claim.
        Unknown context properties evaluate to the EMPTY STRING rather
        than erroring, so it produced nothing, with no syntax error, and
        the failure surfaced only on a live signed tag.

        The documented property is ``job.workflow_sha``. Both wrong
        spellings are asserted absent by name, because the second one,
        ``github.workflow_sha``, DOES exist and is the trap next door:
        it is the CALLER's workflow file, not the reusable one, so it
        would resolve to a plausible SHA and fetch the wrong scripts.
        """
        import re
        uses = set(re.findall(r"\$\{\{\s*(?:github|job)\.[\w.]+\s*\}\}", self.text))
        self.assertIn("${{ job.workflow_sha }}", self.text)
        self.assertEqual(
            self.text.count("${{ job.workflow_sha }}"), 2,
            "each job must resolve the guard revision itself",
        )
        for wrong in ("github.job_workflow_sha", "github.workflow_sha"):
            offenders = [u for u in uses if wrong in u]
            self.assertEqual(
                offenders, [],
                f"{wrong} is not the reusable workflow's own commit: {offenders}",
            )

    def test_the_guard_repository_comes_from_the_job_context(self):
        """Fetching a hardcoded owner/repo would pair a fork's workflow
        with upstream's scripts, silently."""
        self.assertEqual(self.text.count("${{ job.workflow_repository }}"), 2)
        wiring = [
            line for line in self.text.splitlines()
            if "repository:" in line and not line.strip().startswith("#")
        ]
        for line in wiring:
            self.assertIn(
                "steps.tag.outputs.guard-repo", line,
                f"guard checkout uses a hardcoded repository: {line.strip()}",
            )

    def test_an_empty_guard_revision_is_refused_before_the_checkout(self):
        """``actions/checkout`` with an empty ``ref`` takes the default branch.

        So an unset ``job.workflow_sha`` would not fail, it would
        silently run whatever is on the default branch. Both jobs must
        therefore refuse an empty value BEFORE their checkout step.

        This stays load-bearing after the spelling fix for a second
        reason: ``job.workflow_sha`` and its companions are not
        available on GitHub Enterprise Server, where empty is the
        legitimate value.
        """
        lines = self.text.splitlines()
        refusals = [
            i for i, line in enumerate(lines)
            if "job.workflow_sha is empty" in line
        ]
        checkouts = [
            i for i, line in enumerate(lines)
            if "Check out the guards" in line and not line.strip().startswith("#")
        ]
        self.assertEqual(len(checkouts), 2, "expected one guard checkout per job")
        self.assertEqual(len(refusals), 2, "expected one emptiness refusal per job")
        for refusal, checkout in zip(refusals, checkouts):
            self.assertLess(
                refusal, checkout,
                "the emptiness check must precede the checkout it protects",
            )

    def test_an_empty_guard_repository_is_refused_before_the_checkout(self):
        lines = self.text.splitlines()
        refusals = [
            i for i, line in enumerate(lines)
            if "job.workflow_repository is empty" in line
        ]
        checkouts = [
            i for i, line in enumerate(lines)
            if "Check out the guards" in line and not line.strip().startswith("#")
        ]
        self.assertEqual(len(refusals), 2, "expected one refusal per job")
        for refusal, checkout in zip(refusals, checkouts):
            self.assertLess(refusal, checkout)

    def test_no_step_claims_to_confirm_the_pinned_revision(self):
        """The renamed step must not get its old name back.

        "Confirm the guards are the revision the caller pinned" compared
        a value against itself. The name was the problem as much as the
        code was: it asserted provenance to every reader of the log
        while establishing only that the checkout honoured a ref. A
        workflow cannot establish its own identity from the inside, so
        no step here may say that it does.
        """
        names = [
            step.get("name", "")
            for job in yaml.safe_load(self.text)["jobs"].values()
            for step in job["steps"]
        ]
        for name in names:
            lowered = name.lower()
            self.assertNotIn(
                "revision the caller pinned", lowered,
                f"step '{name}' claims a guarantee it cannot provide",
            )
        self.assertEqual(
            sum("honoured the ref" in n for n in names), 2,
            "each job should name that step for what it actually checks",
        )

    def test_the_renamed_step_fails_for_the_reason_it_names(self):
        """Run the step's REAL body against a real checkout that disagrees.

        The old step could not fail for the reason it named: both sides
        of its comparison came from one variable, so it agreed with
        itself. The renamed step claims something narrower, that
        ``actions/checkout`` resolved the ref to the commit we asked
        for, and that claim is falsifiable. Here it is falsified.

        The body is extracted from the workflow rather than retyped, so
        this cannot drift away from the step it is testing.
        """
        if BASH is None:
            self.skipTest("bash is not available on this host")
        if shutil.which("git") is None:
            self.skipTest("git is not available on this host")

        steps = [
            s for job in yaml.safe_load(self.text)["jobs"].values()
            for s in job["steps"]
            if "honoured the ref" in s.get("name", "")
        ]
        self.assertEqual(len(steps), 2)
        body = steps[0]["run"]

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "_release_guards"
            repo.mkdir()

            def git(*args):
                subprocess.run(
                    ["git", "-C", str(repo), *args],
                    check=True, capture_output=True, text=True,
                )

            git("init", "-q")
            git("config", "user.email", "guard@example.invalid")
            git("config", "user.name", "guard")
            (repo / "f.txt").write_text("a\n", encoding="utf-8")
            git("add", "f.txt")
            git("commit", "-qm", "a")
            first = subprocess.run(
                ["git", "-C", str(repo), "rev-parse", "HEAD"],
                capture_output=True, text=True, check=True,
            ).stdout.strip()
            (repo / "f.txt").write_text("b\n", encoding="utf-8")
            git("commit", "-qam", "b")
            second = subprocess.run(
                ["git", "-C", str(repo), "rev-parse", "HEAD"],
                capture_output=True, text=True, check=True,
            ).stdout.strip()
            self.assertNotEqual(first, second)

            def run_step(expected):
                return subprocess.run(
                    [BASH, "-c", body],
                    cwd=tmp, capture_output=True, text=True,
                    env=dict(os.environ, EXPECTED=expected),
                )

            # HEAD is `second`. Asking for `first` is a checkout that did
            # not honour its ref, and the step must say exactly that.
            bad = run_step(first)
            self.assertEqual(bad.returncode, 1, bad.stdout + bad.stderr)
            self.assertIn("asked for", bad.stdout + bad.stderr)
            self.assertIn(first, bad.stdout + bad.stderr)

            # And it passes when the checkout did honour the ref, so the
            # failure above is discrimination and not a broken step.
            good = run_step(second)
            self.assertEqual(good.returncode, 0, good.stdout + good.stderr)
            self.assertIn("checkout honoured the ref", good.stdout)

    def test_the_digest_anchor_is_wired_and_optional(self):
        self.assertIn("guard-digests:", self.text)
        self.assertIn("tools/verify_guard_digests.sh", self.text)
        self.assertEqual(
            self.text.count("no guard-digests supplied"), 2,
            "each job must say plainly when it has no independent anchor",
        )

    def test_guard_two_can_reach_the_api_for_provenance(self):
        """Without GH_TOKEN, `capa install` in the clean room degrades to
        the GPG layer and warns instead of verifying provenance, while
        the room still goes green."""
        steps = yaml.safe_load(self.text)["jobs"]["clean-room"]["steps"]
        guard2 = [s for s in steps if s.get("name") == "Guard 2"]
        self.assertEqual(len(guard2), 1)
        self.assertIn("GH_TOKEN", guard2[0].get("env", {}))

    def test_both_jobs_refuse_a_ref_that_is_not_a_version_tag(self):
        self.assertEqual(self.text.count("is not a version tag"), 2)

    def test_no_input_is_interpolated_into_a_shell_body(self):
        """Inputs must reach the shell through ``env:``, never ``${{ }}``.

        An interpolated expression is pasted into the program text
        before bash ever sees it, so a value containing shell syntax
        becomes shell syntax. These guards run inside a release workflow
        holding an OIDC token, which makes them the last place in the
        system that should hand an input that power. The first draft of
        this workflow interpolated eleven of them.
        """
        import re
        doc = yaml.safe_load(self.text)
        offenders = []
        for job_name, job in doc["jobs"].items():
            for step in job["steps"]:
                for expr in re.findall(r"\$\{\{[^}]+\}\}", step.get("run", "")):
                    offenders.append(f"{job_name} / {step.get('name')}: {expr}")
        self.assertEqual(offenders, [], "interpolated into a run body:\n  " +
                         "\n  ".join(offenders))

    def test_the_workflow_is_valid_yaml(self):
        doc = yaml.safe_load(self.text)
        # `on:` is the YAML 1.1 boolean True, which is why this reads it
        # by that key rather than the string.
        trigger = doc.get(True, doc.get("on"))
        self.assertIn("workflow_call", trigger)
        self.assertEqual(doc["permissions"], {})
        for name, job in doc["jobs"].items():
            self.assertNotIn(
                "write", str(job.get("permissions", {}).get("contents", "")),
                f"job {name} must not hold a contents write token",
            )


class GuardsCannotSilentlyNotRunTests(unittest.TestCase):
    """The guards on the guards must not be skippable.

    This is the defect CodeQL's ``py/uninitialized-local-variable``
    alerts led to, and it was worse than the alerts. Eleven checks
    across this file and ``test_release_workflow.py`` were wrapped in
    ``try: import yaml / except ImportError: skip``, while PyYAML was
    declared in no extra of ``pyproject.toml``. So the skip was not a
    courtesy for a contributor who omitted ``pip install -e .[test]``,
    it was what happened by DEFAULT: a clean install ran none of them
    and printed OK. Among the eleven were "every action is pinned to a
    commit SHA" and "every uploaded artefact is attested".

    The declaration in the ``[test]`` extra is what makes the
    unconditional import safe, so this asserts the declaration is still
    there. Deleting it would quietly restore the old behaviour.
    """

    def test_pyyaml_is_a_declared_test_dependency(self):
        text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        in_optional = False
        test_extra = None
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("["):
                in_optional = stripped == "[project.optional-dependencies]"
                continue
            if in_optional and stripped.startswith("test"):
                test_extra = stripped
        self.assertIsNotNone(test_extra, "no [test] extra in pyproject.toml")
        self.assertIn(
            "pyyaml", test_extra.lower(),
            "PyYAML must stay a declared test dependency, or the release "
            "supply-chain guards go back to skipping silently",
        )

    def test_no_workflow_guard_module_makes_an_import_optional(self):
        """A guarded import here is a guard that can decline to run.

        Parsed rather than grepped: these modules discuss the defect in
        their own prose, and a textual search matches the explanation as
        readily as the thing explained.
        """
        import ast
        for name in ("test_release_guards.py", "test_release_workflow.py"):
            source = (REPO_ROOT / "tests" / name).read_text(encoding="utf-8")
            handlers = [
                node for node in ast.walk(ast.parse(source))
                if isinstance(node, ast.ExceptHandler)
                and isinstance(node.type, ast.Name)
                and node.type.id == "ImportError"
            ]
            with self.subTest(module=name):
                self.assertEqual(
                    [h.lineno for h in handlers], [],
                    f"{name} catches ImportError, so a supply-chain check "
                    f"there can skip itself; that is not a check",
                )


class OwnReleaseIsGuardedTests(unittest.TestCase):
    """This repository must not be exempt from its own guard.

    ``release-binaries.yml`` builds, attests and uploads on a ``v*`` tag
    while ``pyproject.toml`` declares the version separately. That is the
    identical exposure capa_authgate v0.2.0 shipped through, so guard 1
    gates it, and every publishing job must depend on that gate. A guard
    that exists but nothing waits for is decoration.
    """

    WORKFLOW = REPO_ROOT / ".github" / "workflows" / "release-binaries.yml"

    def setUp(self):
        self.text = self.WORKFLOW.read_text(encoding="utf-8")

    def test_the_guard_runs_the_shared_script(self):
        self.assertIn("tools/check_tag_version.sh", self.text)
        self.assertIn("pyproject.toml", self.text)

    def test_every_publishing_job_waits_for_the_guard(self):
        jobs = yaml.safe_load(self.text)["jobs"]
        self.assertIn("guard", jobs)
        for name, job in jobs.items():
            if name == "guard":
                continue
            needs = job.get("needs")
            needs = [needs] if isinstance(needs, str) else (needs or [])
            self.assertIn(
                "guard", needs,
                f"job '{name}' publishes without waiting for the guard",
            )


if __name__ == "__main__":
    unittest.main()
