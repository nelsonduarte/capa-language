"""Release guard 1, ``tools/check_tag_version.sh``, tested where it lives.

WHY THIS FILE IS HERE AND NOT IN AN ADOPTER. capa_authgate used to keep
a byte-identical copy of this guard under its own ``tools/``, purely so
that the guard could be rehearsed offline, with a drift test holding the
copy identical to the pinned one. That copy was a second copy of a
security control inside the very fleet whose drift apparatus exists
because copies drift, and its own header recorded that it had ALREADY
drifted once: it was forked before the shared guard gained its third
argument, so the two accepted different arguments and printed different
messages while looking interchangeable.

So the copy is gone and the test moved here, to the one repository that
holds the file the release actually runs. The acknowledged loss is that
a contributor with only an adopter checked out can no longer rehearse
this guard offline. That was weighed and accepted, because a rehearsable
copy that lies is worse than a canonical one that is out of reach.

WHAT THE CASES ARE WORTH. A guard is only worth what its FAILURES are
worth. Asserting it says OK on the happy path proves almost nothing; a
``true`` would pass that. So every case below except the passing ones
asserts a NON-zero exit, including the case where the only matching
version in the manifest belongs to a dependency, which is how this guard
could most plausibly have passed for the wrong reason.

The guard is shell, so this drives it as a subprocess. It runs under
``python -m unittest discover tests``, which is what CI runs, on every
operating system in the matrix.
"""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
GUARD = REPO_ROOT / "tools" / "check_tag_version.sh"
PYPROJECT = REPO_ROOT / "pyproject.toml"

BASH = shutil.which("bash")


def bash_path(path) -> str:
    """Render a filesystem path the way the ``bash`` on this host wants it."""
    text = str(path)
    if os.name == "nt" and len(text) > 1 and text[1] == ":":
        return "/" + text[0].lower() + text[2:].replace("\\", "/")
    return text


MANIFESTS = {
    "good.toml": '[package]\nname = "capa_authgate"\nversion = "0.2.4"\ncapa = ">=1.18.1"\n',
    # The real v0.2.0 defect: tagged and published while the manifest
    # still said 0.1.0.
    "stale.toml": '[package]\nname = "capa_authgate"\nversion = "0.1.0"\n',
    "noversion.toml": '[package]\nname = "capa_authgate"\ncapa = ">=1.18.1"\n',
    "empty.toml": '[package]\nname = "capa_authgate"\nversion = ""\n',
    "dup.toml": '[package]\nname = "x"\nversion = "0.2.4"\nversion = "9.9.9"\n',
    "deponly.toml": '[package]\nname = "x"\n\n[dependencies.capa_jwt]\nversion = "0.2.4"\n',
    "comment.toml": '[package]\nname = "x"\nversion = "0.2.4"  # trailing comment\n',
    # The pyproject dialect the third argument exists for, plus the
    # sub-table that must NOT satisfy it ([project.urls] closes the
    # region).
    "pyproject.toml": (
        '[project]\nname = "x"\nversion = "0.2.4"\n\n[project.urls]\nversion = "9.9.9"\n'
    ),
}


@unittest.skipIf(BASH is None, "bash is not available on this host")
class CheckTagVersionTests(unittest.TestCase):
    """``tools/check_tag_version.sh``, exercised as the release invokes it."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.work = Path(cls._tmp.name)
        for name, text in MANIFESTS.items():
            (cls.work / name).write_text(text, encoding="utf-8", newline="\n")

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def guard(self, *args):
        proc = subprocess.run(
            [BASH, bash_path(GUARD), *args],
            capture_output=True,
            text=True,
            cwd=self.work,
        )
        return proc.returncode, proc.stdout + proc.stderr

    def expect(self, want, desc, *args):
        code, out = self.guard(*args)
        self.assertEqual(code, want, f"{desc}: wanted exit {want}\n{out}")
        return out

    # --- the happy path, which on its own proves almost nothing --------

    def test_a_matching_tag_and_version_passes(self):
        out = self.expect(0, "matching tag and version", "v0.2.4", "good.toml")
        self.assertIn("OK: tag v0.2.4", out)

    def test_a_version_with_a_trailing_comment_passes(self):
        self.expect(0, "version with a trailing comment", "v0.2.4", "comment.toml")

    # --- every way of not knowing, each of which must be an error ------

    def test_the_real_defect_tag_ahead_of_manifest(self):
        out = self.expect(1, "tag ahead of manifest", "v0.2.0", "stale.toml")
        self.assertIn("does not match the version declared", out)

    def test_a_tag_behind_the_manifest(self):
        self.expect(1, "tag behind the manifest", "v0.1.0", "good.toml")

    def test_a_tag_without_the_v_prefix(self):
        self.expect(1, "tag without the v prefix", "0.2.4", "good.toml")

    def test_a_missing_manifest(self):
        out = self.expect(1, "missing manifest", "v0.2.4", "absent.toml")
        self.assertIn("not found", out)

    def test_an_empty_tag(self):
        """An unset GITHUB_REF_NAME must not be read as agreement."""
        out = self.expect(1, "empty tag", "", "good.toml")
        self.assertIn("no tag given", out)

    def test_a_manifest_with_no_version_key(self):
        self.expect(1, "no [package] version", "v0.2.4", "noversion.toml")

    def test_a_version_that_parses_as_empty(self):
        self.expect(1, "version present but empty", "v0.2.4", "empty.toml")

    def test_two_version_lines_in_one_table(self):
        out = self.expect(1, "two [package] version lines", "v0.2.4", "dup.toml")
        self.assertIn("expected exactly 1", out)

    def test_only_a_dependency_declares_the_version(self):
        """The most plausible way this guard could pass for the wrong reason."""
        self.expect(1, "only a dependency declares it", "v0.2.4", "deponly.toml")

    # --- the third argument, the one the fork never had ----------------

    def test_the_project_dialect_when_asked_for(self):
        self.expect(0, "the [project] dialect", "v0.2.4", "pyproject.toml", "project")

    def test_the_wrong_table_named_for_the_manifest(self):
        self.expect(1, "wrong table named", "v0.2.4", "pyproject.toml", "package")

    def test_a_sub_table_does_not_satisfy_the_parent(self):
        """[project.urls] closes the region, so its version is not read."""
        self.expect(1, "sub-table version", "v9.9.9", "pyproject.toml", "project")

    def test_a_table_name_that_is_not_an_identifier(self):
        """The name is interpolated into an awk regex, so it is restricted.

        A metacharacter could widen the header match and let the guard
        read a version out of a table nobody asked about.
        """
        for bad in ("pack.*", "[package]", "", "a b"):
            with self.subTest(table=bad):
                out = self.expect(1, "bad table name", "v0.2.4", "good.toml", bad)
                self.assertIn("not a plain identifier", out)

    # --- against this repository's own manifest ------------------------

    def test_the_live_pyproject_against_its_own_tag(self):
        """The guard as this repository's release actually invokes it."""
        version = None
        in_project = False
        for line in PYPROJECT.read_text(encoding="utf-8").splitlines():
            if line.startswith("["):
                in_project = line.strip() == "[project]"
                continue
            if in_project and line.replace(" ", "").startswith("version="):
                version = line.split("=", 1)[1].strip().strip("\"'")
        self.assertIsNotNone(version, "pyproject.toml declares no [project] version")

        proc = subprocess.run(
            [BASH, bash_path(GUARD), f"v{version}", "pyproject.toml", "project"],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

        proc = subprocess.run(
            [BASH, bash_path(GUARD), "v9.9.9", "pyproject.toml", "project"],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
        )
        self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)


if __name__ == "__main__":
    unittest.main()
