"""Tests for the Capa package manager.

Three layers:

  * ``TestManifestParser`` covers the ``capa.toml`` parser in
    isolation; manifest strings are read from in-memory paths.
  * ``TestInstallLocal`` exercises ``capa install`` against path
    dependencies, which need no network.
  * ``TestInstallGit`` exercises a git source by setting up a
    local bare repository on disk and pointing ``capa.toml`` at
    its ``file://`` URL. Skipped when ``git`` is unavailable.
  * ``TestLoaderIntegration`` runs the full pipeline end-to-end:
    a project with ``capa.toml`` referencing a local library
    transpiles + executes without ``CAPA_PATH`` being set.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

from capa.pkg import (
    Dependency,
    InstallError,
    Manifest,
    ManifestError,
    install,
    read_manifest,
    read_lock,
)


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(content), encoding="utf-8")


class _TempDirMixin:
    def setUp(self) -> None:
        self._tmp = Path(tempfile.mkdtemp(prefix="capa_pkg_test_")).resolve()

    def tearDown(self) -> None:
        shutil.rmtree(self._tmp, ignore_errors=True)


def _has_git() -> bool:
    try:
        r = subprocess.run(
            ["git", "--version"],
            capture_output=True, text=True, encoding="utf-8",
        )
        return r.returncode == 0
    except FileNotFoundError:
        return False


class TestManifestParser(_TempDirMixin, unittest.TestCase):

    def test_minimal_manifest(self):
        p = self._tmp / "capa.toml"
        _write(p, '''
            [package]
            name = "demo"
            version = "0.1.0"
        ''')
        m = read_manifest(p)
        self.assertEqual(m.name, "demo")
        self.assertEqual(m.version, "0.1.0")
        self.assertEqual(m.dependencies, [])
        self.assertIsNone(m.capa_requirement)

    def test_manifest_with_capa_requirement(self):
        p = self._tmp / "capa.toml"
        _write(p, '''
            [package]
            name = "demo"
            version = "0.1.0"
            capa = ">=0.8.4"
        ''')
        m = read_manifest(p)
        self.assertEqual(m.capa_requirement, ">=0.8.4")

    def test_git_dependency_with_tag(self):
        p = self._tmp / "capa.toml"
        _write(p, '''
            [package]
            name = "demo"
            version = "0.1.0"

            [dependencies]
            mylib = { git = "https://example.invalid/mylib.git", tag = "v0.1" }
        ''')
        m = read_manifest(p)
        self.assertEqual(len(m.dependencies), 1)
        d = m.dependencies[0]
        self.assertEqual(d.name, "mylib")
        self.assertTrue(d.is_git)
        self.assertEqual(d.git, "https://example.invalid/mylib.git")
        self.assertEqual(d.tag, "v0.1")
        self.assertIsNone(d.rev)

    def test_git_dependency_with_rev(self):
        p = self._tmp / "capa.toml"
        _write(p, '''
            [package]
            name = "demo"
            version = "0.1.0"

            [dependencies]
            mylib = { git = "https://example.invalid/mylib.git", rev = "abc123" }
        ''')
        m = read_manifest(p)
        d = m.dependencies[0]
        self.assertEqual(d.rev, "abc123")
        self.assertIsNone(d.tag)

    def test_path_dependency(self):
        p = self._tmp / "capa.toml"
        _write(p, '''
            [package]
            name = "demo"
            version = "0.1.0"

            [dependencies]
            mylib = { path = "../mylib" }
        ''')
        m = read_manifest(p)
        d = m.dependencies[0]
        self.assertTrue(d.is_path)
        self.assertEqual(d.path, "../mylib")
        self.assertFalse(d.is_git)

    def test_missing_package_table(self):
        p = self._tmp / "capa.toml"
        _write(p, '[dependencies]\n')
        with self.assertRaises(ManifestError) as cm:
            read_manifest(p)
        self.assertIn("missing [package]", str(cm.exception))

    def test_missing_required_name(self):
        p = self._tmp / "capa.toml"
        _write(p, '''
            [package]
            version = "0.1.0"
        ''')
        with self.assertRaises(ManifestError) as cm:
            read_manifest(p)
        self.assertIn("'name'", str(cm.exception))

    def test_unknown_top_level_key(self):
        p = self._tmp / "capa.toml"
        _write(p, '''
            [package]
            name = "demo"
            version = "0.1.0"
            [unknown_section]
            x = 1
        ''')
        with self.assertRaises(ManifestError) as cm:
            read_manifest(p)
        self.assertIn("unknown_section", str(cm.exception))

    def test_dep_with_both_git_and_path_rejected(self):
        p = self._tmp / "capa.toml"
        _write(p, '''
            [package]
            name = "demo"
            version = "0.1.0"

            [dependencies]
            mylib = { git = "x", path = "y", tag = "v1" }
        ''')
        with self.assertRaises(ManifestError) as cm:
            read_manifest(p)
        self.assertIn("both 'git' and 'path'", str(cm.exception))

    def test_git_dep_without_pin_rejected(self):
        p = self._tmp / "capa.toml"
        _write(p, '''
            [package]
            name = "demo"
            version = "0.1.0"

            [dependencies]
            mylib = { git = "https://example.invalid/mylib.git" }
        ''')
        with self.assertRaises(ManifestError) as cm:
            read_manifest(p)
        self.assertIn("needs a pin", str(cm.exception))

    def test_dep_without_any_source_rejected(self):
        p = self._tmp / "capa.toml"
        _write(p, '''
            [package]
            name = "demo"
            version = "0.1.0"

            [dependencies]
            mylib = { }
        ''')
        with self.assertRaises(ManifestError) as cm:
            read_manifest(p)
        self.assertIn("needs a source", str(cm.exception))


class TestInstallLocal(_TempDirMixin, unittest.TestCase):
    """Path-source deps: no git required."""

    def test_install_with_path_dep_writes_no_lock_entry(self):
        # Build a sibling library and a project that depends on it
        # by path. install() should validate the path exists; the
        # lockfile only carries git deps.
        lib_dir = self._tmp / "mylib"
        _write(lib_dir / "log.capa", 'pub fun hi() -> String\n    return "hi"\n')
        project = self._tmp / "proj"
        _write(project / "capa.toml", '''
            [package]
            name = "proj"
            version = "0.1.0"

            [dependencies]
            mylib = { path = "../mylib" }
        ''')
        manifest = install(project)
        self.assertEqual(manifest.name, "proj")
        # Lockfile written but empty: no git deps to record.
        lock = read_lock(project / "capa.lock")
        self.assertEqual(lock, [])

    def test_install_with_missing_path_dep_errors(self):
        project = self._tmp / "proj"
        _write(project / "capa.toml", '''
            [package]
            name = "proj"
            version = "0.1.0"

            [dependencies]
            mylib = { path = "../does-not-exist" }
        ''')
        with self.assertRaises(InstallError) as cm:
            install(project)
        self.assertIn("does not exist", str(cm.exception))

    def test_install_without_manifest_errors(self):
        empty = self._tmp / "empty"
        empty.mkdir()
        with self.assertRaises(InstallError) as cm:
            install(empty)
        self.assertIn("no capa.toml", str(cm.exception))


@unittest.skipUnless(_has_git(), "git not on PATH")
class TestInstallGit(_TempDirMixin, unittest.TestCase):
    """Spin up a local git repo and use it as a dependency source."""

    def _make_local_git_repo(self, repo_dir: Path) -> str:
        """Create a small git repo with a tagged commit at ``repo_dir``.
        Returns a ``file://`` URL usable as a clone source.
        """
        repo_dir.mkdir(parents=True, exist_ok=True)
        env = {
            **os.environ,
            "GIT_AUTHOR_NAME": "capa-test",
            "GIT_AUTHOR_EMAIL": "test@example.invalid",
            "GIT_COMMITTER_NAME": "capa-test",
            "GIT_COMMITTER_EMAIL": "test@example.invalid",
        }

        def git(*args: str) -> None:
            r = subprocess.run(
                ["git", "-C", str(repo_dir), *args],
                capture_output=True, text=True, encoding="utf-8", env=env,
            )
            if r.returncode != 0:
                raise RuntimeError(f"git {args}: {r.stderr}")

        git("init", "-b", "main")
        (repo_dir / "log.capa").write_text(
            'pub fun greet() -> String\n    return "hi from git dep"\n',
            encoding="utf-8",
        )
        git("add", "log.capa")
        git("commit", "-m", "initial")
        git("tag", "v0.1")
        # Convert local path to a file:// URL. Path.as_uri() works
        # on every platform git supports.
        return repo_dir.as_uri()

    def test_install_clones_git_dep_at_tag(self):
        upstream = self._tmp / "upstream"
        url = self._make_local_git_repo(upstream)
        project = self._tmp / "proj"
        _write(project / "capa.toml", f'''
            [package]
            name = "proj"
            version = "0.1.0"

            [dependencies]
            mylib = {{ git = "{url}", tag = "v0.1" }}
        ''')
        manifest = install(project)
        # Vendor populated.
        vendored = project / "vendor" / "mylib" / "log.capa"
        self.assertTrue(vendored.exists())
        self.assertIn("hi from git dep", vendored.read_text(encoding="utf-8"))
        # Lockfile carries one git entry with a resolved SHA.
        lock = read_lock(project / "capa.lock")
        self.assertEqual(len(lock), 1)
        self.assertEqual(lock[0].name, "mylib")
        self.assertEqual(lock[0].pin, "v0.1")
        self.assertEqual(lock[0].pin_kind, "tag")
        self.assertRegex(lock[0].commit, r"^[0-9a-f]{7,}$")

    def test_install_is_idempotent_across_pin_change(self):
        # First install at v0.1, then re-write the manifest to point
        # at a different pin. The second install must replace the
        # vendor checkout cleanly rather than failing on the existing
        # directory.
        upstream = self._tmp / "upstream"
        url = self._make_local_git_repo(upstream)
        # Add a second tagged commit.
        env = {
            **os.environ,
            "GIT_AUTHOR_NAME": "capa-test",
            "GIT_AUTHOR_EMAIL": "test@example.invalid",
            "GIT_COMMITTER_NAME": "capa-test",
            "GIT_COMMITTER_EMAIL": "test@example.invalid",
        }
        (upstream / "log.capa").write_text(
            'pub fun greet() -> String\n    return "v0.2"\n',
            encoding="utf-8",
        )
        subprocess.run(
            ["git", "-C", str(upstream), "commit", "-am", "v0.2"],
            check=True, capture_output=True, text=True, env=env,
        )
        subprocess.run(
            ["git", "-C", str(upstream), "tag", "v0.2"],
            check=True, capture_output=True, text=True, env=env,
        )
        project = self._tmp / "proj"
        _write(project / "capa.toml", f'''
            [package]
            name = "proj"
            version = "0.1.0"

            [dependencies]
            mylib = {{ git = "{url}", tag = "v0.1" }}
        ''')
        install(project)
        # Bump to v0.2.
        _write(project / "capa.toml", f'''
            [package]
            name = "proj"
            version = "0.1.0"

            [dependencies]
            mylib = {{ git = "{url}", tag = "v0.2" }}
        ''')
        install(project)
        body = (project / "vendor" / "mylib" / "log.capa").read_text("utf-8")
        self.assertIn("v0.2", body)

    def test_install_refuses_silently_moved_tag(self):
        # Force-pushed-tag scenario: the lockfile pins a SHA; the
        # upstream then re-tags v0.1 to a different commit. A second
        # ``install`` must REFUSE rather than silently overwrite the
        # lock, so the consumer notices an unexpected upstream
        # change before linking the new code.
        from capa.pkg import LockMismatchError
        upstream = self._tmp / "upstream"
        url = self._make_local_git_repo(upstream)
        project = self._tmp / "proj"
        _write(project / "capa.toml", f'''
            [package]
            name = "proj"
            version = "0.1.0"

            [dependencies]
            mylib = {{ git = "{url}", tag = "v0.1" }}
        ''')
        install(project)  # writes capa.lock pinning SHA_1
        lock_first = read_lock(project / "capa.lock")
        sha_first = lock_first[0].commit
        # Move v0.1 to a new commit upstream.
        env = {
            **os.environ,
            "GIT_AUTHOR_NAME": "capa-test",
            "GIT_AUTHOR_EMAIL": "test@example.invalid",
            "GIT_COMMITTER_NAME": "capa-test",
            "GIT_COMMITTER_EMAIL": "test@example.invalid",
        }
        (upstream / "log.capa").write_text(
            'pub fun greet() -> String\n    return "tampered"\n',
            encoding="utf-8",
        )
        subprocess.run(
            ["git", "-C", str(upstream), "commit", "-am", "tamper"],
            check=True, capture_output=True, text=True, env=env,
        )
        subprocess.run(
            ["git", "-C", str(upstream), "tag", "-f", "v0.1"],
            check=True, capture_output=True, text=True, env=env,
        )
        # Plain re-install: must raise LockMismatchError; the
        # lockfile on disk must NOT have been overwritten.
        with self.assertRaises(LockMismatchError) as cm:
            install(project)
        self.assertIn("v0.1", str(cm.exception))
        self.assertIn("mylib", str(cm.exception))
        lock_after_refusal = read_lock(project / "capa.lock")
        self.assertEqual(lock_after_refusal[0].commit, sha_first)
        # Allow-update path: lockfile updates to the new SHA.
        install(project, allow_lock_update=True)
        lock_after_update = read_lock(project / "capa.lock")
        self.assertNotEqual(lock_after_update[0].commit, sha_first)
        body = (project / "vendor" / "mylib" / "log.capa").read_text("utf-8")
        self.assertIn("tampered", body)


class TestLoaderIntegration(_TempDirMixin, unittest.TestCase):
    """A project with ``capa.toml`` + a path dep transpiles and
    executes without ``CAPA_PATH`` being set: the loader picks up
    the dependency's parent dir automatically.
    """

    def test_path_dep_resolves_through_loader(self):
        # Library lives in a sibling directory; project imports it.
        lib_root = self._tmp / "deps"
        (lib_root / "shared").mkdir(parents=True)
        (lib_root / "shared" / "tools.capa").write_text(
            'pub fun cheer() -> String\n    return "hooray"\n',
            encoding="utf-8",
        )
        project = self._tmp / "proj"
        _write(project / "capa.toml", '''
            [package]
            name = "proj"
            version = "0.1.0"

            [dependencies]
            shared = { path = "../deps/shared" }
        ''')
        _write(project / "main.capa", '''
            import shared.tools
            fun main(stdio: Stdio)
                stdio.println(cheer())
        ''')
        # Run install (validates the path) - not strictly needed for
        # the loader, but documents the intended flow.
        install(project)
        # Now execute. capa --run is launched with cwd=project so the
        # loader sees capa.toml and picks up the path dep.
        result = subprocess.run(
            [sys.executable, "-m", "capa", "--run", "main.capa"],
            cwd=project,
            capture_output=True, text=True, encoding="utf-8",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "hooray\n")


if __name__ == "__main__":
    unittest.main()
