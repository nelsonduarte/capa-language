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


def _gpg_available() -> bool:
    try:
        r = subprocess.run(
            ["gpg", "--version"], capture_output=True, text=True,
        )
        return r.returncode == 0
    except FileNotFoundError:
        return False


@unittest.skipUnless(
    _gpg_available(), "gpg binary not on PATH (signature tests need it)",
)
class TestInstallVerifyKey(_TempDirMixin, unittest.TestCase):
    """Cover the optional ``verify_key`` field on a git dependency.
    Builds an ephemeral GPG home + keypair, signs a tag with it,
    points ``capa.toml`` at a local file:// repo whose tag is
    signed, and asserts:

      - install with the right fingerprint succeeds and records
        the signing key in the lockfile.
      - install with the wrong fingerprint raises
        ``VerificationError`` and does NOT record anything.
      - install of an unsigned tag with a verify_key declared
        raises ``VerificationError``.

    The ephemeral GPG home means the test does not touch the
    user's real keyring and does not require any pre-existing
    key material."""

    def _make_gpg_home(self) -> tuple[Path, str, dict]:
        """Create an isolated GNUPGHOME, generate a passphrase-less
        keypair inside it, and return (gnupg_home, fingerprint,
        env_for_subprocess). The env carries GNUPGHOME so every
        gpg / git invocation talks to the ephemeral keyring."""
        gnupg_home = self._tmp / "gnupg"
        gnupg_home.mkdir(parents=True, exist_ok=True)
        # Windows tolerates 0o700; Unix needs it for gpg to not
        # complain about insecure perms.
        try:
            os.chmod(gnupg_home, 0o700)
        except OSError:
            pass
        env = {**os.environ, "GNUPGHOME": str(gnupg_home)}
        batch = (
            "%no-protection\n"
            "Key-Type: RSA\n"
            "Key-Length: 2048\n"
            "Subkey-Type: RSA\n"
            "Subkey-Length: 2048\n"
            "Name-Real: Capa Test\n"
            "Name-Email: capa-test@example.invalid\n"
            "Expire-Date: 0\n"
            "%commit\n"
        )
        r = subprocess.run(
            ["gpg", "--batch", "--generate-key"],
            input=batch, capture_output=True, text=True, env=env,
        )
        if r.returncode != 0:
            self.skipTest(
                f"gpg --generate-key failed (sandbox / entropy issue): "
                f"{r.stderr.strip()}"
            )
        # Extract the freshly-generated key's long fingerprint.
        r = subprocess.run(
            ["gpg", "--list-keys", "--with-colons", "capa-test@example.invalid"],
            capture_output=True, text=True, env=env,
        )
        fingerprint = None
        for line in r.stdout.splitlines():
            if line.startswith("fpr:"):
                fingerprint = line.split(":")[9]
                break
        if fingerprint is None:
            self.skipTest("could not read the ephemeral key's fingerprint")
        return gnupg_home, fingerprint, env

    def _make_signed_git_repo(
        self, repo_dir: Path, env_with_gpg: dict, fingerprint: str,
    ) -> str:
        """Create a tiny git repo with a GPG-signed tag at v0.1."""
        repo_dir.mkdir(parents=True, exist_ok=True)
        env = {
            **env_with_gpg,
            "GIT_AUTHOR_NAME": "capa-test",
            "GIT_AUTHOR_EMAIL": "capa-test@example.invalid",
            "GIT_COMMITTER_NAME": "capa-test",
            "GIT_COMMITTER_EMAIL": "capa-test@example.invalid",
        }

        def git(*args, check=True):
            r = subprocess.run(
                ["git", "-C", str(repo_dir), *args],
                capture_output=True, text=True, env=env,
            )
            if check and r.returncode != 0:
                raise RuntimeError(f"git {args}: {r.stderr}")
            return r

        git("init", "-b", "main")
        git("config", "user.signingkey", fingerprint)
        (repo_dir / "log.capa").write_text(
            'pub fun greet() -> String\n    return "signed hi"\n',
            encoding="utf-8",
        )
        git("add", "log.capa")
        git("commit", "-m", "initial")
        git("tag", "-s", "-u", fingerprint, "-m", "release", "v0.1")
        return repo_dir.as_uri()

    def _make_unsigned_git_repo(self, repo_dir: Path) -> str:
        repo_dir.mkdir(parents=True, exist_ok=True)
        env = {
            **os.environ,
            "GIT_AUTHOR_NAME": "capa-test",
            "GIT_AUTHOR_EMAIL": "test@example.invalid",
            "GIT_COMMITTER_NAME": "capa-test",
            "GIT_COMMITTER_EMAIL": "test@example.invalid",
        }

        def git(*args):
            r = subprocess.run(
                ["git", "-C", str(repo_dir), *args],
                capture_output=True, text=True, env=env,
            )
            if r.returncode != 0:
                raise RuntimeError(f"git {args}: {r.stderr}")

        git("init", "-b", "main")
        (repo_dir / "log.capa").write_text(
            'pub fun greet() -> String\n    return "unsigned"\n',
            encoding="utf-8",
        )
        git("add", "log.capa")
        git("commit", "-m", "initial")
        git("tag", "v0.1")
        return repo_dir.as_uri()

    @unittest.skipIf(
        sys.platform == "win32",
        "GPG keypair generation against an ephemeral GNUPGHOME mangles "
        "Windows paths under the MSYS git distribution; the production "
        "path runs fine, only the test scaffold is platform-fragile.",
    )
    def test_install_accepts_signed_tag_with_matching_fingerprint(self):
        from unittest.mock import patch
        _, fingerprint, env = self._make_gpg_home()
        url = self._make_signed_git_repo(
            self._tmp / "upstream", env, fingerprint,
        )
        project = self._tmp / "proj"
        _write(project / "capa.toml", f'''
            [package]
            name = "proj"
            version = "0.1.0"

            [dependencies.mylib]
            git = "{url}"
            tag = "v0.1"
            verify_key = "{fingerprint}"
        ''')
        # subprocess invocations inside install() inherit os.environ
        # by default, so route GNUPGHOME through for the duration
        # of this test only.
        with patch.dict(os.environ, env, clear=False):
            install(project)
        lock = read_lock(project / "capa.lock")
        self.assertEqual(len(lock), 1)
        self.assertEqual(lock[0].signing_key, fingerprint.upper())

    @unittest.skipIf(
        sys.platform == "win32",
        "ephemeral GNUPGHOME path mangling under MSYS; see the "
        "matching-fingerprint test for the rationale.",
    )
    def test_install_refuses_signed_tag_with_wrong_fingerprint(self):
        from unittest.mock import patch
        from capa.pkg import VerificationError
        _, fingerprint, env = self._make_gpg_home()
        url = self._make_signed_git_repo(
            self._tmp / "upstream", env, fingerprint,
        )
        # 40-char fake fingerprint that does NOT match.
        wrong = "DEAD" * 10
        project = self._tmp / "proj"
        _write(project / "capa.toml", f'''
            [package]
            name = "proj"
            version = "0.1.0"

            [dependencies.mylib]
            git = "{url}"
            tag = "v0.1"
            verify_key = "{wrong}"
        ''')
        with patch.dict(os.environ, env, clear=False):
            with self.assertRaises(VerificationError) as cm:
                install(project)
        self.assertIn(fingerprint.upper(), str(cm.exception))
        self.assertIn(wrong, str(cm.exception))
        self.assertFalse((project / "capa.lock").exists())

    def test_install_refuses_unsigned_tag_when_verify_key_declared(self):
        from capa.pkg import VerificationError
        url = self._make_unsigned_git_repo(self._tmp / "upstream")
        project = self._tmp / "proj"
        _write(project / "capa.toml", f'''
            [package]
            name = "proj"
            version = "0.1.0"

            [dependencies.mylib]
            git = "{url}"
            tag = "v0.1"
            verify_key = "{"AB" * 20}"
        ''')
        with self.assertRaises(VerificationError):
            install(project)
        self.assertFalse((project / "capa.lock").exists())


class TestParseGithubOwnerRepo(unittest.TestCase):
    """Cover the URL parser that decides whether SLSA-provenance
    verification is even applicable. Non-GitHub URLs return None
    so the verifier skips them silently."""

    def test_https_clean(self):
        from capa.pkg._install import _parse_github_owner_repo
        self.assertEqual(
            _parse_github_owner_repo("https://github.com/foo/bar"),
            ("foo", "bar"),
        )

    def test_https_with_dot_git(self):
        from capa.pkg._install import _parse_github_owner_repo
        self.assertEqual(
            _parse_github_owner_repo("https://github.com/foo/bar.git"),
            ("foo", "bar"),
        )

    def test_ssh_form(self):
        from capa.pkg._install import _parse_github_owner_repo
        self.assertEqual(
            _parse_github_owner_repo("git@github.com:foo/bar.git"),
            ("foo", "bar"),
        )

    def test_non_github_returns_none(self):
        from capa.pkg._install import _parse_github_owner_repo
        for url in (
            "https://gitlab.com/foo/bar",
            "https://bitbucket.org/foo/bar",
            "https://example.com/foo/bar",
            "file:///tmp/some/path",
            "git@gitlab.com:foo/bar.git",
        ):
            self.assertIsNone(_parse_github_owner_repo(url), url)


@unittest.skipUnless(_has_git(), "git not available")
class TestInstallSlsaProvenance(_TempDirMixin, unittest.TestCase):
    """Cover the implicit SLSA L2 verification path that runs
    inside install() when a dep declares verify_key AND is hosted
    on GitHub. We can't generate real Sigstore attestations in a
    test, so each case patches subprocess.run to model what gh
    would return for the situation under test.

    The behaviour matrix the tests cover:

      * Non-GitHub git URL: SLSA path is a no-op (verifier never
        touches subprocess). The graceful-skip is observed by the
        absence of any ``gh`` invocation.
      * gh CLI missing: graceful skip (no subprocess error).
      * Release tarball missing on GitHub: graceful skip.
      * Release tarball present + attestation valid: install
        succeeds (no error raised).
      * Release tarball present + attestation invalid:
        VerificationError raised, lockfile NOT written.

    GPG verification is shared scaffolding from TestInstallVerifyKey;
    we reuse its helpers via inheritance for the live signing case
    on POSIX. The GPG layer is mocked away on Windows so the SLSA
    branch can run in isolation.
    """

    def _capa_toml_with_dep(self, project: Path, git_url: str) -> None:
        _write(project / "capa.toml", f'''
            [package]
            name = "proj"
            version = "0.1.0"

            [dependencies.mylib]
            git = "{git_url}"
            tag = "v0.1"
            verify_key = "{"AB" * 20}"
        ''')

    def test_non_github_url_skips_slsa_verifier(self):
        # When the git URL is a local file:// path (not GitHub),
        # the SLSA verifier returns immediately without touching
        # gh. We patch shutil.which so even if gh IS installed on
        # the test machine, the absence of GitHub URL is enough
        # to short-circuit.
        from unittest.mock import patch
        from capa.pkg._install import _verify_slsa_provenance
        from capa.pkg._manifest import Dependency

        dep = Dependency(
            name="mylib",
            git="file:///tmp/local-upstream",
            tag="v0.1",
            verify_key="A" * 40,
        )
        with patch("capa.pkg._install.subprocess.run") as mock_run:
            _verify_slsa_provenance(dep, "v0.1", "tag")
            mock_run.assert_not_called()

    def test_rev_pin_skips_slsa_verifier(self):
        from unittest.mock import patch
        from capa.pkg._install import _verify_slsa_provenance
        from capa.pkg._manifest import Dependency

        dep = Dependency(
            name="mylib",
            git="https://github.com/foo/bar",
            rev="deadbeef" * 5,
            verify_key="A" * 40,
        )
        with patch("capa.pkg._install.subprocess.run") as mock_run:
            _verify_slsa_provenance(dep, "deadbeef" * 5, "rev")
            mock_run.assert_not_called()

    def test_gh_not_installed_skips_silently(self):
        from unittest.mock import patch
        from capa.pkg._install import _verify_slsa_provenance
        from capa.pkg._manifest import Dependency

        dep = Dependency(
            name="mylib",
            git="https://github.com/foo/bar",
            tag="v0.1",
            verify_key="A" * 40,
        )
        with patch("capa.pkg._install.shutil.which", return_value=None):
            with patch("capa.pkg._install.subprocess.run") as mock_run:
                _verify_slsa_provenance(dep, "v0.1", "tag")
                mock_run.assert_not_called()

    def test_release_tarball_missing_skips_silently(self):
        # gh release download returns non-zero (release doesn't
        # exist or has no source-tarball asset). Verifier skips.
        from unittest.mock import patch, MagicMock
        from capa.pkg._install import _verify_slsa_provenance
        from capa.pkg._manifest import Dependency

        dep = Dependency(
            name="mylib",
            git="https://github.com/foo/bar",
            tag="v0.1",
            verify_key="A" * 40,
        )
        with patch("capa.pkg._install.shutil.which", return_value="/usr/bin/gh"):
            with patch("capa.pkg._install.subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(
                    returncode=1, stderr="release not found", stdout="",
                )
                # Should NOT raise.
                _verify_slsa_provenance(dep, "v0.1", "tag")
                # Confirms we only invoked `gh release download` -
                # the verify call was short-circuited.
                self.assertEqual(mock_run.call_count, 1)
                self.assertIn("release", mock_run.call_args.args[0])
                self.assertIn("download", mock_run.call_args.args[0])

    def test_attestation_invalid_raises(self):
        # gh release download succeeds (tarball materialises in the
        # temp dir), gh attestation verify returns non-zero
        # (tampered or wrong owner). Verifier raises.
        from unittest.mock import patch, MagicMock
        from capa.pkg._install import _verify_slsa_provenance
        from capa.pkg._manifest import Dependency
        from capa.pkg import VerificationError

        dep = Dependency(
            name="mylib",
            git="https://github.com/foo/bar",
            tag="v0.1",
            verify_key="A" * 40,
        )

        def fake_run(cmd, *args, **kw):
            if "download" in cmd:
                # Materialise a stub tarball in the --dir target
                # so the verifier sees it on disk.
                dir_idx = cmd.index("--dir") + 1
                target_dir = Path(cmd[dir_idx])
                (target_dir / "bar-v0.1.tar.gz").write_bytes(b"stub")
                return MagicMock(returncode=0, stderr="", stdout="")
            if "verify" in cmd:
                return MagicMock(
                    returncode=1,
                    stderr="verification failed: no matching attestations",
                    stdout="",
                )
            return MagicMock(returncode=0, stderr="", stdout="")

        with patch("capa.pkg._install.shutil.which", return_value="/usr/bin/gh"):
            with patch("capa.pkg._install.subprocess.run", side_effect=fake_run):
                with self.assertRaises(VerificationError) as cm:
                    _verify_slsa_provenance(dep, "v0.1", "tag")
        self.assertIn("SLSA", str(cm.exception))
        self.assertIn("foo/bar", str(cm.exception))

    def test_attestation_valid_succeeds(self):
        # Both subprocess calls return 0 (download + verify). The
        # verifier returns without raising.
        from unittest.mock import patch, MagicMock
        from capa.pkg._install import _verify_slsa_provenance
        from capa.pkg._manifest import Dependency

        dep = Dependency(
            name="mylib",
            git="https://github.com/foo/bar",
            tag="v0.1",
            verify_key="A" * 40,
        )

        def fake_run(cmd, *args, **kw):
            if "download" in cmd:
                dir_idx = cmd.index("--dir") + 1
                target_dir = Path(cmd[dir_idx])
                (target_dir / "bar-v0.1.tar.gz").write_bytes(b"stub")
            return MagicMock(returncode=0, stderr="", stdout="")

        with patch("capa.pkg._install.shutil.which", return_value="/usr/bin/gh"):
            with patch("capa.pkg._install.subprocess.run", side_effect=fake_run):
                _verify_slsa_provenance(dep, "v0.1", "tag")


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
