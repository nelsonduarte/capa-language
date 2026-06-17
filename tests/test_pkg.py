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
import time
import unittest
from pathlib import Path

from capa.pkg import (
    Dependency,
    InstallError,
    Manifest,
    ManifestError,
    RegistryEntry,
    RegistryError,
    VendorVerificationError,
    add_dependency,
    install,
    read_manifest,
    read_lock,
    resolve_name,
    search_packages,
    verify_vendored_deps,
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


class TestGitUrlAllowList(_TempDirMixin, unittest.TestCase):
    """Audit 2026-05-25 (item #5): close the ext:: / option-injection
    attack surface around ``git clone <user-controlled-string>``.

    Manifest-parse-time rejection of dangerous URLs keeps the
    string from ever reaching ``_run_git`` in ``_install.py``."""

    def _capa_toml_with_git(self, git: str) -> Path:
        p = self._tmp / "capa.toml"
        _write(p, f'''
            [package]
            name = "demo"
            version = "0.1.0"

            [dependencies]
            mylib = {{ git = "{git}", tag = "v0.1" }}
        ''')
        return p

    def test_https_allowed(self):
        m = read_manifest(self._capa_toml_with_git("https://github.com/x/y"))
        self.assertEqual(m.dependencies[0].git, "https://github.com/x/y")

    def test_http_allowed(self):
        m = read_manifest(self._capa_toml_with_git("http://example.invalid/x"))
        self.assertEqual(m.dependencies[0].git, "http://example.invalid/x")

    def test_ssh_scheme_allowed(self):
        m = read_manifest(self._capa_toml_with_git("ssh://git@example.invalid/x"))
        self.assertEqual(m.dependencies[0].git, "ssh://git@example.invalid/x")

    def test_git_scheme_allowed(self):
        m = read_manifest(self._capa_toml_with_git("git://example.invalid/x"))
        self.assertEqual(m.dependencies[0].git, "git://example.invalid/x")

    def test_file_scheme_allowed(self):
        m = read_manifest(self._capa_toml_with_git("file:///tmp/local-repo"))
        self.assertEqual(m.dependencies[0].git, "file:///tmp/local-repo")

    def test_file_absolute_paths_allowed(self):
        # Plain absolute file:// paths (no ``..``) stay accepted: the
        # legitimate local-mirror / test-repo use case.
        for url in (
            "file:///home/user/repo",
            "file:///C:/abs/path/repo",
            "file:///var/lib/mirrors/mylib.git",
        ):
            with self.subTest(url=url):
                m = read_manifest(self._capa_toml_with_git(url))
                self.assertEqual(m.dependencies[0].git, url)

    def test_file_path_traversal_rejected(self):
        # file:// must not become a path-traversal primitive: a ``..``
        # component can escape the intended directory and vendor
        # arbitrary local content. Both separators are caught.
        for url in (
            "file://../../../etc/passwd",
            "file://../../x",
            "file://..\\\\..\\\\x",
            "file:///home/user/../../etc/passwd",
        ):
            with self.subTest(url=url):
                with self.assertRaises(ManifestError) as cm:
                    read_manifest(self._capa_toml_with_git(url))
                self.assertIn("traversal", str(cm.exception).lower())

    def test_file_percent_encoded_traversal_rejected(self):
        # The literal ``..`` filter alone is bypassable: git decodes a
        # file:// path's percent-encoding before resolving it, so an
        # encoded ``%2e%2e`` (``..``) still traverses. These must be
        # rejected on the decoded form, including a mixed
        # encoded/literal-separator shape.
        for url in (
            "file://%2e%2e/x",
            "file:///a/%2e%2e/b",
            "file://%2e%2e%2f..",
            "file://%2e%2e\\\\..\\\\x",
            "file://%2E%2E/x",
        ):
            with self.subTest(url=url):
                with self.assertRaises(ManifestError) as cm:
                    read_manifest(self._capa_toml_with_git(url))
                self.assertIn("traversal", str(cm.exception).lower())

    def test_file_double_encoded_dot_allowed(self):
        # ``%252e`` decodes once (as git does) to a literal ``%2e``
        # filename component, not ``..``; it is not a traversal and must
        # stay accepted so legitimate odd-but-literal paths still work.
        url = "file:///repos/%252e%252e/repo"
        m = read_manifest(self._capa_toml_with_git(url))
        self.assertEqual(m.dependencies[0].git, url)

    def test_git_ssh_shortcut_allowed(self):
        m = read_manifest(self._capa_toml_with_git("git@github.com:x/y.git"))
        self.assertEqual(m.dependencies[0].git, "git@github.com:x/y.git")

    def test_ext_transport_rejected(self):
        # ``ext::sh -c <cmd>`` is the textbook RCE shape from
        # CVE-2017-1000117 and its family.
        with self.assertRaises(ManifestError) as cm:
            read_manifest(self._capa_toml_with_git("ext::sh -c id"))
        self.assertIn("allow-listed transports", str(cm.exception))

    def test_url_starting_with_dash_rejected(self):
        # ``git clone -uupload-pack=cmd`` would pass the URL through
        # as an option. Refuse before it can land in argv.
        with self.assertRaises(ManifestError) as cm:
            read_manifest(self._capa_toml_with_git("--upload-pack=evil"))
        self.assertIn("starts with '-'", str(cm.exception))

    def test_git_ssh_shortcut_with_option_injection_rejected(self):
        # The path segment after ``:`` in the SSH shortcut can also
        # carry a ``-`` to trigger option parsing on the remote side
        # of some git versions.
        with self.assertRaises(ManifestError) as cm:
            read_manifest(
                self._capa_toml_with_git("git@host:--upload-pack=evil"),
            )
        self.assertIn("starts with '-'", str(cm.exception))

    def test_scheme_url_with_dash_host_rejected(self):
        # ``ssh://-oProxyCommand=calc/repo`` does NOT start with '-'
        # (it starts with ``ssh://``) so the URL-position check above
        # misses it, but the host the ssh transport sees does. Modern
        # git mitigates, but the promised defence-in-depth must reject
        # a host component starting with '-' across schemes.
        for url in (
            "ssh://-evil/repo",
            "https://-evil/repo",
            "ssh://user@-evil/repo",
            "ssh://-oProxyCommand=calc/repo",
        ):
            with self.subTest(url=url):
                with self.assertRaises(ManifestError) as cm:
                    read_manifest(self._capa_toml_with_git(url))
                self.assertIn("starts with '-'", str(cm.exception))

    def test_scheme_url_with_normal_host_allowed(self):
        # Hosts that merely contain a dash, ports, and user@ prefixes
        # must still pass; only a LEADING dash on the host is refused.
        for url in (
            "https://my-host.example/x/y",
            "ssh://git@github.com/x/y",
            "https://github.com:443/x/y",
        ):
            with self.subTest(url=url):
                m = read_manifest(self._capa_toml_with_git(url))
                self.assertEqual(m.dependencies[0].git, url)

    def test_unknown_scheme_rejected(self):
        # rsync:// is real but not in our allow-list; bumping the
        # allow-list should be a deliberate decision.
        with self.assertRaises(ManifestError) as cm:
            read_manifest(self._capa_toml_with_git("rsync://example.invalid/x"))
        self.assertIn("allow-listed transports", str(cm.exception))

    def test_bare_path_rejected(self):
        # A naked filesystem path (no file:// prefix) bypasses the
        # scheme check; treat it as an error so anyone who wants a
        # local clone has to use file:// explicitly.
        with self.assertRaises(ManifestError) as cm:
            read_manifest(self._capa_toml_with_git("/tmp/local-repo"))
        self.assertIn("allow-listed transports", str(cm.exception))


class TestVerifySignedPinPrimaryAnchor(unittest.TestCase):
    """Audit 2026-06-17 PKG-2: ``_verify_signed_pin`` must anchor the
    declared ``verify_key`` on the PRIMARY key fingerprint (last field
    of the GnuPG ``VALIDSIG`` line per doc/DETAILS), not on the field
    that names the signing (sub)key. This lets a publisher rotate to a
    dedicated signing subkey without breaking verification, since gpg
    already proves the subkey<-primary binding by emitting the primary
    fpr. The cases drive a mocked ``git verify-tag --raw`` so no real
    keyring is needed."""

    _PRIMARY = "A" * 40
    _SUBKEY = "B" * 40

    @staticmethod
    def _validsig_line(signing_fpr: str, primary_fpr: str) -> str:
        # Full 11-token VALIDSIG: [GNUPG:] VALIDSIG <sig-fpr> <date>
        # <ts> <expire> <ver> <reserved> <pkalgo> <hashalgo> <class>
        # <primary-key-fpr>.
        return (
            f"[GNUPG:] VALIDSIG {signing_fpr} 2026-06-17 1750000000 0 "
            f"4 0 22 8 00 {primary_fpr}"
        )

    def _run(self, validsig: str, expected_fpr: str):
        from unittest.mock import patch, MagicMock
        from capa.pkg._install import _verify_signed_pin
        from pathlib import Path as _P
        result = MagicMock(returncode=0, stderr=validsig, stdout="")
        with patch(
            "capa.pkg._install.subprocess.run", return_value=result
        ):
            return _verify_signed_pin(
                _P("/tmp/dest"), "tag", "v1.0", expected_fpr, "mylib",
            )

    def test_primary_only_signature_verifies(self):
        # Current registry case: the primary itself signs, so signing
        # fpr == primary fpr == verify_key. Must still pass.
        line = self._validsig_line(self._PRIMARY, self._PRIMARY)
        self.assertEqual(self._run(line, self._PRIMARY), self._PRIMARY)

    def test_subkey_rotation_verifies_against_primary(self):
        # Rotation case: a signing subkey produced the signature
        # (parts[2] == subkey) but the primary fpr (parts[-1]) equals
        # the declared verify_key. Anchoring on the primary -> PASS.
        line = self._validsig_line(self._SUBKEY, self._PRIMARY)
        self.assertEqual(self._run(line, self._PRIMARY), self._PRIMARY)

    def test_wrong_primary_fails_and_names_subkey(self):
        # The primary does NOT match the declared verify_key: refuse,
        # and the diagnostic names both the subkey used and the primary.
        from capa.pkg._install import VerificationError
        line = self._validsig_line(self._SUBKEY, "C" * 40)
        with self.assertRaises(VerificationError) as cm:
            self._run(line, self._PRIMARY)
        msg = str(cm.exception)
        self.assertIn("C" * 40, msg)
        self.assertIn(self._SUBKEY, msg)


class TestDependencyNameAllowList(_TempDirMixin, unittest.TestCase):
    """Audit 2026-05-25 C1: dependency keys are appended to
    ``vendor_dir`` at install time. TOML's quoted-key syntax lets
    an attacker put ``../foo`` or an absolute path in there;
    without a manifest-level regex anchor the value reaches the
    install layer where it becomes a write-anywhere primitive
    (``_rmtree_force`` then ``git clone`` of attacker content).
    Reject at parse time."""

    def _capa_toml_with_dep_name(self, dep_name: str) -> Path:
        p = self._tmp / "capa.toml"
        _write(p, f'''
            [package]
            name = "demo"
            version = "0.1.0"

            [dependencies]
            "{dep_name}" = {{ git = "https://example.invalid/x", tag = "v0.1" }}
        ''')
        return p

    def test_simple_identifier_allowed(self):
        m = read_manifest(self._capa_toml_with_dep_name("mylib"))
        self.assertEqual(m.dependencies[0].name, "mylib")

    def test_underscore_and_dash_allowed(self):
        m = read_manifest(self._capa_toml_with_dep_name("my_lib-2"))
        self.assertEqual(m.dependencies[0].name, "my_lib-2")

    def test_parent_traversal_rejected(self):
        # The textbook attack from the audit: ``vendor_dir / "../evil"``
        # escapes the vendor tree entirely.
        with self.assertRaises(ManifestError) as cm:
            read_manifest(self._capa_toml_with_dep_name("../evil"))
        self.assertIn("invalid dependency name", str(cm.exception))

    def test_path_separator_rejected(self):
        with self.assertRaises(ManifestError) as cm:
            read_manifest(self._capa_toml_with_dep_name("sub/dir"))
        self.assertIn("invalid dependency name", str(cm.exception))

    def test_backslash_rejected(self):
        with self.assertRaises(ManifestError) as cm:
            read_manifest(self._capa_toml_with_dep_name("a\\\\b"))
        self.assertIn("invalid dependency name", str(cm.exception))

    def test_absolute_unix_path_rejected(self):
        with self.assertRaises(ManifestError) as cm:
            read_manifest(self._capa_toml_with_dep_name("/etc/passwd"))
        self.assertIn("invalid dependency name", str(cm.exception))

    def test_leading_dot_rejected(self):
        with self.assertRaises(ManifestError) as cm:
            read_manifest(self._capa_toml_with_dep_name(".hidden"))
        self.assertIn("invalid dependency name", str(cm.exception))

    def test_leading_dash_rejected(self):
        # A leading dash could also be parsed as an option in any
        # tool that later sees the name as positional argument.
        with self.assertRaises(ManifestError) as cm:
            read_manifest(self._capa_toml_with_dep_name("-evil"))
        self.assertIn("invalid dependency name", str(cm.exception))

    def test_empty_name_rejected(self):
        with self.assertRaises(ManifestError) as cm:
            read_manifest(self._capa_toml_with_dep_name(""))
        self.assertIn("invalid dependency name", str(cm.exception))

    def test_whitespace_rejected(self):
        with self.assertRaises(ManifestError) as cm:
            read_manifest(self._capa_toml_with_dep_name("a b"))
        self.assertIn("invalid dependency name", str(cm.exception))

    def test_overlong_name_rejected(self):
        # The regex caps at 64 chars. Anything longer is rejected
        # so a build-system pathological case (260-char Windows path
        # limit) cannot be brewed by an upstream.
        with self.assertRaises(ManifestError) as cm:
            read_manifest(self._capa_toml_with_dep_name("a" * 200))
        self.assertIn("invalid dependency name", str(cm.exception))


class TestGitPinAllowList(_TempDirMixin, unittest.TestCase):
    """Audit 2026-05-25 H2: pin strings flow into git argv as
    positionals at multiple call sites (``clone --branch <pin>``,
    ``checkout --detach <pin>``, ``verify-tag --raw <pin>``). The
    last one in particular puts the pin in an option position.
    Lock pins down at parse time."""

    def _capa_toml_with_pin(self, key: str, pin: str) -> Path:
        p = self._tmp / "capa.toml"
        _write(p, f'''
            [package]
            name = "demo"
            version = "0.1.0"

            [dependencies]
            mylib = {{ git = "https://example.invalid/x", {key} = "{pin}" }}
        ''')
        return p

    def test_semver_tag_allowed(self):
        m = read_manifest(self._capa_toml_with_pin("tag", "v1.2.3"))
        self.assertEqual(m.dependencies[0].tag, "v1.2.3")

    def test_sha_rev_allowed(self):
        m = read_manifest(self._capa_toml_with_pin("rev", "abc123def456"))
        self.assertEqual(m.dependencies[0].rev, "abc123def456")

    def test_tag_with_dots_and_plus_allowed(self):
        m = read_manifest(self._capa_toml_with_pin("tag", "1.0.0+build.42"))
        self.assertEqual(m.dependencies[0].tag, "1.0.0+build.42")

    def test_tag_starting_with_dash_rejected(self):
        # ``git verify-tag --raw --no-such-flag`` is the audit's
        # H2 shape; refuse before it lands in argv.
        with self.assertRaises(ManifestError) as cm:
            read_manifest(self._capa_toml_with_pin("tag", "-no-such-flag"))
        self.assertIn("not a valid git ref shape", str(cm.exception))

    def test_pin_with_whitespace_rejected(self):
        with self.assertRaises(ManifestError) as cm:
            read_manifest(self._capa_toml_with_pin("tag", "v1 -x"))
        self.assertIn("not a valid git ref shape", str(cm.exception))

    def test_pin_with_path_separator_rejected(self):
        with self.assertRaises(ManifestError) as cm:
            read_manifest(self._capa_toml_with_pin("tag", "v1/../v2"))
        self.assertIn("not a valid git ref shape", str(cm.exception))

    def test_pin_with_backslash_rejected(self):
        with self.assertRaises(ManifestError) as cm:
            read_manifest(self._capa_toml_with_pin("rev", "abc\\\\def"))
        self.assertIn("not a valid git ref shape", str(cm.exception))

    def test_empty_pin_rejected(self):
        with self.assertRaises(ManifestError) as cm:
            read_manifest(self._capa_toml_with_pin("tag", ""))
        self.assertIn("not a valid git ref shape", str(cm.exception))


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

    def test_path_dep_outside_tree_warns(self):
        # A ``../`` escape (and an absolute path) is accepted but is
        # invisible to the lockfile / SBOM, so install warns on stderr.
        import io
        from contextlib import redirect_stderr
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
        buf = io.StringIO()
        with redirect_stderr(buf):
            install(project)
        err = buf.getvalue()
        self.assertIn("outside the project tree", err)
        self.assertIn("mylib", err)

    def test_path_dep_inside_tree_no_warning(self):
        # A path dep that stays within the project tree is the common,
        # SBOM-friendly case and must NOT warn.
        import io
        from contextlib import redirect_stderr
        project = self._tmp / "proj"
        _write(project / "local" / "log.capa",
               'pub fun hi() -> String\n    return "hi"\n')
        _write(project / "capa.toml", '''
            [package]
            name = "proj"
            version = "0.1.0"

            [dependencies]
            mylib = { path = "./local" }
        ''')
        buf = io.StringIO()
        with redirect_stderr(buf):
            install(project)
        self.assertNotIn("outside the project tree", buf.getvalue())

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

    def test_moved_tag_refusal_does_not_overwrite_vendor(self):
        # Audit 2026-05-25 H3: pre-2026-05-25 the install loop
        # cloned over ``vendor/<name>`` and THEN compared SHAs, so
        # a moved upstream tag was applied to disk before the
        # LockMismatchError was raised. Any IDE / language server /
        # ``capa build`` reading the working tree in the window
        # between the overwrite and the error message saw the new
        # sources. The fix pre-checks the remote tag via
        # ``git ls-remote`` and refuses before touching ``vendor/``.
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
        install(project)  # vendor/mylib now holds the v0.1 content
        vendor_file = project / "vendor" / "mylib" / "log.capa"
        original_body = vendor_file.read_text("utf-8")
        # Move v0.1 to a new commit upstream.
        env = {
            **os.environ,
            "GIT_AUTHOR_NAME": "capa-test",
            "GIT_AUTHOR_EMAIL": "test@example.invalid",
            "GIT_COMMITTER_NAME": "capa-test",
            "GIT_COMMITTER_EMAIL": "test@example.invalid",
        }
        vendor_file_relative_text = (
            'pub fun greet() -> String\n    return "tampered"\n'
        )
        (upstream / "log.capa").write_text(
            vendor_file_relative_text, encoding="utf-8",
        )
        subprocess.run(
            ["git", "-C", str(upstream), "commit", "-am", "tamper"],
            check=True, capture_output=True, text=True, env=env,
        )
        subprocess.run(
            ["git", "-C", str(upstream), "tag", "-f", "v0.1"],
            check=True, capture_output=True, text=True, env=env,
        )
        with self.assertRaises(LockMismatchError):
            install(project)
        # The vendored content must be the ORIGINAL v0.1 sources,
        # not the tampered text. Pre-fix this assertion failed
        # because the clone landed before the SHA check.
        body_after_refusal = vendor_file.read_text("utf-8")
        self.assertEqual(body_after_refusal, original_body)
        self.assertNotIn("tampered", body_after_refusal)


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
        gpg / git invocation talks to the ephemeral keyring.

        The ephemeral key is Ed25519 with NO signing subkey. This
        matters: when an RSA master + RSA subkey pair is used,
        Linux GPG signs commits/tags with the subkey by default
        while ``gpg --list-keys`` returns the master fingerprint,
        and ``git verify-tag --raw`` reports the subkey fingerprint
        on the VALIDSIG line. The two don't match, so any test
        that asserts the listed fingerprint appears in the
        verification error message would fail on Linux while
        passing on Windows MSYS (whose GPG uses the master). Going
        Ed25519 single-key sidesteps the whole subkey class of
        flakiness. It also matches the algorithm of the real
        publisher key, so the test exercises the same shape."""
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
            "Key-Type: EDDSA\n"
            "Key-Curve: ed25519\n"
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


class TestCapaAdd(_TempDirMixin, unittest.TestCase):

    _BASE = '''\
        # my project
        [package]
        name = "demo"
        version = "0.1.0"
        capa = ">=0.8.4"
    '''

    def _project(self, manifest: str = None) -> Path:
        p = self._tmp / "capa.toml"
        _write(p, manifest if manifest is not None else self._BASE)
        return self._tmp

    def test_add_writes_dependency_block(self):
        project = self._project()
        original = (project / "capa.toml").read_text(encoding="utf-8")
        pin = add_dependency(
            project, "foo",
            "https://github.com/example/foo", tag="v1.0.0",
        )
        text = (project / "capa.toml").read_text(encoding="utf-8")
        self.assertIn("[dependencies.foo]", text)
        self.assertIn('git = "https://github.com/example/foo"', text)
        self.assertIn('tag = "v1.0.0"', text)
        # Original content (comments + package table) preserved.
        self.assertIn("# my project", text)
        self.assertIn('name = "demo"', text)
        self.assertTrue(text.startswith(original.rstrip() + "\n"))
        self.assertEqual(pin, "git=https://github.com/example/foo, tag=v1.0.0")
        # And it parses back cleanly.
        m = read_manifest(project / "capa.toml")
        self.assertEqual([d.name for d in m.dependencies], ["foo"])
        self.assertEqual(m.dependencies[0].tag, "v1.0.0")

    def test_add_rev_pin(self):
        project = self._project()
        add_dependency(
            project, "foo", "https://github.com/example/foo",
            rev="abc123def456",
        )
        m = read_manifest(project / "capa.toml")
        self.assertEqual(m.dependencies[0].rev, "abc123def456")
        self.assertIsNone(m.dependencies[0].tag)

    def test_add_branch_pin_written_as_tag(self):
        project = self._project()
        pin = add_dependency(
            project, "foo", "https://github.com/example/foo",
            branch="main",
        )
        text = (project / "capa.toml").read_text(encoding="utf-8")
        self.assertIn('tag = "main"', text)
        self.assertEqual(pin, "git=https://github.com/example/foo, tag=main")

    def test_add_rejects_duplicate_without_force(self):
        project = self._project('''\
            [package]
            name = "demo"
            version = "0.1.0"

            [dependencies.foo]
            git = "https://github.com/example/foo"
            tag = "v0.1.0"
        ''')
        with self.assertRaises(ManifestError) as ctx:
            add_dependency(
                project, "foo", "https://github.com/example/foo",
                tag="v2.0.0",
            )
        # Error states the existing pin.
        self.assertIn("tag=v0.1.0", str(ctx.exception))
        # With force=True it overwrites.
        add_dependency(
            project, "foo", "https://github.com/example/foo",
            tag="v2.0.0", force=True,
        )
        m = read_manifest(project / "capa.toml")
        foo = [d for d in m.dependencies if d.name == "foo"]
        self.assertEqual(len(foo), 1)
        self.assertEqual(foo[0].tag, "v2.0.0")

    def test_add_force_over_inline_form_same_table(self):
        # The inline form ``foo = { git = ..., tag = ... }`` is what
        # docs/packages.md teaches; a --force overwrite must replace it
        # in place, not append a second ``[dependencies.foo]`` block
        # that produces a TOML duplicate-key parse failure.
        project = self._project('''\
            [package]
            name = "demo"
            version = "0.1.0"

            [dependencies]
            foo = { git = "https://github.com/example/foo", tag = "v1.0.0" }
        ''')
        add_dependency(
            project, "foo", "https://github.com/example/foo",
            tag="v2.0.0", force=True,
        )
        # File parses (no duplicate key) and carries exactly one foo.
        m = read_manifest(project / "capa.toml")
        foo = [d for d in m.dependencies if d.name == "foo"]
        self.assertEqual(len(foo), 1)
        self.assertEqual(foo[0].tag, "v2.0.0")

    def test_add_force_inline_to_dev_does_not_leave_both(self):
        # Moving an inline [dependencies] entry to [dev-dependencies]
        # with --force --dev must remove the old inline entry, not
        # leave foo declared in both tables (a hard parse error).
        project = self._project('''\
            [package]
            name = "demo"
            version = "0.1.0"

            [dependencies]
            foo = { git = "https://github.com/example/foo", tag = "v1.0.0" }
        ''')
        add_dependency(
            project, "foo", "https://github.com/example/foo",
            tag="v2.0.0", force=True, dev=True,
        )
        m = read_manifest(project / "capa.toml")
        self.assertEqual([d.name for d in m.dependencies], [])
        dev = [d for d in m.dev_dependencies if d.name == "foo"]
        self.assertEqual(len(dev), 1)
        self.assertEqual(dev[0].tag, "v2.0.0")

    def test_add_force_inline_preserves_sibling_entries(self):
        # A --force overwrite of one inline entry must not touch a
        # sibling inline entry in the same table.
        project = self._project('''\
            [package]
            name = "demo"
            version = "0.1.0"

            [dependencies]
            bar = { git = "https://github.com/example/bar", tag = "v0.1.0" }
            foo = { git = "https://github.com/example/foo", tag = "v1.0.0" }
        ''')
        add_dependency(
            project, "foo", "https://github.com/example/foo",
            tag="v2.0.0", force=True,
        )
        m = read_manifest(project / "capa.toml")
        by_name = {d.name: d.tag for d in m.dependencies}
        self.assertEqual(by_name, {"bar": "v0.1.0", "foo": "v2.0.0"})

    def test_add_rejects_dangerous_git_url(self):
        project = self._project()
        with self.assertRaises(ManifestError):
            add_dependency(
                project, "foo", "ext::sh -c evil", tag="v1.0.0",
            )
        # The file must be untouched after a rejected add.
        text = (project / "capa.toml").read_text(encoding="utf-8")
        self.assertNotIn("dependencies.foo", text)

    def test_add_requires_exactly_one_pin(self):
        project = self._project()
        with self.assertRaises(ManifestError):
            add_dependency(project, "foo", "https://github.com/example/foo")
        with self.assertRaises(ManifestError):
            add_dependency(
                project, "foo", "https://github.com/example/foo",
                tag="v1.0.0", rev="abc123",
            )

    def test_add_with_verify_key(self):
        project = self._project()
        key = "6C1D222D491FB88031E041A536CFB426101AA24B"
        add_dependency(
            project, "foo", "https://github.com/example/foo",
            tag="v1.0.0", verify_key=key,
        )
        text = (project / "capa.toml").read_text(encoding="utf-8")
        self.assertIn(f'verify_key = "{key}"', text)
        m = read_manifest(project / "capa.toml")
        self.assertEqual(m.dependencies[0].verify_key, key)

    def test_add_missing_capa_toml(self):
        with self.assertRaises(ManifestError) as ctx:
            add_dependency(
                self._tmp, "foo", "https://github.com/example/foo",
                tag="v1.0.0",
            )
        self.assertIn("capa init", str(ctx.exception))


class TestRegistryResolve(_TempDirMixin, unittest.TestCase):
    """``resolve_name`` against an index served from a ``file://`` URL.

    The fetch is made testable without a live server by writing the
    index to a temp file and pointing ``registry_url`` at its
    ``file://`` URL: ``urllib.request.urlopen`` (which ``_fetch_index``
    uses) handles ``file://`` natively, so the real fetch + parse +
    cache path runs end to end. A separate ``cache_dir`` keeps each
    test's cache isolated from ``~/.capa``.
    """

    _KEY = "6C1D222D491FB88031E041A536CFB426101AA24B"

    def setUp(self) -> None:
        super().setUp()
        # These tests exercise NAME RESOLUTION, not signature verification;
        # their unsigned file:// indexes are incidental. Opt out of the
        # enforced signing gate so the resolution assertions run as before.
        from unittest.mock import patch
        self._env_patch = patch.dict(
            os.environ, {"CAPA_REGISTRY_ALLOW_UNSIGNED": "1"}
        )
        self._env_patch.start()

    def tearDown(self) -> None:
        self._env_patch.stop()
        super().tearDown()

    def _index_url(self, body: str) -> str:
        p = self._tmp / "index.json"
        p.write_text(textwrap.dedent(body), encoding="utf-8")
        return p.as_uri()

    def _cache_dir(self) -> Path:
        d = self._tmp / "cache"
        d.mkdir(parents=True, exist_ok=True)
        return d

    def _good_index(self) -> str:
        return f'''\
            {{
              "registry_version": 1,
              "updated": "2026-05-27",
              "packages": {{
                "capa_http": {{
                  "git": "https://github.com/nelsonduarte/capa_http",
                  "verify_key": "{self._KEY}",
                  "latest": "v0.1.3",
                  "description": "HTTP client"
                }}
              }}
            }}
        '''

    def test_resolve_known_name(self):
        url = self._index_url(self._good_index())
        entry = resolve_name(
            "capa_http", registry_url=url, cache_dir=self._cache_dir(),
        )
        self.assertIsInstance(entry, RegistryEntry)
        self.assertEqual(entry.name, "capa_http")
        self.assertEqual(entry.git, "https://github.com/nelsonduarte/capa_http")
        self.assertEqual(entry.verify_key, self._KEY)
        self.assertEqual(entry.latest, "v0.1.3")
        self.assertEqual(entry.description, "HTTP client")

    def test_resolve_unknown_name(self):
        url = self._index_url(self._good_index())
        with self.assertRaises(RegistryError) as ctx:
            resolve_name(
                "nope", registry_url=url, cache_dir=self._cache_dir(),
            )
        self.assertIn("nope", str(ctx.exception))

    def test_resolve_rejects_future_registry_version(self):
        url = self._index_url('''\
            {
              "registry_version": 999,
              "packages": {}
            }
        ''')
        with self.assertRaises(RegistryError) as ctx:
            resolve_name(
                "capa_http", registry_url=url, cache_dir=self._cache_dir(),
            )
        self.assertIn("upgrade", str(ctx.exception).lower())

    def test_resolve_rejects_dangerous_git_in_index(self):
        url = self._index_url('''\
            {
              "registry_version": 1,
              "packages": {
                "evil": { "git": "ext::sh -c evil", "latest": "v1" }
              }
            }
        ''')
        with self.assertRaises(RegistryError) as ctx:
            resolve_name(
                "evil", registry_url=url, cache_dir=self._cache_dir(),
            )
        # The message surfaces the shared validator's allow-list reason.
        self.assertIn("disallowed git URL", str(ctx.exception))

    def test_resolve_uses_cache_on_fetch_failure(self):
        cache_dir = self._cache_dir()
        # Prime the cache with a valid index.
        cache_file = cache_dir / "registry-index.json"
        cache_file.write_text(
            textwrap.dedent(self._good_index()), encoding="utf-8"
        )
        # Make the cache look stale so the network is attempted, then
        # fails, forcing the stale-cache fallback.
        old = time.time() - 7200
        os.utime(cache_file, (old, old))
        unreachable = "file:///no/such/registry/index.json"
        entry = resolve_name(
            "capa_http", registry_url=unreachable, cache_dir=cache_dir,
        )
        self.assertEqual(entry.git, "https://github.com/nelsonduarte/capa_http")

    def test_resolve_malformed_index(self):
        # Not valid JSON.
        bad_json = self._index_url("{ this is not json ")
        with self.assertRaises(RegistryError):
            resolve_name(
                "capa_http", registry_url=bad_json,
                cache_dir=self._cache_dir(),
            )
        # Valid JSON but no 'packages' table.
        no_packages = self._index_url('''\
            { "registry_version": 1 }
        ''')
        with self.assertRaises(RegistryError) as ctx:
            resolve_name(
                "capa_http", registry_url=no_packages,
                cache_dir=self._cache_dir(),
            )
        self.assertIn("packages", str(ctx.exception))


class TestRegistrySearch(_TempDirMixin, unittest.TestCase):
    """``search_packages`` against an index served from a ``file://`` URL.

    Same ``file://`` index pattern as ``TestRegistryResolve``: the real
    fetch + parse + cache path runs end to end against a temp file, with
    a per-test ``cache_dir`` isolated from ``~/.capa``. A synthetic
    multi-package index keeps the assertions deterministic.
    """

    def setUp(self) -> None:
        super().setUp()
        # These tests exercise SEARCH, not signature verification; their
        # unsigned file:// indexes are incidental. Opt out of the enforced
        # signing gate so the search assertions run as before.
        from unittest.mock import patch
        self._env_patch = patch.dict(
            os.environ, {"CAPA_REGISTRY_ALLOW_UNSIGNED": "1"}
        )
        self._env_patch.start()

    def tearDown(self) -> None:
        self._env_patch.stop()
        super().tearDown()

    def _index_url(self, body: str) -> str:
        p = self._tmp / "index.json"
        p.write_text(textwrap.dedent(body), encoding="utf-8")
        return p.as_uri()

    def _cache_dir(self) -> Path:
        d = self._tmp / "cache"
        d.mkdir(parents=True, exist_ok=True)
        return d

    def _multi_index(self) -> str:
        return '''\
            {
              "registry_version": 1,
              "updated": "2026-05-27",
              "packages": {
                "capa_http": {
                  "git": "https://github.com/nelsonduarte/capa_http",
                  "latest": "v0.1.3",
                  "description": "HTTP client over the Net capability"
                },
                "capa_log": {
                  "git": "https://github.com/nelsonduarte/capa_log",
                  "latest": "v0.1.2",
                  "description": "Structured logging with levels"
                },
                "capa_datetime": {
                  "git": "https://github.com/nelsonduarte/capa_datetime",
                  "latest": "v0.1.0",
                  "description": "Calendar and clock helpers"
                }
              }
            }
        '''

    def _search(self, query: str) -> list:
        return search_packages(
            query,
            registry_url=self._index_url(self._multi_index()),
            cache_dir=self._cache_dir(),
        )

    def test_search_by_name(self):
        results = self._search("http")
        self.assertEqual([e.name for e in results], ["capa_http"])

    def test_search_by_description(self):
        # "logging" appears in capa_log's description but in no name.
        results = self._search("logging")
        self.assertEqual([e.name for e in results], ["capa_log"])

    def test_search_case_insensitive(self):
        results = self._search("HTTP")
        self.assertEqual([e.name for e in results], ["capa_http"])

    def test_search_empty_query_lists_all(self):
        results = self._search("")
        self.assertEqual(
            [e.name for e in results],
            ["capa_datetime", "capa_http", "capa_log"],
        )

    def test_search_no_match(self):
        self.assertEqual(self._search("zzznope"), [])


class TestCapaAddRegistry(_TempDirMixin, unittest.TestCase):
    """``capa add <name>`` with no ``--git`` resolves via the registry."""

    _BASE = '''\
        [package]
        name = "demo"
        version = "0.1.0"
    '''

    def test_add_resolves_name_from_registry_when_no_git(self):
        import io
        import contextlib
        from unittest.mock import patch
        from capa import cli

        _write(self._tmp / "capa.toml", self._BASE)
        key = "6C1D222D491FB88031E041A536CFB426101AA24B"
        fake = RegistryEntry(
            name="capa_http",
            git="https://github.com/nelsonduarte/capa_http",
            verify_key=key,
            latest="v0.1.3",
            description="HTTP client",
        )

        cwd = os.getcwd()
        os.chdir(self._tmp)
        try:
            buf = io.StringIO()
            with patch("capa.pkg.resolve_name", return_value=fake), \
                    contextlib.redirect_stdout(buf):
                rc = cli._dispatch_add(["capa_http", "--no-install"])
        finally:
            os.chdir(cwd)

        self.assertEqual(rc, 0)
        out = buf.getvalue()
        self.assertIn(
            "resolved capa_http -> "
            "https://github.com/nelsonduarte/capa_http (latest v0.1.3) "
            "via registry",
            out,
        )
        text = (self._tmp / "capa.toml").read_text(encoding="utf-8")
        self.assertIn("[dependencies.capa_http]", text)
        self.assertIn(
            'git = "https://github.com/nelsonduarte/capa_http"', text
        )
        self.assertIn('tag = "v0.1.3"', text)
        self.assertIn(f'verify_key = "{key}"', text)
        m = read_manifest(self._tmp / "capa.toml")
        dep = m.dependencies[0]
        self.assertEqual(dep.name, "capa_http")
        self.assertEqual(dep.tag, "v0.1.3")
        self.assertEqual(dep.verify_key, key)


class TestRegistryIndexSignature(_TempDirMixin, unittest.TestCase):
    """Detached-signature verification of the registry index, with the
    warn-then-enforce phasing (docs/design/signed-registry-index.md).

    The fail-open paths (unconfigured root key, absent signature) need
    no gpg and always run. The fail-closed paths split:

      * "signature present but gpg says invalid / wrong key" needs a
        real gpg + an ephemeral keyring to produce a genuine VALIDSIG
        whose fingerprint mismatches the pinned root -> skipUnless.
      * the cache-poisoning re-verification reuses the same machinery.

    Each test patches ``_REGISTRY_ROOT_KEY`` and the warn-once guards in
    ``capa.pkg._registry`` directly, then drives ``resolve_name`` through
    a ``file://`` index so the real fetch + cache + verify path runs.
    """

    _KEY = "6C1D222D491FB88031E041A536CFB426101AA24B"

    def _good_index(self) -> str:
        return textwrap.dedent(f'''\
            {{
              "registry_version": 1,
              "updated": "2026-05-27",
              "packages": {{
                "capa_http": {{
                  "git": "https://github.com/nelsonduarte/capa_http",
                  "verify_key": "{self._KEY}",
                  "latest": "v0.1.3",
                  "description": "HTTP client"
                }}
              }}
            }}
        ''')

    def _index_url(self, body: str) -> str:
        p = self._tmp / "index.json"
        p.write_text(body, encoding="utf-8")
        return p.as_uri()

    def _cache_dir(self) -> Path:
        d = self._tmp / "cache"
        d.mkdir(parents=True, exist_ok=True)
        return d

    def setUp(self) -> None:
        super().setUp()
        # Reset the once-per-process warn guards so each test observes a
        # fresh warning (the module remembers across tests otherwise).
        import capa.pkg._registry as reg
        reg._warned_unconfigured = False
        reg._warned_reasons.clear()

    # --- fail-open paths (no gpg required) -------------------------------

    def test_unconfigured_root_key_fails_open_with_warning(self):
        # Pre-1.0 build state: _REGISTRY_ROOT_KEY == "". The shipped
        # toolchain now bakes the real key, so patch it back to "" to
        # simulate the unconfigured build. An index with no .asc must
        # resolve AND warn (fail-open).
        import io
        import contextlib
        from unittest.mock import patch
        url = self._index_url(self._good_index())
        buf = io.StringIO()
        with patch("capa.pkg._registry._REGISTRY_ROOT_KEY", ""), \
                contextlib.redirect_stderr(buf):
            entry = resolve_name(
                "capa_http", registry_url=url, cache_dir=self._cache_dir(),
            )
        self.assertEqual(entry.name, "capa_http")
        self.assertIn("not configured", buf.getvalue().lower())

    def test_unsigned_index_with_root_configured_fails_closed(self):
        # Root key configured (the enforced default) but the index has no
        # sibling .asc and no opt-out env -> fail-closed. A missing
        # signature is a downgrade-attack vector once the key is known.
        from unittest.mock import patch
        url = self._index_url(self._good_index())
        with patch("capa.pkg._registry._REGISTRY_ROOT_KEY", self._KEY):
            with self.assertRaises(RegistryError) as ctx:
                resolve_name(
                    "capa_http", registry_url=url,
                    cache_dir=self._cache_dir(),
                )
        self.assertIn("unsigned", str(ctx.exception).lower())

    def test_unsigned_index_with_opt_out_env_resolves(self):
        # Same as above but with CAPA_REGISTRY_ALLOW_UNSIGNED=1: the
        # explicit air-gapped / self-hosted-mirror opt-out warns once and
        # resolves instead of failing closed.
        import io
        import contextlib
        from unittest.mock import patch
        url = self._index_url(self._good_index())
        buf = io.StringIO()
        with patch("capa.pkg._registry._REGISTRY_ROOT_KEY", self._KEY), \
                patch.dict(
                    os.environ, {"CAPA_REGISTRY_ALLOW_UNSIGNED": "1"}
                ), \
                contextlib.redirect_stderr(buf):
            entry = resolve_name(
                "capa_http", registry_url=url, cache_dir=self._cache_dir(),
            )
        self.assertEqual(entry.name, "capa_http")
        self.assertIn("unsigned", buf.getvalue().lower())

    @unittest.skipUnless(
        _gpg_available(), "gpg binary not on PATH",
    )
    def test_present_but_garbage_signature_fails_closed(self):
        # A .asc that is NOT a valid GPG signature: gpg --verify returns
        # non-zero, so this is fail-closed regardless of whether the
        # signature could ever match (no keyring needed; gpg rejects
        # malformed armour outright). Skips only if gpg is absent: without
        # gpg the production path warns-and-trusts (gpg-not-on-PATH is an
        # environment limitation, not an attack vector), so fail-closed
        # cannot be asserted.
        from unittest.mock import patch
        body = self._good_index()
        idx = self._tmp / "index.json"
        idx.write_text(body, encoding="utf-8")
        (self._tmp / "index.json.asc").write_text(
            "-----BEGIN PGP SIGNATURE-----\nnot a real signature\n"
            "-----END PGP SIGNATURE-----\n",
            encoding="utf-8",
        )
        url = idx.as_uri()
        with patch("capa.pkg._registry._REGISTRY_ROOT_KEY", self._KEY):
            with self.assertRaises(RegistryError) as ctx:
                resolve_name(
                    "capa_http", registry_url=url,
                    cache_dir=self._cache_dir(),
                )
        msg = str(ctx.exception).lower()
        self.assertIn("signature verification failed", msg)

        # Security property: the opt-out env is for "no signature at all",
        # NEVER for "a signature that does not validate". A present-but-bad
        # signature must STILL fail closed even with the escape hatch set.
        with patch("capa.pkg._registry._REGISTRY_ROOT_KEY", self._KEY), \
                patch.dict(
                    os.environ, {"CAPA_REGISTRY_ALLOW_UNSIGNED": "1"}
                ):
            with self.assertRaises(RegistryError):
                resolve_name(
                    "capa_http", registry_url=url,
                    cache_dir=self._cache_dir(),
                )

    def test_signed_index_gpg_absent_fails_closed(self):
        # Audit 2026-06-17: a signature is present but gpg is not on
        # PATH. The index is the registry trust root, so an
        # unverifiable signed index must FAIL CLOSED (was previously a
        # warn-and-trust fail-open), matching tag verification in
        # _install.py. Modelled by patching subprocess.run to raise
        # FileNotFoundError (the "gpg missing" signal) so the test runs
        # regardless of whether gpg is actually installed.
        from unittest.mock import patch
        body = self._good_index()
        idx = self._tmp / "index.json"
        idx.write_text(body, encoding="utf-8")
        (self._tmp / "index.json.asc").write_text(
            "-----BEGIN PGP SIGNATURE-----\nsig\n"
            "-----END PGP SIGNATURE-----\n",
            encoding="utf-8",
        )
        url = idx.as_uri()
        with patch("capa.pkg._registry._REGISTRY_ROOT_KEY", self._KEY), \
                patch(
                    "capa.pkg._registry.subprocess.run",
                    side_effect=FileNotFoundError(),
                ):
            with self.assertRaises(RegistryError) as ctx:
                resolve_name(
                    "capa_http", registry_url=url,
                    cache_dir=self._cache_dir(),
                )
        msg = str(ctx.exception).lower()
        self.assertIn("gpg", msg)
        self.assertIn("allow_unsigned", msg)

    def test_signed_index_gpg_absent_opt_out_resolves(self):
        # Same as above but with CAPA_REGISTRY_ALLOW_UNSIGNED=1: the
        # explicit air-gapped / self-hosted opt-out warns once and
        # resolves instead of failing closed.
        import io
        import contextlib
        from unittest.mock import patch
        body = self._good_index()
        idx = self._tmp / "index.json"
        idx.write_text(body, encoding="utf-8")
        (self._tmp / "index.json.asc").write_text(
            "-----BEGIN PGP SIGNATURE-----\nsig\n"
            "-----END PGP SIGNATURE-----\n",
            encoding="utf-8",
        )
        url = idx.as_uri()
        buf = io.StringIO()
        with patch("capa.pkg._registry._REGISTRY_ROOT_KEY", self._KEY), \
                patch(
                    "capa.pkg._registry.subprocess.run",
                    side_effect=FileNotFoundError(),
                ), \
                patch.dict(
                    os.environ, {"CAPA_REGISTRY_ALLOW_UNSIGNED": "1"}
                ), \
                contextlib.redirect_stderr(buf):
            entry = resolve_name(
                "capa_http", registry_url=url, cache_dir=self._cache_dir(),
            )
        self.assertEqual(entry.name, "capa_http")
        self.assertIn("gpg", buf.getvalue().lower())

    # --- fail-closed positive/negative with a real ephemeral key --------

    def _make_gpg_home(self) -> tuple[Path, str, dict]:
        """Ephemeral GNUPGHOME + passphrase-less Ed25519 key; returns
        (gnupg_home, fingerprint, env). Mirrors TestInstallVerifyKey."""
        gnupg_home = self._tmp / "gnupg"
        gnupg_home.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(gnupg_home, 0o700)
        except OSError:
            pass
        env = {**os.environ, "GNUPGHOME": str(gnupg_home)}
        batch = (
            "%no-protection\n"
            "Key-Type: EDDSA\n"
            "Key-Curve: ed25519\n"
            "Name-Real: Capa Registry Test\n"
            "Name-Email: capa-registry-test@example.invalid\n"
            "Expire-Date: 0\n"
            "%commit\n"
        )
        r = subprocess.run(
            ["gpg", "--batch", "--generate-key"],
            input=batch, capture_output=True, text=True, env=env,
        )
        if r.returncode != 0:
            self.skipTest(
                f"gpg --generate-key failed: {r.stderr.strip()}"
            )
        r = subprocess.run(
            ["gpg", "--list-keys", "--with-colons",
             "capa-registry-test@example.invalid"],
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

    def _sign(self, index_path: Path, env: dict, fpr: str) -> str:
        """Detach-sign ``index_path`` with the ephemeral key, write the
        sibling .asc, and return its armoured text."""
        r = subprocess.run(
            ["gpg", "--batch", "--yes", "--armor", "--detach-sign",
             "--local-user", fpr, "--output", "-", str(index_path)],
            capture_output=True, text=True, env=env,
        )
        if r.returncode != 0:
            self.skipTest(f"gpg detach-sign failed: {r.stderr.strip()}")
        sig = r.stdout
        index_path.with_name(index_path.name + ".asc").write_text(
            sig, encoding="utf-8",
        )
        return sig

    @unittest.skipUnless(
        _gpg_available(), "gpg binary not on PATH",
    )
    @unittest.skipIf(
        sys.platform == "win32",
        "ephemeral GNUPGHOME path mangling under MSYS git/gpg; the "
        "production verify path runs fine, only the test scaffold is "
        "platform-fragile (same as TestInstallVerifyKey).",
    )
    def test_valid_signature_resolves(self):
        from unittest.mock import patch
        _, fpr, env = self._make_gpg_home()
        idx = self._tmp / "index.json"
        idx.write_text(self._good_index(), encoding="utf-8")
        self._sign(idx, env, fpr)
        url = idx.as_uri()
        with patch.dict(os.environ, env, clear=False), \
                patch("capa.pkg._registry._REGISTRY_ROOT_KEY", fpr):
            entry = resolve_name(
                "capa_http", registry_url=url, cache_dir=self._cache_dir(),
            )
        self.assertEqual(entry.name, "capa_http")

    @unittest.skipUnless(
        _gpg_available(), "gpg binary not on PATH",
    )
    @unittest.skipIf(
        sys.platform == "win32",
        "ephemeral GNUPGHOME path mangling under MSYS; see "
        "test_valid_signature_resolves.",
    )
    def test_valid_signature_wrong_root_key_fails_closed(self):
        # A genuine VALIDSIG, but the pinned root key is a different
        # fingerprint -> mismatch -> fail-closed.
        from unittest.mock import patch
        _, fpr, env = self._make_gpg_home()
        idx = self._tmp / "index.json"
        idx.write_text(self._good_index(), encoding="utf-8")
        self._sign(idx, env, fpr)
        url = idx.as_uri()
        wrong = "DEAD" * 10
        with patch.dict(os.environ, env, clear=False), \
                patch("capa.pkg._registry._REGISTRY_ROOT_KEY", wrong):
            with self.assertRaises(RegistryError) as ctx:
                resolve_name(
                    "capa_http", registry_url=url,
                    cache_dir=self._cache_dir(),
                )
        self.assertIn(fpr.upper(), str(ctx.exception))

    @unittest.skipUnless(
        _gpg_available(), "gpg binary not on PATH",
    )
    @unittest.skipIf(
        sys.platform == "win32",
        "ephemeral GNUPGHOME path mangling under MSYS; see "
        "test_valid_signature_resolves.",
    )
    def test_tampered_index_bytes_fail_closed(self):
        # Sign the good index, then tamper the bytes the signature was
        # made over -> gpg --verify returns non-zero -> fail-closed.
        from unittest.mock import patch
        _, fpr, env = self._make_gpg_home()
        idx = self._tmp / "index.json"
        idx.write_text(self._good_index(), encoding="utf-8")
        self._sign(idx, env, fpr)
        # Tamper AFTER signing: swap the git URL to an attacker's repo.
        tampered = self._good_index().replace(
            "nelsonduarte/capa_http", "attacker/evil"
        )
        idx.write_text(tampered, encoding="utf-8")
        url = idx.as_uri()
        with patch.dict(os.environ, env, clear=False), \
                patch("capa.pkg._registry._REGISTRY_ROOT_KEY", fpr):
            with self.assertRaises(RegistryError):
                resolve_name(
                    "capa_http", registry_url=url,
                    cache_dir=self._cache_dir(),
                )

    @unittest.skipUnless(
        _gpg_available(), "gpg binary not on PATH",
    )
    @unittest.skipIf(
        sys.platform == "win32",
        "ephemeral GNUPGHOME path mangling under MSYS; see "
        "test_valid_signature_resolves.",
    )
    def test_crlf_served_index_fails_closed_with_lineending_hint(self):
        # Sign the index over its LF bytes, then SERVE it with CRLF line
        # endings (a publishing/transport mangling, not tampering). The
        # raw served bytes no longer match the signature, so acceptance
        # must STILL fail-closed (we never normalise to accept). The
        # diagnostic re-check should recognise the LF form validates and
        # add the CRLF/LF hint to the error message.
        from unittest.mock import patch
        _, fpr, env = self._make_gpg_home()
        idx = self._tmp / "index.json"
        # Sign over canonical LF bytes.
        lf_bytes = self._good_index().replace("\r\n", "\n").encode("utf-8")
        idx.write_bytes(lf_bytes)
        self._sign(idx, env, fpr)
        # Now serve the SAME content with CRLF endings (write_bytes to keep
        # exact control over line endings; write_text would re-translate).
        crlf_bytes = lf_bytes.replace(b"\n", b"\r\n")
        idx.write_bytes(crlf_bytes)
        url = idx.as_uri()
        with patch.dict(os.environ, env, clear=False), \
                patch("capa.pkg._registry._REGISTRY_ROOT_KEY", fpr):
            with self.assertRaises(RegistryError) as ctx:
                resolve_name(
                    "capa_http", registry_url=url,
                    cache_dir=self._cache_dir(),
                )
        msg = str(ctx.exception).lower()
        # Fail-closed proof: it did NOT silently accept.
        self.assertIn("signature verification failed", msg)
        # Diagnostic proof: the CRLF/LF hint is present.
        self.assertIn("line-ending", msg)
        self.assertIn("crlf", msg)

    @unittest.skipUnless(
        _gpg_available(), "gpg binary not on PATH",
    )
    @unittest.skipIf(
        sys.platform == "win32",
        "ephemeral GNUPGHOME path mangling under MSYS; see "
        "test_valid_signature_resolves.",
    )
    def test_tampered_index_has_no_lineending_hint(self):
        # A genuine content tamper (not just line endings) must fail
        # closed WITHOUT the CRLF/LF hint, so the diagnostic does not emit
        # false positives that would downplay real tampering.
        from unittest.mock import patch
        _, fpr, env = self._make_gpg_home()
        idx = self._tmp / "index.json"
        lf_bytes = self._good_index().replace("\r\n", "\n").encode("utf-8")
        idx.write_bytes(lf_bytes)
        self._sign(idx, env, fpr)
        # Tamper the content (swap the git URL); keep LF line endings so
        # the only difference from the signed form is real tampering.
        tampered = (
            self._good_index().replace("\r\n", "\n").replace(
                "nelsonduarte/capa_http", "attacker/evil"
            ).encode("utf-8")
        )
        idx.write_bytes(tampered)
        url = idx.as_uri()
        with patch.dict(os.environ, env, clear=False), \
                patch("capa.pkg._registry._REGISTRY_ROOT_KEY", fpr):
            with self.assertRaises(RegistryError) as ctx:
                resolve_name(
                    "capa_http", registry_url=url,
                    cache_dir=self._cache_dir(),
                )
        msg = str(ctx.exception).lower()
        self.assertIn("signature verification failed", msg)
        self.assertNotIn("line-ending", msg)

    @unittest.skipUnless(
        _gpg_available(), "gpg binary not on PATH",
    )
    def test_poisoned_cache_without_matching_sig_fails_closed(self):
        # Cache-poisoning vector: a fresh, well-formed cache entry with a
        # swapped git+verify_key but NO valid matching .asc, root key
        # configured -> the cache read must re-verify and reject it.
        # Needs only gpg (not an ephemeral keyring): a garbage .asc makes
        # gpg --verify return non-zero, so this runs live on every box
        # that has gpg, Windows included.
        from unittest.mock import patch
        cache_dir = self._cache_dir()
        # Write a poisoned cache directly (simulating another process).
        poisoned = self._good_index().replace(
            "nelsonduarte/capa_http", "attacker/evil"
        ).replace(self._KEY, "AB" * 20)
        (cache_dir / "registry-index.json").write_text(
            poisoned, encoding="utf-8",
        )
        # An absent .asc with root configured would hit the "unsigned"
        # fail-open branch (no rejection). To exercise fail-CLOSED on the
        # cache, plant a garbage .asc so gpg --verify returns non-zero.
        (cache_dir / "registry-index.json.asc").write_text(
            "-----BEGIN PGP SIGNATURE-----\nbogus\n"
            "-----END PGP SIGNATURE-----\n",
            encoding="utf-8",
        )
        # Cache is fresh, so it is read without a network round-trip.
        url = "https://example.invalid/index.json"
        with patch("capa.pkg._registry._REGISTRY_ROOT_KEY", self._KEY):
            with self.assertRaises(RegistryError):
                resolve_name(
                    "capa_http", registry_url=url, cache_dir=cache_dir,
                )


class TestDevDependenciesManifest(_TempDirMixin, unittest.TestCase):
    """``[dev-dependencies]`` parsing: same schema and the same
    security validation as ``[dependencies]``, plus the cross-table
    name-collision rule."""

    def _manifest(self, body: str) -> Path:
        p = self._tmp / "capa.toml"
        _write(p, body)
        return p

    def test_dev_dependencies_parsed_separately(self):
        p = self._manifest('''
            [package]
            name = "demo"
            version = "0.1.0"

            [dependencies]
            mylib = { git = "https://github.com/u/mylib", tag = "v0.1" }

            [dev-dependencies]
            testlib = { git = "https://github.com/u/testlib", rev = "abc123" }
            localtool = { path = "../localtool" }
        ''')
        m = read_manifest(p)
        self.assertEqual([d.name for d in m.dependencies], ["mylib"])
        self.assertEqual(
            [d.name for d in m.dev_dependencies], ["testlib", "localtool"],
        )
        self.assertEqual(m.dev_dependencies[0].rev, "abc123")
        self.assertTrue(m.dev_dependencies[1].is_path)

    def test_dev_dependencies_absent_means_empty_list(self):
        p = self._manifest('''
            [package]
            name = "demo"
            version = "0.1.0"
        ''')
        self.assertEqual(read_manifest(p).dev_dependencies, [])

    def test_dev_dep_dangerous_git_url_rejected(self):
        # The ext:: transport allow-list applies to the dev table too.
        p = self._manifest('''
            [package]
            name = "demo"
            version = "0.1.0"

            [dev-dependencies]
            evil = { git = "ext::sh -c whoami", tag = "v1" }
        ''')
        with self.assertRaises(ManifestError) as ctx:
            read_manifest(p)
        self.assertIn("transport", str(ctx.exception))

    def test_dev_dep_traversal_name_rejected(self):
        p = self._manifest('''
            [package]
            name = "demo"
            version = "0.1.0"

            [dev-dependencies]
            "../evil" = { git = "https://github.com/u/evil", tag = "v1" }
        ''')
        with self.assertRaises(ManifestError) as ctx:
            read_manifest(p)
        self.assertIn("invalid dependency name", str(ctx.exception))

    def test_dev_dep_without_pin_rejected(self):
        p = self._manifest('''
            [package]
            name = "demo"
            version = "0.1.0"

            [dev-dependencies]
            foo = { git = "https://github.com/u/foo" }
        ''')
        with self.assertRaises(ManifestError) as ctx:
            read_manifest(p)
        self.assertIn("needs a pin", str(ctx.exception))

    def test_name_in_both_tables_rejected(self):
        p = self._manifest('''
            [package]
            name = "demo"
            version = "0.1.0"

            [dependencies]
            mylib = { git = "https://github.com/u/mylib", tag = "v0.1" }

            [dev-dependencies]
            mylib = { git = "https://github.com/u/mylib", tag = "v0.2" }
        ''')
        with self.assertRaises(ManifestError) as ctx:
            read_manifest(p)
        msg = str(ctx.exception)
        self.assertIn("both [dependencies] and [dev-dependencies]", msg)
        self.assertIn("mylib", msg)

    def test_lock_round_trips_dev_marker(self):
        from capa.pkg._manifest import LockedDependency, write_lock
        lock_path = self._tmp / "capa.lock"
        entries = [
            LockedDependency(
                name="mylib", git="https://github.com/u/mylib",
                pin="v0.1", pin_kind="tag", commit="a" * 40,
            ),
            LockedDependency(
                name="testlib", git="https://github.com/u/testlib",
                pin="v0.2", pin_kind="tag", commit="b" * 40, dev=True,
            ),
        ]
        write_lock(lock_path, entries)
        text = lock_path.read_text(encoding="utf-8")
        # Only the dev entry carries the marker.
        self.assertEqual(text.count("dev = true"), 1)
        back = read_lock(lock_path)
        self.assertEqual([(d.name, d.dev) for d in back],
                         [("mylib", False), ("testlib", True)])

    def test_lock_rejects_non_bool_dev(self):
        _write(self._tmp / "capa.lock", '''
            [[dependencies]]
            name = "mylib"
            git = "https://github.com/u/mylib"
            pin = "v0.1"
            pin_kind = "tag"
            commit = "abc"
            dev = "yes"
        ''')
        with self.assertRaises(ManifestError) as ctx:
            read_lock(self._tmp / "capa.lock")
        self.assertIn("'dev' must be a boolean", str(ctx.exception))


class TestDevDependenciesInstall(_TempDirMixin, unittest.TestCase):
    """Install semantics: dev-deps are fetched for the invocation
    root and never for a package consumed as a dependency."""

    def test_dev_path_dep_is_validated(self):
        project = self._tmp / "proj"
        _write(project / "capa.toml", '''
            [package]
            name = "proj"
            version = "0.1.0"

            [dev-dependencies]
            tool = { path = "../does-not-exist" }
        ''')
        with self.assertRaises(InstallError) as ctx:
            install(project)
        self.assertIn("does not exist", str(ctx.exception))

    def test_consumed_as_dep_does_not_install_its_dev_deps(self):
        # Project A depends (by path) on package B; B declares a git
        # dev-dependency whose URL does not even resolve. install(A)
        # must succeed without ever reading B's manifest: no clone is
        # attempted, nothing lands in vendor/, the lock stays empty.
        lib = self._tmp / "libB"
        _write(lib / "capa.toml", '''
            [package]
            name = "libB"
            version = "0.1.0"

            [dev-dependencies]
            ghost = { git = "file:///nonexistent/ghost", tag = "v9.9" }
        ''')
        _write(lib / "b.capa", 'pub fun b() -> Int\n    return 1\n')
        project = self._tmp / "proj"
        _write(project / "capa.toml", '''
            [package]
            name = "proj"
            version = "0.1.0"

            [dependencies]
            libB = { path = "../libB" }
        ''')
        manifest = install(project)
        self.assertEqual(manifest.name, "proj")
        self.assertFalse((project / "vendor" / "ghost").exists())
        self.assertEqual(read_lock(project / "capa.lock"), [])


@unittest.skipUnless(_has_git(), "git not on PATH")
class TestDevDependenciesInstallGit(_TempDirMixin, unittest.TestCase):
    """Root install vendors git dev-deps and marks them in the lock."""

    def _make_local_git_repo(self, repo_dir: Path, body: str) -> str:
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
        (repo_dir / "lib.capa").write_text(body, encoding="utf-8")
        git("add", "lib.capa")
        git("commit", "-m", "initial")
        git("tag", "v0.1")
        return repo_dir.as_uri()

    def test_root_install_vendors_dev_dep_and_marks_lock(self):
        dep_url = self._make_local_git_repo(
            self._tmp / "updep",
            'pub fun real() -> Int\n    return 1\n',
        )
        dev_url = self._make_local_git_repo(
            self._tmp / "updev",
            'pub fun check(stdio: Stdio, ok: Bool)\n'
            '    stdio.println("${ok}")\n',
        )
        project = self._tmp / "proj"
        _write(project / "capa.toml", f'''
            [package]
            name = "proj"
            version = "0.1.0"

            [dependencies]
            mylib = {{ git = "{dep_url}", tag = "v0.1" }}

            [dev-dependencies]
            testlib = {{ git = "{dev_url}", tag = "v0.1" }}
        ''')
        install(project)
        self.assertTrue((project / "vendor" / "mylib" / "lib.capa").exists())
        self.assertTrue((project / "vendor" / "testlib" / "lib.capa").exists())
        lock = {d.name: d for d in read_lock(project / "capa.lock")}
        self.assertEqual(set(lock), {"mylib", "testlib"})
        self.assertFalse(lock["mylib"].dev)
        self.assertTrue(lock["testlib"].dev)
        # The lockfile text itself carries the auditable marker.
        text = (project / "capa.lock").read_text(encoding="utf-8")
        self.assertEqual(text.count("dev = true"), 1)

    def test_install_is_idempotent_with_dev_deps(self):
        # A second install against the written lock must succeed (the
        # lock pre-check covers dev entries with the same SHA logic).
        dev_url = self._make_local_git_repo(
            self._tmp / "updev",
            'pub fun t() -> Int\n    return 2\n',
        )
        project = self._tmp / "proj"
        _write(project / "capa.toml", f'''
            [package]
            name = "proj"
            version = "0.1.0"

            [dev-dependencies]
            testlib = {{ git = "{dev_url}", tag = "v0.1" }}
        ''')
        install(project)
        first = read_lock(project / "capa.lock")
        install(project)
        self.assertEqual(read_lock(project / "capa.lock"), first)


class TestDevDependenciesLoader(_TempDirMixin, unittest.TestCase):
    """Modules from dev-deps are importable by the root project's
    test files exactly like regular deps (same vendor / search-path
    plumbing)."""

    def test_dev_path_dep_resolves_for_test_file(self):
        helper = self._tmp / "helpers" / "testkit"
        _write(
            helper / "asserts.capa",
            'pub fun label() -> String\n    return "from dev dep"\n',
        )
        project = self._tmp / "proj"
        _write(project / "capa.toml", '''
            [package]
            name = "proj"
            version = "0.1.0"

            [dev-dependencies]
            testkit = { path = "../helpers/testkit" }
        ''')
        _write(project / "tests" / "test_smoke.capa", '''
            import testkit.asserts
            fun main(stdio: Stdio)
                stdio.println(label())
        ''')
        install(project)
        result = subprocess.run(
            [sys.executable, "-m", "capa", "--run",
             str(Path("tests") / "test_smoke.capa")],
            cwd=project,
            capture_output=True, text=True, encoding="utf-8",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "from dev dep\n")


class TestCapaAddDev(_TempDirMixin, unittest.TestCase):
    """``capa add --dev`` writes into [dev-dependencies] and the
    duplicate check spans both tables."""

    _BASE = '''\
        [package]
        name = "demo"
        version = "0.1.0"
    '''

    def _project(self, manifest: str = None) -> Path:
        _write(
            self._tmp / "capa.toml",
            manifest if manifest is not None else self._BASE,
        )
        return self._tmp

    def test_add_dev_writes_dev_dependency_block(self):
        project = self._project()
        add_dependency(
            project, "testlib", "https://github.com/example/testlib",
            tag="v1.0.0", dev=True,
        )
        text = (project / "capa.toml").read_text(encoding="utf-8")
        self.assertIn("[dev-dependencies.testlib]", text)
        self.assertNotIn("[dependencies.testlib]", text)
        m = read_manifest(project / "capa.toml")
        self.assertEqual(m.dependencies, [])
        self.assertEqual([d.name for d in m.dev_dependencies], ["testlib"])

    def test_add_dev_rejects_name_already_a_regular_dep(self):
        project = self._project('''\
            [package]
            name = "demo"
            version = "0.1.0"

            [dependencies.foo]
            git = "https://github.com/example/foo"
            tag = "v0.1.0"
        ''')
        with self.assertRaises(ManifestError) as ctx:
            add_dependency(
                project, "foo", "https://github.com/example/foo",
                tag="v0.2.0", dev=True,
            )
        self.assertIn("[dependencies]", str(ctx.exception))
        # The manifest is untouched after the refusal.
        m = read_manifest(project / "capa.toml")
        self.assertEqual([d.name for d in m.dependencies], ["foo"])
        self.assertEqual(m.dev_dependencies, [])

    def test_add_dev_force_moves_dep_between_tables(self):
        project = self._project('''\
            [package]
            name = "demo"
            version = "0.1.0"

            [dependencies.foo]
            git = "https://github.com/example/foo"
            tag = "v0.1.0"
        ''')
        add_dependency(
            project, "foo", "https://github.com/example/foo",
            tag="v0.2.0", dev=True, force=True,
        )
        m = read_manifest(project / "capa.toml")
        self.assertEqual(m.dependencies, [])
        self.assertEqual([d.name for d in m.dev_dependencies], ["foo"])
        self.assertEqual(m.dev_dependencies[0].tag, "v0.2.0")

    def test_add_regular_rejects_name_already_a_dev_dep(self):
        project = self._project('''\
            [package]
            name = "demo"
            version = "0.1.0"

            [dev-dependencies.bar]
            git = "https://github.com/example/bar"
            tag = "v0.1.0"
        ''')
        with self.assertRaises(ManifestError) as ctx:
            add_dependency(
                project, "bar", "https://github.com/example/bar",
                tag="v0.2.0",
            )
        self.assertIn("[dev-dependencies]", str(ctx.exception))


class TestVerifyVendoredDeps(_TempDirMixin, unittest.TestCase):
    """PKG-1: build-time re-verification of ./vendor against capa.lock.

    The SHA-of-vendor lookup is injected via the ``head_sha`` callback
    so the fail-closed logic is exercised without spinning up real git
    repositories on every run. A separate CLI-level test (test_cli.py)
    covers the real-git end-to-end wiring."""

    _SHA1 = "1111111111111111111111111111111111111111"
    _SHA2 = "2222222222222222222222222222222222222222"

    def _project(self, *, toml: str, lock: str | None = None) -> Path:
        proj = self._tmp / "proj"
        proj.mkdir()
        _write(proj / "capa.toml", toml)
        if lock is not None:
            _write(proj / "capa.lock", lock)
        return proj

    _GIT_TOML = '''
        [package]
        name = "demo"
        version = "0.1.0"

        [dependencies]
        mylib = { git = "https://example.invalid/mylib.git", tag = "v0.1" }
    '''

    def _lock_for(self, commit: str) -> str:
        return (
            "[[dependencies]]\n"
            'name = "mylib"\n'
            'git = "https://example.invalid/mylib.git"\n'
            'pin = "v0.1"\n'
            'pin_kind = "tag"\n'
            f'commit = "{commit}"\n'
        )

    def test_matching_sha_passes(self):
        proj = self._project(
            toml=self._GIT_TOML, lock=self._lock_for(self._SHA1),
        )
        manifest = read_manifest(proj / "capa.toml")
        # vendor HEAD == lock.commit: no exception.
        verify_vendored_deps(
            proj, manifest, head_sha=lambda _p: self._SHA1,
        )

    def test_mismatched_sha_fails_and_names_dep(self):
        proj = self._project(
            toml=self._GIT_TOML, lock=self._lock_for(self._SHA1),
        )
        manifest = read_manifest(proj / "capa.toml")
        with self.assertRaises(VendorVerificationError) as ctx:
            verify_vendored_deps(
                proj, manifest, head_sha=lambda _p: self._SHA2,
            )
        msg = str(ctx.exception)
        self.assertIn("mylib", msg)
        self.assertIn(self._SHA1, msg)   # locked
        self.assertIn(self._SHA2, msg)   # vendor
        self.assertIn("capa install", msg)
        self.assertIn("CAPA_NO_VERIFY", msg)

    def test_missing_lock_with_git_deps_fails(self):
        proj = self._project(toml=self._GIT_TOML, lock=None)
        manifest = read_manifest(proj / "capa.toml")
        with self.assertRaises(VendorVerificationError) as ctx:
            verify_vendored_deps(
                proj, manifest, head_sha=lambda _p: self._SHA1,
            )
        msg = str(ctx.exception)
        self.assertIn("mylib", msg)
        self.assertIn("capa.lock", msg)
        self.assertIn("capa install", msg)

    def test_vendor_without_git_fails(self):
        proj = self._project(
            toml=self._GIT_TOML, lock=self._lock_for(self._SHA1),
        )
        manifest = read_manifest(proj / "capa.toml")
        # head_sha returns None -> vendor dir missing / has no .git.
        with self.assertRaises(VendorVerificationError) as ctx:
            verify_vendored_deps(
                proj, manifest, head_sha=lambda _p: None,
            )
        msg = str(ctx.exception)
        self.assertIn("mylib", msg)
        self.assertIn(".git", msg)
        self.assertIn("capa install", msg)

    def test_git_dep_absent_from_lock_fails(self):
        # Lock pins a DIFFERENT name than the manifest declares.
        other_lock = (
            "[[dependencies]]\n"
            'name = "otherlib"\n'
            'git = "https://example.invalid/otherlib.git"\n'
            'pin = "v0.1"\n'
            'pin_kind = "tag"\n'
            f'commit = "{self._SHA1}"\n'
        )
        proj = self._project(toml=self._GIT_TOML, lock=other_lock)
        manifest = read_manifest(proj / "capa.toml")
        with self.assertRaises(VendorVerificationError) as ctx:
            verify_vendored_deps(
                proj, manifest, head_sha=lambda _p: self._SHA1,
            )
        msg = str(ctx.exception)
        self.assertIn("mylib", msg)
        self.assertIn("capa.lock", msg)

    def test_opt_out_skips_with_warning(self):
        proj = self._project(toml=self._GIT_TOML, lock=None)
        manifest = read_manifest(proj / "capa.toml")
        from unittest.mock import patch
        warnings: list[str] = []
        # A mismatch that WOULD fail closed; the opt-out skips it.
        with patch.dict(os.environ, {"CAPA_NO_VERIFY": "1"}):
            # Reset the once-per-process guard so this test sees the warn.
            import capa.pkg._verify as _v
            _v._warned_opt_out = False
            verify_vendored_deps(
                proj, manifest,
                head_sha=lambda _p: self._SHA2,
                warn=warnings.append,
            )
        self.assertEqual(len(warnings), 1)
        self.assertIn("CAPA_NO_VERIFY", warnings[0])
        self.assertIn("OFF", warnings[0])

    def test_no_git_deps_is_noop(self):
        # A path-only project: verification never engages, no lock needed.
        toml = '''
            [package]
            name = "demo"
            version = "0.1.0"

            [dependencies]
            util = { path = "deps/util" }
        '''
        proj = self._project(toml=toml, lock=None)
        manifest = read_manifest(proj / "capa.toml")
        # No lock, no vendor, no exception: path deps are not verified.
        verify_vendored_deps(
            proj, manifest,
            head_sha=lambda _p: self.fail("should not query vendor SHA"),
        )

    def test_path_dep_alongside_git_dep_not_verified(self):
        # A git dep (verified) and a path dep (ignored) together: only
        # the git dep's SHA is queried.
        toml = '''
            [package]
            name = "demo"
            version = "0.1.0"

            [dependencies]
            mylib = { git = "https://example.invalid/mylib.git", tag = "v0.1" }
            util = { path = "deps/util" }
        '''
        proj = self._project(toml=toml, lock=self._lock_for(self._SHA1))
        manifest = read_manifest(proj / "capa.toml")
        queried: list[Path] = []

        def _head(p: Path) -> str:
            queried.append(p)
            return self._SHA1

        verify_vendored_deps(proj, manifest, head_sha=_head)
        # Exactly one SHA query, for the git dep's vendor dir.
        self.assertEqual(len(queried), 1)
        self.assertTrue(str(queried[0]).endswith("mylib"))


if __name__ == "__main__":
    unittest.main()
