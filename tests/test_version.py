"""Guards against the compiler version drifting out of sync.

The package version is single-sourced from ``pyproject.toml``
(``[project].version``); ``capa.__version__`` derives from it at
import time (see ``capa/__init__.py``). Every version-stamping
consumer, the CLI ``--version``, ``init_project``'s
``.capa-version`` file, and the manifest / SBOM / provenance / AOT
builders, reads ``capa.__version__``.

Historically ``__version__`` was a hard-coded literal that the
release process forgot to bump alongside ``pyproject.toml``, so
released binaries and the provenance they stamp reported a stale
compiler version. For a language whose headline is
machine-verifiable SBOMs, a wrong version in the provenance is a
real correctness bug. These tests lock the single-source invariant
so the two can never diverge again.
"""

import re
import unittest
from pathlib import Path

import capa

_PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"


def _pyproject_version() -> str:
    raw = _PYPROJECT.read_text(encoding="utf-8")
    try:
        import tomllib

        return tomllib.loads(raw)["project"]["version"]
    except ImportError:  # Python 3.10 has no tomllib.
        match = re.search(
            r'(?m)^\s*version\s*=\s*["\']([^"\']+)["\']',
            raw,
        )
        assert match is not None, "no [project].version found in pyproject.toml"
        return match.group(1)


class TestVersionSingleSource(unittest.TestCase):
    def test_version_matches_pyproject(self):
        """``capa.__version__`` must equal ``pyproject.toml``'s version.

        This is the invariant that breaks the stale-literal bug: the
        two are single-sourced, so a release that bumps pyproject.toml
        cannot leave ``__version__`` behind.
        """
        self.assertTrue(_PYPROJECT.is_file(), "pyproject.toml not found")
        self.assertEqual(capa.__version__, _pyproject_version())

    def test_version_is_not_a_stale_sentinel(self):
        """A resolved version is never the fallback sentinel in a checkout."""
        # In the source tree pyproject.toml is always present, so the
        # sentinel must never surface here.
        self.assertNotEqual(capa.__version__, "0+unknown")
        self.assertNotEqual(capa.__version__, "")

    def test_version_never_reintroduces_the_old_literal(self):
        """The removed hard-coded literal must not creep back in."""
        # 1.13.0 was the stale hard-coded value the release process
        # kept forgetting to bump; guard against a regression to any
        # hard-coded literal by pinning to the true source instead.
        self.assertEqual(capa.__version__, _pyproject_version())

    def test_resolver_reads_project_version_from_pyproject(self):
        """The tomllib/regex pyproject parser returns the [project] version."""
        raw = _PYPROJECT.read_bytes()
        self.assertEqual(
            capa._version_from_pyproject(raw),
            _pyproject_version(),
        )

    def test_resolver_ignores_dependency_pins(self):
        """A pyproject without [project].version yields None, not a pin."""
        bogus = b'[build-system]\nrequires = ["setuptools>=68", "wheel"]\n'
        self.assertIsNone(capa._version_from_pyproject(bogus))


if __name__ == "__main__":
    unittest.main()
