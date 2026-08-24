"""Fail-closed guard: the CI dependency install must stay hash-pinned.

The development and CI dependencies install from two universal,
uv-generated lockfiles (``requirements-test.lock`` and
``requirements-ci.lock``) under ``pip install --require-hashes``, so
every wheel CI installs is verified against a sha256 and no transitive
resolution happens at CI time. The published compiler stays
dependency-free; these locks are a CI-only input.

The security property is that CI installs ONLY fully-hashed, fully-pinned
dependencies. Nothing pinned it, which is the same silent-erosion class
as the PyYAML incident (an undeclared dependency let eleven supply-chain
guards skip while printing OK; see
``tests/test_release_guards.py::MutationTests`` and the fail-loud floor
``tests/test_wasm_harness_present.py``). Two ways this guarantee could
quietly disappear, each caught here:

  - someone drops ``--require-hashes`` from an install step, so pip stops
    verifying hashes even though the lock still carries them; or
  - a lockfile gains an entry with no ``--hash=`` (a hash-incomplete
    lock, e.g. regenerated without ``--generate-hashes``), so
    ``--require-hashes`` has nothing to verify that entry against and pip
    would refuse it (or, worse, a future relax would install it
    unverified).

Both guards derive the set of lockfiles from the workflow itself: the
install commands in ``tests.yml`` are the single source of which locks
matter, so a lock added to (or removed from) the CI install path is
automatically covered without a second hand-synced list.
"""

import re
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "tests.yml"

#: A `pip install ... -r <name>.lock` invocation inside a shell `run:`
#: block, capturing the lockfile it installs from.
_PIP_LOCK_INSTALL = re.compile(
    r"\bpip\s+install\b[^\n]*?-r\s+(\S+\.lock)\b"
)

#: The uv/pip flag that makes pip verify every wheel against a hash and
#: refuse a requirement with none.
_REQUIRE_HASHES = "--require-hashes"


def lock_installs(workflow_text: str):
    """Yield ``(job, lock, command)`` for every pip install of a
    ``.lock`` file in the workflow.

    A ``run:`` block is a shell script, so each install command is a
    single line; scanning line by line keeps a command's flags and its
    ``-r <lock>`` together, which is exactly what the flag-presence guard
    needs to check.
    """
    doc = yaml.safe_load(workflow_text)
    for job_name, job in (doc.get("jobs") or {}).items():
        for step in job.get("steps", []) or []:
            for line in step.get("run", "").splitlines():
                match = _PIP_LOCK_INSTALL.search(line)
                if match:
                    yield job_name, match.group(1), line.strip()


def lock_entries(lock_text: str):
    """Yield ``(name, has_hash)`` for every top-level requirement block.

    A uv/pip requirements lock lists each requirement as a block that
    starts at column 0 (``name==version [; marker] \\``) followed by
    indented ``--hash=`` continuation lines and a ``# via`` comment. The
    hashes live on the continuation lines, so a block is fully hashed iff
    at least one of its lines carries ``--hash=``.
    """
    name = None
    has_hash = False
    for raw in lock_text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        starts_block = raw[:1] not in (" ", "\t") and "==" in stripped
        if starts_block:
            if name is not None:
                yield name, has_hash
            name = re.split(r"[<>=!;\s]", stripped, maxsplit=1)[0]
            has_hash = "--hash=" in stripped
        elif name is not None and "--hash=" in stripped:
            has_hash = True
    if name is not None:
        yield name, has_hash


class SupplyChainHashPinCannotSilentlyErodeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = WORKFLOW.read_text(encoding="utf-8")
        cls.installs = list(lock_installs(cls.text))

    def test_ci_installs_from_a_hash_pinned_lock(self):
        """The guard is only worth its mutations: if the workflow no
        longer installs from a lockfile at all, both guards below would
        pass vacuously. Pin that at least one hashed-lock install exists.
        """
        self.assertTrue(
            self.installs,
            "no `pip install -r <lock>` step found in tests.yml; the "
            "hash-pinned dependency install path has gone, so the "
            "guards below verify nothing.",
        )

    def test_every_lock_install_passes_require_hashes(self):
        """FLAG PRESENCE. Every install that reads a lockfile must pass
        ``--require-hashes``, or pip stops verifying the pinned hashes and
        the supply-chain guarantee is gone while the lock still looks
        pinned."""
        for job, lock, command in self.installs:
            with self.subTest(job=job, lock=lock):
                self.assertIn(
                    _REQUIRE_HASHES, command,
                    f"the {job} job installs {lock} without "
                    f"{_REQUIRE_HASHES}, so pip no longer verifies the "
                    "pinned wheel hashes: `" + command + "`",
                )

    def test_every_installed_lock_is_fully_hashed(self):
        """HASH COMPLETENESS. Every lockfile the workflow installs must
        carry a hash on every requirement. A hash-less entry (a lock
        regenerated without ``--generate-hashes``) silently erodes the
        guarantee: there is nothing for ``--require-hashes`` to verify it
        against."""
        locks = {lock for _, lock, _ in self.installs}
        self.assertTrue(locks, "no lockfiles are installed by the workflow")
        for lock in sorted(locks):
            path = REPO_ROOT / lock
            with self.subTest(lock=lock):
                self.assertTrue(
                    path.is_file(),
                    f"{lock} is installed by the workflow but does not "
                    "exist in the repository.",
                )
                entries = list(lock_entries(path.read_text(encoding="utf-8")))
                self.assertTrue(
                    entries,
                    f"{lock} parsed to zero requirements; the lock format "
                    "changed and this guard would no longer verify it.",
                )
                unhashed = [name for name, has_hash in entries if not has_hash]
                self.assertEqual(
                    unhashed, [],
                    f"{lock} has requirement(s) with no --hash=: "
                    f"{', '.join(unhashed)}. Regenerate the lock with "
                    "uv's --generate-hashes so --require-hashes has a hash "
                    "to verify every wheel against.",
                )


if __name__ == "__main__":
    unittest.main()
