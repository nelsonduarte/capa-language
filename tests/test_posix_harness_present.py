"""Fail-closed guard: the POSIX-only symlink SECURITY guards must not
vanish silently in the CI leg that is supposed to run them.

Three guard modules gate load-bearing symlink security properties on
"can this platform create symlinks":

* ``tests/test_fs_toctou.py::TestSymlinkSwap`` and
  ``tests/test_db_toctou.py::TestSymlinkSwap`` -- a symlink swapped in
  after the pre-check is denied by the post-open handle re-validation.
* ``tests/test_attenuation.py::TestFsPathCanonicalisation`` -- a symlink
  pointing outside a ``restrict_to`` prefix is denied, one inside is
  allowed.

All three gate on ``tests._posix_probe.symlinks_available()``
(``not sys.platform.startswith("win")``), so on Windows they skip: a
skip reads as a pass and the symlink-swap / path-confinement denials
stop being verified. If the Linux (``ubuntu-latest``) leg that DOES run
them were dropped or mis-configured, those guards would skip everywhere
with a GREEN board and the property would go UNVERIFIED with no failure.
That is the identical shape of the PyYAML incident, where an undeclared
dependency let eleven supply-chain guards skip while printing OK (see
``tests/test_release_guards.py::MutationTests`` and the sibling floors
``tests/test_wasm_harness_present.py`` and
``tests/test_supply_chain_lock_hashes.py``).

This mirrors the ``test_wasm_harness_present.py`` (F1) floor EXACTLY: the
signal is the ``CAPA_REQUIRE_POSIX`` environment variable (same ``== "1"``
read convention as ``CAPA_REQUIRE_WASM`` / ``CAPA_REQUIRE_PROVENANCE`` /
``CAPA_NO_VERIFY``), which the ``test`` job's ubuntu leg sets. When it is
set the platform MUST be able to run the symlink guards, so a wrong
platform in that environment fails LOUDLY here instead of letting the
guards skip green. When it is not set (a developer machine, the Windows /
macOS matrix legs) the guard passes -- the skip is then an honest "this
host has no symlinks", not a silent regression.

Scope note (GPG is deliberately NOT covered). The GPG-signature tests in
``tests/test_pkg.py`` also carry Windows skips, but those are
SCAFFOLD-ONLY: they ``skipIf(win32, ...)`` because building an ephemeral
GNUPGHOME + keypair mangles paths under the MSYS git distribution, while
the production ``gpg --verify`` path runs fine and the fail-closed
signature tests run live wherever the ``gpg`` binary is present (all
three CI OSes, macOS included). Their skip removes no security coverage,
so forcing this floor onto them would be theater. The floor is scoped to
the genuinely-POSIX-security set: the three symlink classes whose
ABSENCE is a real silent loss.

The floor does NOT hand-copy the guards' skip predicate. There is exactly
ONE ``symlinks_available`` (``tests/_posix_probe.py``); the floor consults
that same function the guards gate on, and ``test_guard_modules_import_the_single_probe``
fails loud if any guard module ever re-copies the predicate instead of
importing the one source. It pins the wiring the same way
``test_wasm_harness_present.py`` pins the ``wasi`` job: the ``test`` job's
ubuntu leg must keep setting ``CAPA_REQUIRE_POSIX`` or the loud failures
above never bite.
"""

import importlib
import os
import unittest
from pathlib import Path

import yaml

from tests import _posix_probe

REPO_ROOT = Path(__file__).resolve().parent.parent

#: The symlink SECURITY guards this floor keeps honest, named as
#: ``module.ClassName`` so the pin below reads as documentation too.
#: Every one of these gates on ``tests._posix_probe.symlinks_available``.
_POSIX_SECURITY_GUARDS = (
    ("tests.test_fs_toctou", "TestSymlinkSwap"),
    ("tests.test_db_toctou", "TestSymlinkSwap"),
    ("tests.test_attenuation", "TestFsPathCanonicalisation"),
)


def _posix_is_required() -> bool:
    """Only the exact value ``"1"`` counts, matching the
    ``CAPA_REQUIRE_WASM`` / ``CAPA_REQUIRE_PROVENANCE`` convention so a
    stray truthy-looking value does not quietly change the guard."""
    return os.environ.get("CAPA_REQUIRE_POSIX") == "1"


class PosixSecurityGuardsCannotSilentlyNotRunTests(unittest.TestCase):
    def test_symlinks_available_when_required(self):
        """When ``CAPA_REQUIRE_POSIX=1`` the single symlink-availability
        probe every guard gates on must report True, so the guard bodies
        actually run. A non-symlink platform in that environment is a
        LOUD failure here, naming each guard module that would silently
        skip, not a quiet skip over in the guards themselves."""
        if not _posix_is_required():
            self.skipTest(
                "CAPA_REQUIRE_POSIX is not set; this host is not required "
                "to run the symlink security guards (the Windows / macOS "
                "matrix legs and developer machines may lack symlinks)."
            )
        for module, cls_name in _POSIX_SECURITY_GUARDS:
            with self.subTest(harness=f"{module}.{cls_name}"):
                self.assertTrue(
                    _posix_probe.symlinks_available(),
                    "CAPA_REQUIRE_POSIX=1 but "
                    "tests._posix_probe.symlinks_available() is False, so "
                    f"{module}.{cls_name} would skip silently and the suite "
                    "runs no symlink-denial evidence. Fix the platform in "
                    "the environment that sets CAPA_REQUIRE_POSIX.",
                )

    def test_guard_modules_import_the_single_probe(self):
        """There must be exactly ONE ``symlinks_available``. Each guard
        module must import ``tests._posix_probe.symlinks_available`` by
        identity, never re-define its own copy; a re-introduced inline
        predicate would let one set of guards run while another skips on
        a different notion of "POSIX-capable". This is a source invariant,
        so it runs on every host, not only where POSIX is required."""
        for module, _cls_name in _POSIX_SECURITY_GUARDS:
            with self.subTest(module=module):
                mod = importlib.import_module(module)
                probe = getattr(mod, "symlinks_available", None)
                self.assertIsNotNone(
                    probe,
                    f"{module} no longer exposes `symlinks_available`; it "
                    "must import the single predicate from "
                    "tests._posix_probe so the floor and every guard share "
                    "one definition.",
                )
                self.assertIs(
                    probe, _posix_probe.symlinks_available,
                    f"{module}.symlinks_available is not the single "
                    "tests._posix_probe.symlinks_available; a hand-copied "
                    "symlink predicate has been re-introduced and the "
                    "copies can now drift. Import the one source instead.",
                )

    def test_guards_are_not_skipped_when_required(self):
        """The guard classes must not carry a class-level skip when POSIX
        is required: ``TestSymlinkSwap``'s
        ``@skipUnless(_handle_paths_supported())`` collapses to a skip
        exactly when the host cannot resolve an open handle's true path,
        which is the silent vanish this floor forbids. The attenuation
        class carries no class-level skip (its symlink methods gate
        individually), so this pins that it stays that way too."""
        if not _posix_is_required():
            self.skipTest(
                "CAPA_REQUIRE_POSIX is not set; the guards may skip "
                "honestly on a host without symlinks or handle paths."
            )
        for module, cls_name in _POSIX_SECURITY_GUARDS:
            with self.subTest(harness=f"{module}.{cls_name}"):
                cls = getattr(importlib.import_module(module), cls_name)
                self.assertFalse(
                    getattr(cls, "__unittest_skip__", False),
                    f"{module}.{cls_name} is marked skip while "
                    "CAPA_REQUIRE_POSIX=1; a load-bearing symlink security "
                    "guard must not silently opt out in the environment "
                    "that is supposed to run it.",
                )

    def test_test_job_ubuntu_leg_sets_the_requirement(self):
        """Pin the wiring, mirroring
        ``test_wasm_harness_present.test_wasi_ci_job_sets_the_requirement``:
        the ``test`` job's ubuntu leg (the environment that runs the
        symlink guards for real) must set ``CAPA_REQUIRE_POSIX``, or the
        loud failures above never bite and the floor is theater. The env
        is gated to the ubuntu leg so the Windows / macOS matrix legs,
        which legitimately may lack symlinks, are not forced to fail."""
        workflow = REPO_ROOT / ".github" / "workflows" / "tests.yml"
        doc = yaml.safe_load(workflow.read_text(encoding="utf-8"))
        test_job = doc["jobs"].get("test")
        self.assertIsNotNone(
            test_job,
            "tests.yml has no `test` job; that is the matrix environment "
            "whose ubuntu leg runs the symlink security guards.",
        )
        job_env = test_job.get("env", {}) or {}
        value = str(job_env.get("CAPA_REQUIRE_POSIX", ""))
        self.assertIn(
            "ubuntu", value,
            "the test job must set CAPA_REQUIRE_POSIX on (and only on) its "
            "ubuntu leg so the symlink security guards fail loud rather than "
            "skip silently, without forcing the Windows / macOS legs to "
            f"fail; got CAPA_REQUIRE_POSIX={value!r}.",
        )
        self.assertIn(
            "1", value,
            "the test job's CAPA_REQUIRE_POSIX must resolve to 1 on the "
            f"ubuntu leg; got {value!r}.",
        )


if __name__ == "__main__":
    unittest.main()
