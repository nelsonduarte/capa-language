"""Fail-closed guard: the Wasm capability-soundness harnesses must not
vanish silently in an environment that is supposed to run them.

``tests/test_properties.py`` carries two load-bearing MACHINE-RUN
harnesses for the Wasm backend's capability discipline:
``TestWasmRuntimeSubsetOfManifest`` (every cap the .wasm module invokes
is declared in the manifest) and ``TestWasmAttenuationHonoured``
(attenuation replays through the runtime predicate; exclusions hold).
Both are wrapped in ``@unittest.skipUnless(_HAVE_WASM_TOOLCHAIN, ...)``,
so on a host without ``wasm-tools`` + ``wasmtime`` they simply skip: a
skip reads as a pass and the Wasm soundness evidence silently stops
running. That is the identical shape of the PyYAML incident, where an
undeclared dependency let eleven supply-chain guards skip while printing
OK (see ``tests/test_release_guards.py::GuardsCannotSilentlyNotRunTests``
and the sibling ``tests/test_ifc_harness_present.py``).

Unlike ``hypothesis`` (a declared ``[test]`` dependency that every
suite-running host must have), the Wasm toolchain is a native binary the
base CI matrix legitimately does NOT install; only the dedicated
``wasi`` job does. So "supposed to run" cannot be a pyproject
declaration here. The signal is the ``CAPA_REQUIRE_WASM`` environment
variable (same ``== "1"`` read convention as ``CAPA_REQUIRE_PROVENANCE``
and ``CAPA_NO_VERIFY``), which the ``wasi`` job sets: when it is set the
toolchain MUST be present, so a broken toolchain install fails LOUDLY
here instead of letting the two harnesses skip green. When it is not set
(a developer machine, the base matrix) the guard passes -- the skip is
then an honest "this host has no toolchain", not a silent regression.

The third test pins the wiring, mirroring
``test_ifc_harness_present.test_hypothesis_is_a_declared_test_dependency``:
the ``wasi`` job must keep setting ``CAPA_REQUIRE_WASM``, or the loud
failure above stops being the intended state in the one environment that
is supposed to exercise the harnesses.
"""

import os
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent

#: The Wasm soundness harnesses this guard keeps honest. Named as
#: ``module.ClassName`` so the pin below reads as documentation too.
_WASM_SOUNDNESS_HARNESSES = (
    "TestWasmRuntimeSubsetOfManifest",
    "TestWasmAttenuationHonoured",
)


def _wasm_is_required() -> bool:
    """Only the exact value ``"1"`` counts, matching the
    ``CAPA_REQUIRE_PROVENANCE`` / ``CAPA_NO_VERIFY`` convention so a
    stray truthy-looking value does not quietly change the guard."""
    return os.environ.get("CAPA_REQUIRE_WASM") == "1"


class WasmSoundnessHarnessesCannotSilentlyNotRunTests(unittest.TestCase):
    def test_toolchain_present_when_required(self):
        """When ``CAPA_REQUIRE_WASM=1`` the Wasm toolchain must be
        detected, so the two harnesses actually run. A missing toolchain
        in that environment is a LOUD failure here, not a silent skip
        over in ``test_properties``."""
        if not _wasm_is_required():
            self.skipTest(
                "CAPA_REQUIRE_WASM is not set; this host is not required "
                "to run the Wasm soundness harnesses (the base CI matrix "
                "and developer machines run without the toolchain)."
            )
        from tests.test_properties import _HAVE_WASM_TOOLCHAIN
        self.assertTrue(
            _HAVE_WASM_TOOLCHAIN,
            "CAPA_REQUIRE_WASM=1 but the Wasm toolchain (wasm-tools + "
            "wasmtime) was not detected, so the Wasm capability-soundness "
            "harnesses (TestWasmRuntimeSubsetOfManifest, "
            "TestWasmAttenuationHonoured) would skip silently and the "
            "suite runs no Wasm soundness evidence. Fix the toolchain "
            "install in the environment that sets CAPA_REQUIRE_WASM.",
        )

    def test_harnesses_are_not_skipped_when_required(self):
        """The harness classes must not carry a class-level skip when
        the toolchain is required: their ``@skipUnless`` collapses to a
        skip exactly when the toolchain is absent, which is the silent
        vanish this guard forbids."""
        if not _wasm_is_required():
            self.skipTest(
                "CAPA_REQUIRE_WASM is not set; the harnesses may skip "
                "honestly on a toolchain-less host."
            )
        import tests.test_properties as props
        for name in _WASM_SOUNDNESS_HARNESSES:
            with self.subTest(harness=name):
                cls = getattr(props, name)
                self.assertFalse(
                    getattr(cls, "__unittest_skip__", False),
                    f"{name} is marked skip while CAPA_REQUIRE_WASM=1; a "
                    "load-bearing Wasm soundness harness must not silently "
                    "opt out in the environment that is supposed to run it.",
                )

    def test_wasi_ci_job_sets_the_requirement(self):
        """Pin the wiring: the ``wasi`` job in ``tests.yml`` (the one
        environment that installs the toolchain) must set
        ``CAPA_REQUIRE_WASM``, or the loud failures above never bite and
        the guard is theater. Deleting the env would quietly restore the
        silent skip."""
        workflow = REPO_ROOT / ".github" / "workflows" / "tests.yml"
        doc = yaml.safe_load(workflow.read_text(encoding="utf-8"))
        wasi_job = doc["jobs"].get("wasi")
        self.assertIsNotNone(
            wasi_job,
            "tests.yml has no `wasi` job; that is the environment that "
            "installs the Wasm toolchain and must require it.",
        )
        job_env = wasi_job.get("env", {}) or {}
        self.assertEqual(
            str(job_env.get("CAPA_REQUIRE_WASM")), "1",
            "the wasi job must set CAPA_REQUIRE_WASM=1 so the Wasm "
            "soundness harnesses fail loud rather than skip silently when "
            "the toolchain install breaks.",
        )


if __name__ == "__main__":
    unittest.main()
