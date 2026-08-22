"""Fail-closed guard: the IFC soundness harnesses must not vanish silently.

``tests/test_ifc_noninterference.py`` and ``tests/test_ifc_fidelity.py`` are
the load-bearing MACHINE-RUN evidence that Capa's information-flow
enforcement is sound. Both raise ``unittest.SkipTest`` at IMPORT when
``hypothesis`` is absent, so on a host without the ``[test]`` extra they
simply vanish: a skip reads as a pass and the soundness suite silently
stops running. That is the identical shape of the PyYAML incident, where an
undeclared dependency let eleven supply-chain guards skip while printing OK
(see ``tests/test_release_guards.py::GuardsCannotSilentlyNotRunTests``).

``hypothesis`` is a declared ``[test]`` dependency (``pyproject.toml``), so
in any environment that is SUPPOSED to run the suite it must be importable.
This module mirrors the PyYAML guard's two-part shape: it fails LOUDLY when
the dependency is missing (rather than skipping), and it pins the
declaration so deleting it from the extra cannot quietly restore the silent
skip. It deliberately does NOT import ``hypothesis`` at module top -- doing
so would make THIS guard skip/error the same way, so the check lives inside
the tests where a missing dependency becomes a FAILURE, not a skip.
"""

import importlib
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

#: The soundness harnesses this guard keeps honest. Each skips at import
#: without ``hypothesis``; that skip must never pass unnoticed.
_SOUNDNESS_MODULES = (
    "tests.test_ifc_noninterference",
    "tests.test_ifc_fidelity",
)


class IfcSoundnessHarnessesCannotSilentlyNotRunTests(unittest.TestCase):
    def test_hypothesis_is_importable(self):
        """A missing ``hypothesis`` is a LOUD failure here, not a silent
        skip elsewhere. Install the test extra with
        ``pip install -e .[test]``."""
        try:
            import hypothesis  # noqa: F401
        except ImportError as exc:  # pragma: no cover - only without the extra
            self.fail(
                "hypothesis is not installed, so the IFC soundness harnesses "
                "(test_ifc_noninterference, test_ifc_fidelity) skip silently "
                "and the suite runs no noninterference evidence. Install the "
                f"declared test extra with `pip install -e .[test]` ({exc})."
            )

    def test_soundness_harnesses_are_collectable(self):
        """Each soundness module must actually import, not skip. A
        ``SkipTest`` raised during a test is normally swallowed as a skip;
        we catch it and convert it to a FAILURE so a harness that quietly
        opts out fails here instead of passing unnoticed."""
        for name in _SOUNDNESS_MODULES:
            with self.subTest(module=name):
                try:
                    importlib.import_module(name)
                except unittest.SkipTest as exc:
                    self.fail(
                        f"{name} skipped at import ({exc}); a load-bearing "
                        "IFC soundness harness must not silently opt out of "
                        "the suite. Install `pip install -e .[test]`."
                    )

    def test_hypothesis_is_a_declared_test_dependency(self):
        """Pin the declaration, mirroring
        ``test_release_guards.py::test_pyyaml_is_a_declared_test_dependency``.
        The declaration in the ``[test]`` extra is what makes the loud
        failure above the intended state in any suite-running environment;
        deleting it would quietly normalise the silent skip."""
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
            "hypothesis", test_extra.lower(),
            "hypothesis must stay a declared test dependency, or the IFC "
            "soundness harnesses go back to skipping silently.",
        )


if __name__ == "__main__":
    unittest.main()
