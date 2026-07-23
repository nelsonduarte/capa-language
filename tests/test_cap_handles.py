"""Tests for the capability handle table foundation
(``capa.runtime._cap_handles``). Audit slice 25.1 (2026-05-30):
landing the foundation alone so the wiring slices (25.2 - 25.8)
have a stable target."""

import pathlib
import re
import unittest

from capa.runtime._cap_handles import (
    CapHandleError,
    CapHandleTable,
    bootstrap_root_handles,
    root_handle_map,
)
from capa.ir._capa_types import (
    BUILTIN_CAPS,
    ERASED_CAPS,
    HANDLE_BEARING_CAPS,
    PYTHON_ONLY_CAPS,
)
from capa.ir._emit_wit import _KNOWN_CAPABILITIES
from capa.lsp.completion import _BUILTIN_CAPABILITIES
from capa.runtime._capabilities import (
    Clock,
    Db,
    Env,
    Fs,
    Net,
    Proc,
    Random,
    Stdio,
    Unsafe,
)
from capa.typesys import CAPABILITY_NAMES


# NOTE: ``capa.runtime._wasm_host`` imports ``wasmtime`` at module
# load, so it is NOT imported at top level here: the plain ``test``
# CI job does not install the ``wasm`` extra and importing it would
# ERROR the whole module at collection (a failed import is an error,
# not a skip). Nothing in this module needs it any more: the
# root-handle guard used to import ``_wasm_host._root_handle_map``
# behind a skip, and since 2026-07-23 that map lives in
# ``capa.runtime._cap_handles`` (wasmtime-free) so BOTH hosts can
# share one copy. The guard therefore runs unskipped on the no-wasm
# job, which is what a registry guard should always have done --
# that is the whole reason these guards live here instead of in the
# skip-happy ``tests/test_properties.py``.


# The Agda mechanisation in ``proofs/`` is a FOURTH copy of the
# capability set: ``CapaSyntax.agda`` declares one ``Cap``
# constructor per built-in. It drifted for years unnoticed - the
# model carried seven capabilities while the compiler carried ten,
# so Capability Soundness and Manifest Completeness quantified over
# a subset that silently excluded ``Proc``, ``Db`` and ``Serve``.
# Nothing could catch that: Agda typechecks the model happily
# whatever the compiler does, and the compiler never reads the
# model.
#
# These guards parse the Agda source as text. That is deliberate:
# it keeps the check running on every CI job (the ``agda`` workflow
# only fires on pushes touching ``proofs/``, and no test job has an
# Agda toolchain), and reading a file at test time cannot break
# collection the way an optional import can.
_REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
_PROOFS_DIR = _REPO_ROOT / "proofs"
_PROOFS_SYNTAX = _PROOFS_DIR / "CapaSyntax.agda"
_AGDA_WORKFLOW = _REPO_ROOT / ".github" / "workflows" / "agda.yml"

_CAP_DATATYPE_RE = re.compile(
    r"^data Cap : Set where\n((?:[ \t]+.*\n|\n)*)", re.MULTILINE
)
_CAP_CONSTRUCTOR_RE = re.compile(r"^\s+(\w+)\s*:\s*Cap\s*$", re.MULTILINE)
_SINGLETON_DIAGONAL_RE = re.compile(
    r"^singletonCS\s+(\w+)\s+(\w+)\s*=\s*true\s*$", re.MULTILINE
)


def _agda_source() -> str:
    """Reads ``proofs/CapaSyntax.agda``.

    Raises ``AssertionError`` rather than ``OSError`` when the file
    is gone, so a moved or deleted model shows up as a readable test
    failure naming the expected path.
    """
    if not _PROOFS_SYNTAX.is_file():
        raise AssertionError(
            "the Agda capability model is missing from "
            f"{_PROOFS_SYNTAX}; if the proofs moved, update "
            "_PROOFS_SYNTAX in tests/test_cap_handles.py"
        )
    return _PROOFS_SYNTAX.read_text(encoding="utf-8")


def _agda_cap_constructors() -> set[str]:
    """Constructor names of the Agda ``Cap`` datatype."""
    block = _CAP_DATATYPE_RE.search(_agda_source())
    if block is None:
        raise AssertionError(
            "could not find `data Cap : Set where` in "
            f"{_PROOFS_SYNTAX}; the guard's parser needs updating"
        )
    return set(_CAP_CONSTRUCTOR_RE.findall(block.group(1)))


def _agda_singleton_diagonal() -> set[str]:
    """Caps ``c`` for which ``singletonCS c c = true`` is written out."""
    return {
        lhs
        for lhs, rhs in _SINGLETON_DIAGONAL_RE.findall(_agda_source())
        if lhs == rhs
    }


class TestCapHandleTable(unittest.TestCase):

    def test_alloc_assigns_monotonic_handles_starting_at_one(self):
        # Handle 0 is reserved as the "no cap" sentinel; real
        # handles start at 1 and grow monotonically.
        t = CapHandleTable()
        h1 = t.alloc(Fs())
        h2 = t.alloc(Fs())
        h3 = t.alloc(Net())
        self.assertEqual([h1, h2, h3], [1, 2, 3])

    def test_lookup_returns_inserted_cap(self):
        t = CapHandleTable()
        fs = Fs()
        h = t.alloc(fs)
        self.assertIs(t.lookup(h, Fs), fs)

    def test_lookup_unknown_handle_raises(self):
        t = CapHandleTable()
        with self.assertRaises(CapHandleError) as ctx:
            t.lookup(999, Fs)
        self.assertIn("unknown capability handle", str(ctx.exception))

    def test_lookup_zero_sentinel_raises(self):
        # Handle 0 must never resolve to a real cap, even after a
        # full table fill - it's the "no cap" sentinel that catches
        # an emitter bug emitting a zero handle.
        t = CapHandleTable()
        t.alloc(Fs())
        with self.assertRaises(CapHandleError):
            t.lookup(0, Fs)

    def test_lookup_wrong_type_raises(self):
        # A Net handle passed where Fs is expected must fail loud
        # at the host bridge - quiet cross-cap escalation would be
        # a much worse failure mode than a runtime error.
        t = CapHandleTable()
        h = t.alloc(Net())
        with self.assertRaises(CapHandleError) as ctx:
            t.lookup(h, Fs)
        msg = str(ctx.exception)
        self.assertIn("resolves to Net", msg)
        self.assertIn("expected Fs", msg)

    def test_restrict_fs_intersects_with_parent(self):
        # restrict_to never widens authority. After two narrowing
        # steps, the resulting cap's allowed-prefix set is the
        # intersection (delegates to Fs.restrict_to's existing
        # monotonicity).
        t = CapHandleTable()
        root = t.alloc(Fs())
        narrow1 = t.restrict_fs(root, "/tmp/a")
        narrow2 = t.restrict_fs(narrow1, "/tmp/a/inner")
        n2 = t.lookup(narrow2, Fs)
        self.assertTrue(n2.allows("/tmp/a/inner/x.txt"))
        # Widening to a parent prefix from a child handle must NOT
        # restore the parent's broader authority - the intersection
        # ensures the child's restriction wins.
        widen_attempt = t.restrict_fs(narrow2, "/tmp/a")
        wa = t.lookup(widen_attempt, Fs)
        self.assertFalse(wa.allows("/tmp/a/outside_inner.txt"))

    def test_restrict_net_chains(self):
        # Net.allows takes a parsed hostname (Net.get does the
        # urlparse before the check). The handle table just hands
        # the restriction logic to Net.restrict_to; this confirms
        # the round-trip preserves Net's existing host-equality
        # semantics.
        t = CapHandleTable()
        root = t.alloc(Net())
        narrow = t.restrict_net(root, "api.example.com")
        n = t.lookup(narrow, Net)
        self.assertTrue(n.allows("api.example.com"))
        self.assertFalse(n.allows("attacker.invalid"))

    def test_restrict_env_chains_and_canonicalises(self):
        # Env case-insensitive on Windows (F4 fix); the handle
        # table delegates to Env.restrict_to_keys which already
        # canonicalises - confirm that survives the alloc round
        # trip.
        t = CapHandleTable()
        root = t.alloc(Env())
        h = t.restrict_env(root, ["NEVER_SET_KEY_12345"])
        env = t.lookup(h, Env)
        self.assertFalse(env.allows("PATH"))
        self.assertFalse(env.allows("path"))

    def test_bootstrap_root_handles(self):
        t = CapHandleTable()
        roots = bootstrap_root_handles(
            t, stdio=Stdio(), fs=Fs(), net=Net(), clock=Clock(),
            random=Random(seed=42), unsafe=Unsafe(),
        )
        # Only the caps that were passed are in the result.
        self.assertEqual(
            sorted(roots.keys()),
            ["clock", "fs", "net", "random", "stdio", "unsafe"],
        )
        # Handles are real (in the table) and type-correct.
        self.assertIsInstance(t.lookup(roots["stdio"], Stdio), Stdio)
        self.assertIsInstance(t.lookup(roots["fs"], Fs), Fs)
        self.assertIsInstance(t.lookup(roots["net"], Net), Net)
        # Absent caps are simply absent from the dict; the
        # discovery walker enforces that ``main`` doesn't ask for
        # them separately.
        self.assertNotIn("db", roots)
        self.assertNotIn("proc", roots)
        self.assertNotIn("env", roots)

    def test_table_len_reflects_allocations(self):
        t = CapHandleTable()
        self.assertEqual(len(t), 0)
        t.alloc(Fs())
        t.alloc(Net())
        t.restrict_fs(1, "/tmp")
        self.assertEqual(len(t), 3)


class TestCapabilityRegistry(unittest.TestCase):
    """Cross-checks on the built-in capability registry.

    The set of built-in capabilities is spelled out in more than one
    place: the front end knows it as ``typesys.CAPABILITY_NAMES``,
    the backends as ``ir._capa_types.BUILTIN_CAPS``, and the Wasm
    side additionally splits it into handle-bearing vs erased. All
    nine caps date from the initial commit and nobody has ever added
    one, so nothing has ever exercised the copies for agreement -
    and two of them had silently drifted. These tests are the guard
    that makes a tenth capability impossible to half-land.

    ``ir/_capa_types.py`` used to promise this cross-check lived in
    ``tests/test_properties.py``; it never did, and that module
    skips wholesale when Hypothesis is missing, so the guard lives
    here where it always runs.
    """

    def test_frontend_and_backend_capability_sets_agree(self):
        # A capability the checker accepts as a type annotation but
        # the backends do not know about lowers to a user type and
        # miscompiles silently; the reverse makes the backend carry
        # dead paths for a name no program can ever write.
        missing_in_backend = CAPABILITY_NAMES - BUILTIN_CAPS
        missing_in_frontend = BUILTIN_CAPS - CAPABILITY_NAMES
        self.assertEqual(
            missing_in_backend, set(),
            "capa.typesys.CAPABILITY_NAMES has capabilities the "
            "backends do not know about (add them to "
            "capa.ir._capa_types.BUILTIN_CAPS): "
            f"{sorted(missing_in_backend)}",
        )
        self.assertEqual(
            missing_in_frontend, set(),
            "capa.ir._capa_types.BUILTIN_CAPS has capabilities the "
            "checker does not accept (add them to "
            "capa.typesys.CAPABILITY_NAMES): "
            f"{sorted(missing_in_frontend)}",
        )

    def test_agda_cap_datatype_matches_the_builtin_capability_set(self):
        # The theorems in proofs/CapaSoundness.agda (Capability
        # Soundness, Manifest Completeness) quantify over the `Cap`
        # datatype. If the datatype is a strict subset of the
        # compiler's capabilities then the proofs are silently about
        # a smaller language than the one that ships, and the
        # artefact overclaims. If it is a superset the model names a
        # capability no program can hold.
        #
        # Every theorem is parametric in the capability tag, so
        # keeping these in step costs one constructor plus one
        # `singletonCS` diagonal line and no proof case.
        constructors = _agda_cap_constructors()
        missing_in_agda = BUILTIN_CAPS - constructors
        missing_in_compiler = constructors - BUILTIN_CAPS
        self.assertEqual(
            missing_in_agda, set(),
            "the Agda model in proofs/CapaSyntax.agda does not cover "
            "every built-in capability, so the soundness theorems "
            "quantify over a subset of the real language; add a "
            "constructor to `data Cap` (and its `singletonCS` "
            f"diagonal) for: {sorted(missing_in_agda)}",
        )
        self.assertEqual(
            missing_in_compiler, set(),
            "proofs/CapaSyntax.agda models capabilities the compiler "
            "does not have; remove them from `data Cap` or add them "
            "to capa.ir._capa_types.BUILTIN_CAPS: "
            f"{sorted(missing_in_compiler)}",
        )

    def test_agda_singleton_capset_has_a_diagonal_for_every_cap(self):
        # `singletonCS` ends in a catch-all `singletonCS _ _ = false`,
        # so a constructor added WITHOUT its diagonal line typechecks
        # clean under --safe and just quietly denotes the empty set
        # for that capability. Agda's coverage checker cannot help
        # here (verified: deleting the `Serve` diagonal still exits
        # 0), so this guard is the only thing standing between a new
        # capability and a wrong `caps-of`.
        constructors = _agda_cap_constructors()
        undiagonalised = constructors - _agda_singleton_diagonal()
        self.assertEqual(
            undiagonalised, set(),
            "`singletonCS` in proofs/CapaSyntax.agda falls through to "
            "the catch-all for these capabilities, so their singleton "
            "cap-set is silently empty; add `singletonCS X X = true` "
            f"above the catch-all for: {sorted(undiagonalised)}",
        )

    def test_every_agda_module_is_typechecked_by_the_agda_workflow(self):
        # An Agda module nobody runs `agda --safe` over is not a
        # proof, it is a text file. The `agda` workflow names each
        # module in an explicit step, so adding `proofs/Foo.agda`
        # without adding its step leaves the module UNCHECKED while
        # every job stays green -- exactly the silent-wrongness shape
        # the `singletonCS` guard above defends against, one level
        # up. Verified by mutation: deleting the CapaAttenuation step
        # from .github/workflows/agda.yml fails this test and nothing
        # else.
        if not _AGDA_WORKFLOW.is_file():
            raise AssertionError(
                f"the Agda CI workflow is missing from {_AGDA_WORKFLOW}; "
                "if it moved, update _AGDA_WORKFLOW in "
                "tests/test_cap_handles.py"
            )
        workflow = _AGDA_WORKFLOW.read_text(encoding="utf-8")
        checked = set(re.findall(r"agda --safe (\w+)\.agda", workflow))
        present = {p.stem for p in _PROOFS_DIR.glob("*.agda")}
        self.assertEqual(
            present - checked, set(),
            "these Agda modules in proofs/ have no `agda --safe` step "
            "in .github/workflows/agda.yml, so CI never typechecks "
            "them: "
            f"{sorted(present - checked)}",
        )
        self.assertEqual(
            checked - present, set(),
            ".github/workflows/agda.yml typechecks modules that do "
            "not exist in proofs/: "
            f"{sorted(checked - present)}",
        )

    def test_every_builtin_cap_is_classified_handle_bearing_or_erased(self):
        # Completeness guard: a new capability must be a deliberate
        # member of exactly one of the two Wasm-lowering classes. If
        # this fires, decide whether the cap carries an i32 handle
        # into the host cap table (attenuable, must survive function
        # boundaries) or is erased, then record it.
        unclassified = BUILTIN_CAPS - HANDLE_BEARING_CAPS - ERASED_CAPS
        self.assertEqual(
            unclassified, set(),
            "capabilities with no Wasm lowering class; add each to "
            "HANDLE_BEARING_CAPS or ERASED_CAPS in "
            f"capa/ir/_capa_types.py: {sorted(unclassified)}",
        )

    def test_handle_bearing_and_erased_are_disjoint_subsets(self):
        self.assertEqual(
            HANDLE_BEARING_CAPS & ERASED_CAPS, set(),
            "a capability cannot be both handle-bearing and erased",
        )
        stray = (HANDLE_BEARING_CAPS | ERASED_CAPS) - BUILTIN_CAPS
        self.assertEqual(
            stray, set(),
            "Wasm lowering classes name capabilities that are not "
            f"built-ins: {sorted(stray)}",
        )

    def test_host_root_handle_map_covers_every_handle_bearing_cap(self):
        # ``WasmHost._invoke_main`` maps each i32 slot of ``main`` to
        # a root handle by the CAP KIND the artifact declares for that
        # slot. A handle-bearing cap missing from that map would make
        # every program declaring it unrunnable.
        #
        # This asserts against ``root_handle_map`` itself, not
        # against ``bootstrap_root_handles``' output. The latter is a
        # strictly larger dict (it serves the erased caps too), so
        # checking it would pass for a cap that bootstrap supports
        # but the kind map omits - exactly the divergence this
        # guard exists to catch.
        roots = bootstrap_root_handles(
            CapHandleTable(),
            fs=Fs(), net=Net(), db=Db(), proc=Proc(),
            env=Env(), clock=Clock(), stdio=Stdio(),
        )
        kind_to_root = root_handle_map(roots)
        for cap in sorted(HANDLE_BEARING_CAPS):
            self.assertIn(
                cap.lower(), kind_to_root,
                f"{cap} bears a Wasm handle but WasmHost's cap-kind "
                "map has no entry for it, so a main declaring it "
                "could not be bound (see root_handle_map)",
            )
            self.assertNotEqual(
                kind_to_root[cap.lower()], 0,
                f"{cap} bears a Wasm handle but _invoke_main never "
                "bootstraps a root instance for it, so its slot would "
                "carry handle 0 (the 'no cap' sentinel)",
            )

    def test_lsp_offers_every_builtin_capability(self):
        # The completion floor listed seven of the nine caps until
        # 2026-07-18 (Proc and Db shipped without being added), so
        # the editor never suggested them.
        self.assertEqual(set(_BUILTIN_CAPABILITIES), set(CAPABILITY_NAMES))

    def test_wit_generator_knows_every_capability_except_python_only(self):
        # The ``PYTHON_ONLY_CAPS`` are deliberately absent from the WIT
        # generator's known set: the Wasm emitter rejects any signature
        # reaching them up front, so they can never get as far as WIT
        # generation. Every OTHER built-in must be known, or its
        # interface would be silently skipped and the host would be
        # asked for an import it was never told to provide.
        #
        # Derived from ``PYTHON_ONLY_CAPS`` rather than a hard-coded
        # ``{"Unsafe"}``: when ``Serve`` landed (2026-07) the literal
        # spelling made this guard fire for the right reason but with
        # the wrong remedy on offer ("teach WIT about Serve", when the
        # correct answer is "Serve never reaches WIT"). Deriving keeps
        # the exemption and its justification the same fact.
        self.assertEqual(
            set(_KNOWN_CAPABILITIES), set(BUILTIN_CAPS) - PYTHON_ONLY_CAPS,
        )

    def test_python_only_caps_are_a_subset_of_the_builtins(self):
        # A stale name here would silently exempt nothing while
        # reading as though it exempted something.
        stray = PYTHON_ONLY_CAPS - BUILTIN_CAPS
        self.assertEqual(
            stray, set(),
            "PYTHON_ONLY_CAPS names capabilities that are not "
            f"built-ins: {sorted(stray)}",
        )

    def test_python_only_caps_are_erased_on_the_wasm_side(self):
        # A cap the Wasm backend REJECTS must not also be declared
        # handle-bearing: that would claim a Wasm lowering for codegen
        # that never runs, and if the rejection ever developed a hole
        # the cap would occupy an i32 slot with no root-handle entry
        # and silently degrade to the Fs root. Erased fails loud
        # instead.
        misclassified = PYTHON_ONLY_CAPS & HANDLE_BEARING_CAPS
        self.assertEqual(
            misclassified, set(),
            "capabilities the Wasm backend rejects must be in "
            f"ERASED_CAPS, not HANDLE_BEARING_CAPS: "
            f"{sorted(misclassified)}",
        )


if __name__ == "__main__":
    unittest.main()
