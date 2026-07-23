"""``main``'s capability slots must be bound by DECLARED TYPE.

Until 2026-07-23 both Wasm hosts decided which root capability each of
``main``'s handle slots received by matching the parameter's NAME, and
fell back to the ``Fs`` root when the name was not one of ``fs`` /
``net`` / ``db`` / ``proc`` / ``env`` / ``clock``. Three measured
consequences, every one of them exiting 0:

1. ``fun main(conn: Net, stdio: Stdio)`` calling
   ``conn.allows("example.com")`` printed ``true`` on the Python
   backend and ``false`` on ``--wasm``: the same source answering a
   security question two different ways.
2. ``fun main(net: Fs, ...)`` got the ``Net`` root because of how the
   parameter was SPELLED; the mismatch surfaced as an ordinary ``Err``
   a program could swallow.
3. ``wasm-tools strip --all`` removes the debug ``name`` section the
   core host read those names from, after which every slot fell to the
   ``Fs`` root. A routine release step changed program behaviour.

The whole targeted capability suite passed throughout, because not one
of its tests varied the parameter name away from the capability's own
lowercase spelling. That is what this module exists to stop.

Every backend-touching import is INSIDE the test method it serves: a
module-level ``import wasmtime`` would break the plain ``python -m
unittest discover tests`` job that has no wasm extra installed, while
staying green under a local pytest.
"""

from __future__ import annotations

import ast
import inspect
import io
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

from capa import Lexer, Parser, analyze, transpile
from capa.ir import compile_wasm, lower
from capa.ir._capa_types import HANDLE_BEARING_CAPS
from capa.ir._cap_binding import (
    CAP_KINDS,
    MAIN_CAP_TYPES_EXPORT_PREFIX,
    CapBindingError,
    main_cap_types_export_name,
    main_handle_cap_types,
    parse_main_cap_types_export_name,
    parse_wit_cap_slot_name,
    resolve_cap_types,
    wit_cap_slot_name,
)
from capa.runtime._cap_handles import (
    CapHandleTable,
    bootstrap_root_handles,
    root_handle_map,
)


def _has_wasmtime() -> bool:
    try:
        import wasmtime  # noqa: F401
        return True
    except ImportError:
        return False


def _has_wasm_tools() -> bool:
    return shutil.which("wasm-tools") is not None


def _parse_and_analyze(src: str):
    tokens = Lexer(src).lex()
    module = Parser(tokens, source=src).parse_module()
    result = analyze(module, source=src)
    if not result.ok:  # pragma: no cover - a broken fixture, not a finding
        raise AssertionError(f"analyzer errors: {result.errors}")
    return module, result


def _capture_stdout(thunk) -> str:
    buf = io.StringIO()
    saved = sys.stdout
    sys.stdout = buf
    try:
        thunk()
    finally:
        sys.stdout = saved
    return buf.getvalue()


def _run_python(src: str) -> None:
    module, result = _parse_and_analyze(src)
    code = transpile(module, types=result.types, bindings=result.bindings)
    ns: dict = {"__name__": "__main__"}
    exec(compile(code, "<cap-binding>", "exec"), ns)


def _wasm_blob(src: str) -> bytes:
    module, result = _parse_and_analyze(src)
    return compile_wasm(module, types=result.types)


def _run_wasm(src: str) -> None:
    from capa.runtime._wasm_host import WasmHost
    WasmHost().run_main(_wasm_blob(src))


def _run_wasm_component(src: str) -> None:
    from capa.cli import _wrap_as_component
    from capa.ir import compile_wit
    from capa.runtime._wasm_component_host import WasmComponentHost
    module, result = _parse_and_analyze(src)
    core_blob = compile_wasm(module, types=result.types)
    wit = compile_wit(module, types=result.types)
    WasmComponentHost().run_main(_wrap_as_component(core_blob, wit))


# One program per handle-bearing capability, each declaring its cap
# under a parameter name that is NOT the capability's own lowercase
# spelling. Five of the six borrow ANOTHER handle-bearing cap's
# spelling, which is the sharper shape: a name-matching host resolves
# them confidently to the wrong authority rather than falling through
# to the default. ``Net`` uses ``conn``, the name from the original
# report, which matches nothing at all.
#
# Every probe is ``allows(...)`` on an unrestricted root, so the
# Python backend answers ``true`` for all six. A slot bound to the
# wrong root fails the host's typed handle lookup and answers
# ``false``, so a name-driven binding is visible as a parity break
# rather than as a crash.
_MISNAMED_PROGRAMS: dict[str, str] = {
    "fs": (
        'fun main(net: Fs, stdio: Stdio)\n'
        '    stdio.println("allows=${net.allows("/tmp")}")\n'
    ),
    "net": (
        'fun main(conn: Net, stdio: Stdio)\n'
        '    stdio.println("allows=${conn.allows("example.com")}")\n'
    ),
    "db": (
        'fun main(fs: Db, stdio: Stdio)\n'
        '    stdio.println("allows=${fs.allows("/tmp/x.db")}")\n'
    ),
    "proc": (
        'fun main(env: Proc, stdio: Stdio)\n'
        '    stdio.println("allows=${env.allows("echo")}")\n'
    ),
    "env": (
        'fun main(clock: Env, stdio: Stdio)\n'
        '    stdio.println("allows=${clock.allows("PATH")}")\n'
    ),
    "clock": (
        'fun main(db: Clock, stdio: Stdio)\n'
        '    stdio.println("allows=${db.allows()}")\n'
    ),
}


# The same six probes with the parameter named after its OWN
# capability. These passed on both backends throughout the defect,
# which is exactly why the capability suite missed it: they are only
# diagnostic once the debug ``name`` section is stripped away, at
# which point the old host lost the names it was matching on and sent
# every slot to the Fs root.
_CANONICAL_PROGRAMS: dict[str, str] = {
    "fs": (
        'fun main(fs: Fs, stdio: Stdio)\n'
        '    stdio.println("allows=${fs.allows("/tmp")}")\n'
    ),
    "net": (
        'fun main(net: Net, stdio: Stdio)\n'
        '    stdio.println("allows=${net.allows("example.com")}")\n'
    ),
    "db": (
        'fun main(db: Db, stdio: Stdio)\n'
        '    stdio.println("allows=${db.allows("/tmp/x.db")}")\n'
    ),
    "proc": (
        'fun main(proc: Proc, stdio: Stdio)\n'
        '    stdio.println("allows=${proc.allows("echo")}")\n'
    ),
    "env": (
        'fun main(env: Env, stdio: Stdio)\n'
        '    stdio.println("allows=${env.allows("PATH")}")\n'
    ),
    "clock": (
        'fun main(clock: Clock, stdio: Stdio)\n'
        '    stdio.println("allows=${clock.allows()}")\n'
    ),
}


# Every probe above, keyed so a subTest failure names the shape.
_ALL_PROBES: dict[str, str] = {
    **{f"{k}/misnamed": v for k, v in _MISNAMED_PROGRAMS.items()},
    **{f"{k}/canonical": v for k, v in _CANONICAL_PROGRAMS.items()},
}


# Two slots whose names are each other's capability: a host that binds
# by name hands the Net slot the Fs root and the Fs slot the Net root,
# a clean swap that no single-slot program can catch.
_SWAPPED_NAMES = (
    'fun main(fs: Net, net: Fs, stdio: Stdio)\n'
    '    stdio.println("net=${fs.allows("example.com")} '
    'fs=${net.allows("/tmp")}")\n'
)


class TestCapBindingEncoding(unittest.TestCase):
    """The wire format and its inverse. No backend needed."""

    def test_export_name_round_trips(self):
        for kinds in ([], ["fs"], ["net", "fs"], sorted(CAP_KINDS)):
            name = main_cap_types_export_name(kinds)
            self.assertTrue(name.startswith(MAIN_CAP_TYPES_EXPORT_PREFIX))
            self.assertEqual(parse_main_cap_types_export_name(name), kinds)

    def test_non_binding_export_name_parses_to_none(self):
        # ``None`` (not ``[]``) so a module carrying no binding is
        # distinguishable from one that declares zero cap slots.
        for name in ("memory", "main", "alloc", "capa:main-cap-type=fs"):
            self.assertIsNone(parse_main_cap_types_export_name(name))
        self.assertEqual(
            parse_main_cap_types_export_name(MAIN_CAP_TYPES_EXPORT_PREFIX),
            [],
        )

    def test_wit_slot_labels_round_trip(self):
        for i, cap in enumerate(sorted(HANDLE_BEARING_CAPS)):
            label = wit_cap_slot_name(i, cap)
            self.assertEqual(parse_wit_cap_slot_name(label), (i, cap.lower()))

    def test_wit_slot_label_is_never_a_bare_cap_kind(self):
        # The old labels WERE bare kinds (``fs`` / ``net`` / ...), and a
        # host could not tell a label it had emitted from a source
        # parameter that happened to be spelled the same. Keeping the
        # two namespaces disjoint is what makes the refusal in
        # ``_read_component_cap_types`` unambiguous.
        for i, cap in enumerate(sorted(HANDLE_BEARING_CAPS)):
            self.assertNotIn(wit_cap_slot_name(i, cap), CAP_KINDS)

    def test_labels_that_are_not_slot_labels_parse_to_none(self):
        for label in ("fs", "net", "my-fs", "cap-fs", "capx0-fs", ""):
            self.assertIsNone(parse_wit_cap_slot_name(label))

    def test_main_handle_cap_types_reads_declared_types_in_order(self):
        module, result = _parse_and_analyze(_SWAPPED_NAMES)
        ir_mod = lower(module, types=result.types)
        # Declared ``(fs: Net, net: Fs, stdio: Stdio)``: the binding
        # follows the TYPES, in order, with the erased Stdio dropped.
        self.assertEqual(main_handle_cap_types(ir_mod), ["net", "fs"])


class TestResolveCapTypesGrantsNothing(unittest.TestCase):
    """R3 / T3: an unresolvable binding fails loudly, and the failure
    happens before any handle could be handed out."""

    def test_missing_binding_is_refused_with_a_rebuild_hint(self):
        with self.assertRaises(CapBindingError) as ctx:
            resolve_cap_types(None, 1, artifact="module")
        msg = str(ctx.exception)
        self.assertIn(MAIN_CAP_TYPES_EXPORT_PREFIX, msg)
        self.assertIn("rebuild", msg)
        self.assertIn("1.19.0", msg)

    def test_arity_disagreement_is_refused(self):
        for declared, slots in (([], 1), (["fs"], 0), (["fs"], 2)):
            with self.subTest(declared=declared, slots=slots):
                with self.assertRaises(CapBindingError) as ctx:
                    resolve_cap_types(declared, slots, artifact="module")
                self.assertIn("no capability", str(ctx.exception).lower())

    def test_unknown_kind_is_refused(self):
        with self.assertRaises(CapBindingError) as ctx:
            resolve_cap_types(["stdio"], 1, artifact="module")
        self.assertIn("unknown capability", str(ctx.exception))

    def test_a_usable_binding_passes_through_unchanged(self):
        self.assertEqual(
            resolve_cap_types(["net", "fs"], 2, artifact="module"),
            ["net", "fs"],
        )
        self.assertEqual(resolve_cap_types([], 0, artifact="module"), [])

    def test_root_map_refuses_rather_than_defaulting(self):
        # R3 has a second face: even with a well-formed binding, a cap
        # whose root the host failed to bootstrap must raise, not hand
        # the slot the ``0`` sentinel and let it fail later (or not at
        # all, for the ops that do not check).
        full = bootstrap_root_handles(
            CapHandleTable(),
            fs=None, net=None, db=None, proc=None,
            env=None, clock=None, stdio=None,
        )
        self.assertEqual(full, {})
        with self.assertRaises(CapBindingError) as ctx:
            root_handle_map(full)
        self.assertIn("no capability is granted", str(ctx.exception))


class TestComponentSlotLabelDecoding(unittest.TestCase):
    """R5 / T3 on the Component path. ``_read_component_cap_types``
    takes a plain ``(label, valtype)`` sequence, so it is testable
    without wasmtime."""

    def _decode(self, labels):
        from capa.runtime._wasm_component_host import (
            _read_component_cap_types,
        )
        return _read_component_cap_types([(lbl, None) for lbl in labels])

    @unittest.skipUnless(_has_wasmtime(), "wasmtime-py not installed")
    def test_slot_labels_decode_to_kinds(self):
        self.assertEqual(self._decode(["cap0-net", "cap1-fs"]), ["net", "fs"])
        self.assertEqual(self._decode([]), [])

    @unittest.skipUnless(_has_wasmtime(), "wasmtime-py not installed")
    def test_legacy_bare_kind_labels_are_refused(self):
        # A component built by 1.19.0 or earlier labels its slots
        # ``fs`` / ``net`` / ... Accepting those as a compatibility
        # mode would reinstate exactly the name matching this change
        # removes, so they are refused.
        with self.assertRaises(CapBindingError) as ctx:
            self._decode(["net"])
        self.assertIn("rebuild", str(ctx.exception))

    @unittest.skipUnless(_has_wasmtime(), "wasmtime-py not installed")
    def test_out_of_order_slot_index_is_refused(self):
        with self.assertRaises(CapBindingError) as ctx:
            self._decode(["cap1-net"])
        self.assertIn("claims slot 1", str(ctx.exception))

    @unittest.skipUnless(_has_wasmtime(), "wasmtime-py not installed")
    def test_unknown_kind_in_a_slot_label_is_refused(self):
        with self.assertRaises(CapBindingError) as ctx:
            self._decode(["cap0-stdio"])
        self.assertIn("unknown", str(ctx.exception))


@unittest.skipUnless(_has_wasmtime(), "wasmtime-py not installed")
class TestCoreHostBinding(unittest.TestCase):
    """R1 / R2 / R4 against real modules under ``WasmHost``."""

    def _binding_of(self, src: str):
        from capa.runtime._wasm_host import _read_main_cap_types
        return _read_main_cap_types(_wasm_blob(src))

    def test_emitted_binding_follows_declared_types_not_names(self):
        self.assertEqual(self._binding_of(_SWAPPED_NAMES), ["net", "fs"])
        for kind, src in _MISNAMED_PROGRAMS.items():
            with self.subTest(kind=kind):
                self.assertEqual(self._binding_of(src), [kind])

    def test_every_module_carries_a_binding_even_with_no_cap_slots(self):
        # A missing export means "older toolchain, refuse", so the
        # empty binding has to be spelled out rather than left implicit.
        self.assertEqual(
            self._binding_of(
                'fun main(stdio: Stdio)\n    stdio.println("hi")\n'
            ),
            [],
        )
        self.assertEqual(self._binding_of("fun main()\n    let _x = 1\n"), [])

    def test_binding_lives_in_the_export_section_not_a_custom_section(self):
        # R2 plus the linear-memory constraint: the binding must sit
        # where neither a strip nor the running program can reach it.
        # Section id 7 is the export section; id 0 is the custom
        # section family (``name``, the capa manifest, ...), and id 11
        # is the data section that populates linear memory.
        blob = _wasm_blob(_MISNAMED_PROGRAMS["net"])
        needle = main_cap_types_export_name(["net"]).encode("utf-8")
        self.assertIn(needle, blob)
        self.assertEqual(
            _sections_containing(blob, needle), {7},
            "the capability binding must appear ONLY in the export "
            "section: a custom section is strippable and a data "
            "section is writable linear memory",
        )

    def test_absent_binding_export_is_refused_not_defaulted(self):
        # Simulates a 1.19.0 artifact by renaming the binding export in
        # place (same length, so the module stays structurally valid).
        # The host must refuse rather than fall back to name matching.
        from capa.runtime._wasm_host import WasmHost
        blob = bytearray(_wasm_blob(_MISNAMED_PROGRAMS["net"]))
        _rename_binding_export(blob)
        with self.assertRaises(CapBindingError) as ctx:
            WasmHost().run_main(bytes(blob))
        msg = str(ctx.exception)
        self.assertIn("rebuild", msg)
        self.assertIn("1.19.0", msg)

    def test_unknown_kind_in_the_binding_is_refused(self):
        from capa.runtime._wasm_host import WasmHost
        blob = bytearray(_wasm_blob(_MISNAMED_PROGRAMS["net"]))
        _retype_binding_export(blob, b"net", b"xyz")
        with self.assertRaises(CapBindingError) as ctx:
            WasmHost().run_main(bytes(blob))
        self.assertIn("unknown capability", str(ctx.exception))

    @unittest.skipUnless(_has_wasm_tools(), "wasm-tools not installed")
    def test_two_binding_exports_are_refused(self):
        # A post-processing step could PREPEND a more generous binding
        # and, with a first-match reader, have it win. The reader scans
        # the whole export list and refuses an ambiguous module.
        from capa.runtime._wasm_host import _read_main_cap_types
        wat = (
            "(module\n"
            "  (global $g i32 (i32.const 1))\n"
            f'  (export "{main_cap_types_export_name(["fs"])}" '
            "(global $g))\n"
            f'  (export "{main_cap_types_export_name(["net"])}" '
            "(global $g))\n"
            ")\n"
        )
        proc = subprocess.run(
            ["wasm-tools", "parse", "-"],
            input=wat.encode("utf-8"), capture_output=True,
        )
        self.assertEqual(
            proc.returncode, 0,
            proc.stderr.decode("utf-8", errors="replace"),
        )
        with self.assertRaises(CapBindingError) as ctx:
            _read_main_cap_types(proc.stdout)
        self.assertIn("2 times", str(ctx.exception))

    def test_no_handle_is_granted_when_the_binding_is_unusable(self):
        # T3's "grants nothing" half, and T4's guard against a future
        # default: whatever shape the failure takes, ``main`` must
        # never be entered. A stub records any call.
        from capa.runtime._wasm_host import WasmHost

        class _RecordingMain:
            def __init__(self):
                self.calls = []

            def __call__(self, *args):
                self.calls.append(args)

        for cap_types in (None, [], ["fs", "net"], ["stdio"], ["nope"]):
            with self.subTest(cap_types=cap_types):
                host = WasmHost()
                main = _RecordingMain()
                with self.assertRaises(CapBindingError):
                    host._invoke_main(
                        main, 1, cap_types, artifact="module",
                    )
                self.assertEqual(
                    main.calls, [],
                    "main was invoked despite an unusable capability "
                    "binding, so the guest received a handle it was "
                    "never entitled to",
                )


@unittest.skipUnless(_has_wasmtime(), "wasmtime-py not installed")
class TestClockQueriesRequireAClockHandle(unittest.TestCase):
    """R6. ``now_secs`` / ``now_monotonic`` looked their receiver up and
    DISCARDED the result, while their comment claimed a bogus handle
    "surfaces here rather than silently returning a real clock
    reading". The guard the comment described did not exist: the
    lookup helper swallowed the error and returned ``None``, which
    nothing then read.

    Driven by rewriting a real module's binding so the ``Clock`` slot
    receives the ``Fs`` root, which is exactly the substitution the
    name-matching binding used to perform by accident."""

    _SRC = (
        'fun main(clock: Clock, fs: Fs, stdio: Stdio)\n'
        '    let ok = fs.allows("/tmp")\n'
        '    let t = clock.now_secs()\n'
        '    stdio.println("positive=${t > 0.0} fs=${ok}")\n'
    )

    def test_an_honest_binding_still_reads_the_clock(self):
        from capa.runtime._wasm_host import WasmHost
        blob = _wasm_blob(self._SRC)
        out = _capture_stdout(lambda: WasmHost().run_main(blob))
        self.assertEqual(out, "positive=true fs=true\n")

    def test_a_non_clock_receiver_traps_instead_of_reading_the_clock(self):
        from capa.runtime._cap_handles import CapHandleError
        from capa.runtime._wasm_host import WasmHost
        blob = bytearray(_wasm_blob(self._SRC))
        _retype_binding_export(blob, b"clock,fs", b"fs,clock")
        with self.assertRaises(CapHandleError) as ctx:
            _capture_stdout(lambda: WasmHost().run_main(bytes(blob)))
        self.assertIn("invalid Clock capability handle", str(ctx.exception))


@unittest.skipUnless(
    _has_wasmtime() and _has_wasm_tools(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestBindingSurvivesStripping(unittest.TestCase):
    """R2 / T2: ``wasm-tools strip --all`` is a routine release step.
    It removes the debug ``name`` section the old host read parameter
    names from, which is why stripping used to change behaviour."""

    def _strip(self, blob: bytes) -> bytes:
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "m.wasm"
            dst = Path(td) / "m.stripped.wasm"
            src.write_bytes(blob)
            proc = subprocess.run(
                ["wasm-tools", "strip", "--all", "-o", str(dst), str(src)],
                capture_output=True,
            )
            self.assertEqual(
                proc.returncode, 0,
                proc.stderr.decode("utf-8", errors="replace"),
            )
            return dst.read_bytes()

    def test_strip_removes_the_name_section_it_used_to_depend_on(self):
        # Establishes that the strip really is destructive, so the
        # survival assertions below are not vacuous.
        blob = _wasm_blob(_MISNAMED_PROGRAMS["net"])
        self.assertIn(b"conn", blob)
        self.assertNotIn(b"conn", self._strip(blob))

    def test_stripped_module_binds_the_same_capabilities(self):
        from capa.runtime._wasm_host import _read_main_cap_types
        for kind, src in _ALL_PROBES.items():
            with self.subTest(kind=kind):
                blob = _wasm_blob(src)
                self.assertEqual(
                    _read_main_cap_types(self._strip(blob)),
                    _read_main_cap_types(blob),
                )

    def test_stripped_module_produces_identical_output(self):
        # Defect consequence 3: ``wasm-tools strip --all`` used to
        # change what a program did. The canonical probes are the
        # sharpest witnesses -- they were CORRECT before the strip and
        # wrong after it, so a release step silently rewrote them.
        from capa.runtime._wasm_host import WasmHost
        for kind, src in _ALL_PROBES.items():
            with self.subTest(kind=kind):
                blob = _wasm_blob(src)
                stripped = self._strip(blob)
                before = _capture_stdout(lambda: WasmHost().run_main(blob))
                after = _capture_stdout(
                    lambda: WasmHost().run_main(stripped)
                )
                self.assertEqual(before, after)
                self.assertEqual(after, "allows=true\n")


@unittest.skipUnless(_has_wasmtime(), "wasmtime-py not installed")
class TestMisnamedCapParamParityCore(unittest.TestCase):
    """T1 on the core host: for EVERY handle-bearing capability, a
    parameter named something other than the capability's own
    lowercase spelling must behave identically on both backends."""

    def _assert_parity(self, src: str, expected: str) -> None:
        py_out = _capture_stdout(lambda: _run_python(src))
        wasm_out = _capture_stdout(lambda: _run_wasm(src))
        self.assertEqual(
            py_out, wasm_out,
            f"Python/Wasm divergence on a misnamed cap parameter:\n"
            f"--- source ---\n{src}"
            f"--- python ---\n{py_out}"
            f"--- wasm ---\n{wasm_out}",
        )
        self.assertEqual(wasm_out, expected)

    def test_every_handle_bearing_cap_under_a_foreign_param_name(self):
        self.assertEqual(
            set(_MISNAMED_PROGRAMS), {c.lower() for c in HANDLE_BEARING_CAPS},
            "a capability gained a Wasm handle without gaining a "
            "misnamed-parameter parity probe",
        )
        for kind, src in _MISNAMED_PROGRAMS.items():
            with self.subTest(cap=kind):
                self._assert_parity(src, "allows=true\n")

    def test_two_slots_named_after_each_others_capability(self):
        self._assert_parity(_SWAPPED_NAMES, "net=true fs=true\n")


@unittest.skipUnless(
    _has_wasmtime() and _has_wasm_tools(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestMisnamedCapParamParityComponent(unittest.TestCase):
    """T1 on the Component Model host (R5). The Component path binds
    from the WIT slot labels rather than the export name, so it needs
    its own coverage of the same shapes."""

    def _assert_parity(self, src: str, expected: str) -> None:
        py_out = _capture_stdout(lambda: _run_python(src))
        cm_out = _capture_stdout(lambda: _run_wasm_component(src))
        self.assertEqual(
            py_out, cm_out,
            f"Python/Wasm-Component divergence on a misnamed cap "
            f"parameter:\n--- source ---\n{src}"
            f"--- python ---\n{py_out}"
            f"--- wasm-component ---\n{cm_out}",
        )
        self.assertEqual(cm_out, expected)

    def test_every_handle_bearing_cap_under_a_foreign_param_name(self):
        for kind, src in _MISNAMED_PROGRAMS.items():
            with self.subTest(cap=kind):
                self._assert_parity(src, "allows=true\n")

    def test_two_slots_named_after_each_others_capability(self):
        self._assert_parity(_SWAPPED_NAMES, "net=true fs=true\n")

    def test_wit_world_labels_slots_by_type_not_by_source_name(self):
        from capa.ir import compile_wit
        module, result = _parse_and_analyze(_SWAPPED_NAMES)
        wit = compile_wit(module, types=result.types)
        self.assertIn("export main: func(cap0-net: u32, cap1-fs: u32);", wit)


class TestNoDefaultCapabilityPath(unittest.TestCase):
    """T4: a future change must not be able to reintroduce a
    "when in doubt, hand out capability X" branch.

    The behavioural half lives in
    :class:`TestCoreHostBinding.test_no_handle_is_granted_when_the_binding_is_unusable`
    and :class:`TestResolveCapTypesGrantsNothing`. This is the
    structural half: the defect was literally
    ``name_to_root.get(name, roots.get("fs", 0))``, a dict lookup with
    a fallback default, so the binding code is not allowed to contain
    a defaulted lookup at all."""

    # (module path, qualified name) of every function that decides,
    # or feeds the decision of, which authority a slot receives.
    _BINDING_FUNCTIONS = [
        ("capa.ir._cap_binding", "resolve_cap_types"),
        ("capa.ir._cap_binding", "parse_main_cap_types_export_name"),
        ("capa.ir._cap_binding", "parse_wit_cap_slot_name"),
        ("capa.ir._cap_binding", "main_handle_cap_types"),
        ("capa.runtime._cap_handles", "root_handle_map"),
        ("capa.runtime._wasm_host", "_read_main_cap_types"),
        ("capa.runtime._wasm_host", "WasmHost.run_main"),
        ("capa.runtime._wasm_host", "WasmHost.run_main_aot"),
        ("capa.runtime._wasm_host", "WasmHost._invoke_main"),
        ("capa.runtime._wasm_component_host", "_read_component_cap_types"),
        ("capa.runtime._wasm_component_host", "WasmComponentHost.run_main"),
        ("capa.runtime._aot", "aot_main_cap_types"),
    ]

    # The two ``run_main`` dispatchers are exempt from the cap-kind
    # LITERAL guard below (not from the defaulted-lookup guard). The
    # Component host names ``env`` / ``fs`` / ``net`` explicitly to
    # override their handles with the ``0`` sentinel under ``--wasi``,
    # where those caps are served by wasi:* interfaces rather than the
    # handle table. Those literals REMOVE authority; the guard is about
    # literals that grant it.
    _CAP_LITERAL_EXEMPT = {
        ("capa.runtime._wasm_component_host", "WasmComponentHost.run_main"),
    }

    def _source_of(self, module_name: str, qualname: str) -> str:
        import importlib
        obj = importlib.import_module(module_name)
        for part in qualname.split("."):
            obj = getattr(obj, part)
        return textwrap.dedent(inspect.getsource(obj))

    def _binding_functions(self):
        for module_name, qualname in self._BINDING_FUNCTIONS:
            if "_wasm" in module_name and not _has_wasmtime():
                continue
            yield module_name, qualname

    def test_no_binding_function_looks_up_a_slot_with_a_default(self):
        for module_name, qualname in self._binding_functions():
            with self.subTest(function=f"{module_name}.{qualname}"):
                src = self._source_of(module_name, qualname)
                for node in ast.walk(ast.parse(src)):
                    if not isinstance(node, ast.Call):
                        continue
                    func = node.func
                    if not isinstance(func, ast.Attribute):
                        continue
                    if func.attr != "get" or len(node.args) < 2:
                        continue
                    self.fail(
                        f"{module_name}.{qualname} performs a defaulted "
                        f"dict lookup (`.get(x, default)`) on line "
                        f"{node.lineno} of its source. The capability "
                        f"binding must never substitute a default: the "
                        f"original defect was exactly "
                        f"`name_to_root.get(name, roots.get('fs', 0))`."
                    )

    def test_the_name_section_reader_is_gone(self):
        # Not merely unused: present-but-unused code is one call site
        # away from being the binding again.
        if not _has_wasmtime():
            self.skipTest("wasmtime-py not installed")
        from capa.runtime import _wasm_host
        self.assertFalse(
            hasattr(_wasm_host, "_read_main_param_names"),
            "the debug-name-section parameter reader is back; binding "
            "capabilities by a strippable name is the defect",
        )

    def test_no_cap_kind_is_hardcoded_in_the_binding_functions(self):
        # A literal ``"fs"`` inside a binding function is how the
        # fallback was spelled. The kinds must come from the registry.
        for module_name, qualname in self._binding_functions():
            if (module_name, qualname) in self._CAP_LITERAL_EXEMPT:
                continue
            with self.subTest(function=f"{module_name}.{qualname}"):
                src = self._source_of(module_name, qualname)
                for node in ast.walk(ast.parse(src)):
                    if not isinstance(node, ast.Constant):
                        continue
                    if not isinstance(node.value, str):
                        continue
                    self.assertNotIn(
                        node.value, CAP_KINDS,
                        f"{module_name}.{qualname} mentions the "
                        f"capability kind {node.value!r} literally; "
                        f"binding decisions must be driven by the "
                        f"artifact's declaration and the capability "
                        f"registry, never by a hardcoded cap name",
                    )


# ---- blob surgery helpers ---------------------------------------
#
# These edit a real ``.wasm`` in place to manufacture the artifacts a
# test needs: a module with no binding, and a module whose binding
# names a capability that does not exist. Both edits keep the export
# NAME's byte length unchanged, so no length prefix and no section
# size has to be re-encoded and the module stays valid.


def _binding_export_offset(blob: bytes) -> int:
    """Byte offset of the binding export's name inside ``blob``."""
    needle = MAIN_CAP_TYPES_EXPORT_PREFIX.encode("utf-8")
    off = blob.find(needle)
    if off < 0:  # pragma: no cover - a broken emitter, not a finding
        raise AssertionError("module carries no capability binding export")
    return off


def _rename_binding_export(blob: bytearray) -> None:
    """Turn the binding export into an unrelated export of the same
    name length, producing the artifact shape a pre-1.20 toolchain
    emitted: from the host's point of view, no binding at all."""
    off = _binding_export_offset(blob)
    prefix_len = len(MAIN_CAP_TYPES_EXPORT_PREFIX)
    blob[off:off + prefix_len] = b"z" * prefix_len


def _retype_binding_export(
    blob: bytearray, old_kinds: bytes, new_kinds: bytes,
) -> None:
    """Rewrite the declared kind list in place. ``new_kinds`` must be
    the same length as ``old_kinds`` (see the module note above)."""
    assert len(old_kinds) == len(new_kinds)
    off = _binding_export_offset(blob)
    at = off + len(MAIN_CAP_TYPES_EXPORT_PREFIX)
    assert bytes(blob[at:at + len(old_kinds)]) == old_kinds
    blob[at:at + len(new_kinds)] = new_kinds


def _read_uleb128(buf: bytes, off: int) -> tuple[int, int]:
    val = 0
    shift = 0
    while True:
        b = buf[off]
        off += 1
        val |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            return val, off
        shift += 7


def _sections_containing(blob: bytes, needle: bytes) -> set[int]:
    """The ids of every top-level section whose payload contains
    ``needle``. Used to prove the binding lives ONLY in the export
    section (id 7): not in a strippable custom section (id 0), and not
    in the data section (id 11) that initialises linear memory."""
    found: set[int] = set()
    off = 8
    while off < len(blob):
        section_id = blob[off]
        off += 1
        size, off = _read_uleb128(blob, off)
        if needle in blob[off:off + size]:
            found.add(section_id)
        off += size
    return found
