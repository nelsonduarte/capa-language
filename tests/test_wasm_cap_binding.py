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
import unittest.mock
from pathlib import Path

from capa import Lexer, Parser, analyze, transpile
from capa.ir import compile_wasm, lower
from capa.ir._capa_types import HANDLE_BEARING_CAPS
from capa.ir._cap_binding import (
    CAP_KINDS,
    CARRIER_AOT_HEADER,
    CARRIER_WASM_EXPORT,
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
            resolve_cap_types(
                None, 1, artifact="module", carrier=CARRIER_WASM_EXPORT,
            )
        msg = str(ctx.exception)
        self.assertIn(MAIN_CAP_TYPES_EXPORT_PREFIX, msg)
        self.assertIn("rebuild", msg)

    def test_the_carrier_named_matches_the_artifact(self):
        # The AOT container is a JSON header with no sections at all,
        # so telling its operator that a `capa:main-cap-types=` EXPORT
        # is missing sends them looking for something the format
        # cannot have.
        with self.assertRaises(CapBindingError) as ctx:
            resolve_cap_types(
                None, 1, artifact="AOT artifact",
                carrier=CARRIER_AOT_HEADER,
            )
        msg = str(ctx.exception)
        self.assertIn("container header", msg)
        self.assertNotIn(MAIN_CAP_TYPES_EXPORT_PREFIX, msg)

    def test_no_refusal_blames_the_running_toolchain_version(self):
        # `capa --version` IS 1.19.0 on a development build that has
        # the binding, so a message saying "artifacts built by 1.19.0
        # or earlier carry no binding" tells half its readers that the
        # version they are running is the broken one. The message
        # anchors on the RELEASE instead.
        import capa
        for kwargs in (
            {"cap_types": None, "n_slots": 1},
            {"cap_types": ["fs"], "n_slots": 2},
            {"cap_types": ["nope"], "n_slots": 1},
        ):
            with self.subTest(**kwargs):
                with self.assertRaises(CapBindingError) as ctx:
                    resolve_cap_types(
                        kwargs["cap_types"], kwargs["n_slots"],
                        artifact="module", carrier=CARRIER_WASM_EXPORT,
                    )
                msg = str(ctx.exception)
                self.assertNotIn(
                    f"built by Capa {capa.__version__}", msg,
                    "the refusal names the running toolchain as the "
                    "broken one",
                )

    def test_arity_disagreement_is_refused(self):
        for declared, slots in (([], 1), (["fs"], 0), (["fs"], 2)):
            with self.subTest(declared=declared, slots=slots):
                with self.assertRaises(CapBindingError) as ctx:
                    resolve_cap_types(
                        declared, slots, artifact="module",
                        carrier=CARRIER_WASM_EXPORT,
                    )
                self.assertIn("no capability", str(ctx.exception).lower())

    def test_unknown_kind_is_refused(self):
        with self.assertRaises(CapBindingError) as ctx:
            resolve_cap_types(
                ["stdio"], 1, artifact="module",
                carrier=CARRIER_WASM_EXPORT,
            )
        self.assertIn("unknown capability", str(ctx.exception))

    def test_a_usable_binding_passes_through_unchanged(self):
        self.assertEqual(
            resolve_cap_types(
                ["net", "fs"], 2, artifact="module",
                carrier=CARRIER_WASM_EXPORT,
            ),
            ["net", "fs"],
        )
        self.assertEqual(
            resolve_cap_types(
                [], 0, artifact="module", carrier=CARRIER_WASM_EXPORT,
            ),
            [],
        )

    def test_root_map_refuses_rather_than_defaulting(self):
        # R3 has a second face: even with a well-formed binding, a cap
        # whose root the host failed to bootstrap must raise, not hand
        # the slot the ``0`` sentinel and let it fail later (or not at
        # all, for the ops that do not check).
        full = bootstrap_root_handles(
            CapHandleTable(),
            declared=["fs"],
            fs=None, net=None, db=None, proc=None,
            env=None, clock=None, stdio=None,
        )
        self.assertEqual(full, {})
        with self.assertRaises(CapBindingError) as ctx:
            # A DECLARED cap whose root was never bootstrapped must raise
            # rather than default to the ``0`` sentinel.
            root_handle_map(full, ["fs"])
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
        # A component built before this change labels its slots
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
        # Simulates a pre-binding artifact by renaming the binding
        # export in place (same length, so the module stays
        # structurally valid). The host must refuse rather than fall
        # back to name matching.
        from capa.runtime._wasm_host import WasmHost
        blob = bytearray(_wasm_blob(_MISNAMED_PROGRAMS["net"]))
        _rename_binding_export(blob)
        with self.assertRaises(CapBindingError) as ctx:
            WasmHost().run_main(bytes(blob))
        msg = str(ctx.exception)
        self.assertIn("rebuild", msg)
        self.assertIn(MAIN_CAP_TYPES_EXPORT_PREFIX, msg)

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

    @unittest.skipUnless(_has_wasm_tools(), "wasm-tools not installed")
    def test_guest_code_does_not_run_before_the_refusal(self):
        # "Grants nothing" has to mean "runs nothing". The binding used
        # to be read AFTER ``instantiate``, which executes the module's
        # ``start`` function and its active data-segment initialisers,
        # so a bindingless module got to do whatever it liked and was
        # only then refused.
        #
        # The ``start`` here TRAPS, which makes "the module executed"
        # and "the module was refused" two distinguishable outcomes
        # without a timing assertion.
        from capa.runtime._wasm_host import WasmHost
        wat = (
            "(module\n"
            "  (global $g i32 (i32.const 1))\n"
            f'  (export "{main_cap_types_export_name(["fs"])}" '
            "(global $g))\n"
            '  (func $main (export "main") (param i32))\n'
            "  (func $boom unreachable)\n"
            "  (start $boom)\n"
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
        blob = proc.stdout

        # Control: with a usable binding the module IS instantiated,
        # so the start function runs and traps. Without this the test
        # below would pass against a module that never executes for
        # some unrelated reason.
        with self.assertRaises(Exception) as ctx:
            WasmHost().run_main(blob)
        self.assertNotIsInstance(ctx.exception, CapBindingError)

        forged = bytearray(blob)
        _rename_binding_export(forged)
        with self.assertRaises(CapBindingError):
            WasmHost().run_main(bytes(forged))

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
                        carrier=CARRIER_WASM_EXPORT,
                    )
                self.assertEqual(
                    main.calls, [],
                    "main was invoked despite an unusable capability "
                    "binding, so the guest received a handle it was "
                    "never entitled to",
                )


@unittest.skipUnless(_has_wasmtime(), "wasmtime-py not installed")
class TestForgedBindingIsContainedOnEveryBridge(unittest.TestCase):
    """A rewritten binding hands a slot the WRONG root capability. The
    handle table's TYPED LOOKUP is what contains that: the op fails
    ``lookup(handle, Env)`` and denies. Containment is only as good as
    its coverage, and three bridges had none.

    ``now_secs``, ``now_monotonic`` and ``env_args``, on BOTH hosts,
    performed the lookup and discarded the result, each with a comment
    claiming a bogus handle failed loudly there. Measured 2026-07-23
    with the binding rewritten so the slot held the Fs root: the core
    host returned the real process argv (``argc=2``) and the component
    host returned a real clock reading (``positive=true``), both exit
    0, no diagnostic. Meanwhile ``fs.allows`` on the same forged run
    correctly answered ``false``, which is what identified the typed
    lookup as the wall being bypassed.

    Every case here runs on the core host AND the Component host,
    because the first round of this fix corrected only the core one and
    shipped a host-to-host divergence on its own new guard."""

    # (label, source, binding as emitted, binding rewritten, expected
    # honest output). Each program uses BOTH caps so the analyzer
    # accepts the signature, and prints the fs probe so a forged run
    # that is contained looks different from one that is honoured.
    _CASES = [
        (
            "now_secs",
            'fun main(clock: Clock, fs: Fs, stdio: Stdio)\n'
            '    let ok = fs.allows("/tmp")\n'
            '    let t = clock.now_secs()\n'
            '    stdio.println("positive=${t > 0.0} fs=${ok}")\n',
            "clock,fs", "fs,clock", "positive=true fs=true\n",
        ),
        (
            "now_monotonic",
            'fun main(clock: Clock, fs: Fs, stdio: Stdio)\n'
            '    let ok = fs.allows("/tmp")\n'
            '    let t = clock.now_monotonic()\n'
            '    stdio.println("mono=${t >= 0.0} fs=${ok}")\n',
            "clock,fs", "fs,clock", "mono=true fs=true\n",
        ),
        (
            "env_args",
            'fun main(env: Env, fs: Fs, stdio: Stdio)\n'
            '    let ok = fs.allows("/tmp")\n'
            '    let a = env.args()\n'
            '    stdio.println("argc=${a.length()} fs=${ok}")\n',
            "env,fs", "fs,env", "argc=2 fs=true\n",
        ),
    ]

    # Non-empty, so a bridge that leaks argv leaks something visible.
    _ARGV = ["SECRET-ARG-1", "SECRET-ARG-2"]

    def _run_core(self, blob):
        from capa.runtime._wasm_host import WasmHost
        return _capture_stdout(
            lambda: WasmHost(args=self._ARGV).run_main(bytes(blob))
        )

    def _run_component(self, src, relabel=None):
        from capa.cli import _wrap_as_component
        from capa.ir import compile_wit
        from capa.runtime._wasm_component_host import WasmComponentHost
        module, result = _parse_and_analyze(src)
        core = compile_wasm(module, types=result.types)
        wit = compile_wit(module, types=result.types)
        if relabel is not None:
            before, after = relabel
            self.assertIn(before, wit)
            wit = wit.replace(before, after)
        component = _wrap_as_component(core, wit)
        return _capture_stdout(
            lambda: WasmComponentHost(args=self._ARGV).run_main(component)
        )

    @staticmethod
    def _slot_labels(kinds: str) -> str:
        """The WIT parameter list for a comma-separated kind list."""
        return ", ".join(
            f"{wit_cap_slot_name(i, k)}: u32"
            for i, k in enumerate(kinds.split(","))
        )

    def test_an_honest_binding_works_on_both_hosts(self):
        # Guards the refusals below against passing for the wrong
        # reason: a program that cannot run at all also never leaks.
        for label, src, _emitted, _forged, expected in self._CASES:
            with self.subTest(bridge=label, host="core"):
                self.assertEqual(self._run_core(_wasm_blob(src)), expected)
            if not _has_wasm_tools():
                continue
            with self.subTest(bridge=label, host="component"):
                self.assertEqual(self._run_component(src), expected)

    def test_core_host_refuses_a_slot_holding_the_wrong_root(self):
        from capa.runtime._cap_handles import CapHandleError
        for label, src, emitted, forged, _expected in self._CASES:
            with self.subTest(bridge=label):
                blob = bytearray(_wasm_blob(src))
                _retype_binding_export(
                    blob, emitted.encode(), forged.encode(),
                )
                with self.assertRaises(CapHandleError) as ctx:
                    self._run_core(blob)
                self.assertIn("resolves to Fs", str(ctx.exception))

    @unittest.skipUnless(_has_wasm_tools(), "wasm-tools not installed")
    def test_component_host_refuses_a_slot_holding_the_wrong_root(self):
        from capa.runtime._cap_handles import CapHandleError
        for label, src, emitted, forged, _expected in self._CASES:
            with self.subTest(bridge=label):
                relabel = (
                    self._slot_labels(emitted), self._slot_labels(forged),
                )
                with self.assertRaises(CapHandleError) as ctx:
                    self._run_component(src, relabel=relabel)
                self.assertIn("resolves to Fs", str(ctx.exception))

    def test_aot_header_rewrite_cannot_grant_an_authority(self):
        # The AOT container header is unauthenticated JSON: it is a
        # local build artifact and nothing signs it. That is tolerable
        # only as long as rewriting it can only ever DENY. Every kind
        # it could name hands the slot a root of the wrong type, and
        # the typed lookup then refuses every op on it. Before this
        # fix an `env` -> `fs` rewrite still returned the real argv.
        import json
        import struct
        from capa.runtime import _aot
        from capa.runtime._cap_handles import CapHandleError
        from capa.runtime._wasm_host import WasmHost
        _label, src, _emitted, _forged, _expected = self._CASES[2]
        artifact = _aot.build_aot(_wasm_blob(src), capa_version="t")
        fmt, hlen = struct.unpack("<II", artifact[4:12])
        header = json.loads(artifact[12:12 + hlen])
        self.assertEqual(header["main_cap_types"], ["env", "fs"])
        header["main_cap_types"] = ["fs", "fs"]
        raw = json.dumps(header).encode("utf-8")
        forged = (
            b"CPAO" + struct.pack("<II", fmt, len(raw)) + raw
            + artifact[12 + hlen:]
        )
        host = WasmHost(args=self._ARGV)
        module, hdr = _aot.load_aot(forged, host.engine)
        with self.assertRaises(CapHandleError) as ctx:
            _capture_stdout(lambda: host.run_main_aot(module, hdr))
        self.assertIn("expected Env", str(ctx.exception))

    def test_aot_header_without_a_binding_is_refused(self):
        # The AOT path resolves the binding from the header BEFORE
        # instantiating, symmetrically with ``run_main``, so a header
        # stripped of ``main_cap_types`` (what a pre-binding build
        # produced) is refused rather than run against a guessed
        # binding. Uses the JSON key carrier, not the export carrier.
        import json
        import struct
        from capa.runtime import _aot
        from capa.runtime._wasm_host import WasmHost
        _label, src, _emitted, _forged, _expected = self._CASES[2]
        artifact = _aot.build_aot(_wasm_blob(src), capa_version="t")
        fmt, hlen = struct.unpack("<II", artifact[4:12])
        header = json.loads(artifact[12:12 + hlen])
        del header["main_cap_types"]
        raw = json.dumps(header).encode("utf-8")
        forged = (
            b"CPAO" + struct.pack("<II", fmt, len(raw)) + raw
            + artifact[12 + hlen:]
        )
        host = WasmHost(args=self._ARGV)
        module, hdr = _aot.load_aot(forged, host.engine)
        with self.assertRaises(CapBindingError) as ctx:
            host.run_main_aot(module, hdr)
        self.assertIn("container header", str(ctx.exception))


@unittest.skipUnless(
    _has_wasmtime() and _has_wasm_tools(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestUndeclaredCapabilityHasNoRoot(unittest.TestCase):
    """A hand-written artifact whose binding names ONLY ``net`` must not
    reach the filesystem by forging the integer the Fs root is
    deterministically assigned.

    The per-instance handle table used to be bootstrapped with a root
    for EVERY handle-bearing capability regardless of what the artifact
    declared, and roots are consecutive integers (stdio=1, fs=2, ...).
    So a module declaring only ``net`` could import ``capa:host/fs.read``
    and call it with the integer 2, hit the live Fs root, and read a
    secret file it never had authority over. Reachable through the
    shipped ``capa run-aot`` verb, exit 0, no diagnostic.

    The fix bootstraps ONLY the declared capabilities' roots, so the
    forged integer resolves to the wrong-type root (or to nothing) at
    the typed handle-table lookup and the op denies at the call. This
    checks the containment on all three hosts that bootstrap the table:
    the core module host (``capa --run --wasm``), the AOT run path
    (``capa run-aot``), and the Component host.
    """

    _SECRET = "s3cr3t-launch-code-do-not-leak"

    def _forged_fs_handle(self) -> int:
        # The integer the Fs root is assigned when the FULL cap set is
        # bootstrapped -- the value the pre-fix table always held an Fs
        # at, hence the value an attacker forges. Derived from the real
        # bootstrap rather than hardcoded, so a change to the allocation
        # order cannot silently make this witness name a stale handle.
        from capa.runtime._capabilities import (
            Clock, Db, Env, Fs, Net, Proc, Stdio,
        )
        probe = bootstrap_root_handles(
            CapHandleTable(),
            declared=[c.lower() for c in HANDLE_BEARING_CAPS],
            stdio=Stdio(), fs=Fs(), net=Net(), db=Db(),
            proc=Proc(), env=Env(), clock=Clock(),
        )
        return probe["fs"]

    def _forge_core_wasm(self, secret_path: Path) -> bytes:
        """A minimal core module: binding declares only ``net``, yet
        ``main`` calls ``capa:host/fs.read`` with the forged Fs-root
        integer and prints the Ok string (or ``denied`` on Err)."""
        path_bytes = str(secret_path).encode("utf-8")
        n = len(path_bytes)
        path_wat = "".join(f"\\{b:02x}" for b in path_bytes)
        heap = ((n + 6 + 7) // 8) * 8
        fs_handle = self._forged_fs_handle()
        binding = main_cap_types_export_name(["net"])
        wat = f"""(module
  (import "capa:host/fs" "read"
    (func $Fs_read (param i32 i32 i32 i32)))
  (import "capa:host/stdio" "println" (func $println (param i32 i32)))
  (memory (export "memory") 1 256)
  (data (i32.const 0) "{path_wat}")
  (data (i32.const {n}) "denied")
  (global $heap_top (mut i32) (i32.const {heap}))
  (func $alloc (export "alloc") (param $size i32) (result i32)
    (local $ret i32) (local $new_top i32)
    (local $needed_pages i32) (local $cur_pages i32)
    global.get $heap_top
    i32.const 7 i32.add i32.const -8 i32.and
    local.set $ret
    local.get $ret local.get $size i32.add
    local.set $new_top
    local.get $new_top i32.const 65535 i32.add i32.const 16 i32.shr_u
    local.set $needed_pages
    memory.size local.set $cur_pages
    local.get $needed_pages local.get $cur_pages i32.gt_u
    if
      local.get $needed_pages local.get $cur_pages i32.sub
      memory.grow i32.const -1 i32.eq
      if unreachable end
    end
    local.get $new_top global.set $heap_top
    local.get $ret
  )
  (func $cabi_realloc (export "cabi_realloc")
      (param $old_ptr i32) (param $old_size i32)
      (param $align i32) (param $new_size i32) (result i32)
    local.get $new_size i32.eqz
    if i32.const 0 return end
    local.get $new_size call $alloc
  )
  (func $main (export "main") (param $net i32)
    (local $ret i32)
    i32.const 20 call $alloc local.set $ret
    ;; fs.read(handle=<forged Fs root>, path_ptr=0, path_len, ret_area)
    i32.const {fs_handle}
    i32.const 0
    i32.const {n}
    local.get $ret
    call $Fs_read
    local.get $ret i32.load offset=0
    i32.eqz
    if
      local.get $ret i32.load offset=4
      local.get $ret i32.load offset=8
      call $println
    else
      i32.const {n}
      i32.const 6
      call $println
    end
  )
  (global $g i32 (i32.const 1))
  (export "{binding}" (global $g))
)
"""
        proc = subprocess.run(
            ["wasm-tools", "parse", "-"],
            input=wat.encode("utf-8"), capture_output=True,
        )
        self.assertEqual(
            proc.returncode, 0,
            proc.stderr.decode("utf-8", errors="replace"),
        )
        return proc.stdout

    # WIT world for the component form: labels ``main``'s only slot
    # ``cap0-net`` (so the Component host reads the binding as ``net``),
    # imports the fs interface the forged core still calls.
    _COMPONENT_WIT = (
        "package capa:host;\n"
        "interface fs {\n"
        "  record io-error { message: string, cause: string, }\n"
        "  read: func(handle: u32, path: string)"
        " -> result<string, io-error>;\n"
        "}\n"
        "interface stdio { println: func(msg: string); }\n"
        "world program {\n"
        "  import fs;\n"
        "  import stdio;\n"
        f"  export main: func({wit_cap_slot_name(0, 'net')}: u32);\n"
        "}\n"
    )

    def _write_secret(self, td) -> Path:
        p = Path(td) / "secret.txt"
        p.write_text(self._SECRET, encoding="utf-8")
        return p

    def _assert_denied(self, out: str) -> None:
        self.assertNotIn(
            self._SECRET, out,
            "the forged Fs handle read the secret file; an undeclared "
            "capability's root is still reachable through the table",
        )
        self.assertIn("denied", out)

    def test_core_host_denies_the_forged_fs_handle(self):
        from capa.runtime._wasm_host import WasmHost
        with tempfile.TemporaryDirectory() as td:
            blob = self._forge_core_wasm(self._write_secret(td))
            out = _capture_stdout(lambda: WasmHost(args=[]).run_main(blob))
        self._assert_denied(out)

    def test_aot_run_path_denies_the_forged_fs_handle(self):
        from capa.runtime import _aot
        from capa.runtime._wasm_host import WasmHost
        with tempfile.TemporaryDirectory() as td:
            blob = self._forge_core_wasm(self._write_secret(td))
            host = WasmHost(args=[])
            artifact = _aot.build_aot(blob, capa_version="t")
            module, hdr = _aot.load_aot(artifact, host.engine)
            out = _capture_stdout(
                lambda: host.run_main_aot(module, hdr)
            )
        self._assert_denied(out)

    def test_component_host_denies_the_forged_fs_handle(self):
        from capa.cli import _wrap_as_component
        from capa.runtime._wasm_component_host import WasmComponentHost
        with tempfile.TemporaryDirectory() as td:
            blob = self._forge_core_wasm(self._write_secret(td))
            comp = _wrap_as_component(blob, self._COMPONENT_WIT, wasi=False)
            out = _capture_stdout(
                lambda: WasmComponentHost(args=[]).run_main(comp)
            )
        self._assert_denied(out)


def _tests_for_none(fn: ast.AST, var: str) -> bool:
    """True when ``fn`` compares ``var`` against None or negates it
    (``not var``). Those are the shapes the fail-closed host bridges
    use to react to a bad handle."""
    for node in ast.walk(fn):
        if isinstance(node, ast.Compare):
            if isinstance(node.left, ast.Name) and node.left.id == var:
                if any(isinstance(op, (ast.Is, ast.IsNot)) for op in node.ops):
                    return True
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            if isinstance(node.operand, ast.Name):
                if node.operand.id == var:
                    return True
    return False


def _swallowing_call_name(node) -> "str | None":
    """The name of the swallowing resolver ``node`` calls, if any.

    Matched by NAME PREFIX (``_lookup``) rather than an allow-list, so
    a new per-cap variant is policed the day it is written. The RAISING
    resolver ``_require_receiver`` calls ``self._cap_handles.lookup``
    (no leading underscore) and is intentionally not matched: it cannot
    honour a bad handle, so it needs no consumer check."""
    if not isinstance(node, ast.Call):
        return None
    func = node.func
    if isinstance(func, ast.Name) and func.id.startswith("_lookup"):
        return func.id
    if isinstance(func, ast.Attribute) and func.attr.startswith("_lookup"):
        return func.attr
    return None


def _parent_map(tree: ast.AST) -> dict:
    parents: dict = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node
    return parents


def _enclosing_function(node, parents: dict):
    cur = parents.get(node)
    while cur is not None:
        if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return cur
        cur = parents.get(cur)
    return None


def _inline_none_tested(call, parent) -> bool:
    """The call's own result is compared against None right here
    (``if self._lookup_or(...) is None``) or negated in a boolean
    position (``not self._lookup_or(...)``)."""
    if isinstance(parent, ast.Compare):
        operands = [parent.left, *parent.comparators]
        has_is = any(
            isinstance(op, (ast.Is, ast.IsNot)) for op in parent.ops
        )
        has_none = any(
            isinstance(o, ast.Constant) and o.value is None
            for o in operands
        )
        if call in operands and has_is and has_none:
            return True
    if isinstance(parent, ast.UnaryOp) and isinstance(parent.op, ast.Not):
        if parent.operand is call:
            return True
    return False


def _swallowing_result_is_checked(call, parents: dict) -> bool:
    """Whether a swallowing-lookup ``call``'s result reaches a
    fail-closed check. A result that does not is a slot that would be
    honoured on a bad handle, which is exactly the C1/C2 bug.

    Four "checked" shapes are accepted, and NOTHING else:

    * ``x = <call>`` where ``x`` is later None-tested in the same
      function (what every real bridge does);
    * ``if (x := <call>) is None`` (the walrus form of the same);
    * ``return <call>`` (the caller inherits the None);
    * ``<call> is None`` / ``not <call>`` inline.

    Every other context - a bare statement, an argument to another
    call (``self._note(<call>)``), a builtin wrapper (``bool(<call>)``),
    an f-string field - flows the result somewhere that does not
    fail-close, so it is a violation. This is the set the earlier
    two-shape check missed."""
    parent = parents.get(call)
    if parent is None:
        return False
    if isinstance(parent, ast.Return) and parent.value is call:
        return True
    if isinstance(parent, ast.Assign) and parent.value is call:
        if len(parent.targets) == 1 and isinstance(parent.targets[0], ast.Name):
            fn = _enclosing_function(call, parents)
            if fn is not None and _tests_for_none(fn, parent.targets[0].id):
                return True
        return False
    if isinstance(parent, ast.NamedExpr) and parent.value is call:
        # ``if (cap := <call>) is None`` tests the walrus expression
        # itself, in the grandparent; ``... := <call>`` used later
        # tests the bound name.
        if _inline_none_tested(parent, parents.get(parent)):
            return True
        if isinstance(parent.target, ast.Name):
            fn = _enclosing_function(call, parents)
            if fn is not None and _tests_for_none(fn, parent.target.id):
                return True
        return False
    return _inline_none_tested(call, parent)


def _unchecked_swallowing_lookups(tree: ast.AST):
    """``(lineno, name)`` for every swallowing lookup in ``tree`` whose
    result is not consumed in a fail-closed shape."""
    parents = _parent_map(tree)
    out = []
    for node in ast.walk(tree):
        name = _swallowing_call_name(node)
        if name is None:
            continue
        if _swallowing_result_is_checked(node, parents):
            continue
        out.append((getattr(node, "lineno", 0), name))
    return out


class TestEveryBridgeRequiresItsReceiver(unittest.TestCase):
    """The structural half of the class above: a FOURTH bridge that
    performs the typed lookup without consulting it must not be able
    to appear.

    Both hosts expose a SWALLOWING resolver (``_lookup_*`` on the core
    host, ``_lookup_or`` on the Component host) returning ``None`` on a
    bad handle so its caller can answer fail-closed, and a RAISING one
    (``_require_receiver``) for bridges with no fail-closed answer to
    give. The rule enforced here is that a swallowing lookup's result
    is always consumed in a way that fail-closes on None:
    ``_swallowing_result_is_checked`` names the four shapes that count,
    and flags everything else - a bare statement, an argument to
    another call, a builtin wrapper, an f-string field. The earlier
    version of this guard only recognised the first two of those
    violation shapes; a reviewer mutation-testing it with
    ``self._note(self._lookup_or(...))`` and ``bool(self._lookup_or(
    ...))`` found the other two slipped through."""

    _HOSTS = [
        "capa/runtime/_wasm_host.py",
        "capa/runtime/_wasm_component_host.py",
    ]

    def _trees(self):
        root = Path(__file__).resolve().parent.parent
        for rel in self._HOSTS:
            path = root / rel
            yield rel, ast.parse(path.read_text(encoding="utf-8"))

    def test_the_rule_can_find_the_calls_it_polices(self):
        # A guard that matches nothing passes forever. Both hosts must
        # actually contain swallowing lookups for the rule to mean
        # anything.
        for rel, tree in self._trees():
            with self.subTest(module=rel):
                calls = [
                    n for n in ast.walk(tree)
                    if _swallowing_call_name(n)
                ]
                self.assertGreater(len(calls), 5, rel)

    def test_no_swallowing_lookup_result_goes_unchecked(self):
        for rel, tree in self._trees():
            unchecked = _unchecked_swallowing_lookups(tree)
            self.assertEqual(
                unchecked, [],
                f"{rel} calls a swallowing lookup whose result never "
                f"reaches a None check at {unchecked}. That resolver "
                f"returns None on a bad handle, so an unchecked result "
                f"honours a slot holding the wrong root. Use "
                f"_require_receiver(), which raises.",
            )

    def test_the_detector_flags_every_discarding_shape(self):
        # Fail-first evidence, and the fix for the reviewer's finding
        # in one place: the detector must FLAG all four ways a result
        # can be thrown away, including the two the old guard missed,
        # and must PASS the four fail-closed shapes. If any BAD snippet
        # stops being flagged, the guard above has regressed to theatre.
        bad = {
            "bare statement":
                "    self._lookup_or(h, Env)\n",
            "assigned, never None-tested":
                "    cap = self._lookup_or(h, Env)\n"
                "    return cap.read()\n",
            "argument to another call":
                "    self._note(self._lookup_or(h, Env))\n",
            "wrapped in a builtin":
                "    bool(self._lookup_or(h, Env))\n",
        }
        good = {
            "assigned and None-tested":
                "    cap = self._lookup_or(h, Env)\n"
                "    if cap is None:\n"
                "        return None\n"
                "    return cap.read()\n",
            "walrus None-test":
                "    if (cap := self._lookup_or(h, Env)) is None:\n"
                "        return None\n"
                "    return cap.read()\n",
            "returned raw":
                "    return self._lookup_or(h, Env)\n",
            "inline None-test":
                "    if self._lookup_or(h, Env) is None:\n"
                "        return None\n"
                "    return 1\n",
        }
        for label, body in bad.items():
            with self.subTest(kind="flagged", shape=label):
                tree = ast.parse(f"def f(self, h, Env):\n{body}")
                self.assertEqual(
                    len(_unchecked_swallowing_lookups(tree)), 1,
                    f"the detector did not flag a discarded lookup "
                    f"({label}); the hole this guard exists to close "
                    f"would slip through",
                )
        for label, body in good.items():
            with self.subTest(kind="passed", shape=label):
                tree = ast.parse(f"def f(self, h, Env):\n{body}")
                self.assertEqual(
                    _unchecked_swallowing_lookups(tree), [],
                    f"the detector flagged a fail-closed lookup "
                    f"({label}) as a violation; a false positive would "
                    f"force real bridges to be exempted and rot the "
                    f"guard",
                )


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


@unittest.skipUnless(
    _has_wasmtime() and _has_wasm_tools(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestPreferWasmDoesNotFailOpen(unittest.TestCase):
    """``--prefer-wasm`` wrapped BOTH the compile and the run in one
    bare ``except Exception: pass`` and re-ran the program on the
    Python pipeline, which has full authority and no handle table.

    A capability refusal is exactly the thing that must not be
    absorbed there: the Wasm backend saying "this artifact's binding
    is unusable" was answered by running it somewhere the question is
    never asked. The fallback now covers the COMPILE only, which is
    what it was documented to be for (programs outside the Phase-6
    subset), and is safe because nothing has executed yet."""

    def test_a_capability_refusal_is_not_absorbed_into_a_python_rerun(self):
        from capa.ir._cap_binding import CapBindingError
        from capa.runtime._wasm_host import WasmHost
        import capa.cli as cli

        src = (
            'fun main(net: Net, stdio: Stdio)\n'
            '    stdio.println("ran=${net.allows("example.com")}")\n'
        )

        def _refuse(self, blob):
            raise CapBindingError("simulated unusable binding")

        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "p.capa"
            path.write_text(src, encoding="utf-8")
            with unittest.mock.patch.object(WasmHost, "run_main", _refuse):
                out = io.StringIO()
                err = io.StringIO()
                saved = sys.stdout, sys.stderr, sys.argv
                sys.stdout, sys.stderr = out, err
                sys.argv = ["capa", "--run", "--prefer-wasm", str(path)]
                try:
                    with self.assertRaises(CapBindingError):
                        cli.main()
                finally:
                    sys.stdout, sys.stderr, sys.argv = saved
            self.assertNotIn(
                "ran=", out.getvalue(),
                "the program was re-run on the Python pipeline after "
                "the Wasm host refused its capability binding, which "
                "is fail-open in the mode whose point is fail-closed",
            )

    def test_a_compile_gap_still_falls_back_silently(self):
        # The documented contract, and the reason the fallback exists.
        # It must survive the narrowing above.
        import capa.cli as cli
        import capa.ir as ir

        def _explode(*a, **kw):
            raise RuntimeError("simulated Phase-6 coverage gap")

        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "p.capa"
            path.write_text(
                'fun main(stdio: Stdio)\n    stdio.println("Hi")\n',
                encoding="utf-8",
            )
            with unittest.mock.patch.object(ir, "compile_wasm", _explode):
                out = io.StringIO()
                saved = sys.stdout, sys.argv
                sys.stdout = out
                sys.argv = ["capa", "--run", "--prefer-wasm", str(path)]
                try:
                    rc = cli.main()
                finally:
                    sys.stdout, sys.argv = saved
        self.assertEqual(rc, 0)
        self.assertIn("Hi", out.getvalue())


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
