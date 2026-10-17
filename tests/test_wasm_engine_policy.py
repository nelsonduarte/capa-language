"""The wasmtime engine policy: one function configures every engine Capa
builds, from one decision table.

Rule under test. ``capa.runtime._engine.ENGINE_FEATURES`` decides, for every
Wasm feature setter the installed binding exposes, whether the feature is on.
It is an allow-list: only what Capa needs is on, every other feature is off,
including a setter the table does not know yet. A setter the table names but
the binding lacks refuses to build the engine (fail closed), and so does a
binding older than the floor declared for the ``[wasm]`` extra.

The classes below cover, in order: the table against the installed binding,
the per-feature decisions, the fail-closed rules, the binding floor (and its
clean refusal on every CLI entry point that builds an engine), every engine
role Capa constructs, the AOT container's engine identity, and a static guard
that no engine is built outside the seam.
"""

from __future__ import annotations

import ast
import io
import json
import os
import shutil
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from capa import Lexer, Parser, analyze

from tests._wasm_feature_probes import CORE_PROBES, UNPROBED_FEATURES

try:
    import wasmtime
    import wasmtime.component as wc
    from wasmtime import _bindings
except ImportError:  # pragma: no cover - the [wasm] extra is absent
    wasmtime = None

_HAVE_WASMTIME = wasmtime is not None
_HAVE_WASM_TOOLS = shutil.which("wasm-tools") is not None
_REPO_ROOT = Path(__file__).resolve().parent.parent

_SETTER_PREFIX = "wasmtime_config_wasm_"
_SETTER_SUFFIX = "_set"

_HELLO = 'fun main(stdio: Stdio)\n    stdio.println("hi")\n'


def _exposed_feature_setters() -> set[str]:
    """Every Wasm feature the installed binding can switch, by row name:
    the C-API setter symbols and the ``Config.wasm_*`` properties."""
    names = {
        n[len(_SETTER_PREFIX):-len(_SETTER_SUFFIX)]
        for n in dir(_bindings)
        if n.startswith(_SETTER_PREFIX) and n.endswith(_SETTER_SUFFIX)
    }
    names |= {
        n[len("wasm_"):] for n in dir(wasmtime.Config) if n.startswith("wasm_")
    }
    return names


def _load(engine, text: str):
    blob = wasmtime.wat2wasm(text)
    if blob[4:8] == b"\x01\x00\x00\x00":
        return wasmtime.Module(engine, blob)
    return wc.Component(engine, blob)


def _wasm_blob(src: str) -> bytes:
    from capa.ir import compile_wasm
    module = Parser(Lexer(src).lex(), source=src).parse_module()
    result = analyze(module, source=src)
    if not result.ok:
        raise AssertionError(f"analyzer errors: {result.errors}")
    return compile_wasm(module, types=result.types, filename="t.capa")


def _container(header: dict, cwasm: bytes) -> bytes:
    from capa.runtime import _aot
    raw = json.dumps(header).encode("utf-8")
    return b"".join([
        b"CPAO", struct.pack("<I", _aot._FORMAT_VERSION),
        struct.pack("<I", len(raw)), raw, cwasm,
    ])


def _run_cli(argv, cwd):
    from capa.cli import main
    out, err = io.StringIO(), io.StringIO()
    original = os.getcwd()
    try:
        os.chdir(str(cwd))
        with mock.patch.object(sys, "argv", ["capa"] + list(argv)), \
                mock.patch.object(sys, "stdout", out), \
                mock.patch.object(sys, "stderr", err):
            try:
                rc = main()
            except SystemExit as e:
                rc = e.code if isinstance(e.code, int) else 1
    finally:
        os.chdir(original)
    return rc, out.getvalue(), err.getvalue()


@unittest.skipUnless(_HAVE_WASMTIME, "wasmtime not installed")
class TestDecisionTable(unittest.TestCase):
    """The table against the installed binding."""

    def test_every_exposed_feature_setter_is_decided(self):
        # A setter the table does not list is forced off at runtime, but
        # it must also turn this test red so the next binding's new
        # feature gets a deliberate decision instead of a silent one.
        from capa.runtime._engine import ENGINE_FEATURES
        undecided = sorted(_exposed_feature_setters() - set(ENGINE_FEATURES))
        self.assertEqual(
            undecided, [],
            f"the installed wasmtime exposes feature setters the engine "
            f"table does not decide: {undecided}",
        )

    def test_every_row_has_a_probe_or_a_stated_reason(self):
        from capa.runtime._engine import ENGINE_FEATURES
        self.assertFalse(set(CORE_PROBES) & set(UNPROBED_FEATURES))
        self.assertEqual(
            set(ENGINE_FEATURES), set(CORE_PROBES) | set(UNPROBED_FEATURES),
        )

    def test_enabled_rows_load_and_disabled_rows_are_refused(self):
        from capa.runtime._engine import ENGINE_FEATURES, new_engine
        for fuel in (False, True):
            engine = new_engine(fuel=fuel)
            for row, text in CORE_PROBES.items():
                with self.subTest(row=row, fuel=fuel):
                    wasmtime.wat2wasm(text)  # the probe itself is valid text
                    if ENGINE_FEATURES[row]:
                        _load(engine, text)
                    else:
                        with self.assertRaises(wasmtime.WasmtimeError):
                            _load(engine, text)


@unittest.skipUnless(_HAVE_WASMTIME, "wasmtime not installed")
class TestFailClosed(unittest.TestCase):

    def test_missing_setter_for_any_row_refuses_the_engine(self):
        from capa.runtime._engine import (
            ENGINE_FEATURES, WasmBindingError, new_engine,
        )
        for row in ENGINE_FEATURES:
            symbol = f"{_SETTER_PREFIX}{row}{_SETTER_SUFFIX}"
            with self.subTest(row=row), \
                    mock.patch.dict(_bindings.__dict__):
                del _bindings.__dict__[symbol]
                with self.assertRaises(WasmBindingError) as ctx:
                    new_engine(fuel=False)
                self.assertIn(row, str(ctx.exception))

    def test_setter_the_table_does_not_know_is_switched_off(self):
        from capa.runtime._engine import new_engine
        calls = []
        symbol = f"{_SETTER_PREFIX}capa_unlisted_probe{_SETTER_SUFFIX}"
        with mock.patch.dict(
            _bindings.__dict__,
            {symbol: lambda ptr, enable: calls.append(enable)},
        ):
            new_engine(fuel=False)
        self.assertEqual(calls, [False])

    def test_engine_identity_tracks_the_decisions(self):
        from capa.runtime import _engine
        base = _engine.engine_identity(fuel=False)
        self.assertNotEqual(base, _engine.engine_identity(fuel=True))
        flipped = dict(_engine.ENGINE_FEATURES, exceptions=True)
        with mock.patch.object(_engine, "ENGINE_FEATURES", flipped):
            self.assertNotEqual(base, _engine.engine_identity(fuel=False))


class TestBindingFloor(unittest.TestCase):
    """The floor is read back from the one place it is declared."""

    def test_below_floor_is_refused_with_an_upgrade_message(self):
        from capa.runtime._engine import WasmBindingError, check_binding_version
        with self.assertRaises(WasmBindingError) as ctx:
            check_binding_version("47.0.1", "48")
        msg = str(ctx.exception)
        self.assertIn("47.0.1", msg)
        self.assertIn("48", msg)
        self.assertIn("pip install", msg)

    def test_at_or_above_floor_is_accepted(self):
        from capa.runtime._engine import check_binding_version
        for installed in ("48", "48.0.0", "48.0.6", "49.0.0", "100.1.2"):
            with self.subTest(installed=installed):
                check_binding_version(installed, "48")

    def test_unreadable_versions_fail_closed(self):
        from capa.runtime._engine import WasmBindingError, check_binding_version
        for installed, floor in ((None, "48"), ("48.0.0", None), ("x", "48")):
            with self.subTest(installed=installed, floor=floor):
                with self.assertRaises(WasmBindingError):
                    check_binding_version(installed, floor)

    def test_floor_parsed_from_both_declaration_forms(self):
        from capa.runtime._engine import floor_from_declaration
        self.assertEqual(
            floor_from_declaration('wasm = ["wasmtime>=48"]\n'), "48",
        )
        self.assertEqual(
            floor_from_declaration('wasmtime>=48.0.2; extra == "wasm"'),
            "48.0.2",
        )
        self.assertIsNone(floor_from_declaration('wasm = ["wasmtime"]'))

    def test_floor_resolves_from_installed_metadata_without_a_checkout(self):
        from capa.runtime import _engine
        reqs = ['pygls>=2.0; extra == "lsp"', 'wasmtime>=48; extra == "wasm"']
        with mock.patch.object(_engine, "_adjacent_pyproject", return_value=None), \
                mock.patch.object(_engine, "_distribution_requires",
                                  return_value=reqs):
            self.assertEqual(_engine.binding_floor(), "48")

    @unittest.skipUnless(_HAVE_WASMTIME, "wasmtime not installed")
    def test_installed_binding_meets_the_declared_floor(self):
        from capa.runtime import _engine
        floor = _engine.binding_floor()
        self.assertIsNotNone(floor)
        _engine.check_binding_version(
            _engine._installed_binding_version(), floor,
        )


@unittest.skipUnless(
    _HAVE_WASMTIME and _HAVE_WASM_TOOLS, "wasm-tools / wasmtime missing",
)
class TestBelowFloorOnEveryCliEntry(unittest.TestCase):
    """Every CLI path that builds an engine reports a too-old binding as a
    one-line diagnostic, never a traceback."""

    _OLD = "47.0.1"

    def _assert_clean_refusal(self, rc, err):
        self.assertEqual(rc, 2)  # a configuration problem, see capa.cli.main
        self.assertIn(self._OLD, err)
        self.assertIn("pip install", err)
        self.assertNotIn("Traceback (most recent call last)", err)

    def test_each_entry(self):
        from capa.runtime import _aot
        with tempfile.TemporaryDirectory() as td:
            prog = Path(td) / "p.capa"
            prog.write_text(_HELLO, encoding="utf-8")
            artifact = Path(td) / "p.cwasm"
            artifact.write_bytes(
                _aot.build_aot(_wasm_blob(_HELLO), capa_version="t"),
            )
            entries = {
                "wasm-run": ["--wasm", "--run", str(prog)],
                "component-run": ["--wasm", "--component", "--run", str(prog)],
                "wasi-run": [
                    "--wasm", "--component", "--wasi", "--run", str(prog),
                ],
                "prefer-wasm": ["--prefer-wasm", "--run", str(prog)],
                "build-release": ["build", "--release", str(prog)],
                "run-aot": ["run-aot", str(artifact)],
            }
            for name, argv in entries.items():
                with self.subTest(entry=name), mock.patch(
                    "capa.runtime._engine._installed_binding_version",
                    return_value=self._OLD,
                ):
                    rc, _out, err = _run_cli(argv, cwd=td)
                    self._assert_clean_refusal(rc, err)


@unittest.skipUnless(_HAVE_WASMTIME, "wasmtime not installed")
class TestEveryEngineRole(unittest.TestCase):
    """Each engine Capa constructs refuses a feature outside the allow-list.

    Two probes per role: exceptions (on by default in the bindings this
    release supports) and SIMD (on by default in every binding), so a role
    that kept the binding default, or applied a deny-list instead of the
    allow-list, is caught."""

    _REFUSED = ("exceptions", "simd")

    def _assert_policy(self, engine, role):
        for row in self._REFUSED:
            with self.subTest(role=role, probe=row):
                with self.assertRaises(wasmtime.WasmtimeError):
                    _load(engine, CORE_PROBES[row])
        _load(engine, CORE_PROBES["tail_call"])

    def test_core_host_engine(self):
        from capa.runtime._wasm_host import WasmHost
        self._assert_policy(WasmHost().engine, "core host")

    def test_foreign_child_engine_with_fuel(self):
        from capa.runtime._wasm_host import WasmHost
        host = WasmHost()
        self._assert_policy(host._foreign_call_engine(), "foreign, fuel on")

    def test_foreign_child_engine_without_fuel(self):
        from capa.runtime._wasm_host import WasmHost
        host = WasmHost()
        host.configure_foreign_limits(fuel=0)
        self._assert_policy(host._foreign_call_engine(), "foreign, fuel off")

    def test_new_foreign_engine(self):
        from capa.runtime._foreign import new_foreign_engine
        self._assert_policy(new_foreign_engine(), "new_foreign_engine")

    def test_component_host_engine(self):
        from capa.runtime._wasm_component_host import WasmComponentHost
        self._assert_policy(WasmComponentHost()._engine, "component host")

    def test_component_host_engine_in_wasi_mode(self):
        from capa.runtime._wasm_component_host import WasmComponentHost
        self._assert_policy(
            WasmComponentHost(wasi=True)._engine, "component host, --wasi",
        )

    def test_aot_build_refuses_and_names_the_feature(self):
        from capa.runtime._aot import build_aot
        for row, needle in (("exceptions", "exceptions"), ("simd", "SIMD")):
            with self.subTest(probe=row):
                with self.assertRaises(Exception) as ctx:
                    build_aot(
                        wasmtime.wat2wasm(CORE_PROBES[row]), capa_version="t",
                    )
                self.assertIn(needle, str(ctx.exception))


@unittest.skipUnless(_HAVE_WASMTIME, "wasmtime not installed")
class TestAotEngineIdentity(unittest.TestCase):
    """An AOT artifact compiled under any other engine configuration is
    refused with ``AotError``, never deserialized into a traceback."""

    def _default_engine_cwasm(self) -> bytes:
        # Deliberately the binding's DEFAULT engine (not the seam): this
        # is the artifact a different engine configuration would produce.
        return wasmtime.Module(
            wasmtime.Engine(), _wasm_blob(_HELLO),
        ).serialize()

    def test_header_carries_the_engine_identity(self):
        from capa.runtime import _aot
        from capa.runtime._engine import engine_identity
        header, _ = _aot.parse_aot(
            _aot.build_aot(_wasm_blob(_HELLO), capa_version="t"),
        )
        self.assertEqual(header.get("engine"), engine_identity(fuel=False))

    def test_artifact_from_another_engine_configuration_is_refused(self):
        # The body is a genuine one this engine could load; only the
        # recorded identity differs, so the identity check alone refuses.
        from capa.runtime import _aot
        from capa.runtime._wasm_host import WasmHost
        header, cwasm = _aot.parse_aot(
            _aot.build_aot(_wasm_blob(_HELLO), capa_version="t"),
        )
        missing = {k: v for k, v in header.items() if k != "engine"}
        other = dict(header, engine="on=simd;off=;fuel=0")
        for label, hdr in (("missing", missing), ("different", other)):
            for engine in (None, WasmHost().engine):
                with self.subTest(identity=label, host_engine=engine is not None):
                    with self.assertRaises(_aot.AotError) as ctx:
                        _aot.load_aot(_container(hdr, cwasm), engine=engine)
                    self.assertIn("capa build --release", str(ctx.exception))

    def test_body_the_engine_cannot_load_is_refused(self):
        # Same header as a genuine artifact (identity included), but the
        # body was compiled by a wider engine, or is truncated.
        from capa.runtime import _aot
        header, cwasm = _aot.parse_aot(
            _aot.build_aot(_wasm_blob(_HELLO), capa_version="t"),
        )
        bodies = {
            "wider engine": self._default_engine_cwasm(),
            "truncated": cwasm[: len(cwasm) // 2],
        }
        for name, body in bodies.items():
            with self.subTest(body=name):
                with self.assertRaises(_aot.AotError):
                    _aot.load_aot(_container(header, body))

    @unittest.skipUnless(_HAVE_WASM_TOOLS, "wasm-tools missing")
    def test_run_aot_reports_a_foreign_artifact_cleanly(self):
        from capa.runtime import _aot
        header, _ = _aot.parse_aot(
            _aot.build_aot(_wasm_blob(_HELLO), capa_version="t"),
        )
        header.pop("engine", None)
        with tempfile.TemporaryDirectory() as td:
            art = Path(td) / "old.cwasm"
            art.write_bytes(_container(header, self._default_engine_cwasm()))
            rc, _out, err = _run_cli(["run-aot", str(art)], cwd=td)
        self.assertEqual(rc, 2)
        self.assertIn("capa build --release", err)
        self.assertNotIn("Traceback (most recent call last)", err)


# Files allowed to construct a wasmtime engine or config directly, each
# with the reason. Everything else goes through capa.runtime._engine.
_DIRECT_ENGINE_ALLOWED = {
    "capa/runtime/_engine.py": "the seam itself",
    "tests/test_wasm_engine_policy.py": (
        "builds a default-engine artifact on purpose, to prove the AOT "
        "loader refuses it"
    ),
}


def _direct_engine_calls(path: Path) -> list[str]:
    """Calls in ``path`` that build a wasmtime Engine or Config, or a Store
    with no engine (which builds a default engine inside the binding).

    Matches ``<anything>.Engine(...)`` / ``<anything>.Config(...)`` and any
    bare name bound by ``from wasmtime import Engine / Config [as X]``, so
    an aliased import is caught as well as the qualified form."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "wasmtime":
            for a in node.names:
                if a.name in ("Engine", "Config", "Store"):
                    aliases[a.asname or a.name] = a.name
    hits = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        name = None
        if isinstance(f, ast.Attribute) and f.attr in ("Engine", "Config", "Store"):
            name = f.attr
        elif isinstance(f, ast.Name) and f.id in aliases:
            name = aliases[f.id]
        if name is None:
            continue
        if name == "Store" and (node.args or node.keywords):
            continue
        hits.append(f"{path.as_posix()}:{node.lineno}: {name}(...)")
    return hits


class TestNoEngineOutsideTheSeam(unittest.TestCase):
    """Static side of the per-role tests: an engine built where no test
    reaches is still found."""

    def test_no_direct_engine_construction(self):
        hits = []
        for top in ("capa", "tests"):
            for path in sorted((_REPO_ROOT / top).rglob("*.py")):
                rel = path.relative_to(_REPO_ROOT).as_posix()
                if rel in _DIRECT_ENGINE_ALLOWED:
                    continue
                hits += _direct_engine_calls(path)
        self.assertEqual(
            hits, [],
            "build engines through capa.runtime._engine.new_engine; "
            "direct constructions found",
        )

    def test_guard_sees_the_aliased_and_engineless_forms(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "m.py"
            p.write_text(
                "import wasmtime\n"
                "from wasmtime import Engine as _E, Store\n"
                "a = _E()\n"
                "b = wasmtime.Config()\n"
                "c = Store()\n"
                "d = wasmtime.Store(a)\n",
                encoding="utf-8",
            )
            hits = _direct_engine_calls(p)
        self.assertEqual(len(hits), 3, hits)


if __name__ == "__main__":
    unittest.main()
