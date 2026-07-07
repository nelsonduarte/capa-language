"""Feature #4 (F1): typed foreign-component declaration + quarantine
rule + manifest treatment.

This is the SOURCE-side increment: a program declares a typed foreign
Wasm Component Model boundary (``extern component Bureau from "..."``),
Capa type-checks calls across it and confines them to the declared
capability parameters, and the SBOM records the boundary as
authority-unknown TOP. The sandboxed RUNTIME that would make the bound
sound is a separate later increment (F2), so a program that actually
INVOKES a foreign component cannot yet be run or codegen'd.

The chosen surface (indentation body, like ``trait`` / ``capability``,
rather than braces)::

    extern component Bureau from "vendor/bureau.wasm"
        fun submit(net: Net, payload: Report) -> Receipt
"""

from __future__ import annotations

import io
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from capa import Lexer, Parser, analyze
from capa import capa_ast as A
from capa.cli import main
from capa.foreign import (
    extern_component_names,
    foreign_call_sites,
    module_invokes_foreign_component,
)
from capa.loader import ModuleLoader
from capa.manifest import build_composed_sbom, build_manifest


def _parse(source: str) -> A.Module:
    tokens = Lexer(source).lex()
    return Parser(tokens, source=source).parse_module()


def _analyse(source: str):
    module = _parse(source)
    return module, analyze(module, source=source)


def _errors(source: str) -> list[str]:
    _module, result = _analyse(source)
    return [e.message for e in result.errors]


def _ok(source: str):
    module, result = _analyse(source)
    if not result.ok:
        raise AssertionError(f"unexpected errors: {[e.message for e in result.errors]}")
    return module, result


_DECL = (
    "type Report { body: String }\n"
    "type Receipt { id: Int }\n"
    "extern component Bureau from \"vendor/bureau.wasm\"\n"
    "    fun submit(net: Net, payload: Report) -> Receipt\n"
)

_DECL_AND_CALL = _DECL + (
    "fun send(net: Net, r: Report) -> Receipt\n"
    "    return Bureau.submit(net, r)\n"
)


class TestParsing(unittest.TestCase):
    def test_declaration_parses(self):
        module = _parse(_DECL)
        ecs = [it for it in module.items if isinstance(it, A.ExternComponent)]
        self.assertEqual(len(ecs), 1)
        ec = ecs[0]
        self.assertEqual(ec.name, "Bureau")
        self.assertEqual(ec.artifact, "vendor/bureau.wasm")
        self.assertEqual([m.name for m in ec.methods], ["submit"])

    def test_declaration_checks_clean(self):
        _ok(_DECL)

    def test_call_checks_clean(self):
        _ok(_DECL_AND_CALL)

    def test_empty_body_rejected(self):
        with self.assertRaises(Exception):
            _parse(
                "extern component Bureau from \"b.wasm\"\n"
            )

    def test_missing_from_rejected(self):
        with self.assertRaises(Exception):
            _parse(
                "extern component Bureau \"b.wasm\"\n"
                "    fun go(net: Net) -> Int\n"
            )

    def test_component_and_from_still_usable_as_identifiers(self):
        # ``component`` / ``from`` are contextual keywords, only special
        # right after ``extern`` / the component name. They stay usable as
        # ordinary identifiers elsewhere.
        _ok(
            "fun f(component: Int, from: Int) -> Int\n"
            "    return component + from\n"
        )


class TestQuarantineRule(unittest.TestCase):
    def test_call_typechecks(self):
        _ok(_DECL_AND_CALL)

    def test_wrong_argument_type_rejected(self):
        errs = _errors(
            "type Report { body: String }\n"
            "extern component Bureau from \"b.wasm\"\n"
            "    fun submit(net: Net, payload: Report) -> Int\n"
            "fun send(net: Net) -> Int\n"
            "    return Bureau.submit(net, 5)\n"
        )
        self.assertTrue(any("argument 2 expects Report" in e for e in errs), errs)

    def test_capability_not_in_signature_rejected(self):
        # Handing Fs where the second parameter is a plain Int is a type
        # error: an extra capability cannot be smuggled across the
        # boundary that the signature does not declare.
        errs = _errors(
            "extern component Bureau from \"b.wasm\"\n"
            "    fun submit(net: Net, x: Int) -> Int\n"
            "fun send(net: Net, fs: Fs) -> Int\n"
            "    return Bureau.submit(net, fs)\n"
        )
        self.assertTrue(any("got Fs" in e for e in errs), errs)

    def test_ambient_capability_is_undefined(self):
        # There is no ambient authority in Capa: a capability value can
        # only be a parameter of the enclosing function. Referencing one
        # the function does not declare is an undefined name.
        errs = _errors(
            "extern component Bureau from \"b.wasm\"\n"
            "    fun submit(net: Net, x: Int) -> Int\n"
            "fun send(x: Int) -> Int\n"
            "    return Bureau.submit(net, x)\n"
        )
        self.assertTrue(any("net" in e and "undefined" in e for e in errs), errs)

    def test_same_capability_aliased_twice_rejected(self):
        errs = _errors(
            "extern component Bureau from \"b.wasm\"\n"
            "    fun submit(a: Net, b: Net) -> Int\n"
            "fun send(net: Net) -> Int\n"
            "    return Bureau.submit(net, net)\n"
        )
        self.assertTrue(any("cannot be aliased" in e for e in errs), errs)

    def test_unknown_method_rejected(self):
        errs = _errors(
            "extern component Bureau from \"b.wasm\"\n"
            "    fun submit(net: Net) -> Int\n"
            "fun send(net: Net) -> Int\n"
            "    return Bureau.nope(net)\n"
        )
        self.assertTrue(
            any("no method 'nope'" in e for e in errs), errs
        )

    def test_arity_mismatch_rejected(self):
        errs = _errors(
            "extern component Bureau from \"b.wasm\"\n"
            "    fun submit(net: Net, x: Int) -> Int\n"
            "fun send(net: Net) -> Int\n"
            "    return Bureau.submit(net)\n"
        )
        self.assertTrue(any("expected 2 arguments" in e for e in errs), errs)


class TestUnsafeRejection(unittest.TestCase):
    def test_unsafe_capability_param_rejected(self):
        errs = _errors(
            "extern component Bad from \"b.wasm\"\n"
            "    fun go(u: Unsafe) -> Int\n"
        )
        self.assertTrue(
            any("Unsafe" in e and "escape hatch" in e for e in errs), errs
        )

    def test_unsafe_nested_in_crossing_type_rejected(self):
        errs = _errors(
            "type Wrap { u: Unsafe }\n"
            "extern component Bad from \"b.wasm\"\n"
            "    fun go(net: Net, w: Wrap) -> Int\n"
        )
        self.assertTrue(any("Unsafe" in e for e in errs), errs)


class TestNonCrossableTypes(unittest.TestCase):
    def test_fun_in_crossing_param_rejected(self):
        errs = _errors(
            "extern component Bad from \"b.wasm\"\n"
            "    fun go(net: Net, cb: Fun(Int) -> Int) -> Int\n"
        )
        self.assertTrue(
            any("function / closure type" in e for e in errs), errs
        )

    def test_fun_in_return_rejected(self):
        errs = _errors(
            "extern component Bad from \"b.wasm\"\n"
            "    fun go(net: Net) -> Fun(Int) -> Int\n"
        )
        self.assertTrue(
            any("function / closure type" in e for e in errs), errs
        )

    def test_user_capability_param_rejected(self):
        errs = _errors(
            "capability Logger\n"
            "    fun log(self, msg: String)\n"
            "extern component Bad from \"b.wasm\"\n"
            "    fun go(lg: Logger) -> Int\n"
        )
        self.assertTrue(
            any("user-defined capability" in e for e in errs), errs
        )

    def test_fun_in_struct_field_param_rejected(self):
        errs = _errors(
            "type Box { f: Fun() -> Unit }\n"
            "extern component B from \"b.wasm\"\n"
            "    fun go(b: Box) -> Int\n"
        )
        self.assertTrue(any("function / closure type" in e for e in errs), errs)

    def test_fun_in_struct_field_return_rejected(self):
        errs = _errors(
            "type Box { f: Fun() -> Unit }\n"
            "extern component B from \"b.wasm\"\n"
            "    fun go(x: Int) -> Box\n"
        )
        self.assertTrue(any("function / closure type" in e for e in errs), errs)

    def test_fun_in_list_inside_struct_field_rejected(self):
        errs = _errors(
            "type Box { xs: List<Fun() -> Unit> }\n"
            "extern component B from \"b.wasm\"\n"
            "    fun go(b: Box) -> Int\n"
        )
        self.assertTrue(any("function / closure type" in e for e in errs), errs)

    def test_fun_in_sum_variant_payload_rejected(self):
        errs = _errors(
            "type Wrap =\n"
            "    W(Fun() -> Unit)\n"
            "extern component B from \"b.wasm\"\n"
            "    fun go(w: Wrap) -> Int\n"
        )
        self.assertTrue(any("function / closure type" in e for e in errs), errs)

    def test_fun_in_sum_variant_payload_return_rejected(self):
        errs = _errors(
            "type Wrap =\n"
            "    W(Fun() -> Unit)\n"
            "extern component B from \"b.wasm\"\n"
            "    fun go(x: Int) -> Wrap\n"
        )
        self.assertTrue(any("function / closure type" in e for e in errs), errs)

    def test_fun_in_struct_of_struct_param_rejected(self):
        errs = _errors(
            "type Inner { f: Fun() -> Unit }\n"
            "type Outer { inner: Inner }\n"
            "extern component B from \"b.wasm\"\n"
            "    fun go(o: Outer) -> Int\n"
        )
        self.assertTrue(any("function / closure type" in e for e in errs), errs)

    def test_fun_in_struct_of_struct_return_rejected(self):
        errs = _errors(
            "type Inner { f: Fun() -> Unit }\n"
            "type Outer { inner: Inner }\n"
            "extern component B from \"b.wasm\"\n"
            "    fun go(x: Int) -> Outer\n"
        )
        self.assertTrue(any("function / closure type" in e for e in errs), errs)

    def test_end_to_end_fun_field_smuggle_rejected(self):
        # The confirmed escape from the adversarial review: a struct with
        # a Fun-typed field, whose closure captures Stdio, handed across
        # the boundary would smuggle Stdio with declared_capabilities=[].
        errs = _errors(
            "type Box { f: Fun() -> Unit }\n"
            "extern component Bureau from \"b.wasm\"\n"
            "    fun submit(b: Box) -> Unit\n"
            "fun run(stdio: Stdio)\n"
            "    let leak = fun () => stdio.println(\"crossed\")\n"
            "    let b = Box { f: leak }\n"
            "    Bureau.submit(b)\n"
        )
        self.assertTrue(any("function / closure type" in e for e in errs), errs)

    def test_recursive_clean_crossing_type_accepted(self):
        # A recursive named type with NO Fun / cap / Unsafe anywhere must
        # still be accepted: the fixpoint is cycle-guarded, not
        # over-rejecting.
        _ok(
            "type Tree { kids: List<Tree>, v: Int }\n"
            "type Report { body: String, t: Tree }\n"
            "extern component B from \"b.wasm\"\n"
            "    fun go(net: Net, r: Report) -> Report\n"
            "fun run(net: Net, r: Report) -> Report\n"
            "    return B.go(net, r)\n"
        )

    def test_cap_bearing_struct_param_rejected(self):
        # A struct that implements a user capability may hold a built-in
        # cap in a field (``SmtpMailer { net: Net }``). Handing it across
        # the boundary as a crossing value type would smuggle Net past the
        # declared-parameter discipline; it is rejected. (Regression: the
        # crossing check must run AFTER ``implements`` is populated.)
        errs = _errors(
            "capability Mailer\n"
            "    fun send(self, to: String)\n"
            "type SmtpMailer { net: Net }\n"
            "impl Mailer for SmtpMailer\n"
            "    fun send(self, to: String)\n"
            "        return\n"
            "extern component Bad from \"b.wasm\"\n"
            "    fun go(net: Net, box: SmtpMailer) -> Int\n"
        )
        self.assertTrue(
            any("SmtpMailer" in e and "nested" in e for e in errs), errs
        )

    def test_generic_method_rejected(self):
        errs = _errors(
            "extern component Bad from \"b.wasm\"\n"
            "    fun go<T>(net: Net, x: T) -> T\n"
        )
        self.assertTrue(any("cannot be generic" in e for e in errs), errs)

    def test_capability_nested_in_return_rejected(self):
        # A capability tucked inside a crossing value type (here a tuple
        # return) cannot cross the boundary: caps cross only as explicit
        # top-level parameters.
        errs = _errors(
            "extern component Bad from \"b.wasm\"\n"
            "    fun go(net: Net) -> (Int, Net)\n"
        )
        self.assertTrue(any("cannot appear in return type" in e for e in errs), errs)


class TestManifest(unittest.TestCase):
    def _manifest(self, source: str):
        module, result = _ok(source)
        return build_manifest(module, expr_labels=result.expr_labels)

    def test_foreign_components_block_records_boundary(self):
        m = self._manifest(_DECL_AND_CALL)
        block = m["foreign_components"]
        self.assertEqual(len(block), 1)
        entry = block[0]
        self.assertEqual(entry["name"], "Bureau")
        self.assertEqual(entry["artifact"], "vendor/bureau.wasm")
        self.assertEqual(entry["declared_capabilities"], ["Net"])
        self.assertEqual(entry["authority"], "unproven-top")
        self.assertEqual([mm["name"] for mm in entry["methods"]], ["submit"])
        self.assertEqual(
            entry["methods"][0]["declared_capabilities"], ["Net"],
        )

    def test_calling_function_flagged(self):
        m = self._manifest(_DECL_AND_CALL)
        send = next(f for f in m["functions"] if f["source_name"] == "send")
        self.assertTrue(send["calls_foreign_component"])
        self.assertEqual(send["foreign_component_calls"], ["Bureau.submit"])

    def test_non_calling_function_not_flagged(self):
        m = self._manifest(_DECL + "fun other() -> Int\n    return 1\n")
        other = next(f for f in m["functions"] if f["source_name"] == "other")
        self.assertFalse(other["calls_foreign_component"])
        self.assertEqual(other["foreign_component_calls"], [])

    def test_summary_counts(self):
        m = self._manifest(_DECL_AND_CALL)
        self.assertEqual(m["summary"]["foreign_components"], 1)
        self.assertEqual(
            m["summary"]["functions_calling_foreign_components"], 1,
        )

    def test_no_foreign_components_empty_block(self):
        m = self._manifest("fun f() -> Int\n    return 1\n")
        self.assertEqual(m["foreign_components"], [])
        self.assertEqual(m["summary"]["foreign_components"], 0)


class TestForeignHelpers(unittest.TestCase):
    def test_names_and_sites(self):
        module = _parse(_DECL_AND_CALL)
        self.assertEqual(extern_component_names(module), {"Bureau"})
        sites = foreign_call_sites(module, {"Bureau"})
        self.assertEqual([(c, m) for c, m, _ in sites], [("Bureau", "submit")])

    def test_module_invokes_true_and_false(self):
        self.assertTrue(module_invokes_foreign_component(_parse(_DECL_AND_CALL)))
        self.assertFalse(module_invokes_foreign_component(_parse(_DECL)))


class TestComposedAuthority(unittest.TestCase):
    """The boundary composes as authority-unknown TOP: F1 records the
    declared bound but does not ENFORCE it, so claiming a bounded node
    now would be unsound. F2 flips it to bounded."""

    def test_calling_program_composes_as_top(self):
        tmp = Path(tempfile.mkdtemp(prefix="capa_foreign_"))
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        root = tmp / "prod"
        (root).mkdir(parents=True, exist_ok=True)
        (root / "capa.toml").write_text(
            '[package]\nname = "p"\nversion = "0.1.0"\n', encoding="utf-8",
        )
        (root / "main.capa").write_text(_DECL_AND_CALL, encoding="utf-8")
        filename = str(root / "main.capa")
        source = (root / "main.capa").read_text(encoding="utf-8")
        loader = ModuleLoader(search_paths=[root.resolve()])
        linked = loader.load_root(source, filename)
        result = analyze(
            linked.module, source=source, filename=filename,
            sources=linked.sources,
        )
        self.assertTrue(result.ok, [e.message for e in result.errors])
        manifest = build_manifest(
            linked.module, filename=filename, expr_labels=result.expr_labels,
        )
        composed = build_composed_sbom(
            linked.module, manifest, root.resolve(),
        )
        self.assertTrue(composed["composed"]["authority_unknown"])
        reasons = composed["composed"]["authority_unknown_reasons"]
        self.assertTrue(
            any("foreign component" in r.get("reason", "") for r in reasons),
            reasons,
        )


def _run_cli(argv, cwd):
    out, err = io.StringIO(), io.StringIO()
    patches = [
        mock.patch.object(sys, "argv", ["capa"] + list(argv)),
        mock.patch.object(sys, "stdout", out),
        mock.patch.object(sys, "stderr", err),
    ]
    original = os.getcwd()
    try:
        os.chdir(str(cwd))
        for p in patches:
            p.start()
        try:
            rc = main()
        except SystemExit as e:
            rc = e.code if isinstance(e.code, int) else (0 if e.code is None else 1)
        return rc, out.getvalue(), err.getvalue()
    finally:
        for p in reversed(patches):
            p.stop()
        os.chdir(original)


class TestCliRunGuard(unittest.TestCase):
    def _write(self, td, source):
        p = Path(td) / "prog.capa"
        p.write_text(source, encoding="utf-8")
        return p

    def test_run_invoking_aggregate_foreign_fails_f2b(self):
        # ``_DECL_AND_CALL`` crosses aggregate types (Report / Receipt),
        # which F2a does not marshal at runtime yet: any execution path
        # (here the Python backend) reports the clean F2b error.
        with tempfile.TemporaryDirectory() as td:
            p = self._write(td, _DECL_AND_CALL + "fun main() -> Int\n    return 0\n")
            rc, _out, err = _run_cli(["--run", str(p)], cwd=td)
            self.assertEqual(rc, 1)
            self.assertIn("String or aggregate crossing type", err)
            self.assertIn("F2b", err)

    def test_wasm_invoking_aggregate_foreign_fails_f2b(self):
        # Same aggregate call on the Wasm backend: still the F2b error
        # (the parent-import leg needs the linear-memory canonical ABI).
        with tempfile.TemporaryDirectory() as td:
            p = self._write(td, _DECL_AND_CALL + "fun main() -> Int\n    return 0\n")
            rc, _out, err = _run_cli(["--wasm", "--run", str(p)], cwd=td)
            self.assertEqual(rc, 1)
            self.assertIn("String or aggregate crossing type", err)
            self.assertIn("F2b", err)

    def test_check_unaffected(self):
        with tempfile.TemporaryDirectory() as td:
            p = self._write(td, _DECL_AND_CALL)
            rc, out, _err = _run_cli(["--check", str(p)], cwd=td)
            self.assertEqual(rc, 0)
            self.assertIn("ok", out)

    def test_manifest_unaffected(self):
        with tempfile.TemporaryDirectory() as td:
            p = self._write(td, _DECL_AND_CALL)
            rc, out, _err = _run_cli(["--manifest", str(p)], cwd=td)
            self.assertEqual(rc, 0)
            self.assertIn("foreign_components", out)

    def test_declaration_only_program_runs(self):
        # A program that only DECLARES a foreign component (never invokes
        # one) is inert and runs normally on both backends.
        with tempfile.TemporaryDirectory() as td:
            p = self._write(td, _DECL + "fun main() -> Int\n    return 0\n")
            rc, _out, _err = _run_cli(["--run", str(p)], cwd=td)
            self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
