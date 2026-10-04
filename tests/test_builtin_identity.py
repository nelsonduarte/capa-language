"""Builtin identity is decided in one place, and the backends agree.

Whether a call names a built-in is a MODULE-SCOPE fact: built-in names
are reserved for every lexical binder (see
``test_builtin_names_reserved``), so a built-in-named call is the
built-in exactly when the linked module declares no item of that name.
``capa._builtin_identity`` decides it once; the IR ``Call`` carries the
decision as a declared field (``callee_kind``) and every consumer reads
that field instead of re-deciding by name.

The module-level shapes below are refused by ``--check`` (a module-level
function may not take a built-in name), so to show that every backend
reads the ONE decision they are also compiled straight from the analyzed
AST, past the refusal, the way the compiler's internal lowering paths
compile a module. All three backends must then run the user function.

Pins:

- PIN-MODULE: every built-in function name x {top-level, dependency
  (bare, qualified, selected), selector alias in and out, transitive
  dependency, tail position}: refused by the analyzer, and the Python
  transpiler, the IR Python emitter and the Wasm backend agree.
- PIN-IMPORT: a module-level ``fun Random`` pulls in no Random host
  import on Wasm and no Random interface in WIT (RED-first); a
  module-level user ``panic`` with no built-in call pulls in no panic
  import (a regression guard: this half already held).
- PIN-AGREE: the PRODUCER check only. The analyzer binding, the
  module-scope decision and the IR ``callee_kind`` agree on a corpus of
  accepted programs. The consumers are pinned by PIN-MODULE and
  PIN-IMPORT, not by this.
"""

from __future__ import annotations

import io
import re
import shutil
import sys
import unittest
from pathlib import Path

from tests._builtin_name_corpus import (
    FUNCTION_SPECS,
    Project,
    assert_specs_cover,
    builtin_function_names,
    builtin_global_names,
    parse,
    renamed,
    TYPE_DECLS,
    type_decl,
    user_fun,
)

_REPO = Path(__file__).resolve().parent.parent


def _has_wasm_toolchain() -> bool:
    if shutil.which("wasm-tools") is None:
        return False
    try:
        import wasmtime  # noqa: F401
    except ImportError:
        return False
    return True


def _capture(thunk) -> str:
    buf, saved = io.StringIO(), sys.stdout
    sys.stdout = buf
    try:
        thunk()
    except BaseException as e:  # noqa: BLE001 - a crash is a result too
        buf.write(f"<{type(e).__name__}>")
    finally:
        sys.stdout = saved
    return buf.getvalue()


def _exec(code: str) -> str:
    def run():
        exec(compile(code, "<builtin-identity>", "exec"),
             {"__name__": "__main__"})
    return _capture(run)


def reserved_marker(name: str) -> str:
    return f"{name!r} is the name of a built-in"


# ---------------------------------------------------------------------------
# PIN-MODULE shapes. ``{N}`` is the built-in name, the user function behind
# it has FUNCTION_SPECS[N]'s shape. The root prints ``r=<marker>``.
# ---------------------------------------------------------------------------

_DEP = "helperpkg/util.capa"
_INNER = "innerpkg/inner.capa"


def _main_calling(call: str, spec: dict) -> str:
    return (
        "fun main(stdio: Stdio)\n"
        f"    let r = {call}\n"
        f"    stdio.println(\"r=${{{spec['post']}}}\")\n"
    )


def module_shapes(name: str) -> dict[str, dict[str, str]]:
    spec = FUNCTION_SPECS[name]
    call = f"{name}({spec['args']})"
    noop = "pub fun noop() -> Unit\n    return\n"
    return {
        "toplevel": {
            "main.capa": user_fun(name, spec) + "\n"
                         + _main_calling(call, spec),
        },
        "tail": {
            "main.capa": user_fun(name, spec) + "\n"
                         + f"fun go({spec['params']}) -> {spec['ret']}\n"
                         + f"    return {call}\n\n"
                         + _main_calling(f"go({spec['args']})", spec),
        },
        "dep_bare": {
            "main.capa": "import helperpkg.util as util\n\n"
                         + _main_calling(call, spec),
            _DEP: user_fun(name, spec, pub=True) + "\n" + noop,
        },
        "dep_qualified": {
            "main.capa": "import helperpkg.util as util\n\n"
                         + _main_calling(f"util.{call}", spec),
            _DEP: user_fun(name, spec, pub=True) + "\n" + noop,
        },
        "dep_selector": {
            "main.capa": f"import helperpkg.util ({name})\n\n"
                         + _main_calling(call, spec),
            _DEP: user_fun(name, spec, pub=True) + "\n" + noop,
        },
        "alias_in": {
            "main.capa": f"import helperpkg.util (other as {name})\n\n"
                         + _main_calling(call, spec),
            _DEP: user_fun("other", spec, pub=True) + "\n" + noop,
        },
        "alias_out": {
            "main.capa": f"import helperpkg.util ({name} as zz)\n\n"
                         + _main_calling(f"zz({spec['args']})", spec),
            _DEP: user_fun(name, spec, pub=True) + "\n" + noop,
        },
        "transitive": {
            "main.capa": "import helperpkg.util as util\n\n"
                         + _main_calling(call, spec),
            _DEP: "import innerpkg.inner as inner\n\n" + noop,
            _INNER: user_fun(name, spec, pub=True),
        },
    }


def _run_backends(files: dict[str, str], *, wasm: bool) -> dict[str, str]:
    """Analyze, then compile the analyzed AST on every backend PAST any
    refusal, and run each. A fresh link per backend keeps one backend's
    lowering from seeing another's mutations."""
    from capa import transpile
    from capa.ir import compile_program, compile_wasm
    out: dict[str, str] = {}

    def fresh():
        p = Project(files)
        try:
            linked, result = p.analyze()
        finally:
            p.close()
        return linked.module, result

    m, r = fresh()
    out["py"] = _exec(transpile(m, types=r.types, bindings=r.bindings))
    m, r = fresh()
    out["ir"] = _exec(compile_program(m, types=r.types, bindings=r.bindings))
    m, r = fresh()
    # The bindings-less lowering path (``--wit``, the internal lowerings).
    out["ir_nobind"] = _exec(compile_program(m, types=r.types))
    if wasm:
        from capa.runtime._wasm_host import WasmHost
        m, r = fresh()
        try:
            blob = compile_wasm(
                m, types=r.types, bindings=r.bindings, embed_manifest=False,
            )
            out["wasm"] = _capture(lambda: WasmHost().run_main(blob))
        except Exception as e:  # noqa: BLE001 - a build failure is a result
            out["wasm"] = f"<build {type(e).__name__}>"
    return out


class TestModuleLevelBuiltinNames(unittest.TestCase):
    """PIN-MODULE."""

    def test_specs_cover_every_builtin_function(self):
        assert_specs_cover(self)

    def test_module_level_builtin_names_are_refused(self):
        missed, cases = [], 0
        for name in builtin_function_names():
            for shape, files in module_shapes(name).items():
                cases += 1
                p = Project(files)
                try:
                    _, r = p.analyze()
                finally:
                    p.close()
                if not any(
                    reserved_marker(name) in e.message for e in r.errors
                ):
                    missed.append(f"{shape}:{name}")
        self.assertEqual(cases, 14 * 8)
        self.assertEqual(missed, [], f"{len(missed)} of {cases} accepted")

    def _agreement(self, *, wasm: bool) -> None:
        diverged, cases = [], 0
        for name in builtin_function_names():
            want = FUNCTION_SPECS[name]["umark"] + "\n"
            for shape, files in module_shapes(name).items():
                cases += 1
                got = _run_backends(files, wasm=wasm)
                if any(v != want for v in got.values()):
                    diverged.append(f"{shape}:{name}: {got}")
        self.assertEqual(cases, 14 * 8)
        self.assertEqual(
            diverged, [],
            f"{len(diverged)} of {cases} programs did not run the user "
            f"function on every backend:\n" + "\n".join(diverged),
        )

    def test_python_backends_run_the_user_function(self):
        self._agreement(wasm=False)

    @unittest.skipUnless(_has_wasm_toolchain(), "wasm toolchain not installed")
    def test_all_three_backends_run_the_user_function(self):
        self._agreement(wasm=True)


# ---------------------------------------------------------------------------
# PIN-IMPORT.
# ---------------------------------------------------------------------------

_FUN_RANDOM = (
    "fun Random() -> Int\n    return 5\n\n"
    "fun main(stdio: Stdio)\n    let r = Random()\n"
    "    stdio.println(\"r=${r}\")\n"
)

_USER_PANIC_ONLY = (
    "fun panic(m: String) -> Int\n    return 7\n\n"
    "fun main(stdio: Stdio)\n    let r = panic(\"benign\")\n"
    "    stdio.println(\"r=${r}\")\n"
)


def _wat_and_wit(src: str) -> tuple[str, str]:
    from capa import analyze
    from capa.ir import compile_wat, compile_wit
    m = parse(src)
    r = analyze(m, source=src)
    wat = compile_wat(m, types=r.types, bindings=r.bindings,
                      embed_manifest=False)
    m = parse(src)
    r = analyze(m, source=src)
    wit = compile_wit(m, types=r.types)
    return wat, wit


def _wat_untyped(src: str) -> str:
    """The WAT of ``src`` lowered with no analysis at all (no types, no
    bindings), as the compiler's internal lowering paths lower a module.
    A lowering failure is a result too (a twin must fail the same way)."""
    from capa.ir import compile_wat
    try:
        return compile_wat(parse(src), embed_manifest=False)
    except Exception as e:  # noqa: BLE001
        return f"<{type(e).__name__}: {e}>"


def _imports(wat: str) -> list[str]:
    return [ln.strip() for ln in wat.splitlines() if "(import " in ln]


def _param_names(spec: dict) -> list[str]:
    return [
        p.split(":")[0].strip() for p in spec["params"].split(",")
        if p.strip()
    ]


class TestBuiltinImports(unittest.TestCase):
    """PIN-IMPORT."""

    def test_user_random_function_pulls_in_no_random_import(self):
        # RED-first: the Wasm discovery used to decide ``Random`` by name.
        wat, wit = _wat_and_wit(_FUN_RANDOM)
        self.assertFalse(
            [i for i in _imports(wat) if "random" in i], _imports(wat),
        )
        self.assertNotIn("interface random", wit)

    def test_user_panic_function_pulls_in_no_panic_import(self):
        # Regression guard, not RED-first: this half already held.
        wat, wit = _wat_and_wit(_USER_PANIC_ONLY)
        self.assertFalse(
            [i for i in _imports(wat) if "capa:host/panic" in i],
            _imports(wat),
        )
        self.assertNotIn("import panic;", wit)

    def test_wat_and_wit_agree_on_the_panic_import(self):
        # The core module and the WIT world read ONE panic-reachability
        # decision, so they cannot disagree.
        programs = {
            "builtin": 'fun main()\n    panic("benign")\n',
            "unwrap": (
                "fun main()\n    let o: Option<Int> = Some(1)\n"
                "    let v = o.unwrap()\n"
            ),
            "none": "fun main()\n    let v = 1\n",
            "user": _USER_PANIC_ONLY,
        }
        expected = {"builtin": True, "unwrap": True, "none": False,
                    "user": False}
        for label, src in programs.items():
            wat, wit = _wat_and_wit(src)
            in_wat = any("capa:host/panic" in i for i in _imports(wat))
            in_wit = "import panic;" in wit
            self.assertEqual((label, in_wat), (label, expected[label]))
            self.assertEqual((label, in_wit), (label, expected[label]))

    @unittest.skipUnless(_has_wasm_toolchain(), "wasm toolchain not installed")
    def test_user_random_function_runs_on_every_backend(self):
        got = _run_backends({"main.capa": _FUN_RANDOM}, wasm=True)
        self.assertEqual(
            got, {k: "r=5\n" for k in ("py", "ir", "ir_nobind", "wasm")},
        )

    def test_module_function_compiles_exactly_like_its_renamed_twin(self):
        # The strongest consumer net: a module whose function merely has a
        # built-in's name must compile to the SAME core module as the twin
        # whose function has a fresh name (modulo that name). Any consumer
        # that decides by name instead of reading the Call's callee_kind
        # leaves a footprint here: an intrinsic in place of the call, a
        # runtime helper or host import, the bundled JSON parser, or a
        # lost ``return_call`` in tail position.
        differ, cases = [], 0
        for name in builtin_function_names():
            twin = renamed(name)
            for shape in ("toplevel", "tail"):
                src = module_shapes(name)[shape]["main.capa"]
                twin_src = re.sub(rf"\b{re.escape(name)}\b", twin, src)
                # With the analysis' types (the CLI path), and with none
                # (the compiler's analysis-free lowering path).
                for label, compile_ in (
                    ("typed", lambda s: _wat_and_wit(s)[0]),
                    ("untyped", _wat_untyped),
                ):
                    cases += 1
                    wat = compile_(src)
                    twin_wat = re.sub(
                        rf"\b{re.escape(twin)}\b", name, compile_(twin_src),
                    )
                    if wat != twin_wat:
                        differ.append(f"{shape}:{label}:{name}")
        self.assertEqual(cases, 14 * 2 * 2)
        self.assertEqual(differ, [], f"{len(differ)} of {cases} differ")


#: Built-in names that are not functions but that a backend still treats
#: specially at a call (``IoError(msg)`` builds the built-in value,
#: ``Random()`` the capability). A module function taking one of these
#: names is refused too; past the refusal every backend must run it.
_CONSTRUCTOR_NAMED = {
    "IoError": (
        "fun IoError(m: String) -> Int\n    return 5\n\n"
        "fun main(stdio: Stdio)\n    let r = IoError(\"benign\")\n"
        "    stdio.println(\"r=${r}\")\n"
    ),
    "Random": _FUN_RANDOM,
}


class TestConstructorNamedModuleFunctions(unittest.TestCase):

    def test_refused(self):
        for name, src in _CONSTRUCTOR_NAMED.items():
            p = Project({"main.capa": src})
            try:
                _, r = p.analyze()
            finally:
                p.close()
            self.assertTrue(
                any(reserved_marker(name) in e.message for e in r.errors),
                (name, [e.message for e in r.errors]),
            )

    def test_compiles_exactly_like_its_renamed_twin(self):
        for name, src in _CONSTRUCTOR_NAMED.items():
            twin = renamed(name)
            twin_src = re.sub(rf"\b{re.escape(name)}\b", twin, src)
            # With the analysis' types (the CLI path), and with none (the
            # compiler's analysis-free lowering path).
            for label, compile_ in (
                ("typed", lambda s: _wat_and_wit(s)[0]),
                ("untyped", _wat_untyped),
            ):
                self.assertEqual(
                    compile_(src),
                    re.sub(rf"\b{re.escape(twin)}\b", name, compile_(twin_src)),
                    (name, label),
                )

    @unittest.skipUnless(_has_wasm_toolchain(), "wasm toolchain not installed")
    def test_every_backend_runs_the_module_function(self):
        for name, src in _CONSTRUCTOR_NAMED.items():
            got = _run_backends({"main.capa": src}, wasm=True)
            self.assertEqual(
                got, {k: "r=5\n" for k in ("py", "ir", "ir_nobind", "wasm")},
                name,
            )


class TestSummaryTwin(unittest.TestCase):
    """Not RED-first (module scope was already exact for these shapes in
    the cross-function summary): a regression guard that the summary pass
    reads the one identity decision. The summary of a module whose
    function has a built-in's name equals that of its renamed twin."""

    def test_summary_matches_renamed_twin_for_every_builtin_function(self):
        from capa.analyzer import Analyzer
        differ = []
        for name in builtin_function_names():
            spec = FUNCTION_SPECS[name]
            twin = renamed(name)
            body = (
                user_fun(name, spec) + "\n"
                + f"fun relay({spec['params']}) -> {spec['ret']}\n"
                + f"    return {name}({', '.join(_param_names(spec))})\n"
            )
            got = []
            for src in (body, re.sub(rf"\b{re.escape(name)}\b", twin, body)):
                az = Analyzer(source=src)
                az.analyze(parse(src))
                summaries = (
                    az._ifc_summaries, az._ifc_field_effects,
                    az._ifc_return_effects, az._ifc_sink_caps,
                    az._ifc_sink_paths, az._ifc_capture_sink_paths,
                    az._ifc_sink_pc, az._ct_sensitive_params,
                )
                got.append(re.sub(
                    rf"\b{re.escape(twin)}\b", name, repr(summaries),
                ))
            if got[0] != got[1]:
                differ.append(name)
        self.assertEqual(differ, [])


# ---------------------------------------------------------------------------
# PIN-AGREE: the producer check (and only that).
# ---------------------------------------------------------------------------


def _accepted_corpus() -> list[tuple[str, str]]:
    """Every single-file example the analyzer accepts, plus programs that
    call each built-in function directly."""
    from capa import analyze
    out = []
    for path in sorted((_REPO / "examples").glob("*.capa")):
        src = path.read_text(encoding="utf-8")
        try:
            m = parse(src, filename=str(path))
        except Exception:  # noqa: BLE001 - a non-parsing example is skipped
            continue
        if any(type(it).__name__ == "Import" for it in m.items):
            continue
        if analyze(m, source=src).ok:
            out.append((path.name, src))
    out.append(("direct_calls", (
        "fun main(stdio: Stdio)\n"
        "    let a = to_int(1.5)\n    let b = to_float(2)\n"
        "    let c = parse_int(\"7\")\n    let d = parse_float(\"7.5\")\n"
        "    let m: Map<String, Int> = new_map()\n    m.set(\"k\", 1)\n"
        "    let s: Set<Int> = new_set()\n    s.add(1)\n"
        "    let j = parse_json(\"1\")\n"
        "    let o: Option<Int> = Some(1)\n"
        "    stdio.println(\"${a} ${b}\")\n"
    )))
    return out


class TestIdentityProducerAgreement(unittest.TestCase):
    """PIN-AGREE (producer only)."""

    def test_binding_decision_and_ir_field_agree(self):
        from capa import analyze
        from capa import capa_ast as A
        from capa._builtin_identity import (
            builtin_callee, is_builtin_symbol, module_scope_names,
        )
        from capa.ir import lower
        from capa.ir._nodes import Call
        from capa.ir._walk import walk_module
        reserved = set(builtin_global_names())
        disagree, seen_ast, seen_ir = [], 0, 0
        corpus = _accepted_corpus()
        self.assertGreater(len(corpus), 20)
        for label, src in corpus:
            m = parse(src)
            r = analyze(m, source=src)
            names = module_scope_names(m)
            for node in A.walk(m):
                if isinstance(node, A.Ident) and node.name in reserved:
                    sym = r.bindings.get(id(node))
                    if sym is None:
                        continue
                    seen_ast += 1
                    if is_builtin_symbol(sym) != builtin_callee(
                        node.name, names,
                    ):
                        disagree.append(f"{label}: ast {node.name}")
            ir_mod = lower(m, types=r.types, bindings=r.bindings)
            for _fn, instr in walk_module(ir_mod):
                if isinstance(instr, Call) and instr.callee_name in reserved:
                    seen_ir += 1
                    if instr.calls_builtin() != builtin_callee(
                        instr.callee_name, names,
                    ):
                        disagree.append(f"{label}: ir {instr.callee_name}")
        self.assertGreater(seen_ast, 50)
        self.assertGreater(seen_ir, 20)
        self.assertEqual(disagree, [])


# ---------------------------------------------------------------------------
# The guards around the one decision.
# ---------------------------------------------------------------------------


def _calls_named(module, name: str):
    from capa import capa_ast as A
    return [
        n for n in A.walk(module)
        if isinstance(n, A.Call) and isinstance(n.callee, A.Ident)
        and n.callee.name == name
    ]


class TestIdentityGuards(unittest.TestCase):

    def test_exit_analysis_reads_the_identity_decision(self):
        # ``panic("x")`` here names a declared TYPE, not the built-in abort,
        # so the function does not diverge and is missing its return. (The
        # type declaration itself is refused too; the analysis continues.)
        src = (
            "type panic { m: String }\n\n"
            "fun f() -> Int\n"
            "    panic(\"x\")\n"
        )
        from capa import analyze
        r = analyze(parse(src), source=src)
        self.assertTrue(
            any("not every path ends in `return`" in e.message
                for e in r.errors),
            [e.message for e in r.errors],
        )

    def test_a_binding_that_disagrees_with_the_decision_is_refused(self):
        from capa._builtin_identity import IdentityDisagreement, builtin_call
        from capa.analyzer import Symbol, SymbolKind
        from capa.builtins import BUILTIN_POS
        call = _calls_named(parse("fun f()\n    let z = to_int(1.5)\n"), "to_int")[0]
        user = Symbol(name="to_int", kind=SymbolKind.FUNCTION, pos=call.pos)
        builtin = Symbol(
            name="to_int", kind=SymbolKind.FUNCTION, pos=BUILTIN_POS,
        )
        # The module declares nothing: the decision is "built-in", so a
        # binding to a user symbol disagrees.
        with self.assertRaises(IdentityDisagreement):
            builtin_call(call, frozenset(), bindings={id(call.callee): user})
        # The module declares ``to_int``: the decision is "user", so a
        # binding to the built-in disagrees.
        with self.assertRaises(IdentityDisagreement):
            builtin_call(
                call, frozenset({"to_int"}),
                bindings={id(call.callee): builtin},
            )
        # Agreement passes in both directions.
        self.assertTrue(builtin_call(
            call, frozenset(), bindings={id(call.callee): builtin},
        ))
        self.assertFalse(builtin_call(
            call, frozenset({"to_int"}), bindings={id(call.callee): user},
        ))

    def test_module_scope_guard_fires_on_a_missing_name(self):
        from capa.analyzer import Analyzer
        src = "trait Shape\n    fun go(self) -> Int\n\nfun f() -> Int\n    return 1\n"
        m = parse(src)
        az = Analyzer(source=src)
        az._install_builtins()
        az._init_module_scope(m)
        az._collect_globals(m)
        az._assert_module_scope_agrees()  # consistent: no error
        az._module_scope_names = az._module_scope_names - {"Shape"}
        with self.assertRaises(AssertionError):
            az._assert_module_scope_agrees()

    def test_every_declaration_kind_takes_its_name_from_the_builtin(self):
        # For every kind of top-level declaration that can take a built-in
        # function's name, the identity decision says "not the built-in"
        # on every path: the module-scope names, the analyzer's own read,
        # and the IR lowered with no analysis. A control with no
        # declaration says "built-in" on the same paths.
        from capa import analyze
        from capa._builtin_identity import module_scope_names
        from capa.ir import lower
        from capa.ir._nodes import Call
        from capa.ir._walk import walk_module
        from capa.analyzer import Analyzer
        wrong, cases = [], 0

        def paths(src, name):
            m = parse(src)
            in_scope = name in module_scope_names(m)
            az = Analyzer(source=src)
            az.analyze(m)
            call = _calls_named(m, name)[0]
            analyzer_says = az._is_builtin_call(call, name)
            try:
                ir = lower(parse(src))
                ir_says = [
                    i.calls_builtin() for _f, i in walk_module(ir)
                    if isinstance(i, Call) and i.callee_name == name
                ]
            except Exception as e:  # noqa: BLE001 - recorded, compared
                ir_says = [f"<{type(e).__name__}>"]
            return in_scope, analyzer_says, ir_says

        for kind in TYPE_DECLS:
            for name in builtin_function_names():
                cases += 1
                use = (
                    "fun use_it()\n"
                    f"    let r = {name}({FUNCTION_SPECS[name]['args']})\n"
                )
                got = paths(type_decl(kind, name) + "\n" + use, name)
                if got[0] is not True or got[1] is not False or True in got[2]:
                    wrong.append(f"{kind}:{name}: {got}")
                ctrl = paths(use, name)
                if ctrl[0] is not False or ctrl[1] is not True:
                    wrong.append(f"control:{kind}:{name}: {ctrl}")
        self.assertEqual(cases, len(TYPE_DECLS) * 14)
        self.assertEqual(wrong, [])


if __name__ == "__main__":
    unittest.main()
