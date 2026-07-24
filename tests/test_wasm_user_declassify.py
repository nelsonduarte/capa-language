"""A user-defined ``fun declassify`` must be COMPILED AS A CALL, not
stripped to identity like the built-in.

``capa/ir/_lower_expr.py`` lowers the built-in ``declassify(value,
reason)`` to a compile-time identity relabel (roadmap S2.5): the value
flows through with no ``Call`` instruction emitted. That rewrite used to
key on the callee NAME, so a user-defined ``fun declassify(value,
reason)`` was silently bypassed on the Wasm backend: the call was
replaced by its first argument instead of being invoked. The same source
printed the user function's result under ``--run`` (Python) and the
untouched first argument under ``--run --wasm``, both exit 0, no
diagnostic -- a silent backend divergence.

The gate now keys on the callee's BINDING identity via the shared
``capa._declassify.is_declassify_call`` predicate (the one the analyzer
and the manifest already use), so only the built-in is stripped. These
tests pin:

- the lowering itself (no Wasm toolchain needed): a user ``declassify``
  leaves a ``Call`` in the CIR, the built-in leaves none;
- the runtime divergence: a user ``declassify`` with an observable
  return value produces identical output on both backends;
- the built-in still lowers to identity on Wasm (a no-op relabel, not a
  call to a function that does not exist);
- the gate keys on identity, not on the two-argument shape: a user
  ``declassify`` of a different arity is compiled as a call too.
"""

from __future__ import annotations

import dataclasses
import io
import shutil
import sys
import unittest

from capa import Lexer, Parser, analyze, transpile
from capa.ir import compile_wasm, lower
from capa.ir._nodes import Call


# A user function named ``declassify`` whose return value ("USERFUNC_RAN")
# is distinguishable from its first argument ("original"). If the call is
# wrongly stripped to identity, the program prints "original".
_USER_DECLASSIFY_SRC = (
    "fun declassify(value: String, reason: String) -> String\n"
    "    return \"USERFUNC_RAN\"\n"
    "fun main(stdio: Stdio)\n"
    "    let original = \"original\"\n"
    "    stdio.println(declassify(original, \"test\"))\n"
)

# A one-argument user ``declassify``: the gate must key on binding
# identity, not on the built-in's two-argument shape.
_USER_DECLASSIFY_ARITY1_SRC = (
    "fun declassify(value: String) -> String\n"
    "    return \"USERFUNC_RAN\"\n"
    "fun main(stdio: Stdio)\n"
    "    let original = \"original\"\n"
    "    stdio.println(declassify(original))\n"
)

# The BUILT-IN declassify on a genuinely @secret value. It must stay a
# compile-time identity relabel: the value ("sekret") flows through.
_BUILTIN_DECLASSIFY_SRC = (
    "fun reveal(token: @secret String, stdio: Stdio)\n"
    "    stdio.println(declassify(token, reason: \"audited\"))\n"
    "fun main(stdio: Stdio)\n"
    "    reveal(\"sekret\", stdio)\n"
)


def _has_wasm_tools() -> bool:
    return shutil.which("wasm-tools") is not None


def _has_wasmtime_py() -> bool:
    try:
        import wasmtime  # noqa: F401
        return True
    except ImportError:
        return False


def _parse_and_analyze(src: str):
    module = Parser(Lexer(src).lex(), source=src).parse_module()
    result = analyze(module, source=src)
    if not result.ok:
        raise AssertionError(
            f"analyzer errors: {[e.message for e in result.errors]}"
        )
    return module, result


def _find_calls(node, out: list) -> None:
    """Collect every :class:`Call` instruction reachable from ``node``,
    recursing through the dataclass fields (nested control-flow bodies,
    match arms) that carry instruction lists."""
    if isinstance(node, Call):
        out.append(node)
    if dataclasses.is_dataclass(node) and not isinstance(node, type):
        for f in dataclasses.fields(node):
            _find_calls(getattr(node, f.name), out)
    elif isinstance(node, (list, tuple)):
        for item in node:
            _find_calls(item, out)


def _declassify_calls(src: str) -> list:
    """Lower ``src`` (threading the analyzer bindings, as the shipping
    Wasm path does) and return every ``Call`` to ``declassify`` left in
    the CIR."""
    module, result = _parse_and_analyze(src)
    ir_mod = lower(module, types=result.types, bindings=result.bindings)
    calls: list = []
    for fn in ir_mod.functions:
        _find_calls(fn.body, calls)
    return [c for c in calls if c.callee_name == "declassify"]


def _capture_stdout(thunk) -> None:
    """Run ``thunk`` with stdout redirected; return the captured text."""
    buf = io.StringIO()
    saved = sys.stdout
    sys.stdout = buf
    try:
        thunk()
    finally:
        sys.stdout = saved
    return buf.getvalue()


def _run_python(src: str) -> str:
    module, result = _parse_and_analyze(src)
    code = transpile(module, types=result.types, bindings=result.bindings)
    ns: dict = {"__name__": "__main__"}
    return _capture_stdout(
        lambda: exec(compile(code, "<declassify>", "exec"), ns)
    )


def _run_wasm(src: str) -> str:
    # Imported inside the method so the module still collects without the
    # Wasm side-stack; the class-level skipUnless guards actual runs.
    from capa.runtime._wasm_host import WasmHost
    module, result = _parse_and_analyze(src)
    # Thread ``bindings`` exactly as the CLI's --wasm path does, so the
    # declassify lowering can resolve the callee by binding identity.
    blob = compile_wasm(module, types=result.types, bindings=result.bindings)
    return _capture_stdout(lambda: WasmHost().run_main(blob))


class TestUserDeclassifyLowering(unittest.TestCase):
    """CIR-level checks. No Wasm toolchain needed, so these always run."""

    def test_user_declassify_lowers_to_a_call(self):
        # The user function must be invoked: a Call to ``declassify``
        # survives lowering rather than being stripped to identity.
        self.assertEqual(len(_declassify_calls(_USER_DECLASSIFY_SRC)), 1)

    def test_user_declassify_arity1_lowers_to_a_call(self):
        self.assertEqual(
            len(_declassify_calls(_USER_DECLASSIFY_ARITY1_SRC)), 1
        )

    def test_builtin_declassify_leaves_no_call(self):
        # The built-in stays a compile-time identity relabel: no Call.
        self.assertEqual(len(_declassify_calls(_BUILTIN_DECLASSIFY_SRC)), 0)


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestUserDeclassifyBackendParity(unittest.TestCase):
    """Both-backend execution: the divergence that ships to users."""

    def test_user_declassify_runs_on_both_backends(self):
        py_out = _run_python(_USER_DECLASSIFY_SRC)
        wasm_out = _run_wasm(_USER_DECLASSIFY_SRC)
        # Pre-fix: Python printed "USERFUNC_RAN", Wasm printed "original".
        self.assertEqual(py_out, "USERFUNC_RAN\n")
        self.assertEqual(py_out, wasm_out)

    def test_user_declassify_arity1_runs_on_both_backends(self):
        py_out = _run_python(_USER_DECLASSIFY_ARITY1_SRC)
        wasm_out = _run_wasm(_USER_DECLASSIFY_ARITY1_SRC)
        self.assertEqual(py_out, "USERFUNC_RAN\n")
        self.assertEqual(py_out, wasm_out)

    def test_builtin_declassify_stays_identity_on_both_backends(self):
        py_out = _run_python(_BUILTIN_DECLASSIFY_SRC)
        wasm_out = _run_wasm(_BUILTIN_DECLASSIFY_SRC)
        # The built-in relabels @secret -> @public; the value flows on.
        self.assertEqual(py_out, "sekret\n")
        self.assertEqual(py_out, wasm_out)


if __name__ == "__main__":
    unittest.main()
