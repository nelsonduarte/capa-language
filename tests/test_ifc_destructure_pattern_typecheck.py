"""Type-checking a nominal struct-DESTRUCTURING pattern against its
scrutinee (closed IFC bypass + type-soundness hole).

A struct-destructuring pattern (``let Other { a } = t``,
``for Other { a } in xs``, or a ``match`` arm) binds each named field with
the type it has in the PATTERN's struct, never the scrutinee's. Before this
fix the pattern's struct name was never checked against the scrutinee's
type, so:

* a public-twin pattern over a ``@secret`` value laundered the secret into
  a public binding, silently, under ``@strict_ifc`` and on both backends
  (D2 / C1 / C3);
* a ``match`` twin added a silent Python-drops / Wasm-leaks divergence;
* a pattern naming a field the value lacks passed ``--check`` and then
  faulted at runtime (D1).

One reject upstream, in the pattern binder, closes all four: a rejected
program never reaches the IFC summary or codegen. Laundering is closed
EXACTLY when the scrutinee's static type is a CONCRETE struct in the module
type table; struct-ness is resolved through the GLOBAL type registry
(``global_scope``), not the value scope, so a local ``let`` / ``var`` /
``param`` / ``for`` binder named like the struct type cannot shadow the type
away and slip the guard.

DISCLOSED OPEN RESIDUALS (each accepted TODAY, pinned so a future tightening
is a deliberate, visible change):

* a GENERIC-TYPED struct field. The destructure binder assigns each bound
  name the pattern struct's RAW ``struct_fields`` type without substituting
  the scrutinee's generic ARGUMENTS, so a field whose declared type is a type
  parameter binds as a bare ``TyVar``, and a public-twin destructure of that
  ``TyVar`` launders (no concrete struct resolves, so the guard does not
  fire). NOT confined to a generic FUNCTION parameter (``fun f<T>(t: T)``
  then ``let Other { a } = t``): reachable from ordinary, fully concrete,
  non-generic code through any generic-typed struct field, e.g.
  ``let Box { v } = b; let Other { a } = v`` for ``b: Box<ASecret>`` (or via
  ``Pair<ASecret, _>``). ``--check`` stays clean even under ``@strict_ifc``;
  at runtime the split is Python-LEAKS / Wasm-ERRORS (the Wasm lowerer
  rejects the un-substituted ``TyVar``). Needs the binder to substitute the
  scrutinee's generic args into the field types (monomorphization);
* a TRAIT-typed scrutinee (``s: Shape`` then ``let OtherCircle { r } = s``):
  ``ty.name`` resolves to a trait, not a struct, so the downcast stays
  accepted and a public-twin downcast is not caught (Python leak / Wasm
  crash; needs a runtime tag check);
* a SUM / primitive scrutinee (``let Other { a } = <sum value>``): the
  scrutinee is not a struct in the table, so the mismatch is not caught
  here; it faults LOUD on both backends at runtime (a pre-existing
  D1-cousin, no silent leak).
"""

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from capa import Lexer, Parser, analyze, transpile
from capa.ir import compile_wasm


def _parse(src: str):
    return Parser(Lexer(src).lex(), source=src).parse_module()


def _analyze(src: str):
    return analyze(_parse(src), source=src)


def _strict(src: str, fn: str) -> str:
    """Opt the caller ``fn`` (holding the destructure) into ``@strict_ifc``
    -- the tier where an IFC flow is a hard error. A type error, by
    contrast, is a hard error at BOTH tiers."""
    return src.replace("fun " + fn + "(", "@strict_ifc()\nfun " + fn + "(", 1)


def _flow_warnings(r):
    return [w for w in r.warnings if "information-flow" in w.message]


def _flow_errors(r):
    return [e for e in r.errors if "information-flow" in e.message]


def _mismatch_errors(r):
    return [e for e in r.errors if "destructuring pattern names" in e.message]


def _capture(thunk) -> str:
    import io
    import sys as _sys
    buf = io.StringIO()
    saved = _sys.stdout
    _sys.stdout = buf
    try:
        thunk()
    finally:
        _sys.stdout = saved
    return buf.getvalue()


def _run_py(src: str) -> str:
    module = _parse(src)
    result = analyze(module, source=src)
    code = transpile(module, types=result.types, bindings=result.bindings)
    ns: dict = {"__name__": "__main__"}
    return _capture(lambda: exec(compile(code, "<dpt>", "exec"), ns))


def _run_wasm(src: str) -> str:
    from capa.runtime._wasm_host import WasmHost
    module = _parse(src)
    result = analyze(module, source=src)
    blob = compile_wasm(module, types=result.types)
    return _capture(lambda: WasmHost().run_main(blob))


def _wasm_unavailable():
    if shutil.which("wasm-tools") is None:
        return "wasm-tools not installed"
    try:
        import wasmtime  # noqa: F401
    except ImportError:
        return "wasmtime-py not installed"
    return None


def _cli(argv, cwd=None):
    """Run ``python -m capa`` in a child process; return the exit code."""
    proc = subprocess.run(
        [sys.executable, "-m", "capa", *argv],
        capture_output=True, text=True, encoding="utf-8", cwd=cwd,
    )
    return proc.returncode, proc.stdout, proc.stderr


# ---- shared type shapes ---------------------------------------------------

# A one-field secret struct and its PUBLIC TWIN (same field name, public
# label), plus a struct whose field is ABSENT from the secret struct.
_SEC = (
    "type ASecret { a: @secret String }\n"
    "type Other { a: String }\n"
    "type Ghost { z: String }\n"
)

# A three-level struct whose deepest leaf ``v`` is @secret, and a full PUBLIC
# TWIN of the same shape (``OtherOuter`` -> ``OtherMid`` -> ``OtherInner``,
# every leaf public). Destructuring an ``Outer`` value through the twin would
# launder the secret leaf into a public binding.
_DEEP = (
    "type Inner { v: @secret String, note: String }\n"
    "type Mid { f3: Inner }\n"
    "type Outer { f2: Mid }\n"
    "type OtherInner { v: String, note: String }\n"
    "type OtherMid { f3: OtherInner }\n"
    "type OtherOuter { f2: OtherMid }\n"
)
_MK = (
    "    let o = Outer { f2: Mid "
    "{ f3: Inner { v: \"s3cr3t\", note: \"pub\" } } }\n"
)


# ---- REJECT: a struct pattern over a concrete-struct scrutinee of a ------
# ---- DIFFERENT type is a hard type error at BOTH tiers -------------------

# D2: the public-twin destructure launders the secret field.
D2 = (_SEC +
    "fun leak(t: ASecret, stdio: Stdio)\n"
    "    let Other { a } = t\n"
    "    stdio.println(a)\n"
    "fun main(stdio: Stdio)\n"
    "    leak(ASecret { a: \"s3cr3t\" }, stdio)\n")

# C1: the deep-return twin -- destructure a field, return its @secret leaf.
C1 = (_DEEP +
    "fun leak(t: Outer) -> String\n"
    "    let OtherOuter { f2 } = t\n"
    "    return f2.f3.v\n"
    "fun main(stdio: Stdio)\n" + _MK +
    "    stdio.println(leak(o))\n")

# C3: the for-destructure twin over a List<Outer>.
C3 = (_DEEP +
    "fun leak(secs: List<Outer>) -> String\n"
    "    for OtherOuter { f2 } in secs\n"
    "        return f2.f3.v\n"
    "    return \"none\"\n"
    "fun main(stdio: Stdio)\n" + _MK +
    "    stdio.println(leak([o]))\n")

# The match twin (silent Python-drops / Wasm-leaks divergence pre-fix).
MATCH = (_SEC +
    "fun leak(t: ASecret, stdio: Stdio)\n"
    "    match t\n"
    "        Other { a } -> stdio.println(a)\n"
    "fun main(stdio: Stdio)\n"
    "    leak(ASecret { a: \"s3cr3t\" }, stdio)\n")

# D1: the pattern names a field the scrutinee lacks (runtime fault pre-fix).
D1 = (_SEC +
    "fun leak(t: ASecret, stdio: Stdio)\n"
    "    let Ghost { z } = t\n"
    "    stdio.println(z)\n"
    "fun main(stdio: Stdio)\n"
    "    leak(ASecret { a: \"s3cr3t\" }, stdio)\n")

# name -> (source, function holding the destructure)
_REJECT = {
    "D2_public_twin": (D2, "leak"),
    "C1_deep_return_twin": (C1, "leak"),
    "C3_for_destructure_twin": (C3, "leak"),
    "match_twin": (MATCH, "leak"),
    "D1_absent_field": (D1, "leak"),
}


class TestDestructureMismatchRejected(unittest.TestCase):
    """Every public-twin / wrong-type / absent-field destructure is a hard
    type error with ONE clean diagnostic, at the default tier AND under
    ``@strict_ifc``, and produces no IFC noise."""

    def test_one_clean_diagnostic_default_tier(self):
        for name, (src, _fn) in _REJECT.items():
            with self.subTest(shape=name):
                r = _analyze(src)
                self.assertFalse(r.ok)
                self.assertEqual(len(r.errors), 1,
                                 [e.message for e in r.errors])
                self.assertEqual(len(_mismatch_errors(r)), 1,
                                 [e.message for e in r.errors])
                self.assertEqual(len(_flow_warnings(r)), 0,
                                 [w.message for w in r.warnings])

    def test_one_clean_diagnostic_strict_tier(self):
        for name, (src, fn) in _REJECT.items():
            with self.subTest(shape=name):
                r = _analyze(_strict(src, fn))
                self.assertFalse(r.ok)
                self.assertEqual(len(_mismatch_errors(r)), 1,
                                 [e.message for e in r.errors])


class TestDestructureMismatchRefusedByRuntimes(unittest.TestCase):
    """A rejected program is refused by ``--check``, ``--run`` and
    ``--run --wasm`` alike (exit 1); it never reaches codegen."""

    def test_all_runtimes_refuse(self):
        with tempfile.TemporaryDirectory() as td:
            for name, (src, _fn) in _REJECT.items():
                with self.subTest(shape=name):
                    p = Path(td) / f"{name}.capa"
                    p.write_text(src, encoding="utf-8")
                    for argv in (
                        ["--check", str(p)],
                        ["--run", str(p)],
                        ["--run", "--wasm", str(p)],
                    ):
                        rc, _out, _err = _cli(argv)
                        self.assertEqual(rc, 1, (name, argv, _err))


# ---- SHADOW regression (Defect 1): a local binder named like the --------
# ---- scrutinee's struct type must NOT shadow the type away --------------

# In each shape the scrutinee's type ``Outer`` is also bound as a VALUE in the
# function's value scope. Resolving struct-ness through the value scope would
# find that binding (not a TYPE_STRUCT) and skip the guard, laundering the
# secret. Resolving through the global type registry keeps the reject.

# A ``let`` value shadow.
SHADOW_LET = (_DEEP +
    "fun leak(t: Outer) -> String\n"
    "    let Outer = \"x\"\n"
    "    let OtherOuter { f2 } = t\n"
    "    return f2.f3.v\n"
    "fun main(stdio: Stdio)\n" + _MK +
    "    stdio.println(leak(o))\n")

# A ``var`` value shadow.
SHADOW_VAR = (_DEEP +
    "fun leak(t: Outer) -> String\n"
    "    var Outer = \"x\"\n"
    "    let OtherOuter { f2 } = t\n"
    "    return f2.f3.v\n"
    "fun main(stdio: Stdio)\n" + _MK +
    "    stdio.println(leak(o))\n")

# A PARAMETER named like the struct type.
SHADOW_PARAM = (_DEEP +
    "fun leak(Outer: String, t: Outer) -> String\n"
    "    let OtherOuter { f2 } = t\n"
    "    return f2.f3.v\n"
    "fun main(stdio: Stdio)\n" + _MK +
    "    stdio.println(leak(\"z\", o))\n")

# A shadow in a NESTED block.
SHADOW_NESTED = (_DEEP +
    "fun leak(t: Outer, flag: Bool) -> String\n"
    "    if flag\n"
    "        let Outer = \"x\"\n"
    "        let OtherOuter { f2 } = t\n"
    "        return f2.f3.v\n"
    "    return \"none\"\n"
    "fun main(stdio: Stdio)\n" + _MK +
    "    stdio.println(leak(o, true))\n")

# A ``for``-loop binder named like the struct type.
SHADOW_FOR = (_DEEP +
    "fun leak(t: Outer, xs: List<String>) -> String\n"
    "    for Outer in xs\n"
    "        let OtherOuter { f2 } = t\n"
    "        return f2.f3.v\n"
    "    return \"none\"\n"
    "fun main(stdio: Stdio)\n" + _MK +
    "    stdio.println(leak(o, [\"a\"]))\n")

_SHADOW = {
    "shadow_let": SHADOW_LET,
    "shadow_var": SHADOW_VAR,
    "shadow_param": SHADOW_PARAM,
    "shadow_nested_block": SHADOW_NESTED,
    "shadow_for_binder": SHADOW_FOR,
}


class TestDestructureShadowStillRejected(unittest.TestCase):
    """A value binder named like the scrutinee's struct type does not shadow
    the type away: the guard resolves struct-ness through the global type
    registry, so every shadow shape still rejects with one clean
    diagnostic and is refused by both runtimes."""

    def test_shadow_rejected_one_diagnostic(self):
        for name, src in _SHADOW.items():
            with self.subTest(shape=name):
                r = _analyze(src)
                self.assertFalse(r.ok)
                self.assertEqual(len(r.errors), 1,
                                 [e.message for e in r.errors])
                self.assertEqual(len(_mismatch_errors(r)), 1,
                                 [e.message for e in r.errors])

    def test_shadow_refused_by_runtimes(self):
        with tempfile.TemporaryDirectory() as td:
            for name, src in _SHADOW.items():
                with self.subTest(shape=name):
                    p = Path(td) / f"{name}.capa"
                    p.write_text(src, encoding="utf-8")
                    for argv in (
                        ["--check", str(p)],
                        ["--run", str(p)],
                        ["--run", "--wasm", str(p)],
                    ):
                        rc, _out, _err = _cli(argv)
                        self.assertEqual(rc, 1, (name, argv, _err))


# ---- ACCEPT: a correct-type destructure passes, and the IFC deep-return --
# ---- channel it feeds still flags -----------------------------------------

# The correct-type deep-return destructure still LEAKS and must still flag.
ACCEPT_DEEP = (
    "type Inner { v: @secret String, note: String }\n"
    "type Mid { f3: Inner }\n"
    "type Outer { f2: Mid }\n"
    "fun leak(t: Outer) -> String\n"
    "    let Outer { f2 } = t\n"
    "    return f2.f3.v\n"
    "fun main(stdio: Stdio)\n" + _MK +
    "    stdio.println(leak(o))\n")

# The correct-type for-destructure still LEAKS and must still flag.
ACCEPT_FOR = (
    "type Inner { v: @secret String, note: String }\n"
    "type Mid { f3: Inner }\n"
    "type Outer { f2: Mid }\n"
    "fun leak(secs: List<Outer>) -> String\n"
    "    for Outer { f2 } in secs\n"
    "        return f2.f3.v\n"
    "    return \"none\"\n"
    "fun main(stdio: Stdio)\n" + _MK +
    "    stdio.println(leak([o]))\n")


class TestCorrectTypeDeepChannelStillFlags(unittest.TestCase):
    """The correct-type destructure is accepted, and the deep-return IFC
    channel it feeds still flags (warning at default, hard error under
    ``@strict_ifc``), and both backends print the secret."""

    def test_flags_both_tiers(self):
        for name, src in (("let", ACCEPT_DEEP), ("for", ACCEPT_FOR)):
            with self.subTest(shape=name):
                r = _analyze(src)
                self.assertTrue(r.ok, [e.message for e in r.errors])
                self.assertGreaterEqual(len(_flow_warnings(r)), 1,
                                        [w.message for w in r.warnings])
                rs = _analyze(_strict(src, "main"))
                self.assertFalse(rs.ok)
                self.assertGreaterEqual(len(_flow_errors(rs)), 1,
                                        [e.message for e in rs.errors])

    def test_leaks_both_backends(self):
        skip = _wasm_unavailable()
        for name, src in (("let", ACCEPT_DEEP), ("for", ACCEPT_FOR)):
            with self.subTest(shape=name):
                self.assertEqual(_run_py(src), "s3cr3t\n")
                if skip is None:
                    self.assertEqual(_run_wasm(src), "s3cr3t\n")


# ---- ACCEPT: correct-type shapes that must NOT trip the guard ------------

# Generic head: a ``Box<Int>`` value destructured by a ``Box`` pattern (head
# name matches, generic args ignored).
ACCEPT_GENERIC = (
    "type Box<T> { v: T }\n"
    "fun main(stdio: Stdio)\n"
    "    let b = Box { v: 3 }\n"
    "    let Box { v } = b\n"
    "    stdio.println(\"${v}\")\n")

# Trait downcast: ``let Circle { r } = s`` where ``s: Shape`` MUST stay
# accepted (the scrutinee type is a trait, not a struct).
ACCEPT_TRAIT_DOWNCAST = (
    "trait Shape\n"
    "    fun area(self) -> Int\n"
    "type Circle { r: Int }\n"
    "impl Shape for Circle\n"
    "    fun area(self) -> Int\n"
    "        return self.r\n"
    "fun f(s: Shape) -> Int\n"
    "    let Circle { r } = s\n"
    "    return r\n"
    "fun main(stdio: Stdio)\n"
    "    stdio.println(\"${f(Circle { r: 3 })}\")\n")

# A generic TYPE-VARIABLE scrutinee: no concrete struct resolves, accepted.
ACCEPT_TYVAR = (
    "type Rec { f2: Int }\n"
    "fun f<T>(t: T) -> Int\n"
    "    let Rec { f2 } = t\n"
    "    return f2\n"
    "fun main(stdio: Stdio)\n"
    "    stdio.println(\"${f(Rec { f2: 3 })}\")\n")

# Shorthand + rename in one pattern: ``{ f2: m, g }``.
ACCEPT_SHORTHAND_RENAME = (
    "type Rec2 { f2: Int, g: Int }\n"
    "fun main(stdio: Stdio)\n"
    "    let o = Rec2 { f2: 1, g: 2 }\n"
    "    let Rec2 { f2: m, g } = o\n"
    "    stdio.println(\"${m} ${g}\")\n")

# A correct-type match arm over a struct scrutinee.
ACCEPT_MATCH = (
    "type P { x: Int }\n"
    "fun main(stdio: Stdio)\n"
    "    let p = P { x: 5 }\n"
    "    match p\n"
    "        P { x } -> stdio.println(\"${x}\")\n")

# A variant / sum ``match`` is unaffected by the struct-pattern guard.
ACCEPT_VARIANT_MATCH = (
    "type Color =\n"
    "    Red\n"
    "    Blue\n"
    "fun name(c: Color) -> String\n"
    "    return match c\n"
    "        Red -> \"r\"\n"
    "        Blue -> \"b\"\n"
    "fun main(stdio: Stdio)\n"
    "    stdio.println(name(Red))\n")

_ACCEPT_CHECK = {
    "generic_head": ACCEPT_GENERIC,
    "trait_downcast": ACCEPT_TRAIT_DOWNCAST,
    "tyvar_scrutinee": ACCEPT_TYVAR,
    "shorthand_rename": ACCEPT_SHORTHAND_RENAME,
    "correct_match": ACCEPT_MATCH,
    "variant_match": ACCEPT_VARIANT_MATCH,
}


class TestCorrectTypeAccepted(unittest.TestCase):
    """Correct-type / generic-head / trait-downcast / tyvar / shorthand /
    match shapes are accepted with no destructuring-mismatch error."""

    def test_accepted(self):
        for name, src in _ACCEPT_CHECK.items():
            with self.subTest(shape=name):
                r = _analyze(src)
                self.assertTrue(r.ok, [e.message for e in r.errors])
                self.assertEqual(len(_mismatch_errors(r)), 0,
                                 [e.message for e in r.errors])


class TestTyUnknownScrutineeNoSpuriousError(unittest.TestCase):
    """A ``TyUnknown`` scrutinee (undefined RHS) yields only the pre-existing
    'undefined name' error, no spurious destructuring-mismatch cascade."""

    SRC = (
        "type Rec3 { f2: Int }\n"
        "fun main(stdio: Stdio)\n"
        "    let Rec3 { f2 } = undefined_thing\n"
        "    stdio.println(\"${f2}\")\n")

    def test_only_undefined_name(self):
        r = _analyze(self.SRC)
        self.assertFalse(r.ok)
        self.assertTrue(any("undefined name" in e.message for e in r.errors),
                        [e.message for e in r.errors])
        self.assertEqual(len(_mismatch_errors(r)), 0,
                         [e.message for e in r.errors])


class TestImportedCorrectTypeDestructureAccepted(unittest.TestCase):
    """A correct-type destructure of an IMPORTED struct is accepted: the
    global type registry carries the imported type, so the head-name match
    holds and the guard does not fire.

    Driven through the in-process loader + analyzer + transpiler (the tree
    under test), not a ``python -m capa`` subprocess: a subprocess resolves
    whatever ``capa`` is installed on PATH, which need not be this branch."""

    def test_imported_destructure_ok(self):
        from capa.loader import ModuleLoader
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            (tdp / "lib.capa").write_text(
                "pub type Point { x: Int, y: Int }\n"
                "pub fun origin() -> Point\n"
                "    return Point { x: 0, y: 0 }\n",
                encoding="utf-8",
            )
            root = tdp / "root.capa"
            root_src = (
                "import lib\n"
                "fun main(stdio: Stdio)\n"
                "    let Point { x, y } = origin()\n"
                "    stdio.println(\"${x} ${y}\")\n"
            )
            root.write_text(root_src, encoding="utf-8")
            linked = ModuleLoader().load_root(root_src, str(root))
            result = analyze(
                linked.module, source=root_src, filename=str(root),
                sources=linked.sources,
                module_privates=linked.module_privates,
            )
            self.assertTrue(result.ok, [e.message for e in result.errors])
            self.assertEqual(len(_mismatch_errors(result)), 0,
                             [e.message for e in result.errors])
            # End-to-end on the branch's transpiler: the accepted import
            # destructure runs and prints the imported struct's fields.
            code = transpile(
                linked.module, types=result.types,
                bindings=result.bindings,
            )
            ns: dict = {"__name__": "__main__"}
            out = _capture(
                lambda: exec(compile(code, "<imp>", "exec"), ns)
            )
            self.assertEqual(out, "0 0\n")


# ---- DISCLOSED-RESIDUAL pins (accepted TODAY, KNOWN-OPEN) ----------------

# A generic TYPE-PARAMETER scrutinee destructured via a public twin: no
# concrete struct resolves, so it is accepted and LEAKS on Python.
RES_TYVAR_LAUNDER = (_SEC +
    "fun leak<T>(t: T, stdio: Stdio)\n"
    "    let Other { a } = t\n"
    "    stdio.println(a)\n"
    "fun main(stdio: Stdio)\n"
    "    leak(ASecret { a: \"s3cr3t\" }, stdio)\n")

# The SAME residual reached from ORDINARY, fully concrete, non-generic code:
# ``b: Box<ASecret>`` destructured to ``v`` binds ``v`` as a raw ``TyVar T``
# (the binder does not substitute the scrutinee's generic arg into the field
# type), so the public-twin destructure of ``v`` launders. Accepted even
# under ``@strict_ifc``; Python LEAKS while Wasm ERRORS on the raw ``TyVar``.
RES_GENERIC_FIELD_LAUNDER = (_SEC +
    "type Box<T> { v: T }\n"
    "fun leak(b: Box<ASecret>, stdio: Stdio)\n"
    "    let Box { v } = b\n"
    "    let Other { a } = v\n"
    "    stdio.println(a)\n"
    "fun main(stdio: Stdio)\n"
    "    leak(Box { v: ASecret { a: \"s3cr3t\" } }, stdio)\n")

# A trait-typed scrutinee destructured via a public twin: ``ty.name`` is a
# trait, so the guard does not fire; accepted and LEAKS on Python.
RES_TRAIT_LAUNDER = (
    "trait Shape\n"
    "    fun area(self) -> Int\n"
    "type Circle { r: @secret Int }\n"
    "type OtherCircle { r: Int }\n"
    "impl Shape for Circle\n"
    "    fun area(self) -> Int\n"
    "        return 0\n"
    "fun leak(s: Shape, stdio: Stdio)\n"
    "    let OtherCircle { r } = s\n"
    "    stdio.println(\"${r}\")\n"
    "fun main(stdio: Stdio)\n"
    "    leak(Circle { r: 7 }, stdio)\n")

# A struct pattern over a SUM value: accepted at --check (not a struct
# scrutinee), then faults LOUD on both backends at runtime (a D1-cousin, no
# silent leak).
RES_SUM_D1_COUSIN = (
    "type Other { a: String }\n"
    "type Color =\n"
    "    Red\n"
    "    Blue\n"
    "fun main(stdio: Stdio)\n"
    "    let c = Red\n"
    "    let Other { a } = c\n"
    "    stdio.println(a)\n")


class TestDisclosedResidualsPinned(unittest.TestCase):
    """The disclosed open residuals behave AS DOCUMENTED: the generic and
    trait scrutinees are accepted and leak on Python; the sum-scrutinee
    D1-cousin is accepted at --check and faults loud on both backends."""

    def test_tyvar_launder_accepted_and_leaks(self):
        r = _analyze(RES_TYVAR_LAUNDER)
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_flow_warnings(r)), 0,
                         [w.message for w in r.warnings])
        self.assertEqual(_run_py(RES_TYVAR_LAUNDER), "s3cr3t\n")

    def test_generic_field_launder_from_concrete_code(self):
        # Reachable from ordinary concrete code: clean at BOTH tiers, then a
        # Python-LEAKS / Wasm-ERRORS split at runtime.
        r = _analyze(RES_GENERIC_FIELD_LAUNDER)
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_flow_warnings(r)), 0,
                         [w.message for w in r.warnings])
        rs = _analyze(_strict(RES_GENERIC_FIELD_LAUNDER, "leak"))
        self.assertEqual(len(_flow_errors(rs)), 0,
                         [e.message for e in rs.errors])
        self.assertEqual(_run_py(RES_GENERIC_FIELD_LAUNDER), "s3cr3t\n")
        # Wasm rejects the un-substituted TyVar (the disclosed split).
        if _wasm_unavailable() is None:
            with self.assertRaises(Exception):
                _run_wasm(RES_GENERIC_FIELD_LAUNDER)

    def test_trait_launder_accepted_and_leaks(self):
        r = _analyze(RES_TRAIT_LAUNDER)
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_mismatch_errors(r)), 0,
                         [e.message for e in r.errors])
        self.assertEqual(_run_py(RES_TRAIT_LAUNDER), "7\n")

    def test_sum_scrutinee_accepted_then_faults_loud(self):
        r = _analyze(RES_SUM_D1_COUSIN)
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_mismatch_errors(r)), 0,
                         [e.message for e in r.errors])
        # Fails LOUD on Python (no silent leak).
        with self.assertRaises(Exception):
            _run_py(RES_SUM_D1_COUSIN)
        # And LOUD on Wasm too, when the toolchain is present.
        if _wasm_unavailable() is None:
            with self.assertRaises(Exception):
                _run_wasm(RES_SUM_D1_COUSIN)


if __name__ == "__main__":
    unittest.main()
