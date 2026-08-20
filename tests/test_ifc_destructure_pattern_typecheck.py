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

A GENERIC-TYPED struct field is now CLOSED: the destructure binder
substitutes the scrutinee's generic ARGUMENTS into the field types, so a
field whose declared type is a type parameter (``v: T`` in ``Box<T>``) binds
at its instantiated CONCRETE type (``v: ASecret`` for a ``Box<ASecret>``
scrutinee). A downstream public-twin destructure of that field then resolves
a concrete struct and the mismatch guard fires, closing the launder that ran
through any generic-typed struct field from ordinary concrete code
(``let Box { v } = b; let Other { a } = v`` for ``b: Box<ASecret>``, or via
``Pair<ASecret, _>``).

The DIRECT RIGID generic TYPE-PARAMETER scrutinee is now closed. When the
scrutinee's static type is a bare type parameter (``fun f<T>(t: T)`` then
``let Other { a } = t``), or an intermediate whose field type substitutes to
itself (``fun f<T>(b: Box<T>)``, where ``v: T`` stays a ``TyVar``), the value
of ``T`` is opaque inside the generic body (parametricity), so destructuring
it as a concrete struct is an unsound downcast the binder now rejects. The
same reject also closes the differently-named generic-container intermediate
(``type Wrap<E>`` inside ``fun leak<T>``, whose payload stays a rigid
``TyVar('T')``), a strict improvement over base. The severity of the two arms
differs and the tests pin each accurately:

* the STRUCT-destructure channel (a rigid-``T`` value, or a ``Box<T>`` field
  bound at ``T``, destructured through a public twin) was a SILENT @secret
  leak on BOTH backends (both bind the field under the twin's public label
  and disclose the secret); this is the severe channel closed;
* the VARIANT-MATCH arm (a rigid-``T`` value matched against a concrete
  variant pattern) was NOT a silent both-backends leak: the Python backend
  structurally no-ops (the opaque value never matches the twin) and the Wasm
  backend faults loud. Rejecting it is fail-closed hardening and removes that
  backend divergence.

A FLEXIBLE ``?`` inference placeholder is EXCLUDED from the reject: an as-yet
unresolved element type (the empty-list for-destructure, ``let xs = [];
for Point { x } in xs``) is pinned to a concrete type later and stays legal.

The SAME-NAMED generic-constructor launder is now CLOSED. A rigid value
constructed through a generic STRUCT literal or VARIANT call whose type
parameter shares the caller's rigid NAME (``type Wrap<T>`` used inside
``fun leak<T>``, and the nested ``type Wrap<T> { v: List<T> }`` sibling) kept
its rigid provenance only up to the construction seam: ``unify``'s reflexive
same-name short-circuit returns without binding, and the seam then collapsed
the type argument to ``TyUnknown``, erasing the rigid ``T`` so a downstream
public-twin destructure resolved nothing and the @secret leaked, silently, on
both backends. A single shared construction-site helper
(``_constructor_result_args``, routed by both the struct-literal seam and the
variant-call seam) restores the rigid marker the seam was dropping: when a
field / payload carries the same rigid ``TyVar(p)`` unify left unbound, the
constructed value keeps ``TyVar(p)`` instead of erasing to ``TyUnknown``, so
the value behaves exactly like holding the rigid ``t`` directly and the
existing rigid-scrutinee reject fires at the twin destructure. ``unify`` is
untouched; a DIFFERENT constructor-parameter name (``type Wrap<E>``) already
bound the payload rigid and was already rejected. The remaining same-name
erasure SITES the prior analysis named (closure-return, ``?``-on-``Result``,
map/filter) are separate seams and stay open.

DISCLOSED OPEN RESIDUALS (each accepted TODAY, pinned so a future tightening
is a deliberate, visible change):

* a TRAIT-typed scrutinee (``s: Shape`` then ``let OtherCircle { r } = s``):
  ``ty.name`` resolves to a trait, not a struct and not a type variable, so
  the downcast stays accepted and a public-twin downcast is not caught
  (Python leak; needs a runtime tag check);
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
    "shorthand_rename": ACCEPT_SHORTHAND_RENAME,
    "correct_match": ACCEPT_MATCH,
    "variant_match": ACCEPT_VARIANT_MATCH,
}


class TestCorrectTypeAccepted(unittest.TestCase):
    """Correct-type / generic-head / trait-downcast / shorthand / match
    shapes are accepted with no destructuring-mismatch error."""

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


# ---- CLOSED: the generic-typed-field launder now REJECTS -----------------
#
# The binder substitutes the scrutinee's generic ARGUMENTS into the field
# types, so a field declared at a type parameter binds at its instantiated
# CONCRETE type and a downstream public-twin destructure trips the mismatch
# guard. Each shape below reached the silent launder before the fix and is
# now a hard type error at BOTH tiers, refused by both runtimes.

_BOX = "type Box<T> { v: T }\n"
_PAIR = "type Pair<A, B> { first: A, second: B }\n"
_WRAP = "type Wrap<T> { v: T }\n"

# Ordinary concrete code: a ``Box<ASecret>`` field bound, then twin-destructured.
CLOSED_GENERIC_FIELD = (_SEC + _BOX +
    "fun leak(b: Box<ASecret>, stdio: Stdio)\n"
    "    let Box { v } = b\n"
    "    let Other { a } = v\n"
    "    stdio.println(a)\n"
    "fun main(stdio: Stdio)\n"
    "    leak(Box { v: ASecret { a: \"s3cr3t\" } }, stdio)\n")

# The first field of a ``Pair<ASecret, Int>``.
CLOSED_PAIR_FIRST = (_SEC + _PAIR +
    "fun leak(p: Pair<ASecret, Int>, stdio: Stdio)\n"
    "    let Pair { first, second } = p\n"
    "    let Other { a } = first\n"
    "    stdio.println(a)\n"
    "fun main(stdio: Stdio)\n"
    "    leak(Pair { first: ASecret { a: \"s3cr3t\" }, second: 1 }, stdio)\n")

# A for-loop over ``List<Box<ASecret>>``.
CLOSED_FOR_BOX = (_SEC + _BOX +
    "fun leak(xs: List<Box<ASecret>>, stdio: Stdio)\n"
    "    for Box { v } in xs\n"
    "        let Other { a } = v\n"
    "        stdio.println(a)\n"
    "fun main(stdio: Stdio)\n"
    "    leak([Box { v: ASecret { a: \"s3cr3t\" } }], stdio)\n")

# A for-loop over ``List<Wrap<ASecret>>``.
CLOSED_FOR_WRAP = (_SEC + _WRAP +
    "fun leak(xs: List<Wrap<ASecret>>, stdio: Stdio)\n"
    "    for Wrap { v } in xs\n"
    "        let Other { a } = v\n"
    "        stdio.println(a)\n"
    "fun main(stdio: Stdio)\n"
    "    leak([Wrap { v: ASecret { a: \"s3cr3t\" } }], stdio)\n")

# A ``match`` arm StructPat twin over the bound field.
CLOSED_MATCH_TWIN = (_SEC + _BOX +
    "fun leak(b: Box<ASecret>, stdio: Stdio)\n"
    "    let Box { v } = b\n"
    "    match v\n"
    "        Other { a } -> stdio.println(a)\n"
    "fun main(stdio: Stdio)\n"
    "    leak(Box { v: ASecret { a: \"s3cr3t\" } }, stdio)\n")

# A nested ``Box<Box<ASecret>>``.
CLOSED_NESTED = (_SEC + _BOX +
    "fun leak(b: Box<Box<ASecret>>, stdio: Stdio)\n"
    "    let Box { v } = b\n"
    "    let Box { v: inner } = v\n"
    "    let Other { a } = inner\n"
    "    stdio.println(a)\n"
    "fun main(stdio: Stdio)\n"
    "    leak(Box { v: Box { v: ASecret { a: \"s3cr3t\" } } }, stdio)\n")

# A generic struct RETURNED from a function, then twin-destructured.
CLOSED_RETURNED = (_SEC + _BOX +
    "fun mk() -> Box<ASecret>\n"
    "    return Box { v: ASecret { a: \"s3cr3t\" } }\n"
    "fun leak(stdio: Stdio)\n"
    "    let Box { v } = mk()\n"
    "    let Other { a } = v\n"
    "    stdio.println(a)\n"
    "fun main(stdio: Stdio)\n"
    "    leak(stdio)\n")

_CLOSED_REJECT = {
    "generic_field": (CLOSED_GENERIC_FIELD, "leak"),
    "pair_first": (CLOSED_PAIR_FIRST, "leak"),
    "for_box": (CLOSED_FOR_BOX, "leak"),
    "for_wrap": (CLOSED_FOR_WRAP, "leak"),
    "match_twin": (CLOSED_MATCH_TWIN, "leak"),
    "nested_box": (CLOSED_NESTED, "leak"),
    "returned": (CLOSED_RETURNED, "leak"),
}


class TestGenericFieldLaunderNowRejected(unittest.TestCase):
    """The generic-typed-field launder is CLOSED: every shape is a hard type
    error with the mismatch diagnostic at the default tier AND under
    ``@strict_ifc``, and is refused by both runtimes."""

    def test_mismatch_at_both_tiers(self):
        for name, (src, fn) in _CLOSED_REJECT.items():
            with self.subTest(shape=name):
                r = _analyze(src)
                self.assertFalse(r.ok, [e.message for e in r.errors])
                self.assertEqual(len(_mismatch_errors(r)), 1,
                                 [e.message for e in r.errors])
                self.assertEqual(len(_flow_warnings(r)), 0,
                                 [w.message for w in r.warnings])
                rs = _analyze(_strict(src, fn))
                self.assertEqual(len(_mismatch_errors(rs)), 1,
                                 [e.message for e in rs.errors])

    def test_all_runtimes_refuse(self):
        with tempfile.TemporaryDirectory() as td:
            for name, (src, _fn) in _CLOSED_REJECT.items():
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


# ---- IFC FLAGS the direct secret field -----------------------------------
#
# The substitution binds the field at its concrete @secret type, so a DIRECT
# read of that field is now a genuine IFC flow: a warning at the default tier
# (the program still runs and prints the secret), a hard error under
# ``@strict_ifc``.

FLAG_BOX = (_SEC + _BOX +
    "fun leak(b: Box<ASecret>, stdio: Stdio)\n"
    "    let Box { v } = b\n"
    "    stdio.println(v.a)\n"
    "fun main(stdio: Stdio)\n"
    "    leak(Box { v: ASecret { a: \"s3cr3t\" } }, stdio)\n")

FLAG_PAIR = (_SEC + _PAIR +
    "fun leak(p: Pair<ASecret, Int>, stdio: Stdio)\n"
    "    let Pair { first, second } = p\n"
    "    stdio.println(first.a)\n"
    "fun main(stdio: Stdio)\n"
    "    leak(Pair { first: ASecret { a: \"s3cr3t\" }, second: 1 }, stdio)\n")

_FLAG = {"box": FLAG_BOX, "pair": FLAG_PAIR}


class TestDirectSecretFieldFlagged(unittest.TestCase):
    """A direct read of the now-concretely-typed @secret field flags: warning
    at the default tier (still runs, prints the secret on Python), hard error
    under ``@strict_ifc``."""

    def test_flags_both_tiers(self):
        for name, src in _FLAG.items():
            with self.subTest(shape=name):
                r = _analyze(src)
                self.assertTrue(r.ok, [e.message for e in r.errors])
                self.assertGreaterEqual(len(_flow_warnings(r)), 1,
                                        [w.message for w in r.warnings])
                rs = _analyze(_strict(src, "leak"))
                self.assertFalse(rs.ok)
                self.assertGreaterEqual(len(_flow_errors(rs)), 1,
                                        [e.message for e in rs.errors])

    def test_runs_and_leaks_on_python(self):
        for name, src in _FLAG.items():
            with self.subTest(shape=name):
                self.assertEqual(_run_py(src), "s3cr3t\n")


# ---- ACCEPT + run: every legitimate generic destructure passes and runs ---

# ``Box<Int>`` -> binds ``v: Int``.
OK_BOX_INT = (_BOX +
    "fun main(stdio: Stdio)\n"
    "    let b = Box { v: 3 }\n"
    "    let Box { v } = b\n"
    "    stdio.println(\"${v}\")\n")

# A nested ``Box<Box<Int>>``.
OK_NESTED_INT = (_BOX +
    "fun main(stdio: Stdio)\n"
    "    let b = Box { v: Box { v: 5 } }\n"
    "    let Box { v } = b\n"
    "    let Box { v: inner } = v\n"
    "    stdio.println(\"${inner}\")\n")

# A public field of a secret-bearing struct, read under ``@strict_ifc``.
_SEC2 = "type Sec { s: @secret String, note: String }\n"
OK_PUBLIC_FIELD = (_SEC2 + _BOX +
    "@strict_ifc()\n"
    "fun read(b: Box<Sec>, stdio: Stdio)\n"
    "    let Box { v } = b\n"
    "    stdio.println(v.note)\n"
    "fun main(stdio: Stdio)\n"
    "    read(Box { v: Sec { s: \"x\", note: \"ok\" } }, stdio)\n")

# A same-struct destructure of a public field.
OK_SAME_STRUCT = (_SEC2 +
    "fun main(stdio: Stdio)\n"
    "    let s = Sec { s: \"x\", note: \"ok\" }\n"
    "    let Sec { note } = s\n"
    "    stdio.println(note)\n")

# A for-loop ``for Box { v } in xs``.
OK_FOR = (_BOX +
    "fun main(stdio: Stdio)\n"
    "    let xs = [Box { v: 1 }, Box { v: 2 }]\n"
    "    for Box { v } in xs\n"
    "        stdio.println(\"${v}\")\n")

# A match arm ``Box { v }``.
OK_MATCH = (_BOX +
    "fun main(stdio: Stdio)\n"
    "    let b = Box { v: 7 }\n"
    "    match b\n"
    "        Box { v } -> stdio.println(\"${v}\")\n")

# A rename binder ``let Box { v: inner } = b``.
OK_RENAME = (_BOX +
    "fun main(stdio: Stdio)\n"
    "    let b = Box { v: 9 }\n"
    "    let Box { v: inner } = b\n"
    "    stdio.println(\"${inner}\")\n")

# A generic-head struct destructure cannot lower to Wasm: the Wasm backend
# rejects the field's type parameter with "type 'T' has no Wasm encoding" (a
# pre-existing, analyzer-INDEPENDENT limitation, present on base). These run
# on Python only. The one plain-struct shape (``same_struct``) runs on both.
_OK_RUN = {
    "box_int": (OK_BOX_INT, "3\n"),
    "nested_int": (OK_NESTED_INT, "5\n"),
    "public_field_strict": (OK_PUBLIC_FIELD, "ok\n"),
    "same_struct": (OK_SAME_STRUCT, "ok\n"),
    "for_loop": (OK_FOR, "1\n2\n"),
    "match_arm": (OK_MATCH, "7\n"),
    "rename": (OK_RENAME, "9\n"),
}
# Only the non-generic destructure lowers to Wasm.
_OK_RUN_WASM = {"same_struct"}


class TestLegitimateGenericDestructureRuns(unittest.TestCase):
    """Every legitimate generic-head destructure is accepted with no mismatch
    error and runs to the expected output on Python; the plain-struct shape
    runs on Wasm too."""

    def test_accepted(self):
        for name, (src, _out) in _OK_RUN.items():
            with self.subTest(shape=name):
                r = _analyze(src)
                self.assertTrue(r.ok, [e.message for e in r.errors])
                self.assertEqual(len(_mismatch_errors(r)), 0,
                                 [e.message for e in r.errors])

    def test_runs_python(self):
        for name, (src, out) in _OK_RUN.items():
            with self.subTest(shape=name):
                self.assertEqual(_run_py(src), out)

    def test_plain_struct_runs_wasm(self):
        if _wasm_unavailable() is not None:
            self.skipTest(_wasm_unavailable())
        for name in _OK_RUN_WASM:
            src, out = _OK_RUN[name]
            with self.subTest(shape=name):
                self.assertEqual(_run_wasm(src), out)


# ---- PRECISION GAIN: the fix REPAIRS two pre-existing false positives -----
#
# Before the fix, a field bound from a generic struct kept the raw ``TyVar``,
# so a field access or method call on it was WRONGLY rejected with "cannot
# access field / call method on a value of generic type parameter 'T'". The
# substitution binds the field at its concrete type, so both now type-check
# and run.

GAIN_FIELD = (
    "type Inner { n: Int }\n" + _BOX +
    "fun main(stdio: Stdio)\n"
    "    let b = Box { v: Inner { n: 42 } }\n"
    "    let Box { v } = b\n"
    "    stdio.println(\"${v.n}\")\n")

GAIN_METHOD = (
    "type Inner { n: Int }\n"
    "impl Inner\n"
    "    fun get(self) -> Int\n"
    "        return self.n\n" + _BOX +
    "fun main(stdio: Stdio)\n"
    "    let b = Box { v: Inner { n: 8 } }\n"
    "    let Box { v } = b\n"
    "    stdio.println(\"${v.get()}\")\n")

_GAIN = {"field_access": (GAIN_FIELD, "42\n"), "method_call": (GAIN_METHOD, "8\n")}


class TestPrecisionGainRepairedFalsePositives(unittest.TestCase):
    """The two pre-existing false positives (field access / method call on a
    field bound from a generic struct) are now accepted and run on Python.
    (Wasm cannot lower a generic-struct destructure at all; see above.)"""

    def test_accepted_and_runs_python(self):
        for name, (src, out) in _GAIN.items():
            with self.subTest(shape=name):
                r = _analyze(src)
                self.assertTrue(r.ok, [e.message for e in r.errors])
                self.assertEqual(_run_py(src), out)


# ---- CLOSED: the RIGID type-parameter scrutinee now REJECTS --------------
#
# A struct / variant destructuring pattern whose scrutinee's static type is a
# RIGID type variable (a bare declared ``T`` from ``fun f<T>``) is now a hard
# type error at BOTH tiers, refused by both runtimes. Inside the generic body
# the value of ``T`` is opaque (parametricity), so destructuring it as a
# concrete struct / variant is an unsound downcast; rejecting it also closes
# the @secret launder. The two arms differ in severity (see below).


def _variant_rigid_errors(r):
    return [e for e in r.errors
            if "cannot be matched as a concrete variant" in e.message]


# STRUCT ARM, SEVERE: a rigid-``T`` value destructured through a public twin
# is a SILENT @secret leak on BOTH backends. Now rejected.
RIGID_TYVAR_LAUNDER = (_SEC +
    "fun leak<T>(t: T, stdio: Stdio)\n"
    "    let Other { a } = t\n"
    "    stdio.println(a)\n"
    "fun main(stdio: Stdio)\n"
    "    leak(ASecret { a: \"s3cr3t\" }, stdio)\n")

# STRUCT ARM, SEVERE: a ``Box<T>`` intermediate inside a generic function.
# The field type ``T`` substitutes to itself and stays a ``TyVar``, so the
# second (twin) destructure has a rigid-``T`` scrutinee. A SILENT @secret leak
# on BOTH backends before this fix; now rejected at the twin destructure.
RIGID_BOX_INTERMEDIATE = (_SEC +
    "type Box<T> { v: T }\n"
    "fun leak<T>(b: Box<T>, stdio: Stdio)\n"
    "    let Box { v } = b\n"
    "    let Other { a } = v\n"
    "    stdio.println(a)\n"
    "fun main(stdio: Stdio)\n"
    "    leak(Box { v: ASecret { a: \"s3cr3t\" } }, stdio)\n")

# STRUCT ARM, non-secret but parametrically UNSOUND: the degenerate rigid-``T``
# destructure (formerly a ``tyvar_scrutinee`` accept). The compiler cannot
# prove the opaque ``T`` value is a ``Rec``; this is now rejected as a
# deliberate, visible tightening.
RIGID_DEGENERATE = (
    "type Rec { f2: Int }\n"
    "fun f<T>(t: T) -> Int\n"
    "    let Rec { f2 } = t\n"
    "    return f2\n"
    "fun main(stdio: Stdio)\n"
    "    stdio.println(\"${f(Rec { f2: 3 })}\")\n")

_RIGID_STRUCT_REJECT = {
    "tyvar_launder": (RIGID_TYVAR_LAUNDER, "leak"),
    "box_intermediate": (RIGID_BOX_INTERMEDIATE, "leak"),
    "degenerate": (RIGID_DEGENERATE, "f"),
}

# VARIANT ARM, fail-closed hardening (NOT a silent both-backends leak): a
# rigid-``T`` value matched against a concrete variant pattern. Before this
# fix the Python backend structurally no-ops and the Wasm backend faults loud;
# rejecting it removes that divergence. One diagnostic per offending arm.
RIGID_VARIANT_MATCH = (
    "fun f<T>(t: T) -> Int\n"
    "    match t\n"
    "        Some(x) -> return 1\n"
    "        None -> return 0\n"
    "fun main(stdio: Stdio)\n"
    "    stdio.println(\"${f(Some(1))}\")\n")


class TestRigidTypeParamDestructureRejected(unittest.TestCase):
    """The rigid type-parameter destructure is CLOSED: every struct shape is
    a hard type error with ONE mismatch diagnostic at BOTH tiers, no IFC
    noise, refused by both runtimes."""

    def test_struct_mismatch_at_both_tiers(self):
        for name, (src, fn) in _RIGID_STRUCT_REJECT.items():
            with self.subTest(shape=name):
                r = _analyze(src)
                self.assertFalse(r.ok, [e.message for e in r.errors])
                self.assertEqual(len(_mismatch_errors(r)), 1,
                                 [e.message for e in r.errors])
                self.assertEqual(len(r.errors), 1,
                                 [e.message for e in r.errors])
                self.assertEqual(len(_flow_warnings(r)), 0,
                                 [w.message for w in r.warnings])
                rs = _analyze(_strict(src, fn))
                self.assertEqual(len(_mismatch_errors(rs)), 1,
                                 [e.message for e in rs.errors])

    def test_struct_all_runtimes_refuse(self):
        with tempfile.TemporaryDirectory() as td:
            for name, (src, _fn) in _RIGID_STRUCT_REJECT.items():
                with self.subTest(shape=name):
                    p = Path(td) / f"rigid_{name}.capa"
                    p.write_text(src, encoding="utf-8")
                    for argv in (
                        ["--check", str(p)],
                        ["--run", str(p)],
                        ["--run", "--wasm", str(p)],
                    ):
                        rc, _out, _err = _cli(argv)
                        self.assertEqual(rc, 1, (name, argv, _err))

    def test_variant_match_rejected(self):
        # Fail-closed hardening, not a silent both-backends leak. One
        # diagnostic per concrete variant arm over the rigid scrutinee.
        r = _analyze(RIGID_VARIANT_MATCH)
        self.assertFalse(r.ok)
        self.assertEqual(len(_variant_rigid_errors(r)), 2,
                         [e.message for e in r.errors])

    def test_variant_match_runtimes_refuse(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "rigid_variant.capa"
            p.write_text(RIGID_VARIANT_MATCH, encoding="utf-8")
            for argv in (
                ["--check", str(p)],
                ["--run", str(p)],
                ["--run", "--wasm", str(p)],
            ):
                rc, _out, _err = _cli(argv)
                self.assertEqual(rc, 1, (argv, _err))


# ---- ACCEPT: the zero-collateral battery of legitimate generic ------------
# ---- destructures -- the proof the rigid-scrutinee rule has no ------------
# ---- legitimate collateral. Each is accepted and (where it lowers) runs. --

# A concrete-container ``Box<T>`` destructured by a ``Box`` pattern: the
# scrutinee is ``Box<T>`` (a concrete container head), NOT a bare ``T``.
OK_BOX_OF_T = (_BOX +
    "fun f<T>(b: Box<T>) -> T\n"
    "    let Box { v } = b\n"
    "    return v\n"
    "fun main(stdio: Stdio)\n"
    "    stdio.println(\"${f(Box { v: 5 })}\")\n")

# A generic method destructuring ``self: Box<T>``.
OK_SELF_BOX = (_BOX +
    "impl Box<T>\n"
    "    fun get(self) -> T\n"
    "        let Box { v } = self\n"
    "        return v\n"
    "fun main(stdio: Stdio)\n"
    "    stdio.println(\"${Box { v: 3 }.get()}\")\n")

# A nested ``Box<Box<T>>``: both destructures have a concrete container head.
OK_NESTED_BOX_T = (_BOX +
    "fun f<T>(b: Box<Box<T>>) -> T\n"
    "    let Box { v } = b\n"
    "    let Box { v: inner } = v\n"
    "    return inner\n"
    "fun main(stdio: Stdio)\n"
    "    stdio.println(\"${f(Box { v: Box { v: 9 } })}\")\n")

# A ``match`` over a concrete generic container.
OK_MATCH_CONTAINER = (_BOX +
    "fun main(stdio: Stdio)\n"
    "    let b = Box { v: 7 }\n"
    "    match b\n"
    "        Box { v } -> stdio.println(\"${v}\")\n")

# A ``for`` over a concrete generic container.
OK_FOR_CONTAINER = (_BOX +
    "fun main(stdio: Stdio)\n"
    "    let xs = [Box { v: 1 }, Box { v: 2 }]\n"
    "    for Box { v } in xs\n"
    "        stdio.println(\"${v}\")\n")

# An inferred destructure (the scrutinee type is inferred concrete).
OK_INFERRED = (_BOX +
    "fun main(stdio: Stdio)\n"
    "    let b = Box { v: 4 }\n"
    "    let Box { v } = b\n"
    "    stdio.println(\"${v}\")\n")

# A tuple ``(T, T)`` destructure: a tuple pattern, not a struct / variant, so
# the rigid-scrutinee rule does not touch it.
OK_TUPLE_TT = (
    "fun f<T>(p: (T, T)) -> T\n"
    "    let (a, b) = p\n"
    "    return a\n"
    "fun main(stdio: Stdio)\n"
    "    stdio.println(\"${f((1, 2))}\")\n")

# A partial ``Pair<A, B>`` destructure: the scrutinee is a concrete container
# head with two type arguments, not a bare parameter.
OK_PAIR_PARTIAL = (_PAIR +
    "fun f<A, B>(p: Pair<A, B>) -> A\n"
    "    let Pair { first, second } = p\n"
    "    return first\n"
    "fun main(stdio: Stdio)\n"
    "    stdio.println(\"${f(Pair { first: 1, second: 2 })}\")\n")

# The FLEXIBLE-``?`` exclusion, load-bearing: an empty-list for-destructure.
# The element type is an unresolved flexible variable, NOT a rigid ``T``, so
# it must STILL compile and run (the loop body never executes).
OK_FLEXIBLE_EMPTY = (
    "type Point { x: Int }\n"
    "fun main(stdio: Stdio)\n"
    "    let xs = []\n"
    "    for Point { x } in xs\n"
    "        stdio.println(\"${x}\")\n"
    "    stdio.println(\"done\")\n")

# name -> (source, expected Python output). Every shape here binds a field at
# a type parameter or destructures an unresolved-element container, neither of
# which the Wasm backend can lower (a pre-existing, analyzer-INDEPENDENT
# limitation: "type 'T' has no Wasm encoding" for the generic heads, and no
# struct layout for the empty-list flexible element). They are checked for
# --check-cleanliness and Python execution; the SEVERE repros above are what
# exercise both runtimes.
_OK_BATTERY = {
    "box_of_T": (OK_BOX_OF_T, "5\n"),
    "self_box": (OK_SELF_BOX, "3\n"),
    "nested_box_T": (OK_NESTED_BOX_T, "9\n"),
    "match_container": (OK_MATCH_CONTAINER, "7\n"),
    "for_container": (OK_FOR_CONTAINER, "1\n2\n"),
    "inferred": (OK_INFERRED, "4\n"),
    "tuple_TT": (OK_TUPLE_TT, "1\n"),
    "pair_partial": (OK_PAIR_PARTIAL, "1\n"),
    "flexible_empty": (OK_FLEXIBLE_EMPTY, "done\n"),
}


class TestZeroCollateralBattery(unittest.TestCase):
    """The rigid-scrutinee rule has NO legitimate collateral: a battery of
    legitimate generic destructures (concrete container heads, tuples, a
    partial pair, an inferred scrutinee, and the flexible-``?`` empty-list
    for-destructure) all stay accepted with no mismatch error and run to the
    expected Python output."""

    def test_all_accepted(self):
        for name, (src, _out) in _OK_BATTERY.items():
            with self.subTest(shape=name):
                r = _analyze(src)
                self.assertTrue(r.ok, [e.message for e in r.errors])
                self.assertEqual(len(_mismatch_errors(r)), 0,
                                 [e.message for e in r.errors])
                self.assertEqual(len(_variant_rigid_errors(r)), 0,
                                 [e.message for e in r.errors])

    def test_all_run_python(self):
        for name, (src, out) in _OK_BATTERY.items():
            with self.subTest(shape=name):
                self.assertEqual(_run_py(src), out)


# ---- DISCLOSED-RESIDUAL pins (accepted TODAY, KNOWN-OPEN) ----------------

# A trait-typed scrutinee destructured via a public twin: ``ty.name`` is a
# trait (not a struct and not a type variable), so the guard does not fire;
# accepted and LEAKS on Python. Out of the rigid-scrutinee rule's scope.
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

# A rigid value laundered through a SAME-NAMED generic VARIANT constructor
# payload. ``type Wrap<T>`` shares the caller's rigid parameter NAME
# (``fun leak<T>``), so constructing ``Wrapped(t)`` unifies the payload variable
# ``T`` against the rigid ``T``; ``unify``'s reflexive same-name short-circuit
# returns True WITHOUT binding. Before the construction-site fix the variant
# seam read ``mapping.get('T', TyUnknown)`` and collapsed the type argument to
# ``TyUnknown``, so the match payload ``inner`` bound as ``TyUnknown`` and the
# @secret leaked silently. The shared ``_constructor_result_args`` helper now
# restores ``TyVar('T')``, so ``inner`` binds rigid and the downstream
# public-twin destructure is REJECTED. This is the variant arm of the closed
# class below (its name is kept for continuity with the prior disclosed
# residual). NOT a flexible-``?`` evasion: the differently-named twin also
# rejects.
RES_SAME_NAME_CTOR_LAUNDER = (_SEC +
    "type Wrap<T> =\n"
    "    Wrapped(T)\n"
    "fun leak<T>(t: T, stdio: Stdio)\n"
    "    let w = Wrapped(t)\n"
    "    match w\n"
    "        Wrapped(inner) ->\n"
    "            let Other { a } = inner\n"
    "            stdio.println(a)\n"
    "fun main(stdio: Stdio)\n"
    "    leak(ASecret { a: \"s3cr3t\" }, stdio)\n")

# The SAME shape with a DIFFERENT constructor-parameter name (``Wrap<E>``): the
# payload stays a rigid ``TyVar('T')``, so the binder guard correctly REJECTS
# the twin destructure. Pins that the leak above is a name-collision artifact,
# not a flexible-``?`` evasion, and that the differently-named case is closed.
RES_DIFF_NAME_CTOR_REJECTED = (_SEC +
    "type Wrap<E> =\n"
    "    Wrapped(E)\n"
    "fun leak<T>(t: T, stdio: Stdio)\n"
    "    let w = Wrapped(t)\n"
    "    match w\n"
    "        Wrapped(inner) ->\n"
    "            let Other { a } = inner\n"
    "            stdio.println(a)\n"
    "fun main(stdio: Stdio)\n"
    "    leak(ASecret { a: \"s3cr3t\" }, stdio)\n")

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
    """The disclosed open residuals behave AS DOCUMENTED: the trait scrutinee
    is accepted (concrete named trait type, out of this rule's scope); the
    sum-scrutinee D1-cousin is accepted at --check and faults loud on both
    backends. The same-name-constructor launder is no longer here: it is CLOSED
    (see ``TestSameNameCtorLaunderNowRejected``); ``RES_DIFF_NAME_CTOR_REJECTED``
    stays pinned to confirm the differently-named case rejects as before."""

    def test_trait_launder_accepted_and_leaks(self):
        r = _analyze(RES_TRAIT_LAUNDER)
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_mismatch_errors(r)), 0,
                         [e.message for e in r.errors])
        self.assertEqual(_run_py(RES_TRAIT_LAUNDER), "7\n")

    def test_diff_name_ctor_still_rejected(self):
        # The mechanism boundary: a DIFFERENT constructor-parameter name keeps
        # the payload rigid, so the binder guard fires. This confirms the leak
        # above is a name-collision artifact, not a flexible-``?`` evasion.
        r = _analyze(RES_DIFF_NAME_CTOR_REJECTED)
        self.assertFalse(r.ok)
        self.assertEqual(len(_mismatch_errors(r)), 1,
                         [e.message for e in r.errors])

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


# ---- CLOSED: the SAME-NAMED generic-constructor launder now REJECTS -------
#
# A rigid value constructed through a generic STRUCT literal or VARIANT call
# whose type parameter shares the caller's rigid NAME (``type Wrap<T>`` used
# inside ``fun leak<T>``) used to erase the rigid ``T`` to ``TyUnknown`` at the
# construction seam, so a downstream public-twin destructure resolved nothing
# and the @secret leaked silently on both backends. The shared
# ``_constructor_result_args`` helper restores the rigid marker, so the value
# stays rigid and the existing rigid-scrutinee reject fires. Every shape is now
# a hard type error at BOTH tiers, refused by all three runtimes.

# STRUCT-literal direct: ``let w = Wrap { v: t }`` then a public-twin
# destructure of the field (the target shape).
STRUCTCTOR_DIRECT = (_SEC + _WRAP +
    "fun leak<T>(t: T, stdio: Stdio)\n"
    "    let w = Wrap { v: t }\n"
    "    let Wrap { v } = w\n"
    "    let Other { a } = v\n"
    "    stdio.println(a)\n"
    "fun main(stdio: Stdio)\n"
    "    leak(ASecret { a: \"s3cr3t\" }, stdio)\n")

# NESTED sibling: the field is a ``List<T>``; the rigid ``T`` survives the
# parallel walk one level down, so the for-destructure twin over ``v`` rejects.
_WRAP_LIST = "type WrapL<T> { v: List<T> }\n"
STRUCTCTOR_NESTED = (_SEC + _WRAP_LIST +
    "fun leak<T>(t: T, stdio: Stdio)\n"
    "    let w = WrapL { v: [t] }\n"
    "    let WrapL { v } = w\n"
    "    for Other { a } in v\n"
    "        stdio.println(a)\n"
    "fun main(stdio: Stdio)\n"
    "    leak(ASecret { a: \"s3cr3t\" }, stdio)\n")

# name -> (source, function holding the twin destructure). The variant arm is
# the flipped former disclosed residual.
_CTOR_REJECT = {
    "structctor_direct": (STRUCTCTOR_DIRECT, "leak"),
    "structctor_nested": (STRUCTCTOR_NESTED, "leak"),
    "variant_ctor": (RES_SAME_NAME_CTOR_LAUNDER, "leak"),
}


class TestSameNameCtorLaunderNowRejected(unittest.TestCase):
    """The same-name generic-constructor launder is CLOSED at the construction
    seams: the struct-literal, the nested ``List<T>`` field, and the variant
    call each keep the rigid ``T``, so the twin destructure is a hard type
    error with the mismatch diagnostic at BOTH tiers and is refused by all
    three runtimes."""

    def test_mismatch_at_both_tiers(self):
        for name, (src, fn) in _CTOR_REJECT.items():
            with self.subTest(shape=name):
                r = _analyze(src)
                self.assertFalse(r.ok, [e.message for e in r.errors])
                self.assertEqual(len(_mismatch_errors(r)), 1,
                                 [e.message for e in r.errors])
                self.assertEqual(len(_flow_warnings(r)), 0,
                                 [w.message for w in r.warnings])
                rs = _analyze(_strict(src, fn))
                self.assertEqual(len(_mismatch_errors(rs)), 1,
                                 [e.message for e in rs.errors])

    def test_all_runtimes_refuse(self):
        with tempfile.TemporaryDirectory() as td:
            for name, (src, _fn) in _CTOR_REJECT.items():
                with self.subTest(shape=name):
                    p = Path(td) / f"ctor_{name}.capa"
                    p.write_text(src, encoding="utf-8")
                    for argv in (
                        ["--check", str(p)],
                        ["--run", str(p)],
                        ["--run", "--wasm", str(p)],
                    ):
                        rc, _out, _err = _cli(argv)
                        self.assertEqual(rc, 1, (name, argv, _err))


# ---- CONTROLS: the construction-site fix must NOT over-reject -------------

# ``rewrap<T>`` constructs a generic struct, destructures it to a NAME (not a
# concrete twin), and returns it. The rigid ``T`` is preserved but never
# downcast, so it must still compile and run.
REWRAP_OK = (_WRAP +
    "fun rewrap<T>(t: T) -> T\n"
    "    let w = Wrap { v: t }\n"
    "    let Wrap { v } = w\n"
    "    return v\n"
    "fun main(stdio: Stdio)\n"
    "    stdio.println(\"${rewrap(7)}\")\n")

# A CONCRETE payload constructed inside a generic function: the field binds to
# ``Inner`` (unify binds nothing about ``T`` from it), so the field read is fine.
CONCRETE_PAYLOAD_OK = (
    "type Inner { n: Int }\n" + _WRAP +
    "fun f<T>(t: T, stdio: Stdio)\n"
    "    let w = Wrap { v: Inner { n: 7 } }\n"
    "    let Wrap { v } = w\n"
    "    stdio.println(\"${v.n}\")\n"
    "fun main(stdio: Stdio)\n"
    "    f(\"x\", stdio)\n")

_CTOR_CONTROL = {
    "rewrap": (REWRAP_OK, "7\n"),
    "concrete_payload": (CONCRETE_PAYLOAD_OK, "7\n"),
}


class TestSameNameCtorControlsStillCompile(unittest.TestCase):
    """The over-reject guards: a generic constructor destructured to a NAME
    (``rewrap<T>``) and a concrete-payload construction inside a generic
    function stay accepted with no mismatch error and run on Python. The
    differently-named ``Wrap<E>`` still rejects (its pin lives in
    ``TestDisclosedResidualsPinned``)."""

    def test_accepted_and_runs_python(self):
        for name, (src, out) in _CTOR_CONTROL.items():
            with self.subTest(shape=name):
                r = _analyze(src)
                self.assertTrue(r.ok, [e.message for e in r.errors])
                self.assertEqual(len(_mismatch_errors(r)), 0,
                                 [e.message for e in r.errors])
                self.assertEqual(_run_py(src), out)


class TestConstructorResultArgsSingleSource(unittest.TestCase):
    """Cross-check (Principle 4): the struct-literal and variant construction
    seams BOTH route through the ONE ``_constructor_result_args`` helper, so
    they cannot drift. A direct unit call reproduces the rigid-preservation
    rule for each of the three per-parameter branches."""

    def _analyzer(self):
        from capa.analyzer import Analyzer
        return Analyzer(source="")

    def test_helper_preserves_rigid_and_erases_unconstrained(self):
        from capa.typesys import TyName, TyUnknown, TyVar
        a = self._analyzer()
        rigid = TyVar("T")
        # (1) bound param -> the binding; (2) reflexive same-name collision
        # (expected T, actual the rigid T) -> preserved TyVar('T'); the nested
        # List<T> witness closes with the same walk; (3) unconstrained -> erased.
        bound = a._constructor_result_args(
            ("T",), {"T": TyName("Int", ())}, [(rigid, rigid)],
        )
        self.assertEqual(bound, (TyName("Int", ()),))
        preserved = a._constructor_result_args(
            ("T",), {}, [(rigid, rigid)],
        )
        self.assertEqual(preserved, (rigid,))
        nested = a._constructor_result_args(
            ("T",), {},
            [(TyName("List", (rigid,)), TyName("List", (rigid,)))],
        )
        self.assertEqual(nested, (rigid,))
        erased = a._constructor_result_args(
            ("T",), {}, [(rigid, TyUnknown)],
        )
        self.assertEqual(erased, (TyUnknown,))

    def test_both_seams_call_the_helper(self):
        # Guard against a future edit re-inlining ``mapping.get(p, TyUnknown)``
        # at either seam: the source of each seam must reference the shared
        # helper by name.
        import inspect
        from capa.analyzer import _dispatch, _expressions
        self.assertIn(
            "_constructor_result_args",
            inspect.getsource(_expressions),
        )
        self.assertIn(
            "_constructor_result_args",
            inspect.getsource(_dispatch),
        )


if __name__ == "__main__":
    unittest.main()
