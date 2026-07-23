"""One source of truth for what counts as a declassification.

``declassify(value, reason: "...")`` is the auditable ``@secret ->
@public`` bridge, and its site count ends up inside a SIGNED conformance
artifact. Before ``capa/_declassify.py`` existed, three subsystems
answered "is this a declassification?" by walking the AST with three
DIFFERENT rules, and they disagreed:

- the manifest's collector iterated only ``FunDecl`` bodies and
  ``ImplBlock`` methods, never ``ConstDecl.value``. A ``declassify``
  hoisted into a top-level ``const`` was honoured by the analyzer (the
  const came out ``@public``, so ``--check`` passed and ``--run``
  printed the credential) yet was invisible to ``--manifest``,
  ``--compose-sbom``, ``--check-policies`` and ``--conformance-report``:
  a ``no-declassification`` policy PASSED, with a digest, over a program
  that leaks;
- the manifest matched on the callee NAME, so a user-defined
  ``fun declassify(...)`` produced a PHANTOM declassification record.
  The analyzer, which guards on the callee binding being the built-in,
  still reported the leak, so one artifact asserted an audited
  disclosure and an un-audited secret sink at the same position;
- the cross-function summary pass had a third rule again (name, minus a
  top-level ``fun`` of that name), which missed a ``const`` shadow.

These tests pin the fix from the outside (artifact contents and CLI exit
codes) and from the inside (the item-inventory guard that makes a new
expression-bearing AST item fail LOUDLY rather than fall silently
outside the artifact walk).

Pure Python over the AST / manifest / composed JSON plus subprocess CLI
runs; no wasm tooling, so the module always collects.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from capa import Lexer, Parser, analyze
from capa import capa_ast as A
from capa._declassify import (
    FUNCTION_KINDS,
    UnknownItemError,
    _ITEM_ROOTS,
    is_declassify_call,
    item_expression_roots,
    module_expression_roots,
)
from capa.tokens import Pos
from capa.loader import ModuleLoader
from capa.manifest import (
    build_composed_sbom, build_manifest, evaluate_policies, find_policy_file,
    read_policy_file,
)


# A @secret const, declassified in a SECOND const, then printed. The
# analyzer accepts it (declassify makes the value public); every artifact
# must nonetheless record the disclosure.
CONST_LEVEL = (
    'const K: @secret String = "hunter2"\n'
    'const P: String = declassify(K, reason: "audit demo")\n'
    '\n'
    '@strict_ifc()\n'
    'pub fun main(stdio: Stdio) -> Unit\n'
    '    stdio.println(P)\n'
    '    return\n'
)

# THREE declassifications, two of them hoisted into consts. The
# pre-fix manifest reported one.
MIXED_THREE = (
    'const K: @secret String = "k"\n'
    'const A: String = declassify(K, reason: "r1")\n'
    'const B: String = declassify(K, reason: "r2")\n'
    '\n'
    'pub fun body(t: @secret String, stdio: Stdio) -> Unit\n'
    '    stdio.println(declassify(t, reason: "r3"))\n'
    '    return\n'
)

# A user-defined function named ``declassify``. It is NOT the built-in,
# so it declassifies nothing: the secret still reaches the sink raw.
SHADOWED = (
    'fun declassify(value: String, reason: String) -> String\n'
    '    return value\n'
    '\n'
    'pub fun leak(t: @secret String, stdio: Stdio) -> Unit\n'
    '    stdio.println(declassify(t, reason: "not the builtin"))\n'
    '    return\n'
)

# A genuine, function-body declassification: the shape that already
# worked, kept here so the fix is shown not to disturb it.
FUNCTION_LEVEL = (
    'pub fun handler(token: @secret String, stdio: Stdio) -> Unit\n'
    '    stdio.println(declassify(token, reason: "audit"))\n'
    '    return\n'
)

CLEAN = 'pub fun add(a: Int, b: Int) -> Int\n    return a + b\n'


def _analysed(source: str, filename: str = "t.capa"):
    """Parse + analyse ``source``, returning ``(module, result)``."""
    tokens = Lexer(source).lex()
    module = Parser(tokens, source=source).parse_module()
    result = analyze(module, source=source, filename=filename)
    if not result.ok:
        raise AssertionError(f"analyzer errors: {result.errors}")
    return module, result


def _manifest(source: str, filename: str = "t.capa"):
    """The manifest the CLI would build for ``source`` (analysis
    threaded exactly as every artifact-producing CLI path threads it)."""
    module, result = _analysed(source, filename)
    return build_manifest(
        module, filename=filename,
        bindings=result.bindings, expr_labels=result.expr_labels,
        unaudited_secret_sinks=result.unaudited_secret_sinks,
    )


def _all_sites(manifest) -> list[dict]:
    """Every declassification record in ``manifest``, wherever it lives."""
    out: list[dict] = []
    for fn in manifest["functions"]:
        out.extend(fn["declassifications"])
    out.extend(manifest["module_declassifications"])
    return out


# ---------------------------------------------------------------------------
# THE ITEM-INVENTORY GUARD
# ---------------------------------------------------------------------------


class TestItemInventoryGuard(unittest.TestCase):
    """A new expression-bearing top-level item must not be able to fall
    silently outside the artifact walk."""

    @staticmethod
    def _item_classes():
        """Every ``Item`` subclass the AST package defines, transitively
        (so an indirect subclass added later is still enumerated).

        Restricted to classes declared in ``capa.capa_ast`` -- where every
        real item lives -- so the throwaway subclass the sibling test
        defines does not count as an unregistered item."""
        out: list[type] = []
        stack = list(A.Item.__subclasses__())
        while stack:
            cls = stack.pop()
            if cls.__module__.startswith("capa.capa_ast"):
                out.append(cls)
            stack.extend(cls.__subclasses__())
        return out

    def test_every_item_subclass_is_registered(self):
        # The meta-test: enumerate the AST's own item inventory and demand
        # that the declassification walk knows about each one. Adding an
        # Item subclass without registering it fails HERE, at the seam,
        # rather than by quietly under-counting a conformance artifact.
        missing = sorted(
            cls.__name__ for cls in self._item_classes()
            if cls not in _ITEM_ROOTS
        )
        self.assertEqual(
            missing, [],
            "unregistered top-level item(s) in capa._declassify._ITEM_ROOTS; "
            "register each (with '_no_roots' when it carries no expression) "
            "so the artifact walk cannot silently miss its sites",
        )

    def test_registry_holds_no_stale_entries(self):
        stale = sorted(
            cls.__name__ for cls in _ITEM_ROOTS
            if cls not in set(self._item_classes())
        )
        self.assertEqual(stale, [])

    def test_unregistered_item_raises_rather_than_skips(self):
        # The construction half: an item class the registry does not know
        # is a hard error, not a zero-site answer.
        class NewFangledDecl(A.Item):
            pass

        item = NewFangledDecl(pos=Pos(line=1, col=1, offset=0))
        with self.assertRaises(UnknownItemError):
            item_expression_roots(item)
        with self.assertRaises(UnknownItemError):
            module_expression_roots(
                A.Module(pos=item.pos, items=[item]),
            )

    def test_const_is_the_only_non_function_expression_root(self):
        # The brief's claim, verified rather than trusted: outside
        # functions and impl blocks, ``ConstDecl.value`` is the only
        # expression-carrying item today. If this ever changes, the new
        # kind must be handled by _module_declassifications.
        source = (
            'import x\n'
            'const C: Int = 1\n'
            'type S { a: Int }\n'
            'type E =\n'
            '    One\n'
            '    Two\n'
            'typestate P\n'
            '    Open\n'
            '    Closed\n'
            'capability Cap\n'
            '    fun go() -> Unit\n'
            'fun f() -> Unit\n'
            '    return\n'
            'impl S\n'
            '    fun m(self) -> Unit\n'
            '        return\n'
        )
        tokens = Lexer(source).lex()
        module = Parser(tokens, source=source).parse_module()
        kinds = {
            r.kind for r in module_expression_roots(module)
            if r.kind not in FUNCTION_KINDS
        }
        self.assertEqual(kinds, {"const"})
        # And every item class the parser produced is covered.
        self.assertGreaterEqual(len(module.items), 8)


# ---------------------------------------------------------------------------
# THE SHARED PREDICATE
# ---------------------------------------------------------------------------


class TestSharedPredicate(unittest.TestCase):
    def _calls_named_declassify(self, module):
        found = []

        def walk(node):
            if isinstance(node, A.Call):
                found.append(node)
            if isinstance(node, A.Node):
                for f in node.__dataclass_fields__.values():
                    v = getattr(node, f.name)
                    if isinstance(v, A.Node):
                        walk(v)
                    elif isinstance(v, list):
                        for it in v:
                            if isinstance(it, A.Node):
                                walk(it)

        for item in module.items:
            walk(item)
        return [
            c for c in found
            if isinstance(c.callee, A.Ident) and c.callee.name == "declassify"
        ]

    def test_builtin_call_is_a_declassification(self):
        module, result = _analysed(FUNCTION_LEVEL)
        calls = self._calls_named_declassify(module)
        self.assertEqual(len(calls), 1)
        self.assertTrue(is_declassify_call(calls[0], result.bindings))

    def test_user_defined_declassify_is_not(self):
        module, result = _analysed(SHADOWED)
        calls = self._calls_named_declassify(module)
        self.assertEqual(len(calls), 1)
        self.assertFalse(is_declassify_call(calls[0], result.bindings))

    def test_analyzer_and_manifest_ask_the_same_function(self):
        # The analyzer's own predicate delegates to the shared one, so
        # the two cannot answer differently for the same node.
        from capa.analyzer import Analyzer
        module, result = _analysed(SHADOWED)
        calls = self._calls_named_declassify(module)
        az = Analyzer.__new__(Analyzer)
        az.bindings = result.bindings
        self.assertEqual(
            az._is_declassify_call(calls[0]),
            is_declassify_call(calls[0], result.bindings),
        )

    def test_module_scope_identity_matches_per_call_identity(self):
        # The cross-function summary pass runs BEFORE bindings exist, so
        # it resolves identity through the global scope instead. On a
        # module-scope shadow the two sources must agree; if they did not,
        # a leak could break its sink-reaching chain on one rule and not
        # the other.
        for src, expected in ((FUNCTION_LEVEL, True), (SHADOWED, False)):
            with self.subTest(src=src.splitlines()[0]):
                module, result = _analysed(src)
                call = self._calls_named_declassify(module)[0]
                scope = _GlobalScopeView(result.global_symbols)
                self.assertEqual(
                    is_declassify_call(call, module_scope=scope), expected,
                )
                self.assertEqual(
                    is_declassify_call(call, result.bindings), expected,
                )

    def test_summary_pass_still_tracks_a_leak_through_a_user_declassify(self):
        # The behavioural guard on the summary pass's rule change: a
        # secret routed through a HELPER that calls a user-defined
        # ``declassify`` is still a cross-function leak, because the
        # user's function relabels nothing.
        source = (
            'fun declassify(value: String, reason: String) -> String\n'
            '    return value\n'
            '\n'
            'fun helper(t: String, stdio: Stdio) -> Unit\n'
            '    stdio.println(declassify(t, reason: "nope"))\n'
            '    return\n'
            '\n'
            'fun caller(s: @secret String, stdio: Stdio) -> Unit\n'
            '    helper(s, stdio)\n'
            '    return\n'
        )
        _module, result = _analysed(source)
        self.assertTrue(
            any("information-flow" in w.message for w in result.warnings),
            [w.message for w in result.warnings],
        )


class _GlobalScopeView:
    """The ``.lookup(name)`` surface ``is_declassify_call`` needs, over an
    ``AnalysisResult.global_symbols`` snapshot.

    That snapshot IS ``Analyzer.global_scope.symbols``, built-ins
    included (they are installed into the global scope), so this is the
    same table the summary pass consults, not a stand-in."""

    def __init__(self, global_symbols):
        self._symbols = global_symbols

    def lookup(self, name):
        return self._symbols.get(name)


# ---------------------------------------------------------------------------
# THE MANIFEST SURFACE
# ---------------------------------------------------------------------------


class TestManifestSites(unittest.TestCase):
    def test_const_level_site_is_recorded(self):
        m = _manifest(CONST_LEVEL)
        self.assertEqual(m["summary"]["declassification_sites"], 1)
        sites = m["module_declassifications"]
        self.assertEqual(len(sites), 1)
        self.assertEqual(sites[0]["owner_kind"], "const")
        self.assertEqual(sites[0]["owner"], "P")
        self.assertEqual(sites[0]["source_owner"], "P")
        self.assertEqual(sites[0]["reason"], "audit demo")
        self.assertEqual(sites[0]["value"], "K")
        self.assertEqual(sites[0]["owner_pos"], "t.capa:2:1")

    def test_mixed_hoisted_and_inline_total(self):
        m = _manifest(MIXED_THREE)
        self.assertEqual(m["summary"]["declassification_sites"], 3)
        self.assertEqual(len(m["module_declassifications"]), 2)
        self.assertEqual(
            sorted(s["reason"] for s in _all_sites(m)), ["r1", "r2", "r3"],
        )

    def test_shadowed_declassify_produces_no_record(self):
        m = _manifest(SHADOWED)
        self.assertEqual(m["summary"]["declassification_sites"], 0)
        self.assertEqual(_all_sites(m), [])

    def test_shadowed_declassify_still_reports_the_leak(self):
        # The artifact must not be self-contradictory: with no audited
        # declassification, the un-audited secret sink is the whole story.
        m = _manifest(SHADOWED)
        leak = [f for f in m["functions"] if f["name"] == "leak"][0]
        self.assertEqual(
            [s["capability"] for s in leak["unaudited_secret_sinks"]],
            ["Stdio"],
        )

    def test_function_level_site_still_recorded(self):
        m = _manifest(FUNCTION_LEVEL)
        self.assertEqual(m["summary"]["declassification_sites"], 1)
        self.assertEqual(m["module_declassifications"], [])
        fn = m["functions"][0]
        self.assertEqual([s["reason"] for s in fn["declassifications"]], ["audit"])

    def test_clean_module_reports_zero(self):
        m = _manifest(CLEAN)
        self.assertEqual(m["summary"]["declassification_sites"], 0)
        self.assertEqual(m["module_declassifications"], [])

    def test_public_const_declassify_is_still_a_no_op(self):
        # A declassify of an already-public const is a no-op the analyzer
        # warns about; it must not inflate the count, in a const exactly
        # as in a function body.
        source = (
            'const K: String = "not secret"\n'
            'const P: String = declassify(K, reason: "pointless")\n'
        )
        tokens = Lexer(source).lex()
        module = Parser(tokens, source=source).parse_module()
        result = analyze(module, source=source)
        self.assertTrue(result.ok, result.errors)
        self.assertTrue(any("no-op" in w.message for w in result.warnings))
        m = build_manifest(
            module, filename="t.capa",
            bindings=result.bindings, expr_labels=result.expr_labels,
        )
        self.assertEqual(m["summary"]["declassification_sites"], 0)


# ---------------------------------------------------------------------------
# THE COMPOSED / POLICY SURFACE
# ---------------------------------------------------------------------------


def _write(base: Path, rel: str, text: str) -> None:
    p = base / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


class _Project(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="capa_declass_"))
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))

    def _tree(self, main_src: str, policy: str = "") -> Path:
        root = self.tmp / "app"
        _write(root, "capa.toml", '[package]\nname = "app"\nversion = "0.1.0"\n')
        _write(root, "main.capa", main_src)
        if policy:
            _write(root, "capa-policy.toml", policy)
        return root

    def _dep_tree(self, dep_src: str, main_src: str, policy: str = "") -> Path:
        """A product whose VENDORED dependency holds the declassification,
        so attribution is exercised (the site must land on the dependency,
        not on the root)."""
        root = self.tmp / "prod"
        _write(root, "capa.toml", (
            '[package]\nname = "prod"\nversion = "0.1.0"\n\n'
            '[dependencies.leaky]\n'
            'git = "https://github.com/example/leaky"\ntag = "v1"\n'
        ))
        _write(root, "main.capa", main_src)
        _write(root, "vendor/leaky/capa.toml",
               '[package]\nname = "leaky"\nversion = "0.1.0"\n')
        _write(root, "vendor/leaky/leak.capa", dep_src)
        if policy:
            _write(root, "capa-policy.toml", policy)
        return root

    def _compose(self, root_dir: Path):
        root_dir = root_dir.resolve()
        filename = str(root_dir / "main.capa")
        source = Path(filename).read_text(encoding="utf-8")
        search = [root_dir] + [
            v for v in root_dir.rglob("vendor") if v.is_dir()
        ]
        loader = ModuleLoader(search_paths=search)
        linked = loader.load_root(source, filename)
        result = analyze(
            linked.module, source=source, filename=filename,
            sources=linked.sources, module_privates=linked.module_privates,
        )
        if not result.ok:
            raise AssertionError(f"analyzer errors: {result.errors}")
        manifest = build_manifest(
            linked.module, filename=filename,
            bindings=result.bindings, expr_labels=result.expr_labels,
            unaudited_secret_sinks=result.unaudited_secret_sinks,
        )
        return build_composed_sbom(linked.module, manifest, root_dir)

    def _evaluate(self, root_dir: Path):
        composed = self._compose(root_dir)
        policy_path = find_policy_file(root_dir.resolve())
        policies = read_policy_file(policy_path) if policy_path else []
        return evaluate_policies(composed, policies), composed

    def _cli(self, root_dir: Path, *flags: str):
        """Run the real CLI; return ``(exit code, stdout, stderr)``. The
        exit code is read from the completed process, never through a
        pipeline."""
        proc = subprocess.run(
            [sys.executable, "-m", "capa", *flags,
             str(root_dir / "main.capa")],
            cwd=str(Path(__file__).resolve().parent.parent),
            capture_output=True, text=True,
        )
        return proc.returncode, proc.stdout, proc.stderr


class TestComposedSbom(_Project):
    def test_const_level_site_reaches_the_composed_sbom(self):
        composed = self._compose(self._tree(CONST_LEVEL))
        self.assertTrue(composed["composed"]["has_declassification"])
        self.assertEqual(composed["composed"]["declassification_sites"], 1)

    def test_const_level_site_is_attributed_to_its_package(self):
        composed = self._compose(self._tree(CONST_LEVEL))
        pkg = composed["packages"][0]
        self.assertEqual(pkg["attributed_declassification_sites"], 1)
        site = pkg["attributed_declassifications"][0]
        self.assertEqual(site["reason"], "audit demo")
        # The position carries the owning file, exactly like a function
        # site, so an auditor can locate the disclosure.
        self.assertTrue(site["pos"].startswith("main.capa:"), site["pos"])

    def test_mixed_total_composes(self):
        composed = self._compose(self._tree(MIXED_THREE))
        self.assertEqual(composed["composed"]["declassification_sites"], 3)

    def test_shadowed_declassify_composes_as_zero(self):
        composed = self._compose(self._tree(SHADOWED))
        self.assertEqual(composed["composed"]["declassification_sites"], 0)
        self.assertFalse(composed["composed"]["has_declassification"])

    def test_clean_product_composes_as_zero(self):
        composed = self._compose(self._tree(CLEAN))
        self.assertEqual(composed["composed"]["declassification_sites"], 0)

    def test_dependency_const_site_attributes_to_the_dependency(self):
        # Attribution, the part a per-package policy depends on: the site
        # belongs to the package whose FILE declares the const, not to the
        # root that merely imports it. The loader mangles a non-pub const,
        # so this also pins that the compose key survives mangling.
        composed = self._compose(self._dep_tree(
            CONST_LEVEL.replace("pub fun main", "pub fun leak_it"),
            "import leaky.leak\n\npub fun run() -> Unit\n    return\n",
        ))
        by_name = {p["name"]: p for p in composed["packages"]}
        self.assertEqual(by_name["leaky"]["attributed_declassification_sites"], 1)
        self.assertEqual(by_name["prod"]["attributed_declassification_sites"], 0)
        # The product rolls it up transitively.
        self.assertEqual(composed["composed"]["declassification_sites"], 1)
        site = by_name["leaky"]["attributed_declassifications"][0]
        self.assertEqual(site["reason"], "audit demo")
        self.assertIn("leak.capa", site["pos"])


class TestNoDeclassificationPolicy(_Project):
    _POLICY = '[[policy]]\nid = "nd"\nkind = "no-declassification"\n'

    def _result(self, report, policy_id="nd"):
        for r in report["results"]:
            if r["policy"] == policy_id:
                return r
        raise AssertionError(f"no policy result {policy_id!r}")

    def test_const_level_declassification_violates(self):
        report, _ = self._evaluate(self._tree(CONST_LEVEL, self._POLICY))
        r = self._result(report)
        self.assertFalse(r["pass"])
        self.assertEqual(r["violations"][0]["verdict"], "violation")
        self.assertIn("1 audited declassification", r["violations"][0]["detail"])

    def test_package_scoped_policy_also_violates(self):
        report, _ = self._evaluate(self._tree(
            CONST_LEVEL, self._POLICY + 'package = "app"\n',
        ))
        r = self._result(report)
        self.assertFalse(r["pass"])
        self.assertEqual(r["violations"][0]["package"], "app")

    def test_shadowed_declassify_does_not_violate(self):
        report, _ = self._evaluate(self._tree(SHADOWED, self._POLICY))
        self.assertTrue(self._result(report)["pass"])

    def test_clean_product_still_passes(self):
        report, _ = self._evaluate(self._tree(CLEAN, self._POLICY))
        self.assertTrue(self._result(report)["pass"])

    def test_check_policies_gate_exits_one(self):
        root = self._tree(CONST_LEVEL, self._POLICY)
        code, _out, err = self._cli(root, "--check-policies")
        self.assertEqual(code, 1, err)
        self.assertIn("FAILED", err)
        self.assertIn("declassification", err)

    def test_check_policies_gate_exits_zero_on_clean(self):
        root = self._tree(CLEAN, self._POLICY)
        code, _out, err = self._cli(root, "--check-policies")
        self.assertEqual(code, 0, err)
        self.assertIn("OK", err)

    def test_conformance_report_fails(self):
        root = self._tree(CONST_LEVEL, self._POLICY)
        code, out, err = self._cli(root, "--conformance-report")
        self.assertEqual(code, 0, err)
        doc = json.loads(out)
        self.assertFalse(doc["pass"])
        self.assertIn("content_integrity", doc)

    def test_conformance_report_passes_on_clean(self):
        root = self._tree(CLEAN, self._POLICY)
        code, out, err = self._cli(root, "--conformance-report")
        self.assertEqual(code, 0, err)
        self.assertTrue(json.loads(out)["pass"])

    def test_manifest_cli_reports_the_const_site(self):
        root = self._tree(CONST_LEVEL)
        code, out, err = self._cli(root, "--manifest")
        self.assertEqual(code, 0, err)
        doc = json.loads(out)
        self.assertEqual(doc["summary"]["declassification_sites"], 1)
        self.assertEqual(len(doc["module_declassifications"]), 1)

    def test_manifest_cli_counts_the_mixed_total(self):
        # The under-count, black-box: three declassifications, two of them
        # hoisted into consts. The pre-fix CLI reported one.
        root = self._tree(MIXED_THREE)
        code, out, err = self._cli(root, "--manifest")
        self.assertEqual(code, 0, err)
        doc = json.loads(out)
        self.assertEqual(doc["summary"]["declassification_sites"], 3)

    def test_manifest_cli_records_no_phantom_for_shadowed_name(self):
        root = self._tree(SHADOWED)
        code, out, err = self._cli(root, "--manifest")
        self.assertEqual(code, 0, err)
        doc = json.loads(out)
        self.assertEqual(doc["summary"]["declassification_sites"], 0)


if __name__ == "__main__":
    unittest.main()
