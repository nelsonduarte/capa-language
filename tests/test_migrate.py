"""Tests for ``capa migrate`` gradual-hardening progress reporting."""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from capa import Lexer, Parser, analyze
from capa import capa_ast as A
from capa.migrate import _collect_bound_names, migrate_report, render_report


_EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def _module_from_source(source: str, filename: str = "<test>"):
    """Lex + parse + analyse source, returning the analysed module."""
    tokens = Lexer(source, filename=filename).lex()
    module = Parser(tokens, source=source, filename=filename).parse_module()
    result = analyze(module, source=source, filename=filename)
    assert result.ok, result.errors
    return module


def _report_for_example(name: str) -> dict:
    source = (_EXAMPLES / name).read_text(encoding="utf-8")
    module = _module_from_source(source, filename=name)
    return migrate_report(module, filename=name)


class TestMigrateExamples(unittest.TestCase):
    """Drive the shipped 3-stage migration demo end to end."""

    def test_step1_all_unsafe(self):
        rep = _report_for_example("migrate_logfetcher_step1_unsafe.capa")
        s = rep["summary"]
        # Everything is still behind Unsafe.
        self.assertEqual(s["functions_using_unsafe"], s["total_functions"])
        self.assertEqual(s["percent_unsafe_free"], 0)

    def test_step2_mixed_has_one_typed_function(self):
        rep = _report_for_example("migrate_logfetcher_step2_mixed.capa")
        s = rep["summary"]
        # save_response is now typed (Fs only), so at least one function
        # is Unsafe-free and the percentage has moved off zero.
        free = s["total_functions"] - s["functions_using_unsafe"]
        self.assertGreaterEqual(free, 1)
        self.assertGreater(s["percent_unsafe_free"], 0)
        self.assertLess(s["percent_unsafe_free"], 100)

    def test_step3_fully_typed(self):
        rep = _report_for_example("migrate_logfetcher_step3_typed.capa")
        s = rep["summary"]
        self.assertEqual(s["functions_using_unsafe"], 0)
        self.assertEqual(s["percent_unsafe_free"], 100)
        self.assertEqual(rep["removable"], [])
        self.assertEqual(rep["next_candidates"], [])

    def test_next_candidates_ranked_by_bridge_calls(self):
        # Cheapest-to-harden (fewest bridge calls) comes first.
        rep = _report_for_example("migrate_logfetcher_step1_unsafe.capa")
        counts = [c["bridge_call_count"] for c in rep["next_candidates"]]
        self.assertEqual(counts, sorted(counts))


class TestRemovableDetection(unittest.TestCase):
    """The conservative 'Unsafe declared but never exercised' check."""

    def test_silenced_dead_unsafe_is_removable(self):
        # The analyser rejects a capability param referenced nowhere
        # unless it is underscore-prefixed; the live removable case is
        # that silenced-but-dead param.
        src = (
            "fun f(_u: Unsafe) -> Int\n"
            "    return 42\n"
        )
        rep = migrate_report(_module_from_source(src))
        self.assertEqual(rep["summary"]["functions_removable_unsafe"], 1)
        r = rep["removable"][0]
        self.assertEqual(r["source_name"], "f")
        self.assertEqual(r["param_name"], "_u")

    def test_unsafe_used_via_bridge_is_not_removable(self):
        src = (
            "fun f(u: Unsafe)\n"
            "    let os_mod = py_import(u, \"os\")\n"
        )
        rep = migrate_report(_module_from_source(src))
        self.assertEqual(rep["summary"]["functions_removable_unsafe"], 0)
        self.assertEqual(rep["summary"]["functions_using_unsafe"], 1)

    def test_forwarded_unsafe_is_not_removable(self):
        # g forwards its Unsafe to f; even though g makes no bridge call
        # itself, the token is exercised, so it is not removable.
        src = (
            "fun f(u: Unsafe)\n"
            "    let os_mod = py_import(u, \"os\")\n"
            "\n"
            "fun g(u: Unsafe)\n"
            "    f(u)\n"
        )
        rep = migrate_report(_module_from_source(src))
        names = {r["source_name"] for r in rep["removable"]}
        self.assertNotIn("g", names)
        self.assertNotIn("f", names)

    def test_no_unsafe_at_all_is_fully_hardened(self):
        src = (
            "fun greet(stdio: Stdio)\n"
            "    stdio.println(\"hi\")\n"
        )
        rep = migrate_report(_module_from_source(src))
        self.assertEqual(rep["summary"]["functions_using_unsafe"], 0)
        self.assertEqual(rep["summary"]["percent_unsafe_free"], 100)


class TestTransitiveRemovable(unittest.TestCase):
    """Slice 2: removable detection follows the call graph, so a token
    forwarded only into bridge-free chains counts as removable, while
    every ambiguous shape stays conservatively non-removable."""

    def _removable_by_name(self, src: str) -> dict:
        rep = migrate_report(_module_from_source(src))
        return {r["source_name"]: r for r in rep["removable"]}

    def test_two_level_chain_is_removable(self):
        # top forwards its token to bottom, whose own Unsafe is dead:
        # the token can never reach a bridge, so both are removable.
        src = (
            "fun bottom(_u: Unsafe) -> Int\n"
            "    return 1\n"
            "\n"
            "fun top(u: Unsafe) -> Int\n"
            "    return bottom(u)\n"
        )
        removable = self._removable_by_name(src)
        self.assertIn("bottom", removable)
        self.assertIn("top", removable)
        self.assertFalse(removable["bottom"]["transitive"])
        self.assertEqual(removable["bottom"]["depends_on"], [])
        self.assertTrue(removable["top"]["transitive"])
        self.assertEqual(removable["top"]["depends_on"], ["bottom"])

    def test_three_level_chain_is_removable(self):
        src = (
            "fun bottom(_u: Unsafe) -> Int\n"
            "    return 1\n"
            "\n"
            "fun middle(u: Unsafe) -> Int\n"
            "    return bottom(u)\n"
            "\n"
            "fun top(u: Unsafe) -> Int\n"
            "    return middle(u)\n"
        )
        removable = self._removable_by_name(src)
        self.assertEqual(set(removable), {"bottom", "middle", "top"})
        self.assertEqual(removable["top"]["depends_on"], ["middle"])
        self.assertEqual(removable["middle"]["depends_on"], ["bottom"])

    def test_chain_ending_in_bridge_is_not_removable(self):
        # The bottom of the chain still does py_import: nothing in the
        # chain may drop its Unsafe.
        src = (
            "fun bottom(u: Unsafe)\n"
            "    let os_mod = py_import(u, \"os\")\n"
            "\n"
            "fun middle(u: Unsafe)\n"
            "    bottom(u)\n"
            "\n"
            "fun top(u: Unsafe)\n"
            "    middle(u)\n"
        )
        rep = migrate_report(_module_from_source(src))
        self.assertEqual(rep["removable"], [])
        names = {c["source_name"] for c in rep["next_candidates"]}
        self.assertEqual(names, {"bottom", "middle", "top"})

    def test_mutual_recursion_cycle_is_not_removable(self):
        # a and b only pass the token to each other and never bridge,
        # but a call-graph cycle resolves to the conservative side.
        src = (
            "fun a(u: Unsafe)\n"
            "    b(u)\n"
            "\n"
            "fun b(u: Unsafe)\n"
            "    a(u)\n"
        )
        rep = migrate_report(_module_from_source(src))
        self.assertEqual(rep["removable"], [])

    def test_self_recursion_is_not_removable(self):
        src = (
            "fun f(u: Unsafe)\n"
            "    f(u)\n"
        )
        rep = migrate_report(_module_from_source(src))
        self.assertEqual(rep["removable"], [])

    def test_forward_to_callback_param_is_not_removable(self):
        # The callee is a Fun-typed parameter: its body is unknown, so
        # the forwarded token must count as exercised.
        src = (
            "fun g(f: Fun(Unsafe) -> Unit, u: Unsafe)\n"
            "    f(u)\n"
        )
        rep = migrate_report(_module_from_source(src))
        self.assertEqual(rep["removable"], [])

    def test_forward_via_method_call_is_not_removable(self):
        # The token escapes through a method call on a user capability:
        # the receiver's impl is not resolvable by name, so conservative.
        src = (
            "capability Sink\n"
            "    fun take(self, u: Unsafe)\n"
            "\n"
            "fun g(s: Sink, u: Unsafe)\n"
            "    s.take(u)\n"
        )
        rep = migrate_report(_module_from_source(src))
        self.assertEqual(rep["removable"], [])

    def test_shadowed_callee_is_not_removable(self):
        # Functions are first-class: third let-binds the name of the
        # dead function to a reference to the bridging one and calls
        # through it. The callee name must NOT resolve to the dead
        # top-level homonym; the token genuinely reaches py_import, so
        # neither third nor main may be flagged. Only dead's own
        # silenced parameter is genuinely removable.
        src = (
            "fun bridge(u: Unsafe)\n"
            "    let os_mod = py_import(u, \"os\")\n"
            "\n"
            "fun dead(_u: Unsafe) -> Int\n"
            "    return 1\n"
            "\n"
            "fun third(u: Unsafe)\n"
            "    let dead = bridge\n"
            "    dead(u)\n"
            "\n"
            "fun main(u: Unsafe)\n"
            "    third(u)\n"
        )
        removable = self._removable_by_name(src)
        self.assertNotIn("third", removable)
        self.assertNotIn("main", removable)
        self.assertEqual(set(removable), {"dead"})

    def test_var_shadowed_callee_is_not_removable(self):
        # Same hole through a mutable binding: a var (or a later
        # reassignment) can also rebind a top-level function's name.
        src = (
            "fun bridge(u: Unsafe)\n"
            "    let os_mod = py_import(u, \"os\")\n"
            "\n"
            "fun dead(_u: Unsafe) -> Int\n"
            "    return 1\n"
            "\n"
            "fun third(u: Unsafe)\n"
            "    var dead = bridge\n"
            "    dead(u)\n"
        )
        removable = self._removable_by_name(src)
        self.assertNotIn("third", removable)
        self.assertEqual(set(removable), {"dead"})

    def test_struct_shorthand_shadowed_callee_is_not_removable(self):
        # Same hole through destructuring shorthand: ``Holder { dead }``
        # binds the field name with NO IdentPat node (the parser records
        # the field as ``(name, None)``), so a collector that only looks
        # for IdentPat misses it. third shadows the dead function's name
        # with a bridging function smuggled in a struct field and calls
        # through it; the token genuinely reaches py_import, so neither
        # third nor main may be flagged.
        src = (
            "type Holder { dead: Fun(Unsafe) -> () }\n"
            "\n"
            "fun bridge(u: Unsafe)\n"
            "    let os_mod = py_import(u, \"os\")\n"
            "\n"
            "fun dead(_u: Unsafe) -> Int\n"
            "    return 1\n"
            "\n"
            "fun third(u: Unsafe, h: Holder)\n"
            "    let Holder { dead } = h\n"
            "    dead(u)\n"
            "\n"
            "fun main(u: Unsafe)\n"
            "    third(u, Holder { dead: bridge })\n"
        )
        removable = self._removable_by_name(src)
        self.assertNotIn("third", removable)
        self.assertNotIn("main", removable)
        self.assertEqual(set(removable), {"dead"})

    def test_struct_explicit_field_pattern_shadow_is_not_removable(self):
        # The explicit field-colon-pattern form binds through an
        # ordinary IdentPat sub-pattern (``Holder { fn: dead }`` binds
        # ``dead``); the generic walk must keep covering it.
        src = (
            "type Holder { fn: Fun(Unsafe) -> () }\n"
            "\n"
            "fun bridge(u: Unsafe)\n"
            "    let os_mod = py_import(u, \"os\")\n"
            "\n"
            "fun dead(_u: Unsafe) -> Int\n"
            "    return 1\n"
            "\n"
            "fun third(u: Unsafe, h: Holder)\n"
            "    let Holder { fn: dead } = h\n"
            "    dead(u)\n"
            "\n"
            "fun main(u: Unsafe)\n"
            "    third(u, Holder { fn: bridge })\n"
        )
        removable = self._removable_by_name(src)
        self.assertNotIn("third", removable)
        self.assertNotIn("main", removable)
        self.assertEqual(set(removable), {"dead"})

    def test_struct_explicit_field_name_does_not_poison_resolution(self):
        # Precision check on the explicit form: ``Holder { dead: n }``
        # binds ``n``, NOT the field name ``dead``, so a field that is
        # merely named like the dead function must not push the
        # analysis to the conservative side. The direct ``dead(u)``
        # call resolves to the genuinely dead top-level function and
        # the whole forwarding chain stays removable.
        src = (
            "type Holder { dead: Int }\n"
            "\n"
            "fun dead(_u: Unsafe) -> Int\n"
            "    return 1\n"
            "\n"
            "fun third(u: Unsafe, h: Holder)\n"
            "    let Holder { dead: n } = h\n"
            "    dead(u)\n"
            "\n"
            "fun main(u: Unsafe)\n"
            "    third(u, Holder { dead: 3 })\n"
        )
        removable = self._removable_by_name(src)
        self.assertEqual(set(removable), {"dead", "third", "main"})

    def test_local_function_binding_without_collision_stays_conservative(self):
        # The local name collides with no top-level function: the
        # callee is unknown to the resolver and the analysis must stay
        # on the conservative side (g not removable), exactly as before
        # the shadowing fix.
        src = (
            "fun bridge(u: Unsafe)\n"
            "    let os_mod = py_import(u, \"os\")\n"
            "\n"
            "fun g(u: Unsafe)\n"
            "    let go = bridge\n"
            "    go(u)\n"
        )
        removable = self._removable_by_name(src)
        self.assertNotIn("g", removable)

    def test_unsafe_in_cap_bearing_struct_is_rejected(self):
        # Audit 2026-06-17 C5(a): embedding the Unsafe token in a
        # cap-bearing struct used to be the migrate "signature
        # poison" smuggling shape this suite guarded against. The
        # hole is now closed at the type level - a struct field of
        # type Unsafe is rejected at analysis even when the struct
        # implements a user-cap - so the program can never reach the
        # migrate report at all. Assert the rejection directly.
        src = (
            "capability Wrap\n"
            "    fun ping(self) -> Int\n"
            "\n"
            "type Holder { u: Unsafe }\n"
            "\n"
            "impl Wrap for Holder\n"
            "    fun ping(self) -> Int\n"
            "        return 1\n"
            "\n"
            "fun pack(u: Unsafe) -> Holder\n"
            "    return Holder { u: u }\n"
            "\n"
            "fun g(u: Unsafe) -> Holder\n"
            "    return pack(u)\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertFalse(result.ok)
        self.assertTrue(
            any(
                "Unsafe" in e.message
                and "capability-bearing struct" in e.message
                for e in result.errors
            ),
            result.errors,
        )


class TestBoundNameCollectorParserSync(unittest.TestCase):
    """Parser/collector synchronization guard.

    ``_collect_bound_names`` feeds the callee-resolution veto of the
    removable-Unsafe detection: any binding form it cannot see reopens
    the shadowed-callee false positive (the struct-shorthand hole was
    exactly such a miss, a binding with no IdentPat node). This suite
    pins the contract from both sides: one program exercises every
    pattern form the grammar has today and asserts the collector sees
    every name those forms really bind; a class-coverage check fails
    as soon as a new ``Pattern`` subclass appears in the AST without
    this program (and therefore the collector) being revisited.
    """

    # Exercises every binding form: plain let, tuple destructuring,
    # struct pattern (explicit field sub-pattern AND shorthand), var,
    # reassignment, lambda params, for-loop pattern, match arms with
    # variant payloads, literal and wildcard sub-patterns, and a bound
    # or-pattern (alternatives binding the same name via IdentPat).
    _SRC = (
        "type Pt { x: Int, y: Int }\n"
        "\n"
        "type Box =\n"
        "    One(Int)\n"
        "    Two(Int, Int)\n"
        "    Nil\n"
        "\n"
        "fun everything(pt: Pt, b: Box) -> Int\n"
        "    let plain = 1\n"
        "    let (ta, tb) = (2, 3)\n"
        "    let Pt { x: ex, y } = pt\n"
        "    var mut_name = 4\n"
        "    mut_name = 5\n"
        "    let f = fun(lam: Int) => lam + 1\n"
        "    var acc = 0\n"
        "    for it in [1, 2]\n"
        "        acc = acc + it\n"
        "    let m = match b\n"
        "        One(0) -> 0\n"
        "        One(payload) -> payload\n"
        "        Two(s, _) -> s\n"
        "        Nil -> 9\n"
        "    let o = match b\n"
        "        One(shared) | Two(shared, _) -> shared\n"
        "        _ -> 0\n"
        "    return plain + ta + tb + ex + y + mut_name + f(1) + acc + m + o\n"
    )

    # Every name the program above actually binds locally.
    _EXPECTED = {
        "plain", "ta", "tb", "ex", "y", "mut_name", "f", "lam",
        "acc", "it", "payload", "s", "shared", "m", "o",
    }

    def _fun_decl(self):
        module = _module_from_source(self._SRC)
        return next(
            it for it in module.items
            if isinstance(it, A.FunDecl) and it.name == "everything"
        )

    @staticmethod
    def _walk(node):
        """Generic AST walk mirroring the collector's traversal."""
        yield node
        for fld in node.__dataclass_fields__.values():
            if fld.name == "pos":
                continue
            v = getattr(node, fld.name)
            if isinstance(v, A.Node):
                yield from TestBoundNameCollectorParserSync._walk(v)
            elif isinstance(v, list):
                for item in v:
                    if isinstance(item, A.Node):
                        yield from TestBoundNameCollectorParserSync._walk(item)
                    elif isinstance(item, tuple):
                        for it in item:
                            if isinstance(it, A.Node):
                                yield from (
                                    TestBoundNameCollectorParserSync._walk(it)
                                )

    def test_collector_sees_every_binding_form(self):
        decl = self._fun_decl()
        collected: set = set()
        _collect_bound_names(decl.body, collected)
        self.assertEqual(
            self._EXPECTED - collected, set(),
            "binding form(s) invisible to _collect_bound_names",
        )

    def test_program_exercises_every_pattern_class(self):
        # If the AST grows a new Pattern subclass, this fails until the
        # program above (and, if the form binds names, the collector)
        # is updated, so a future binding form cannot slip by silently.
        def all_subclasses(cls):
            out = set()
            for sub in cls.__subclasses__():
                out.add(sub)
                out |= all_subclasses(sub)
            return out

        decl = self._fun_decl()
        seen = {
            type(n) for n in self._walk(decl) if isinstance(n, A.Pattern)
        }
        self.assertEqual(
            all_subclasses(A.Pattern), seen,
            "pattern form not exercised by the sync program",
        )


class TestPerFileBreakdown(unittest.TestCase):
    """Slice 3: the report decomposes the progress by source file and
    recommends the next file to harden (fewest functions genuinely
    using Unsafe first, i.e. still-using minus removable; clean files
    omitted; ties broken by ascending removable count, then
    declaration order).

    Drives the real loader through tmpdir source files, the same
    harness ``tests/test_loader.py`` / ``tests/test_manifest.py`` use,
    so imported functions group by the file they were actually
    declared in (their ``pos.filename``), not the root file.
    """

    def _tmpdir(self) -> Path:
        d = Path(tempfile.mkdtemp(prefix="capa_migrate_files_test_"))
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        return d

    def _write(self, root: Path, name: str, body: str) -> Path:
        p = root / name
        p.write_text(body, encoding="utf-8")
        return p

    def _report_for(self, root: Path) -> dict:
        from capa.loader import ModuleLoader
        loader = ModuleLoader()
        source = root.read_text(encoding="utf-8")
        linked = loader.load_root(source, str(root))
        result = analyze(
            linked.module, source=source, filename=str(root),
            sources=linked.sources,
            module_privates=linked.module_privates,
        )
        assert result.ok, result.errors
        return migrate_report(linked.module, filename=str(root))

    def _project(self) -> dict:
        """Three files: util (1 bridge + 1 dead + 1 clean), extra
        (1 bridge), root (clean main)."""
        d = self._tmpdir()
        self._write(
            d, "util.capa",
            "pub fun u_bridge(u: Unsafe)\n"
            "    let m = py_import(u, \"os\")\n"
            "\n"
            "pub fun u_dead(_u: Unsafe) -> Int\n"
            "    return 1\n"
            "\n"
            "pub fun u_clean() -> Int\n"
            "    return 2\n",
        )
        self._write(
            d, "extra.capa",
            "pub fun e_one(u: Unsafe)\n"
            "    let m = py_import(u, \"json\")\n",
        )
        root = self._write(
            d, "root.capa",
            "import util\n"
            "import extra\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"hi\")\n",
        )
        return self._report_for(root)

    def _by_basename(self, rep: dict) -> dict:
        return {Path(e["file"]).name: e for e in rep["files"]}

    def test_functions_group_by_their_declaring_file(self):
        rep = self._project()
        files = self._by_basename(rep)
        self.assertEqual(
            set(files), {"util.capa", "extra.capa", "root.capa"},
        )
        # Imported functions land under their own file, with the
        # file's real totals; the root file only holds main.
        self.assertEqual(files["util.capa"]["total_functions"], 3)
        self.assertEqual(files["extra.capa"]["total_functions"], 1)
        self.assertEqual(files["root.capa"]["total_functions"], 1)

    def test_imported_function_pos_points_into_its_own_file(self):
        # Regression for the manifest pos bug: imported declarations
        # used to report the ROOT file's name with the imported file's
        # line numbers. u_dead is declared in util.capa line 4.
        rep = self._project()
        dead = next(
            r for r in rep["removable"] if r["source_name"] == "u_dead"
        )
        self.assertEqual(Path(dead["pos"].rsplit(":", 2)[0]).name, "util.capa")
        candidate_files = {
            Path(c["pos"].rsplit(":", 2)[0]).name
            for c in rep["next_candidates"]
        }
        self.assertEqual(candidate_files, {"util.capa", "extra.capa"})

    def test_per_file_counts_and_percentages(self):
        rep = self._project()
        files = self._by_basename(rep)
        util = files["util.capa"]
        self.assertEqual(util["functions_using_unsafe"], 2)
        self.assertEqual(util["functions_removable_unsafe"], 1)
        self.assertEqual(util["percent_unsafe_free"], 33)
        extra = files["extra.capa"]
        self.assertEqual(extra["functions_using_unsafe"], 1)
        self.assertEqual(extra["functions_removable_unsafe"], 0)
        self.assertEqual(extra["percent_unsafe_free"], 0)
        root = files["root.capa"]
        self.assertEqual(root["functions_using_unsafe"], 0)
        self.assertEqual(root["percent_unsafe_free"], 100)

    def test_ranking_fewest_genuine_unsafe_first_and_clean_files_omitted(self):
        rep = self._project()
        ranking = [Path(f).name for f in rep["file_ranking"]]
        # Both have 1 function genuinely using Unsafe (util's second
        # one is removable, which must not count against it); the tie
        # breaks on ascending removable count (extra 0, util 1). The
        # clean root.capa is done and must not appear at all.
        self.assertEqual(ranking, ["extra.capa", "util.capa"])

    def test_dead_only_file_outranks_genuine_bridge_file(self):
        # A file whose ONLY Unsafe is removable costs nearly nothing
        # to finish, so it must come before a file with a genuine
        # bridge call, even though both have one function "still
        # using" Unsafe and the bridge file is declared first (the
        # old still-using criterion would have ranked bridge.capa
        # first on declaration order).
        d = self._tmpdir()
        self._write(
            d, "bridge.capa",
            "pub fun b_one(u: Unsafe)\n"
            "    let m = py_import(u, \"os\")\n",
        )
        self._write(
            d, "deadonly.capa",
            "pub fun d_dead(_u: Unsafe) -> Int\n"
            "    return 1\n",
        )
        root = self._write(
            d, "root.capa",
            "import bridge\n"
            "import deadonly\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"hi\")\n",
        )
        rep = self._report_for(root)
        ranking = [Path(f).name for f in rep["file_ranking"]]
        self.assertEqual(ranking, ["deadonly.capa", "bridge.capa"])
        # The human rendering must say naturally that only removable
        # Unsafe is left in the recommended file, not the awkward
        # "0 functions genuinely using Unsafe".
        out = render_report(rep)
        next_line = next(
            ln for ln in out.splitlines() if "Next file to harden:" in ln
        )
        self.assertIn("deadonly.capa", next_line)
        self.assertIn("only removable Unsafe left, in 1 function", next_line)
        self.assertNotIn("genuinely using", next_line)

    def test_next_file_with_genuine_unsafe_keeps_genuine_phrasing(self):
        # Counterpart of the dead-only case: a recommended file with a
        # real bridge call still reports its genuine count.
        rep = self._project()
        out = render_report(rep)
        next_line = next(
            ln for ln in out.splitlines() if "Next file to harden:" in ln
        )
        self.assertIn("1 function genuinely using Unsafe", next_line)
        self.assertNotIn("only removable", next_line)

    def test_genuine_tie_breaks_on_fewer_removables(self):
        # Same genuine count (1 each); the file with fewer removable
        # entries is less total work and must come first even though
        # it is declared second.
        d = self._tmpdir()
        self._write(
            d, "mixed.capa",
            "pub fun m_bridge(u: Unsafe)\n"
            "    let m = py_import(u, \"os\")\n"
            "\n"
            "pub fun m_dead(_u: Unsafe) -> Int\n"
            "    return 1\n",
        )
        self._write(
            d, "pure.capa",
            "pub fun p_bridge(u: Unsafe)\n"
            "    let m = py_import(u, \"json\")\n",
        )
        root = self._write(
            d, "root.capa",
            "import mixed\n"
            "import pure\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"hi\")\n",
        )
        rep = self._report_for(root)
        ranking = [Path(f).name for f in rep["file_ranking"]]
        self.assertEqual(ranking, ["pure.capa", "mixed.capa"])

    def test_per_file_paths_are_root_relative_posix(self):
        # Reproducibility: the report's per-file paths (and every
        # per-entry pos) are root-relative with '/' separators, never
        # the loader's machine-specific absolute paths, so the same
        # project reports identically on any machine and OS.
        d = self._tmpdir()
        (d / "sub").mkdir()
        self._write(
            d / "sub", "inner.capa",
            "pub fun s_one(u: Unsafe)\n"
            "    let m = py_import(u, \"os\")\n",
        )
        root = self._write(
            d, "root.capa",
            "import sub.inner\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"hi\")\n",
        )
        rep = self._report_for(root)
        files = {e["file"] for e in rep["files"]}
        self.assertEqual(files, {"sub/inner.capa", "root.capa"})
        self.assertEqual(rep["file_ranking"], ["sub/inner.capa"])
        for c in rep["next_candidates"]:
            self.assertNotIn("\\", c["pos"])
            self.assertFalse(Path(c["pos"].rsplit(":", 2)[0]).is_absolute())

    def test_summary_still_covers_the_whole_program(self):
        # Backwards compatibility: every pre-slice-3 key keeps its
        # program-wide meaning; the breakdown is purely additive.
        rep = self._project()
        self.assertEqual(rep["summary"]["total_functions"], 5)
        self.assertEqual(rep["summary"]["functions_using_unsafe"], 3)
        self.assertEqual(rep["summary"]["functions_removable_unsafe"], 1)
        self.assertEqual(rep["summary"]["percent_unsafe_free"], 40)
        for key in ("file", "summary", "removable", "next_candidates",
                    "files", "file_ranking"):
            self.assertIn(key, rep)
        json.dumps(rep)  # still JSON-serialisable

    def test_multi_file_render_has_breakdown_and_next_file(self):
        rep = self._project()
        out = render_report(rep)
        self.assertIn("Per-file progress:", out)
        self.assertIn("Next file to harden:", out)
        # The recommendation names the top-ranked file.
        next_line = next(
            ln for ln in out.splitlines() if "Next file to harden:" in ln
        )
        self.assertIn("extra.capa", next_line)

    def test_report_file_and_header_use_display_form(self):
        # Reproducibility finish: the JSON ``file`` field and the
        # rendered "Migration progress for ..." header show the same
        # root-relative display form as the pos lines (the basename
        # for the root file), never the native-separator absolute
        # path the command was invoked with.
        d = self._tmpdir()
        root = self._write(
            d, "root.capa",
            "pub fun d_dead(_u: Unsafe) -> Int\n"
            "    return 1\n",
        )
        rep = self._report_for(root)  # invoked with the absolute path
        self.assertEqual(rep["file"], "root.capa")
        out = render_report(rep)
        self.assertEqual(
            out.splitlines()[0], "Migration progress for root.capa",
        )

    def test_single_file_render_has_no_per_file_section(self):
        # A single-file program must render exactly as before slice 3:
        # no per-file section, no next-file recommendation.
        rep = _report_for_example("migrate_logfetcher_step2_mixed.capa")
        self.assertEqual(len(rep["files"]), 1)
        out = render_report(rep)
        self.assertNotIn("Per-file", out)
        self.assertNotIn("Next file to harden", out)


class TestRenderAndDispatch(unittest.TestCase):
    def test_render_is_nonempty_text(self):
        rep = _report_for_example("migrate_logfetcher_step2_mixed.capa")
        out = render_report(rep)
        self.assertIn("Migration progress", out)
        self.assertIn("Unsafe-free", out)

    def test_render_tolerates_pre_slice3_report_without_files_keys(self):
        # A report serialised before slice 3 (e.g. stored JSON re-fed
        # to the renderer) has no files / file_ranking keys; rendering
        # must not crash and must keep the program-wide sections.
        rep = _report_for_example("migrate_logfetcher_step2_mixed.capa")
        del rep["files"]
        del rep["file_ranking"]
        out = render_report(rep)
        self.assertIn("Migration progress", out)
        self.assertNotIn("Per-file", out)

    def test_dispatch_json_is_valid(self):
        # The CLI --json path must emit parseable JSON with the
        # documented keys.
        import io
        import contextlib
        from capa.cli import _dispatch_migrate
        path = _EXAMPLES / "migrate_logfetcher_step2_mixed.capa"
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = _dispatch_migrate([str(path), "--json"])
        self.assertEqual(rc, 0)
        payload = json.loads(buf.getvalue())
        self.assertIn("summary", payload)
        self.assertIn("removable", payload)
        self.assertIn("next_candidates", payload)
        self.assertIn("percent_unsafe_free", payload["summary"])

    def test_dispatch_missing_file_errors(self):
        from capa.cli import _dispatch_migrate
        rc = _dispatch_migrate(["does_not_exist_xyz.capa"])
        self.assertNotEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
