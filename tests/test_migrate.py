"""Tests for ``capa migrate`` gradual-hardening progress reporting."""

import json
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

    def test_token_smuggled_via_cap_bearing_struct_is_not_removable(self):
        # pack embeds the token in a cap-bearing struct it returns; the
        # signature-poison rule must keep the whole chain non-removable
        # even though no bridge call is syntactically in sight.
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
        rep = migrate_report(_module_from_source(src))
        self.assertEqual(rep["removable"], [])


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


class TestRenderAndDispatch(unittest.TestCase):
    def test_render_is_nonempty_text(self):
        rep = _report_for_example("migrate_logfetcher_step2_mixed.capa")
        out = render_report(rep)
        self.assertIn("Migration progress", out)
        self.assertIn("Unsafe-free", out)

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
