"""Soundness harness for the inter-procedural ``--wasi`` ceiling
const-propagation (:mod:`capa.ir._wasi_const_prop`).

The const-prop layer propagates a string literal along the call chain to
an ``Fs`` / ``Net`` / ``Env`` sink, so a path / url / key routed through a
helper (``read_json(fs, path)`` doing ``fs.read(path)``, the literal named
several frames away) resolves to the right preopen / host / key instead of
being fail-closed. The resolved literal set is a SECURITY FRONTIER: an
over-grant (a literal the ceiling materialises that does NOT actually reach
the sink) silently widens authority, which is worse than a refusal.

This harness is the oracle-first safety net. For every program in the
corpus the GROUND TRUTH is the EXACT set of literals that genuinely reach
each sink class, plus whether some genuinely-computed value also reaches it
(``dynamic``). The two soundness assertions, per program per cap:

* SUBSET-NOT-SUPERSET: the analysis's resolved literal set is a SUBSET of
  the ground-truth reaching set. A superset is a fail-OPEN over-grant and
  fails the harness. (Equality is the precise outcome; a strict subset is a
  sound conservative under-approximation, allowed.)

* CLOSED IFF NO COMPUTED: the analysis reports ``dynamic`` whenever the
  ground truth has a genuinely-computed reaching value. Reporting a sink as
  resolvable (not dynamic) when a computed value reaches it is the OTHER
  fail-open shape (it would let a ceiling close on an incomplete set), so
  ``ground_truth.dynamic`` implies ``analysis.dynamic``. (The analysis MAY
  be more conservative -- report dynamic when the ground truth is not --
  which only refuses, never over-grants.)

If any program trips either assertion the const-prop is unsound and must
not ship.
"""

from __future__ import annotations

import unittest
from dataclasses import dataclass

from capa import Lexer, Parser
from capa.ir._wasi_const_prop import resolve_sink_literals, FS_CAP, NET_CAP, \
    ENV_CAP


@dataclass(frozen=True)
class Truth:
    """Ground truth for one sink capability class in one program: the
    EXACT literals that genuinely reach the sink, and whether a genuinely
    computed value also reaches it."""

    literals: frozenset
    dynamic: bool


def _t(literals=(), dynamic=False) -> Truth:
    return Truth(literals=frozenset(literals), dynamic=dynamic)


# ---- corpus ---------------------------------------------------------
#
# Each entry: (name, source, {cap: Truth}). Only the caps a program
# touches need a Truth; an omitted cap defaults to "no literals, not
# dynamic" (the resolver returns the same for an unused cap).

_CORPUS: list[tuple[str, str, dict]] = []


def _case(name: str, src: str, truths: dict) -> None:
    _CORPUS.append((name, src, truths))


# --- direct literal at the sink slot (the pre-existing supported shape):
# must keep resolving exactly, never regress.
_case(
    "direct_literal",
    """
fun main(fs: Fs)
    let _ = match fs.read("data.json") { Err(_) -> "", Ok(s) -> s }
""",
    {FS_CAP: _t({"data.json"})},
)

# --- the MOTIVATING case: literal routed through a single helper frame.
_case(
    "single_helper_routing",
    """
fun read_json(fs: Fs, path: String) -> String
    return match fs.read(path) { Err(_) -> "", Ok(s) -> s }
fun main(fs: Fs)
    let _ = read_json(fs, "data.json")
""",
    {FS_CAP: _t({"data.json"})},
)

# --- multi-level chain (main -> run -> parse -> read_json -> fs.read).
_case(
    "multi_level_chain",
    """
fun read_json(fs: Fs, path: String) -> String
    return match fs.read(path) { Err(_) -> "", Ok(s) -> s }
fun parse(fs: Fs, path: String) -> String
    return read_json(fs, path)
fun run(fs: Fs, p: String) -> String
    return parse(fs, p)
fun main(fs: Fs)
    let sbom_path = "data/sample.json"
    let _ = run(fs, sbom_path)
""",
    {FS_CAP: _t({"data/sample.json"})},
)

# --- multiple call sites with DIFFERENT literals -> UNION (all preopens).
_case(
    "union_over_call_sites",
    """
fun rd(fs: Fs, path: String) -> String
    return match fs.read(path) { Err(_) -> "", Ok(s) -> s }
fun main(fs: Fs)
    let _ = rd(fs, "a.json")
    let _ = rd(fs, "b.json")
    let _ = rd(fs, "c.json")
""",
    {FS_CAP: _t({"a.json", "b.json", "c.json"})},
)

# --- mixed literal + computed reaching the SAME sink -> DYNAMIC (fail
# closed). The literal MUST NOT be materialised in isolation: a sink that
# can also receive a computed value is genuinely dynamic.
_case(
    "mixed_literal_and_computed",
    """
fun rd(fs: Fs, path: String) -> String
    return match fs.read(path) { Err(_) -> "", Ok(s) -> s }
fun main(fs: Fs, x: String)
    let _ = rd(fs, "a.json")
    let _ = rd(fs, x)
""",
    {FS_CAP: _t(set(), dynamic=True)},
)

# --- interpolation with a substitution -> computed -> DYNAMIC.
_case(
    "interpolation_is_dynamic",
    """
fun main(fs: Fs)
    let name = "x"
    let _ = match fs.read("data/${name}.json") { Err(_) -> "", Ok(s) -> s }
""",
    {FS_CAP: _t(set(), dynamic=True)},
)

# --- concatenation -> computed -> DYNAMIC.
_case(
    "concat_is_dynamic",
    """
fun main(fs: Fs, base: String)
    let p = base + "/x.json"
    let _ = match fs.read(p) { Err(_) -> "", Ok(s) -> s }
""",
    {FS_CAP: _t(set(), dynamic=True)},
)

# --- a function result feeding the sink -> computed -> DYNAMIC.
_case(
    "fn_result_is_dynamic",
    """
fun pick() -> String
    return "computed.json"
fun main(fs: Fs)
    let p = pick()
    let _ = match fs.read(p) { Err(_) -> "", Ok(s) -> s }
""",
    {FS_CAP: _t(set(), dynamic=True)},
)

# --- an entry-point parameter (value from OUTSIDE the program) -> DYNAMIC.
_case(
    "external_param_is_dynamic",
    """
fun main(fs: Fs, p: String)
    let _ = match fs.read(p) { Err(_) -> "", Ok(s) -> s }
""",
    {FS_CAP: _t(set(), dynamic=True)},
)

# --- local let fold (the (a) case): a literal bound to a let in the
# sink's own frame.
_case(
    "local_let_fold",
    """
fun main(fs: Fs)
    let p = "local.json"
    let _ = match fs.read(p) { Err(_) -> "", Ok(s) -> s }
""",
    {FS_CAP: _t({"local.json"})},
)

# --- module const fold.
_case(
    "module_const_fold",
    """
const CFG: String = "cfg.json"
fun main(fs: Fs)
    let _ = match fs.read(CFG) { Err(_) -> "", Ok(s) -> s }
""",
    {FS_CAP: _t({"cfg.json"})},
)

# --- a non-trivial const (NOT a plain literal) stays DYNAMIC.
_case(
    "computed_const_is_dynamic",
    """
const A: String = "a"
const B: String = "${A}.json"
fun main(fs: Fs)
    let _ = match fs.read(B) { Err(_) -> "", Ok(s) -> s }
""",
    {FS_CAP: _t(set(), dynamic=True)},
)

# --- mutual recursion in the routing chain (cycle guard must terminate
# and resolve the literal).
_case(
    "mutual_recursion_cycle",
    """
fun a(fs: Fs, p: String) -> String
    return b(fs, p)
fun b(fs: Fs, p: String) -> String
    let _ = match fs.read(p) { Err(_) -> "", Ok(s) -> s }
    return a(fs, p)
fun main(fs: Fs)
    let _ = a(fs, "cyc.json")
""",
    {FS_CAP: _t({"cyc.json"})},
)

# --- reassigned local -> DYNAMIC (a later store can only widen
# uncertainty).
_case(
    "reassigned_local_is_dynamic",
    """
fun main(fs: Fs, x: String)
    var p = "a.json"
    p = x
    let _ = match fs.read(p) { Err(_) -> "", Ok(s) -> s }
""",
    {FS_CAP: _t(set(), dynamic=True)},
)

# --- a path routed through a METHOD is conservatively DYNAMIC (the
# safe default for dynamic-dispatch / receiver-unknown method calls).
_case(
    "method_routing_is_dynamic",
    """
type Reader { tag: Int }
impl Reader
    fun load(self, fs: Fs, path: String) -> String
        return match fs.read(path) { Err(_) -> "", Ok(s) -> s }
fun main(fs: Fs)
    let r = Reader { tag: 0 }
    let _ = r.load(fs, "via_method.json")
""",
    {FS_CAP: _t(set(), dynamic=True)},
)

# --- Net: literal url routed through a helper resolves; the host is
# derived by the ceiling from the literal, so the literal set is what the
# harness checks.
_case(
    "net_helper_routing",
    """
fun fetch(net: Net, url: String) -> String
    return match net.get(url) { Err(_) -> "", Ok(s) -> s }
fun main(net: Net)
    let _ = fetch(net, "https://api.example.com/v1")
""",
    {NET_CAP: _t({"https://api.example.com/v1"})},
)

# --- Net dynamic url through a helper -> DYNAMIC.
_case(
    "net_dynamic_is_dynamic",
    """
fun fetch(net: Net, url: String) -> String
    return match net.get(url) { Err(_) -> "", Ok(s) -> s }
fun main(net: Net, host: String)
    let _ = fetch(net, "https://${host}/v1")
""",
    {NET_CAP: _t(set(), dynamic=True)},
)

# --- Env: literal key routed through a helper resolves.
_case(
    "env_helper_routing",
    """
fun lookup(env: Env, key: String) -> String
    return match env.get(key) { None -> "", Some(v) -> v }
fun main(env: Env)
    let _ = lookup(env, "HOME")
""",
    {ENV_CAP: _t({"HOME"})},
)

# --- Env dynamic key through a helper -> DYNAMIC (the host falls back to
# inherit_env).
_case(
    "env_dynamic_is_dynamic",
    """
fun lookup(env: Env, key: String) -> String
    return match env.get(key) { None -> "", Some(v) -> v }
fun main(env: Env, k: String)
    let _ = lookup(env, k)
""",
    {ENV_CAP: _t(set(), dynamic=True)},
)

# --- a single sink reached by BOTH a literal-routing path and a
# dynamic-routing path through the SAME helper -> DYNAMIC (the union of
# call sites contains a computed one).
_case(
    "helper_shared_literal_and_dynamic",
    """
fun rd(fs: Fs, path: String) -> String
    return match fs.read(path) { Err(_) -> "", Ok(s) -> s }
fun viaLit(fs: Fs) -> String
    return rd(fs, "lit.json")
fun viaDyn(fs: Fs, x: String) -> String
    return rd(fs, x)
fun main(fs: Fs, x: String)
    let _ = viaLit(fs)
    let _ = viaDyn(fs, x)
""",
    {FS_CAP: _t(set(), dynamic=True)},
)

# --- two INDEPENDENT helpers, each fully literal, two distinct preopens
# -> union resolves, not dynamic.
_case(
    "two_independent_literal_helpers",
    """
fun rd(fs: Fs, path: String) -> String
    return match fs.read(path) { Err(_) -> "", Ok(s) -> s }
fun main(fs: Fs)
    let _ = rd(fs, "one/a.json")
    let _ = rd(fs, "two/b.json")
""",
    {FS_CAP: _t({"one/a.json", "two/b.json"})},
)

# --- LITERAL INSIDE A LAMBDA BODY: after the ``_child_exprs`` fix the
# const-prop now visits lambda bodies (so the surface no longer omits
# lambda-body sinks). The literal here GENUINELY reaches ``fs.read``, so
# resolving it is correct and conservative -- it must stay subset-not-
# superset (no extra preopen materialised). This locks that the
# `_child_exprs` change does NOT cause the const-prop to over-grant.
_case(
    "literal_in_lambda_body",
    """
fun main(fs: Fs, env: Env)
    let args = env.args()
    let _ = args.map(fun (a) => match fs.read("in_lambda.json") { Err(_) -> "", Ok(s) -> s })
""",
    {FS_CAP: _t({"in_lambda.json"})},
)

# --- a DYNAMIC value (the lambda parameter) reaching a sink inside the
# lambda body -> DYNAMIC (fail-closed; the body is now visited, so this
# must report dynamic, not silently resolve nothing).
_case(
    "dynamic_in_lambda_body",
    """
fun main(fs: Fs, env: Env)
    let args = env.args()
    let _ = args.map(fun (a) => match fs.read(a) { Err(_) -> "", Ok(s) -> s })
""",
    {FS_CAP: _t(set(), dynamic=True)},
)


class TestConstPropSoundness(unittest.TestCase):
    """Per-program subset-not-superset + closed-iff-no-computed checks."""

    def _resolve(self, src: str) -> dict:
        module = Parser(Lexer(src).lex(), source=src).parse_module()
        return resolve_sink_literals(module)

    def test_corpus_is_sound(self) -> None:
        failures: list[str] = []
        for name, src, truths in _CORPUS:
            res = self._resolve(src)
            for cap in (FS_CAP, NET_CAP, ENV_CAP):
                truth = truths.get(cap, _t())
                got = res[cap]
                # SUBSET-NOT-SUPERSET: never materialise a literal that
                # does not genuinely reach the sink.
                if not got.literals <= truth.literals:
                    over = got.literals - truth.literals
                    failures.append(
                        f"{name}[{cap}]: OVER-GRANT (superset) -- "
                        f"resolved {sorted(over)} not in ground truth "
                        f"{sorted(truth.literals)}"
                    )
                # CLOSED IFF NO COMPUTED: a genuinely-computed reaching
                # value must be reported dynamic (fail-closed).
                if truth.dynamic and not got.dynamic:
                    failures.append(
                        f"{name}[{cap}]: FAIL-OPEN -- ground truth has a "
                        f"computed reaching value but analysis reports "
                        f"not dynamic"
                    )
        if failures:
            self.fail(
                "const-prop soundness violations:\n  "
                + "\n  ".join(failures)
            )

    def test_motivating_case_resolves_exactly(self) -> None:
        # The flagship helper-routing case resolves to EXACTLY the literal
        # (not a strict subset), proving the layer actually closes the
        # ceiling rather than just staying safe by refusing.
        res = self._resolve(
            """
fun read_json(fs: Fs, path: String) -> String
    return match fs.read(path) { Err(_) -> "", Ok(s) -> s }
fun main(fs: Fs)
    let _ = read_json(fs, "data.json")
"""
        )
        self.assertEqual(res[FS_CAP].literals, frozenset({"data.json"}))
        self.assertFalse(res[FS_CAP].dynamic)


if __name__ == "__main__":
    unittest.main()
